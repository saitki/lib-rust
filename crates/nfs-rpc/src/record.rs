//! Record marking de ONC-RPC sobre flujos (TCP), RFC 5531 §11.
//!
//! Cada registro RPC se transmite como una secuencia de fragmentos. Cada
//! fragmento lleva una cabecera de 4 bytes (big-endian): el bit más alto marca
//! el último fragmento y los 31 bits restantes son la longitud de datos.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::RpcError;

const LAST_FRAGMENT: u32 = 0x8000_0000;
const LENGTH_MASK: u32 = 0x7FFF_FFFF;

/// Tamaño máximo de un registro reensamblado (protección anti-OOM). 16 MiB
/// cubre con holgura los `rsize`/`wsize` habituales de NFS.
pub const DEFAULT_MAX_RECORD: usize = 16 * 1024 * 1024;

/// Envuelve `record` en un único fragmento marcado como último (para enviar).
pub fn frame(record: &[u8]) -> Result<Bytes, RpcError> {
    if record.len() > LENGTH_MASK as usize {
        return Err(RpcError::RecordTooLarge);
    }
    let mut out = BytesMut::with_capacity(record.len() + 4);
    out.put_u32(LAST_FRAGMENT | record.len() as u32);
    out.put_slice(record);
    Ok(out.freeze())
}

/// Reensambla registros RPC a partir de un flujo de bytes posiblemente
/// fragmentado de forma arbitraria.
#[derive(Debug)]
pub struct RecordReassembler {
    stream: BytesMut,
    record: BytesMut,
    frag_remaining: Option<usize>,
    last_fragment: bool,
    max_record: usize,
}

impl Default for RecordReassembler {
    fn default() -> Self {
        Self::with_max(DEFAULT_MAX_RECORD)
    }
}

impl RecordReassembler {
    /// Crea un reensamblador con el límite por defecto.
    pub fn new() -> Self {
        Self::default()
    }

    /// Crea un reensamblador con un límite de tamaño de registro explícito.
    pub fn with_max(max_record: usize) -> Self {
        Self {
            stream: BytesMut::new(),
            record: BytesMut::new(),
            frag_remaining: None,
            last_fragment: false,
            max_record,
        }
    }

    /// Añade bytes recién leídos del socket.
    pub fn push(&mut self, data: &[u8]) {
        self.stream.put_slice(data);
    }

    /// Devuelve el siguiente registro completo, o `None` si aún no hay
    /// suficientes bytes.
    pub fn next_record(&mut self) -> Result<Option<Bytes>, RpcError> {
        loop {
            match self.frag_remaining {
                None => {
                    if self.stream.len() < 4 {
                        return Ok(None);
                    }
                    let header = u32::from_be_bytes([
                        self.stream[0],
                        self.stream[1],
                        self.stream[2],
                        self.stream[3],
                    ]);
                    self.stream.advance(4);
                    self.last_fragment = header & LAST_FRAGMENT != 0;
                    let len = (header & LENGTH_MASK) as usize;
                    if self.record.len() + len > self.max_record {
                        return Err(RpcError::RecordTooLarge);
                    }
                    self.frag_remaining = Some(len);
                }
                Some(0) => {
                    if self.last_fragment {
                        let complete = std::mem::take(&mut self.record).freeze();
                        self.frag_remaining = None;
                        self.last_fragment = false;
                        return Ok(Some(complete));
                    }
                    // Fragmento intermedio consumido: leer la siguiente cabecera.
                    self.frag_remaining = None;
                }
                Some(remaining) => {
                    if self.stream.is_empty() {
                        return Ok(None);
                    }
                    let take = remaining.min(self.stream.len());
                    let chunk = self.stream.split_to(take);
                    self.record.put_slice(&chunk);
                    self.frag_remaining = Some(remaining - take);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_fragment_roundtrip() {
        let framed = frame(&[1, 2, 3, 4]).unwrap();
        let mut r = RecordReassembler::new();
        r.push(&framed);
        let rec = r.next_record().unwrap().unwrap();
        assert_eq!(&rec[..], &[1, 2, 3, 4]);
        assert!(r.next_record().unwrap().is_none());
    }

    #[test]
    fn byte_by_byte_feeding() {
        // Alimentar el flujo de un byte en un byte no debe producir registros
        // parciales ni errores.
        let framed = frame(&[10, 20, 30, 40, 50]).unwrap();
        let mut r = RecordReassembler::new();
        for (i, b) in framed.iter().enumerate() {
            r.push(&[*b]);
            let got = r.next_record().unwrap();
            if i + 1 < framed.len() {
                assert!(got.is_none(), "registro completado antes de tiempo");
            } else {
                assert_eq!(got.unwrap()[..], [10, 20, 30, 40, 50]);
            }
        }
    }

    #[test]
    fn two_records_concatenated() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&frame(&[1, 1]).unwrap());
        buf.extend_from_slice(&frame(&[2, 2, 2]).unwrap());
        let mut r = RecordReassembler::new();
        r.push(&buf);
        assert_eq!(r.next_record().unwrap().unwrap()[..], [1, 1]);
        assert_eq!(r.next_record().unwrap().unwrap()[..], [2, 2, 2]);
        assert!(r.next_record().unwrap().is_none());
    }

    #[test]
    fn multi_fragment_record() {
        // Registro partido en dos fragmentos manuales: [no-last "AB"] + [last "CD"].
        let mut buf = Vec::new();
        buf.extend_from_slice(&(2u32).to_be_bytes()); // fragmento no-último, len 2
        buf.extend_from_slice(b"AB");
        buf.extend_from_slice(&(LAST_FRAGMENT | 2).to_be_bytes()); // último, len 2
        buf.extend_from_slice(b"CD");
        let mut r = RecordReassembler::new();
        r.push(&buf);
        assert_eq!(&r.next_record().unwrap().unwrap()[..], b"ABCD");
    }

    #[test]
    fn record_too_large_is_rejected() {
        let mut r = RecordReassembler::with_max(4);
        let header = (LAST_FRAGMENT | 8).to_be_bytes();
        r.push(&header);
        assert!(matches!(r.next_record(), Err(RpcError::RecordTooLarge)));
    }
}
