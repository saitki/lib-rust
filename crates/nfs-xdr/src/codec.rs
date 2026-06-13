//! Funciones de bajo nivel del códec: relleno, comprobaciones de longitud,
//! `opaque` variable y helpers de conveniencia.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{XdrDecode, XdrEncode, XdrError};

/// Bytes de relleno necesarios para alinear `len` a múltiplo de 4 (RFC 4506).
#[inline]
pub(crate) fn padding(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

/// Verifica que quedan al menos `needed` bytes por leer.
#[inline]
pub(crate) fn ensure(buf: &Bytes, needed: usize) -> Result<(), XdrError> {
    let had = buf.remaining();
    if had < needed {
        Err(XdrError::Truncated { needed, had })
    } else {
        Ok(())
    }
}

/// Lee un `u32` XDR (big-endian, 4 bytes).
#[inline]
pub(crate) fn decode_u32(buf: &mut Bytes) -> Result<u32, XdrError> {
    ensure(buf, 4)?;
    Ok(buf.get_u32())
}

/// Codifica un `opaque<>` de longitud variable: prefijo de longitud + datos +
/// relleno a 4 bytes. `limit` es el máximo permitido por el esquema
/// (`usize::MAX` para «sin límite»).
pub fn encode_opaque(buf: &mut BytesMut, data: &[u8], limit: usize) -> Result<(), XdrError> {
    if data.len() > limit {
        return Err(XdrError::LimitExceeded {
            len: data.len(),
            limit,
        });
    }
    if data.len() > u32::MAX as usize {
        return Err(XdrError::LengthOverflow(data.len()));
    }
    buf.put_u32(data.len() as u32);
    buf.put_slice(data);
    buf.put_bytes(0, padding(data.len()));
    Ok(())
}

/// Decodifica un `opaque<>` de longitud variable de forma *zero-copy*: el
/// `Bytes` devuelto comparte el buffer de entrada sin copiar.
pub fn decode_opaque(buf: &mut Bytes, limit: usize) -> Result<Bytes, XdrError> {
    let len = decode_u32(buf)? as usize;
    if len > limit {
        return Err(XdrError::LimitExceeded { len, limit });
    }
    let pad = padding(len);
    // Acotar contra los bytes disponibles ANTES de cortar: evita OOM ante una
    // longitud maliciosa.
    ensure(buf, len + pad)?;
    let data = buf.split_to(len);
    buf.advance(pad);
    Ok(data)
}

/// Serializa un valor a un `Bytes` nuevo.
pub fn to_bytes<T: XdrEncode + ?Sized>(value: &T) -> Result<Bytes, XdrError> {
    let mut buf = BytesMut::new();
    value.encode(&mut buf)?;
    Ok(buf.freeze())
}

/// Deserializa un mensaje completo, exigiendo que no sobren bytes.
pub fn from_bytes<T: XdrDecode>(mut buf: Bytes) -> Result<T, XdrError> {
    let value = T::decode(&mut buf)?;
    if buf.has_remaining() {
        return Err(XdrError::TrailingData(buf.remaining()));
    }
    Ok(value)
}
