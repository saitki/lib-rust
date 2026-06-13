//! PORTMAP v2 (RFC 1833 / rpcbind), programa 100000.
//!
//! Implementa los procedimientos que usa libnfs para descubrir puertos:
//! `GETPORT` y `DUMP`. (rpcbind v3/v4 `GETADDR` con direcciones universales
//! para IPv6 es una extensión prevista; ver `FASE-03`.)

use nfs_rpc::RpcClient;
use nfs_xdr::{Bytes, XdrDecode, XdrEncode, XdrError};

use crate::error::ProtoError;

/// Número de programa de PORTMAP/rpcbind.
pub const PROGRAM: u32 = 100000;
/// Versión 2 del protocolo PORTMAP.
pub const VERSION2: u32 = 2;

/// `IPPROTO_TCP` para el campo `prot` de un `mapping`.
pub const IPPROTO_TCP: u32 = 6;
/// `IPPROTO_UDP` para el campo `prot` de un `mapping`.
pub const IPPROTO_UDP: u32 = 17;

const PMAPPROC_GETPORT: u32 = 3;
const PMAPPROC_DUMP: u32 = 4;

/// Un registro `mapping` del portmapper.
#[derive(XdrEncode, XdrDecode, Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// Número de programa RPC.
    pub prog: u32,
    /// Versión del programa.
    pub vers: u32,
    /// Protocolo de transporte (`IPPROTO_TCP`/`IPPROTO_UDP`).
    pub prot: u32,
    /// Puerto registrado (0 si se consulta).
    pub port: u32,
}

/// Lista de `mapping` devuelta por `DUMP` (lista enlazada XDR `*pmaplist`).
#[derive(Debug, Clone)]
pub struct PortmapList(pub Vec<Mapping>);

impl XdrDecode for PortmapList {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let mut entries = Vec::new();
        while bool::decode(buf)? {
            entries.push(Mapping::decode(buf)?);
        }
        Ok(PortmapList(entries))
    }
}

/// Consulta el puerto en el que está registrado `(prog, vers, prot)`.
///
/// Devuelve `Err(PortNotRegistered)` si el portmapper responde con puerto 0.
pub fn getport(client: &mut RpcClient, prog: u32, vers: u32, prot: u32) -> Result<u16, ProtoError> {
    let query = Mapping {
        prog,
        vers,
        prot,
        port: 0,
    };
    let port: u32 = client.call(PROGRAM, VERSION2, PMAPPROC_GETPORT, &query)?;
    if port == 0 {
        return Err(ProtoError::PortNotRegistered { prog, vers });
    }
    Ok(port as u16)
}

/// Lista todos los servicios registrados en el portmapper.
pub fn dump(client: &mut RpcClient) -> Result<Vec<Mapping>, ProtoError> {
    let list: PortmapList = client.call(PROGRAM, VERSION2, PMAPPROC_DUMP, &())?;
    Ok(list.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfs_xdr::from_bytes;

    #[test]
    fn decode_pmaplist_linked_list() {
        // Dos entradas seguidas de terminador (bool=0).
        #[rustfmt::skip]
        let wire: &[u8] = &[
            0, 0, 0, 1,                          // present
            0, 1, 0x86, 0xA3,  0, 0, 0, 3,  0, 0, 0, 6,  0, 0, 8, 1, // NFS v3 TCP :2049
            0, 0, 0, 1,                          // present
            0, 1, 0x86, 0xA5,  0, 0, 0, 3,  0, 0, 0, 6,  0, 0, 2, 0x7C, // MOUNT v3 TCP :636
            0, 0, 0, 0,                          // terminador
        ];
        let list: PortmapList = from_bytes(Bytes::copy_from_slice(wire)).unwrap();
        assert_eq!(list.0.len(), 2);
        assert_eq!(list.0[0].prog, 100003);
        assert_eq!(list.0[0].port, 2049);
        assert_eq!(list.0[1].prog, 100005);
        assert_eq!(list.0[1].port, 0x27C);
    }
}
