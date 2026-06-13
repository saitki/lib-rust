//! Protocolo MOUNT v3 (RFC 1813 apéndice I), programa 100005.
//!
//! Entrega el *file handle* raíz de un export y lista los exports del servidor.

use nfs_rpc::RpcClient;
use nfs_xdr::{decode_opaque, Bytes, XdrDecode, XdrError};

use crate::error::ProtoError;

/// Número de programa del protocolo MOUNT.
pub const PROGRAM: u32 = 100005;
/// Versión 3 del protocolo MOUNT (la usada por NFSv3).
pub const VERSION3: u32 = 3;

/// Tamaño máximo de un `fhandle3` (`FHSIZE3`).
pub const FHSIZE3: usize = 64;
/// `mountstat3` de éxito.
pub const MNT3_OK: u32 = 0;

const MOUNTPROC3_MNT: u32 = 1;
const MOUNTPROC3_DUMP: u32 = 2;
const MOUNTPROC3_UMNT: u32 = 3;
const MOUNTPROC3_EXPORT: u32 = 5;

/// Resultado exitoso de `MNT`: file handle raíz + flavors de auth aceptados.
#[derive(Debug, Clone)]
pub struct MountOk {
    /// File handle del directorio montado (`fhandle3`, opaque<64>).
    pub fhandle: Bytes,
    /// Flavors de autenticación aceptados por el servidor para ese export.
    pub auth_flavors: Vec<u32>,
}

/// Resultado de `MNT` (`mountres3`).
#[derive(Debug, Clone)]
pub enum Mountres3 {
    /// Montaje correcto.
    Ok(MountOk),
    /// Error de montaje (`mountstat3` distinto de 0).
    Err(u32),
}

impl XdrDecode for Mountres3 {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let status = u32::decode(buf)?;
        if status == MNT3_OK {
            let fhandle = decode_opaque(buf, FHSIZE3)?;
            let auth_flavors = Vec::<u32>::decode(buf)?;
            Ok(Mountres3::Ok(MountOk {
                fhandle,
                auth_flavors,
            }))
        } else {
            Ok(Mountres3::Err(status))
        }
    }
}

/// Una entrada de la lista de exports (`exportnode`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportNode {
    /// Ruta exportada.
    pub dir: String,
    /// Grupos/hosts con acceso (vacío = acceso abierto).
    pub groups: Vec<String>,
}

/// Lista de exports devuelta por `EXPORT` (lista enlazada XDR `*exportnode`).
#[derive(Debug, Clone)]
pub struct ExportList(pub Vec<ExportNode>);

fn decode_string_list(buf: &mut Bytes) -> Result<Vec<String>, XdrError> {
    let mut items = Vec::new();
    while bool::decode(buf)? {
        items.push(String::decode(buf)?);
    }
    Ok(items)
}

impl XdrDecode for ExportList {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let mut nodes = Vec::new();
        while bool::decode(buf)? {
            let dir = String::decode(buf)?;
            let groups = decode_string_list(buf)?;
            nodes.push(ExportNode { dir, groups });
        }
        Ok(ExportList(nodes))
    }
}

/// Una entrada de la lista de montajes activos (`mountbody`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// Host que tiene montado el export.
    pub hostname: String,
    /// Ruta montada.
    pub dir: String,
}

/// Lista de montajes activos devuelta por `DUMP` (lista enlazada `*mountbody`).
#[derive(Debug, Clone)]
pub struct MountList(pub Vec<MountEntry>);

impl XdrDecode for MountList {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let mut entries = Vec::new();
        while bool::decode(buf)? {
            let hostname = String::decode(buf)?;
            let dir = String::decode(buf)?;
            entries.push(MountEntry { hostname, dir });
        }
        Ok(MountList(entries))
    }
}

/// `MNT`: monta `path` y devuelve su file handle raíz.
pub fn mnt(client: &mut RpcClient, path: &str) -> Result<MountOk, ProtoError> {
    let dirpath = path.to_string();
    match client.call(PROGRAM, VERSION3, MOUNTPROC3_MNT, &dirpath)? {
        Mountres3::Ok(ok) => Ok(ok),
        Mountres3::Err(code) => Err(ProtoError::Mount(code)),
    }
}

/// `UMNT`: informa al servidor de que se desmonta `path`.
pub fn umnt(client: &mut RpcClient, path: &str) -> Result<(), ProtoError> {
    let dirpath = path.to_string();
    client.call::<()>(PROGRAM, VERSION3, MOUNTPROC3_UMNT, &dirpath)?;
    Ok(())
}

/// `EXPORT`: lista los exports publicados por el servidor.
pub fn export(client: &mut RpcClient) -> Result<Vec<ExportNode>, ProtoError> {
    let list: ExportList = client.call(PROGRAM, VERSION3, MOUNTPROC3_EXPORT, &())?;
    Ok(list.0)
}

/// `DUMP`: lista los montajes activos que conoce el servidor.
pub fn dump(client: &mut RpcClient) -> Result<Vec<MountEntry>, ProtoError> {
    let list: MountList = client.call(PROGRAM, VERSION3, MOUNTPROC3_DUMP, &())?;
    Ok(list.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfs_xdr::from_bytes;

    #[test]
    fn decode_mountres3_ok() {
        #[rustfmt::skip]
        let wire: &[u8] = &[
            0, 0, 0, 0,             // mountstat3 = MNT3_OK
            0, 0, 0, 4,             // fhandle len = 4
            0xDE, 0xAD, 0xBE, 0xEF, // fhandle data (sin relleno, 4%4==0)
            0, 0, 0, 1,             // auth_flavors: count 1
            0, 0, 0, 1,             // AUTH_SYS
        ];
        let res: Mountres3 = from_bytes(Bytes::copy_from_slice(wire)).unwrap();
        match res {
            Mountres3::Ok(ok) => {
                assert_eq!(&ok.fhandle[..], &[0xDE, 0xAD, 0xBE, 0xEF]);
                assert_eq!(ok.auth_flavors, vec![1]);
            }
            Mountres3::Err(_) => panic!("esperaba Ok"),
        }
    }

    #[test]
    fn decode_mountres3_err() {
        let wire: &[u8] = &[0, 0, 0, 13]; // MNT3ERR_SERVERFAULT
        let res: Mountres3 = from_bytes(Bytes::copy_from_slice(wire)).unwrap();
        assert!(matches!(res, Mountres3::Err(13)));
    }

    #[test]
    fn decode_export_list() {
        #[rustfmt::skip]
        let wire: &[u8] = &[
            0, 0, 0, 1,                                  // exportnode presente
            0, 0, 0, 5,  b'/', b'e', b'x', b'p', b'o', 0, 0, 0, // dir "/expo" (5 + 3 pad)
            0, 0, 0, 1,                                  // grupo presente
            0, 0, 0, 1,  b'*', 0, 0, 0,                  // "*" (1 + 3 pad)
            0, 0, 0, 0,                                  // fin de grupos
            0, 0, 0, 0,                                  // fin de exportnodes
        ];
        let list: ExportList = from_bytes(Bytes::copy_from_slice(wire)).unwrap();
        assert_eq!(list.0.len(), 1);
        assert_eq!(list.0[0].dir, "/expo");
        assert_eq!(list.0[0].groups, vec!["*".to_string()]);
    }
}
