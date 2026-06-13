//! Remote Quota v1/v2 (RQUOTA, programa 100011): consulta de cuotas remotas.

use nfs_rpc::RpcClient;
use nfs_xdr::{Bytes, XdrDecode, XdrEncode, XdrError};

use crate::error::ProtoError;

/// Número de programa de RQUOTA.
pub const PROGRAM: u32 = 100011;
/// Versión 1 de RQUOTA.
pub const VERSION1: u32 = 1;

const RQUOTAPROC_GETQUOTA: u32 = 1;
const RQUOTAPROC_GETACTIVEQUOTA: u32 = 2;

/// Estado correcto de la consulta de cuota.
pub const Q_OK: u32 = 1;
/// No hay cuota para ese id.
pub const Q_NOQUOTA: u32 = 2;
/// Sin permiso para consultar la cuota.
pub const Q_EPERM: u32 = 3;

#[derive(XdrEncode, Clone, Debug)]
struct GetquotaArgs {
    path: String,
    uid: i32,
}

/// Información de cuota (`rquota`). Los límites están en bloques de `bsize`.
#[derive(XdrDecode, Clone, Debug)]
pub struct Rquota {
    /// Tamaño de bloque en bytes.
    pub bsize: i32,
    /// Si la cuota está activa.
    pub active: bool,
    /// Límite duro de bloques.
    pub bhardlimit: u32,
    /// Límite blando de bloques.
    pub bsoftlimit: u32,
    /// Bloques usados actualmente.
    pub curblocks: u32,
    /// Límite duro de ficheros.
    pub fhardlimit: u32,
    /// Límite blando de ficheros.
    pub fsoftlimit: u32,
    /// Ficheros usados actualmente.
    pub curfiles: u32,
    /// Segundos restantes del límite blando de bloques.
    pub btimeleft: u32,
    /// Segundos restantes del límite blando de ficheros.
    pub ftimeleft: u32,
}

/// Resultado de `GETQUOTA` (`getquota_rslt`).
#[derive(Clone, Debug)]
pub enum GetquotaResult {
    /// Cuota obtenida.
    Ok(Rquota),
    /// Estado distinto de `Q_OK`.
    Status(u32),
}

impl XdrDecode for GetquotaResult {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let status = u32::decode(buf)?;
        if status == Q_OK {
            Ok(GetquotaResult::Ok(Rquota::decode(buf)?))
        } else {
            Ok(GetquotaResult::Status(status))
        }
    }
}

/// `GETQUOTA`: cuota del usuario `uid` en el sistema de ficheros que contiene
/// `path`.
pub fn getquota(client: &mut RpcClient, path: &str, uid: i32) -> Result<Rquota, ProtoError> {
    let args = GetquotaArgs {
        path: path.to_string(),
        uid,
    };
    match client.call(PROGRAM, VERSION1, RQUOTAPROC_GETQUOTA, &args)? {
        GetquotaResult::Ok(q) => Ok(q),
        GetquotaResult::Status(s) => Err(ProtoError::Rquota(s)),
    }
}

/// `GETACTIVEQUOTA`: como `getquota` pero solo si la cuota está activa.
pub fn getactivequota(client: &mut RpcClient, path: &str, uid: i32) -> Result<Rquota, ProtoError> {
    let args = GetquotaArgs {
        path: path.to_string(),
        uid,
    };
    match client.call(PROGRAM, VERSION1, RQUOTAPROC_GETACTIVEQUOTA, &args)? {
        GetquotaResult::Ok(q) => Ok(q),
        GetquotaResult::Status(s) => Err(ProtoError::Rquota(s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfs_xdr::{from_bytes, BytesMut};

    #[test]
    fn getquota_ok_decodes() {
        let mut b = BytesMut::new();
        Q_OK.encode(&mut b).unwrap();
        1024i32.encode(&mut b).unwrap(); // bsize
        true.encode(&mut b).unwrap(); // active
        for v in [100u32, 90, 50, 0, 0, 0, 0, 0] {
            v.encode(&mut b).unwrap();
        }
        match from_bytes::<GetquotaResult>(b.freeze()).unwrap() {
            GetquotaResult::Ok(q) => {
                assert_eq!(q.bsize, 1024);
                assert!(q.active);
                assert_eq!(q.bhardlimit, 100);
                assert_eq!(q.curblocks, 50);
            }
            GetquotaResult::Status(_) => panic!("esperaba Ok"),
        }
    }

    #[test]
    fn getquota_noquota_decodes() {
        let mut b = BytesMut::new();
        Q_NOQUOTA.encode(&mut b).unwrap();
        assert!(matches!(
            from_bytes::<GetquotaResult>(b.freeze()).unwrap(),
            GetquotaResult::Status(Q_NOQUOTA)
        ));
    }
}
