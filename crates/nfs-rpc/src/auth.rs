//! Autenticación ONC-RPC: `AUTH_NONE` y `AUTH_SYS` (AUTH_UNIX).
//!
//! RPCSEC_GSS/Kerberos queda fuera de alcance, igual que en libnfs por defecto.

use nfs_xdr::{encode_opaque, to_bytes, BytesMut, XdrDecode, XdrEncode};

use crate::error::RpcError;

/// `flavor` de `AUTH_NONE`.
pub const AUTH_NONE: u32 = 0;
/// `flavor` de `AUTH_SYS` (también llamado AUTH_UNIX).
pub const AUTH_SYS: u32 = 1;
/// Tamaño máximo del cuerpo de `opaque_auth` (RFC 5531: `opaque body<400>`).
pub const MAX_AUTH_BODY: usize = 400;

/// Parámetros de `AUTH_SYS` (`authsys_parms`, RFC 5531 §8.2).
#[derive(XdrEncode, XdrDecode, Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthSysParams {
    /// Marca de tiempo arbitraria (el servidor la ignora).
    pub stamp: u32,
    /// Nombre de la máquina cliente.
    #[xdr(limit = 255)]
    pub machine_name: String,
    /// UID efectivo.
    pub uid: u32,
    /// GID efectivo.
    pub gid: u32,
    /// Lista de GIDs suplementarios.
    #[xdr(limit = 16)]
    pub gids: Vec<u32>,
}

/// Credenciales con las que se firman las llamadas RPC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credentials {
    /// Sin autenticación.
    None,
    /// Autenticación de estilo Unix.
    Sys(AuthSysParams),
}

impl Credentials {
    /// Credencial `AUTH_SYS` mínima con `uid`/`gid` (sin GIDs suplementarios).
    pub fn unix(uid: u32, gid: u32) -> Self {
        Credentials::Sys(AuthSysParams {
            stamp: 0,
            machine_name: String::new(),
            uid,
            gid,
            gids: Vec::new(),
        })
    }

    /// Codifica esta credencial como un `opaque_auth` XDR (flavor + body<400>).
    pub fn encode_auth(&self, buf: &mut BytesMut) -> Result<(), RpcError> {
        match self {
            Credentials::None => {
                AUTH_NONE.encode(buf)?;
                encode_opaque(buf, &[], MAX_AUTH_BODY)?;
            }
            Credentials::Sys(params) => {
                AUTH_SYS.encode(buf)?;
                let body = to_bytes(params)?;
                encode_opaque(buf, &body, MAX_AUTH_BODY)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_none_opaque_auth() {
        let mut buf = BytesMut::new();
        Credentials::None.encode_auth(&mut buf).unwrap();
        // flavor AUTH_NONE(0) + body opaque<> de longitud 0.
        assert_eq!(&buf[..], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn auth_sys_golden_vector() {
        // authsys_parms{ stamp=0, machine="", uid=1000, gid=1000, gids=[] }
        // envuelto en opaque_auth{ flavor=AUTH_SYS(1), body<> }.
        let mut buf = BytesMut::new();
        Credentials::unix(1000, 1000).encode_auth(&mut buf).unwrap();
        #[rustfmt::skip]
        let expected: &[u8] = &[
            0, 0, 0, 1,        // flavor = AUTH_SYS
            0, 0, 0, 20,       // longitud del body = 20 bytes
            0, 0, 0, 0,        // stamp = 0
            0, 0, 0, 0,        // machine_name: longitud 0
            0, 0, 0x03, 0xE8,  // uid = 1000
            0, 0, 0x03, 0xE8,  // gid = 1000
            0, 0, 0, 0,        // gids: count 0
        ];
        assert_eq!(&buf[..], expected);
    }
}
