//! Codificación de `CALL` y parseo de `REPLY` ONC-RPC (RFC 5531).

use nfs_xdr::{decode_opaque, Bytes, BytesMut, XdrDecode, XdrEncode};

use crate::auth::{Credentials, MAX_AUTH_BODY};
use crate::error::RpcError;

/// Versión del protocolo ONC-RPC.
pub const RPC_VERSION: u32 = 2;
/// Número de procedimiento `NULL` (común a todos los programas RPC).
pub const NULL_PROC: u32 = 0;

const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;

// accept_stat
const SUCCESS: u32 = 0;
const PROG_UNAVAIL: u32 = 1;
const PROG_MISMATCH: u32 = 2;
const PROC_UNAVAIL: u32 = 3;
const GARBAGE_ARGS: u32 = 4;
const SYSTEM_ERR: u32 = 5;

// reject_stat
const RPC_MISMATCH: u32 = 0;
const AUTH_ERROR: u32 = 1;

/// Escribe la cabecera de un mensaje `CALL` (sin los argumentos del
/// procedimiento, que el llamante añade a continuación).
///
/// El `verf` (verificador) se envía siempre como `AUTH_NONE`, como hace libnfs
/// para `AUTH_SYS`/`AUTH_NONE`.
pub fn encode_call(
    buf: &mut BytesMut,
    xid: u32,
    prog: u32,
    vers: u32,
    proc_: u32,
    cred: &Credentials,
) -> Result<(), RpcError> {
    xid.encode(buf)?;
    MSG_CALL.encode(buf)?;
    RPC_VERSION.encode(buf)?;
    prog.encode(buf)?;
    vers.encode(buf)?;
    proc_.encode(buf)?;
    cred.encode_auth(buf)?;
    Credentials::None.encode_auth(buf)?;
    Ok(())
}

/// Parsea un mensaje `REPLY`. Devuelve el `xid` y el resultado de la llamada:
/// en caso de éxito, los bytes restantes (el resultado específico del
/// procedimiento) listos para decodificar; en caso contrario, el error RPC.
///
/// Un mensaje no-`REPLY` o estructuralmente inválido devuelve `Err` a nivel de
/// transporte; los fallos de la llamada (`MSG_DENIED`, `accept_stat != SUCCESS`)
/// se devuelven en el `Result` interno.
#[allow(clippy::type_complexity)]
pub fn parse_reply(mut body: Bytes) -> Result<(u32, Result<Bytes, RpcError>), RpcError> {
    let xid = u32::decode(&mut body)?;
    if u32::decode(&mut body)? != MSG_REPLY {
        return Err(RpcError::MalformedReply);
    }
    match u32::decode(&mut body)? {
        MSG_ACCEPTED => {
            // verf: opaque_auth (flavor + body<400>), que ignoramos.
            let _flavor = u32::decode(&mut body)?;
            let _verf = decode_opaque(&mut body, MAX_AUTH_BODY)?;
            let inner = match u32::decode(&mut body)? {
                SUCCESS => Ok(body),
                PROG_UNAVAIL => Err(RpcError::ProgUnavail),
                PROG_MISMATCH => {
                    let low = u32::decode(&mut body)?;
                    let high = u32::decode(&mut body)?;
                    Err(RpcError::ProgMismatch { low, high })
                }
                PROC_UNAVAIL => Err(RpcError::ProcUnavail),
                GARBAGE_ARGS => Err(RpcError::GarbageArgs),
                SYSTEM_ERR => Err(RpcError::SystemErr),
                other => Err(RpcError::UnknownAcceptStat(other)),
            };
            Ok((xid, inner))
        }
        MSG_DENIED => {
            let inner = match u32::decode(&mut body)? {
                RPC_MISMATCH => {
                    let low = u32::decode(&mut body)?;
                    let high = u32::decode(&mut body)?;
                    Err(RpcError::RpcMismatch { low, high })
                }
                AUTH_ERROR => Err(RpcError::AuthError(u32::decode(&mut body)?)),
                _ => Err(RpcError::MalformedReply),
            };
            Ok((xid, inner))
        }
        _ => Err(RpcError::MalformedReply),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Credentials;
    use bytes::BufMut;

    /// Construye un REPLY MSG_ACCEPTED/SUCCESS con `result` como cuerpo.
    fn accepted_success(xid: u32, result: &[u8]) -> Bytes {
        let mut b = BytesMut::new();
        b.put_u32(xid);
        b.put_u32(MSG_REPLY);
        b.put_u32(MSG_ACCEPTED);
        b.put_u32(0); // verf flavor AUTH_NONE
        b.put_u32(0); // verf body len 0
        b.put_u32(SUCCESS);
        b.put_slice(result);
        b.freeze()
    }

    #[test]
    fn call_header_is_well_formed() {
        let mut buf = BytesMut::new();
        encode_call(&mut buf, 0x1234, 100003, 3, 1, &Credentials::unix(0, 0)).unwrap();
        // xid, CALL, rpcvers=2, prog, vers, proc
        assert_eq!(&buf[0..4], &0x1234u32.to_be_bytes());
        assert_eq!(&buf[4..8], &MSG_CALL.to_be_bytes());
        assert_eq!(&buf[8..12], &RPC_VERSION.to_be_bytes());
        assert_eq!(&buf[12..16], &100003u32.to_be_bytes());
        assert_eq!(&buf[16..20], &3u32.to_be_bytes());
        assert_eq!(&buf[20..24], &1u32.to_be_bytes());
    }

    #[test]
    fn parse_success_returns_result_bytes() {
        let reply = accepted_success(7, &[0xAA, 0xBB, 0xCC, 0xDD]);
        let (xid, result) = parse_reply(reply).unwrap();
        assert_eq!(xid, 7);
        assert_eq!(&result.unwrap()[..], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn parse_prog_mismatch() {
        let mut b = BytesMut::new();
        b.put_u32(1);
        b.put_u32(MSG_REPLY);
        b.put_u32(MSG_ACCEPTED);
        b.put_u32(0);
        b.put_u32(0);
        b.put_u32(PROG_MISMATCH);
        b.put_u32(3);
        b.put_u32(4);
        let (_, result) = parse_reply(b.freeze()).unwrap();
        assert!(matches!(
            result,
            Err(RpcError::ProgMismatch { low: 3, high: 4 })
        ));
    }

    #[test]
    fn parse_auth_error() {
        let mut b = BytesMut::new();
        b.put_u32(1);
        b.put_u32(MSG_REPLY);
        b.put_u32(MSG_DENIED);
        b.put_u32(AUTH_ERROR);
        b.put_u32(5);
        let (_, result) = parse_reply(b.freeze()).unwrap();
        assert!(matches!(result, Err(RpcError::AuthError(5))));
    }

    #[test]
    fn non_reply_is_malformed() {
        let mut b = BytesMut::new();
        b.put_u32(1);
        b.put_u32(MSG_CALL); // no es REPLY
        assert!(matches!(
            parse_reply(b.freeze()),
            Err(RpcError::MalformedReply)
        ));
    }
}
