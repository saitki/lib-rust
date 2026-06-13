//! Network Lock Manager v4 (NLM, programa 100021): bloqueo de ficheros en red
//! para NFSv3. Implementa la vía síncrona que usa libnfs en `nfs_fcntl`.

use nfs_rpc::RpcClient;
use nfs_xdr::{Bytes, XdrDecode, XdrEncode, XdrError};

use crate::error::ProtoError;

/// Número de programa de NLM.
pub const PROGRAM: u32 = 100021;
/// Versión 4 de NLM.
pub const VERSION4: u32 = 4;

const NLMPROC4_TEST: u32 = 1;
const NLMPROC4_LOCK: u32 = 2;
const NLMPROC4_CANCEL: u32 = 3;
const NLMPROC4_UNLOCK: u32 = 4;

/// Lock concedido.
pub const NLM4_GRANTED: u32 = 0;
/// Lock denegado (en conflicto).
pub const NLM4_DENIED: u32 = 1;
/// Sin recursos de bloqueo.
pub const NLM4_DENIED_NOLOCKS: u32 = 2;
/// Bloqueado (espera).
pub const NLM4_BLOCKED: u32 = 3;
/// Denegado por periodo de gracia.
pub const NLM4_DENIED_GRACE_PERIOD: u32 = 4;

/// Descripción de un bloqueo (`nlm4_lock`).
#[derive(XdrEncode, Clone, Debug)]
pub struct Nlm4Lock {
    /// Nombre del host que solicita el bloqueo.
    pub caller_name: String,
    /// File handle del objeto (netobj/opaque).
    pub fh: Bytes,
    /// Identificador del propietario del bloqueo (netobj/opaque).
    pub oh: Bytes,
    /// Identificador del proceso (svid).
    pub svid: i32,
    /// Desplazamiento de inicio.
    pub offset: u64,
    /// Longitud (0 = hasta el final).
    pub len: u64,
}

#[derive(XdrEncode, Clone, Debug)]
struct Nlm4LockArgs {
    cookie: Bytes,
    block: bool,
    exclusive: bool,
    lock: Nlm4Lock,
    reclaim: bool,
    state: i32,
}

#[derive(XdrEncode, Clone, Debug)]
struct Nlm4UnlockArgs {
    cookie: Bytes,
    lock: Nlm4Lock,
}

#[derive(XdrEncode, Clone, Debug)]
struct Nlm4CancelArgs {
    cookie: Bytes,
    block: bool,
    exclusive: bool,
    lock: Nlm4Lock,
}

#[derive(XdrEncode, Clone, Debug)]
struct Nlm4TestArgs {
    cookie: Bytes,
    exclusive: bool,
    lock: Nlm4Lock,
}

/// Resultado simple de NLM (`nlm4_res`).
#[derive(XdrDecode, Clone, Debug)]
struct Nlm4Res {
    #[allow(dead_code)]
    cookie: Bytes,
    stat: u32,
}

/// Titular de un bloqueo en conflicto (`nlm4_holder`).
#[derive(Clone, Debug)]
pub struct Nlm4Holder {
    /// Si el bloqueo en conflicto es exclusivo.
    pub exclusive: bool,
    /// svid del titular.
    pub svid: i32,
    /// Desplazamiento del bloqueo en conflicto.
    pub offset: u64,
    /// Longitud del bloqueo en conflicto.
    pub len: u64,
}

/// Resultado de `TEST`: concedido, o denegado con el titular en conflicto.
#[derive(Clone, Debug)]
pub enum TestResult {
    /// El bloqueo se podría conceder.
    Granted,
    /// Hay un bloqueo en conflicto.
    Denied(Nlm4Holder),
    /// Otro estado (`nlm4_stats`).
    Other(u32),
}

impl XdrDecode for TestResult {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let _cookie = Bytes::decode(buf)?;
        let stat = u32::decode(buf)?;
        match stat {
            NLM4_GRANTED => Ok(TestResult::Granted),
            NLM4_DENIED => {
                let exclusive = bool::decode(buf)?;
                let svid = i32::decode(buf)?;
                let _oh = Bytes::decode(buf)?;
                let offset = u64::decode(buf)?;
                let len = u64::decode(buf)?;
                Ok(TestResult::Denied(Nlm4Holder {
                    exclusive,
                    svid,
                    offset,
                    len,
                }))
            }
            other => Ok(TestResult::Other(other)),
        }
    }
}

fn cookie() -> Bytes {
    Bytes::from_static(&[0, 0, 0, 0])
}

fn stat_to_result(stat: u32) -> Result<(), ProtoError> {
    if stat == NLM4_GRANTED {
        Ok(())
    } else {
        Err(ProtoError::Nlm(stat))
    }
}

/// `LOCK`: solicita un bloqueo (no bloqueante: `block = false`).
#[allow(clippy::too_many_arguments)]
pub fn lock(
    client: &mut RpcClient,
    caller_name: &str,
    fh: Bytes,
    owner: Bytes,
    svid: i32,
    offset: u64,
    len: u64,
    exclusive: bool,
) -> Result<(), ProtoError> {
    let args = Nlm4LockArgs {
        cookie: cookie(),
        block: false,
        exclusive,
        lock: Nlm4Lock {
            caller_name: caller_name.to_string(),
            fh,
            oh: owner,
            svid,
            offset,
            len,
        },
        reclaim: false,
        state: 0,
    };
    let res: Nlm4Res = client.call(PROGRAM, VERSION4, NLMPROC4_LOCK, &args)?;
    stat_to_result(res.stat)
}

/// `UNLOCK`: libera un bloqueo.
#[allow(clippy::too_many_arguments)]
pub fn unlock(
    client: &mut RpcClient,
    caller_name: &str,
    fh: Bytes,
    owner: Bytes,
    svid: i32,
    offset: u64,
    len: u64,
) -> Result<(), ProtoError> {
    let args = Nlm4UnlockArgs {
        cookie: cookie(),
        lock: Nlm4Lock {
            caller_name: caller_name.to_string(),
            fh,
            oh: owner,
            svid,
            offset,
            len,
        },
    };
    let res: Nlm4Res = client.call(PROGRAM, VERSION4, NLMPROC4_UNLOCK, &args)?;
    stat_to_result(res.stat)
}

/// `CANCEL`: cancela una solicitud de bloqueo pendiente.
#[allow(clippy::too_many_arguments)]
pub fn cancel(
    client: &mut RpcClient,
    caller_name: &str,
    fh: Bytes,
    owner: Bytes,
    svid: i32,
    offset: u64,
    len: u64,
    exclusive: bool,
) -> Result<(), ProtoError> {
    let args = Nlm4CancelArgs {
        cookie: cookie(),
        block: false,
        exclusive,
        lock: Nlm4Lock {
            caller_name: caller_name.to_string(),
            fh,
            oh: owner,
            svid,
            offset,
            len,
        },
    };
    let res: Nlm4Res = client.call(PROGRAM, VERSION4, NLMPROC4_CANCEL, &args)?;
    stat_to_result(res.stat)
}

/// `TEST`: comprueba si un bloqueo se podría conceder.
#[allow(clippy::too_many_arguments)]
pub fn test(
    client: &mut RpcClient,
    caller_name: &str,
    fh: Bytes,
    owner: Bytes,
    svid: i32,
    offset: u64,
    len: u64,
    exclusive: bool,
) -> Result<TestResult, ProtoError> {
    let args = Nlm4TestArgs {
        cookie: cookie(),
        exclusive,
        lock: Nlm4Lock {
            caller_name: caller_name.to_string(),
            fh,
            oh: owner,
            svid,
            offset,
            len,
        },
    };
    Ok(client.call(PROGRAM, VERSION4, NLMPROC4_TEST, &args)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfs_xdr::{from_bytes, to_bytes, BytesMut};

    #[test]
    fn lockargs_encodes() {
        let args = Nlm4LockArgs {
            cookie: Bytes::from_static(&[0, 0, 0, 0]),
            block: false,
            exclusive: true,
            lock: Nlm4Lock {
                caller_name: "host".to_string(),
                fh: Bytes::from_static(&[1, 2, 3, 4]),
                oh: Bytes::from_static(&[9]),
                svid: 1234,
                offset: 0,
                len: 100,
            },
            reclaim: false,
            state: 0,
        };
        // Round-trip parcial: re-decodificamos los primeros campos a mano.
        let bytes = to_bytes(&args).unwrap();
        assert!(!bytes.is_empty());
        // cookie (len 4 + 4 datos) -> primeros 8 bytes
        assert_eq!(&bytes[0..4], &[0, 0, 0, 4]);
    }

    #[test]
    fn test_result_denied_decodes() {
        let mut b = BytesMut::new();
        // cookie netobj vacío
        0u32.encode(&mut b).unwrap();
        // stat = DENIED
        NLM4_DENIED.encode(&mut b).unwrap();
        // holder: exclusive=true, svid=7, oh vacío, offset=10, len=20
        true.encode(&mut b).unwrap();
        7i32.encode(&mut b).unwrap();
        0u32.encode(&mut b).unwrap();
        10u64.encode(&mut b).unwrap();
        20u64.encode(&mut b).unwrap();
        match from_bytes::<TestResult>(b.freeze()).unwrap() {
            TestResult::Denied(h) => {
                assert!(h.exclusive);
                assert_eq!(h.svid, 7);
                assert_eq!(h.len, 20);
            }
            _ => panic!("esperaba Denied"),
        }
    }
}
