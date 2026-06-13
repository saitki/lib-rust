//! Network Status Monitor v1 (NSM, programa 100024): monitorización de estado
//! para coherencia de bloqueos tras reinicios. Solo cliente (como libnfs); no
//! incluye un daemon `statd` propio.

use nfs_rpc::RpcClient;
use nfs_xdr::{XdrDecode, XdrEncode};

use crate::error::ProtoError;

/// Número de programa de NSM.
pub const PROGRAM: u32 = 100024;
/// Versión 1 de NSM.
pub const VERSION1: u32 = 1;

const SM_STAT: u32 = 1;
const SM_MON: u32 = 2;
const SM_UNMON: u32 = 3;

/// `STAT_SUCC`: el monitor pudo registrar/atender la petición.
pub const STAT_SUCC: u32 = 0;

/// Identificador del solicitante (`my_id`).
#[derive(XdrEncode, Clone, Debug)]
pub struct MyId {
    /// Nombre del host que pide la monitorización.
    pub my_name: String,
    /// Programa RPC a notificar.
    pub my_prog: i32,
    /// Versión del programa a notificar.
    pub my_vers: i32,
    /// Procedimiento a invocar al notificar.
    pub my_proc: i32,
}

/// Identificador de lo que se monitoriza (`mon_id`).
#[derive(XdrEncode, Clone, Debug)]
pub struct MonId {
    /// Host a monitorizar.
    pub mon_name: String,
    /// Identidad del solicitante.
    pub my_id: MyId,
}

#[derive(XdrEncode, Clone, Debug)]
struct MonArgs {
    mon_id: MonId,
    priv_: [u8; 16],
}

#[derive(XdrEncode, Clone, Debug)]
struct SmName {
    mon_name: String,
}

/// Resultado de `STAT`/`MON` (`sm_stat_res`).
#[derive(XdrDecode, Clone, Debug)]
pub struct SmStatRes {
    /// Estado de la operación (`STAT_SUCC` = ok).
    pub res_stat: u32,
    /// Estado/contador del monitor.
    pub state: i32,
}

/// `MON`: pide al statd local que monitorice `mon_name` y notifique a
/// `(my_prog, my_vers, my_proc)` si el host reinicia.
pub fn mon(
    client: &mut RpcClient,
    mon_name: &str,
    my_name: &str,
    my_prog: i32,
    my_vers: i32,
    my_proc: i32,
    priv_: [u8; 16],
) -> Result<SmStatRes, ProtoError> {
    let args = MonArgs {
        mon_id: MonId {
            mon_name: mon_name.to_string(),
            my_id: MyId {
                my_name: my_name.to_string(),
                my_prog,
                my_vers,
                my_proc,
            },
        },
        priv_,
    };
    Ok(client.call(PROGRAM, VERSION1, SM_MON, &args)?)
}

/// `UNMON`: deja de monitorizar `mon_name`.
pub fn unmon(
    client: &mut RpcClient,
    mon_name: &str,
    my_name: &str,
    my_prog: i32,
    my_vers: i32,
    my_proc: i32,
) -> Result<i32, ProtoError> {
    let args = MonId {
        mon_name: mon_name.to_string(),
        my_id: MyId {
            my_name: my_name.to_string(),
            my_prog,
            my_vers,
            my_proc,
        },
    };
    // sm_unmon devuelve `sm_stat { int state }`.
    #[derive(XdrDecode)]
    struct SmStat {
        state: i32,
    }
    let res: SmStat = client.call(PROGRAM, VERSION1, SM_UNMON, &args)?;
    Ok(res.state)
}

/// `STAT`: consulta si un host está siendo monitorizado.
pub fn stat(client: &mut RpcClient, mon_name: &str) -> Result<SmStatRes, ProtoError> {
    let args = SmName {
        mon_name: mon_name.to_string(),
    };
    Ok(client.call(PROGRAM, VERSION1, SM_STAT, &args)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfs_xdr::to_bytes;

    #[test]
    fn mon_args_encode_nonempty() {
        let args = MonArgs {
            mon_id: MonId {
                mon_name: "nfs-server".to_string(),
                my_id: MyId {
                    my_name: "client".to_string(),
                    my_prog: 100021,
                    my_vers: 4,
                    my_proc: 0,
                },
            },
            priv_: [0u8; 16],
        };
        let bytes = to_bytes(&args).unwrap();
        // mon_name "nfs-server" (10) -> len(4)+10+2 relleno = 16 bytes al inicio.
        assert_eq!(&bytes[0..4], &[0, 0, 0, 10]);
        // El opaque[16] final no lleva prefijo de longitud.
        assert_eq!(bytes.len() % 4, 0);
    }
}
