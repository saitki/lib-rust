//! Errores comunes de los protocolos NFS.

use nfs_rpc::RpcError;
use nfs_xdr::XdrError;

/// Error de una operación de protocolo (PORTMAP, MOUNT, NFS…).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// Error de la capa RPC/transporte.
    #[error("RPC: {0}")]
    Rpc(#[from] RpcError),

    /// Error de (de)serialización XDR.
    #[error("XDR: {0}")]
    Xdr(#[from] XdrError),

    /// Error de E/S (p. ej. al resolver el nombre del servidor).
    #[error("E/S: {0}")]
    Io(#[from] std::io::Error),

    /// No se pudo resolver la dirección del servidor.
    #[error("no se pudo resolver el servidor «{0}»")]
    Unresolvable(String),

    /// El programa RPC no está registrado en el portmapper (GETPORT devolvió 0).
    #[error("el servicio (prog={prog}, vers={vers}) no está registrado en el portmapper")]
    PortNotRegistered {
        /// Número de programa consultado.
        prog: u32,
        /// Versión consultada.
        vers: u32,
    },

    /// El protocolo MOUNT devolvió un error (`mountstat3`).
    #[error("MOUNT falló con mountstat3={0}")]
    Mount(u32),

    /// Una operación NFSv3 devolvió un error (`nfsstat3`).
    #[error("NFSv3 falló con nfsstat3={0}")]
    Nfs3(u32),

    /// Una operación NFSv4 devolvió un error (`nfsstat4`).
    #[error("NFSv4 falló con nfsstat4={0}")]
    Nfs4(u32),

    /// El protocolo NLM devolvió un error (`nlm4_stats`).
    #[error("NLM falló con nlm4_stat={0}")]
    Nlm(u32),

    /// El protocolo RQUOTA devolvió un error (`qr_status`).
    #[error("RQUOTA falló con status={0}")]
    Rquota(u32),

    /// Respuesta de protocolo inesperada o no soportada.
    #[error("protocolo: {0}")]
    Protocol(&'static str),
}
