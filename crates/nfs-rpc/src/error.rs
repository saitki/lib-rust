//! Errores del motor ONC-RPC.

/// Error de una operación RPC.
///
/// Distingue errores de transporte (E/S, timeout, conexión) de errores del
/// propio protocolo RPC (`MSG_DENIED`, `accept_stat` distinto de `SUCCESS`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RpcError {
    /// Error de entrada/salida del socket.
    #[error("E/S: {0}")]
    Io(#[from] std::io::Error),

    /// Error de (de)serialización XDR.
    #[error("XDR: {0}")]
    Xdr(#[from] nfs_xdr::XdrError),

    /// Se agotó el tiempo de espera de la respuesta.
    #[error("timeout esperando la respuesta RPC")]
    Timeout,

    /// El extremo remoto cerró la conexión.
    #[error("la conexión se cerró")]
    ConnectionClosed,

    /// Un registro RPC superó el tamaño máximo permitido (protección anti-OOM).
    #[error("registro RPC demasiado grande")]
    RecordTooLarge,

    /// La respuesta no es un `REPLY` válido o está malformada.
    #[error("respuesta RPC inesperada o malformada")]
    MalformedReply,

    /// `MSG_DENIED` / `RPC_MISMATCH`: versión de RPC no soportada por el peer.
    #[error("RPC_MISMATCH: el servidor soporta versiones RPC {low}..={high}")]
    RpcMismatch {
        /// Versión mínima soportada.
        low: u32,
        /// Versión máxima soportada.
        high: u32,
    },

    /// `MSG_DENIED` / `AUTH_ERROR`: el servidor rechazó las credenciales.
    #[error("error de autenticación RPC (auth_stat={0})")]
    AuthError(u32),

    /// `accept_stat` = `PROG_UNAVAIL`.
    #[error("programa RPC no disponible en el servidor")]
    ProgUnavail,

    /// `accept_stat` = `PROG_MISMATCH`.
    #[error("PROG_MISMATCH: el servidor soporta versiones {low}..={high}")]
    ProgMismatch {
        /// Versión mínima soportada del programa.
        low: u32,
        /// Versión máxima soportada del programa.
        high: u32,
    },

    /// `accept_stat` = `PROC_UNAVAIL`.
    #[error("procedimiento RPC no disponible")]
    ProcUnavail,

    /// `accept_stat` = `GARBAGE_ARGS`: el servidor no pudo decodificar los args.
    #[error("el servidor no pudo decodificar los argumentos (GARBAGE_ARGS)")]
    GarbageArgs,

    /// `accept_stat` = `SYSTEM_ERR`.
    #[error("error interno del servidor RPC (SYSTEM_ERR)")]
    SystemErr,

    /// `accept_stat` desconocido.
    #[error("accept_stat desconocido: {0}")]
    UnknownAcceptStat(u32),
}
