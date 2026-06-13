//! Errores del códec XDR.

/// Error producido al codificar o decodificar XDR.
///
/// La decodificación nunca entra en pánico ni reserva memoria sin acotar: una
/// longitud declarada por el peer mayor que los bytes disponibles se reporta
/// como [`XdrError::Truncated`] en lugar de provocar OOM.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum XdrError {
    /// Faltan bytes en la entrada para completar la lectura.
    #[error("entrada truncada: se necesitaban {needed} bytes pero quedaban {had}")]
    Truncated {
        /// Bytes necesarios para la operación.
        needed: usize,
        /// Bytes realmente disponibles.
        had: usize,
    },

    /// Una longitud variable superó el límite declarado por el esquema
    /// (`#[xdr(limit = N)]` o el máximo del tipo en la RFC).
    #[error("longitud {len} supera el límite {limit}")]
    LimitExceeded {
        /// Longitud encontrada.
        len: usize,
        /// Límite permitido.
        limit: usize,
    },

    /// Longitud que no cabe en el `u32` del prefijo XDR.
    #[error("longitud {0} no representable en u32")]
    LengthOverflow(usize),

    /// Valor booleano inválido (XDR exige 0 o 1).
    #[error("bool XDR inválido: {0}")]
    InvalidBool(u32),

    /// Discriminante de `enum` XDR no reconocido.
    #[error("discriminante de enum inválido: {0}")]
    InvalidEnum(i32),

    /// Discriminante de `union` XDR no reconocido y sin caso `default`.
    #[error("discriminante de union inválido: {0}")]
    InvalidUnion(u32),

    /// Una cadena XDR contenía bytes que no son UTF-8 válido.
    #[error("cadena XDR no es UTF-8 válido")]
    InvalidUtf8,

    /// Quedaron bytes sin consumir tras decodificar un mensaje completo.
    #[error("sobran {0} bytes tras la decodificación")]
    TrailingData(usize),
}
