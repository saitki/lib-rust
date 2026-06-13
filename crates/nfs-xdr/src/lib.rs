//! Códec XDR (RFC 4506) para libnfs-rs.
//!
//! Serialización big-endian alineada a 4 bytes para todos los tipos XDR:
//! enteros (`int`/`unsigned`/`hyper`), `bool`, `float`/`double`, `enum`,
//! `opaque` fijo y variable, `string`, arrays, `optional`, estructuras y
//! uniones discriminadas. Es la base sobre la que se construyen ONC-RPC
//! (`nfs-rpc`) y los protocolos NFS (`nfs-proto`).
//!
//! # Ejemplo
//!
//! ```
//! use nfs_xdr::{from_bytes, to_bytes, XdrDecode, XdrEncode};
//!
//! #[derive(XdrEncode, XdrDecode, Debug, PartialEq)]
//! struct Nfstime3 {
//!     seconds: u32,
//!     nseconds: u32,
//! }
//!
//! let t = Nfstime3 { seconds: 1, nseconds: 2 };
//! let bytes = to_bytes(&t).unwrap();
//! assert_eq!(&bytes[..], &[0, 0, 0, 1, 0, 0, 0, 2]);
//! assert_eq!(from_bytes::<Nfstime3>(bytes).unwrap(), t);
//! ```
//!
//! ## Seguridad del decodificador
//!
//! La decodificación nunca entra en pánico ni reserva memoria sin acotar:
//! ninguna longitud declarada por el peer se usa para reservar memoria sin
//! antes comprobarla contra los bytes realmente disponibles.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod codec;
mod error;
mod impls;

pub use codec::{decode_opaque, encode_opaque, from_bytes, to_bytes};
pub use error::XdrError;

// Reexporta los buffers de `bytes` para que el código generado por el derive y
// los consumidores no necesiten depender de `bytes` directamente.
pub use bytes::{Bytes, BytesMut};

/// Macros derive `#[derive(XdrEncode, XdrDecode)]`.
#[cfg(feature = "derive")]
pub use nfs_xdr_derive::{XdrDecode, XdrEncode};

/// Codifica `self` en formato XDR sobre `buf`.
pub trait XdrEncode {
    /// Serializa el valor (big-endian, alineado a 4 bytes) al final de `buf`.
    fn encode(&self, buf: &mut BytesMut) -> Result<(), XdrError>;
}

/// Decodifica un valor desde una secuencia XDR, avanzando el cursor de `buf`.
pub trait XdrDecode: Sized {
    /// Lee y consume del frente de `buf` los bytes que componen el valor.
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError>;
}

/// Devuelve la longitud lógica de un valor de longitud variable (bytes para
/// `opaque`/`string`, número de elementos para arrays). La usa el código
/// generado para validar `#[xdr(limit = N)]`.
pub trait XdrLen {
    /// Longitud lógica del valor.
    fn xdr_len(&self) -> usize;
}
