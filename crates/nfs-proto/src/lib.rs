//! Tipos y procedimientos de los protocolos NFS para libnfs-rs.
//!
//! Construido sobre [`nfs_xdr`] y [`nfs_rpc`]:
//!
//! - [`portmap`] — PORTMAP/rpcbind v2 (`GETPORT`, `DUMP`).
//! - [`mount`] — protocolo MOUNT v3 (`MNT`, `UMNT`, `EXPORT`, `DUMP`).
//! - [`connect`] — flujo de conexión portmap → mount → puerto NFS.
//! - [`nfs3`] — NFSv3 (RFC 1813): tipos y los 22 procedimientos (RAW API).
//! - [`nfs4`] — NFSv4.0 (RFC 7530): COMPOUND, fattr4 y gestión de estado.
//! - [`nlm`] / [`nsm`] / [`rquota`] — bloqueo en red, status monitor y cuotas.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod connect;
pub mod error;
pub mod mount;
pub mod nfs3;
pub mod nfs4;
pub mod nlm;
pub mod nsm;
pub mod portmap;
pub mod rquota;

pub use error::ProtoError;

// Reexports de conveniencia.
pub use nfs_rpc::{self, Credentials, Protocol, RpcClient};
pub use nfs_xdr::{self, Bytes};
