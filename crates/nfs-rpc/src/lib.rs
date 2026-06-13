//! Motor ONC-RPC (RFC 5531) para libnfs-rs.
//!
//! Implementa el cliente SunRPC sobre el que se montan los protocolos NFS:
//! construcción de mensajes `CALL`, parseo de `REPLY`, emparejado por XID,
//! record marking sobre TCP, autenticación `AUTH_NONE`/`AUTH_SYS`, timeouts y
//! reconexión.
//!
//! - [`RpcClient`] — cliente síncrono sobre `std::net` (TCP/UDP).
//! - [`AsyncRpcClient`] — cliente asíncrono sobre `tokio` (*feature* `tokio`).
//! - [`RecordReassembler`] / [`frame`] — record marking, testeables sin red.
//!
//! # Ejemplo (síncrono)
//!
//! ```no_run
//! use std::time::Duration;
//! use nfs_rpc::{Credentials, Protocol, RpcClient};
//!
//! let addr = "127.0.0.1:111".parse().unwrap();
//! let mut client = RpcClient::connect(addr, Protocol::Tcp, Credentials::None, Duration::from_secs(30))?;
//! // PORTMAP (programa 100000, versión 2): ping NULL.
//! client.null(100000, 2)?;
//! # Ok::<(), nfs_rpc::RpcError>(())
//! ```
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod auth;
mod client;
mod error;
mod message;
mod record;

#[cfg(feature = "tokio")]
mod client_async;

pub use auth::{AuthSysParams, Credentials, AUTH_NONE, AUTH_SYS};
pub use client::{Protocol, ReadWriteStream, RpcClient, DEFAULT_TIMEOUT};
pub use error::RpcError;
pub use message::{encode_call, parse_reply, NULL_PROC, RPC_VERSION};
pub use record::{frame, RecordReassembler, DEFAULT_MAX_RECORD};

#[cfg(feature = "tokio")]
pub use client_async::AsyncRpcClient;

// Reexporta los tipos de buffer para que `nfs-proto` no dependa de `bytes`/
// `nfs-xdr` solo para las firmas.
pub use nfs_xdr::{self, Bytes, BytesMut};
