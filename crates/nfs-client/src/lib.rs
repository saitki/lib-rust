//! Cliente NFS en Rust puro: recreación de [libnfs](https://github.com/sahlberg/libnfs).
//!
//! Expone un [`NfsContext`] con operaciones tipo POSIX (open/read/write/stat/…)
//! sobre rutas, un parser de URLs `nfs://` ([`NfsUrl`]) y soporte de NFSv3 y
//! NFSv4 sobre Windows, macOS y Linux. La misma API funciona con ambos backends.
//!
//! # Ejemplo (síncrono)
//!
//! ```no_run
//! use nfs_client::{NfsContext, OpenFlags};
//!
//! let mut nfs = NfsContext::mount_url("nfs://server/export?uid=1000&gid=1000")?;
//! let data = nfs.read_whole("/dir/fichero.txt")?;
//! println!("{} bytes", data.len());
//! # Ok::<(), nfs_client::NfsError>(())
//! ```
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod attr;
mod backend;
mod backend_v3;
mod backend_v4;
mod context;
mod error;
mod url;

#[cfg(feature = "tokio")]
mod async_context;

pub use attr::{Attr, DirEntry, FileType, SetAttr, StatVfs, Timestamp};
pub use context::{LockHandle, NfsContext, NfsFile, OpenFlags};
pub use error::NfsError;
pub use url::NfsUrl;

// Reexport del tipo de buffer usado en la API.
pub use nfs_proto::Bytes;

#[cfg(feature = "tokio")]
pub use async_context::AsyncNfs;
