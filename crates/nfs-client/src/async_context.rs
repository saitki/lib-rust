//! API asíncrona (tokio) y handle compartible entre tareas/hilos.
//!
//! `NfsContext` es síncrono y `Send`. `AsyncNfs` lo envuelve en
//! `Arc<Mutex<…>>` y ejecuta cada operación en el pool de hilos de bloqueo de
//! tokio, de modo que se puede compartir entre tareas con `clone()` sin
//! bloquear el runtime. Es el mismo modelo de hilos que documenta libnfs
//! (`README.multithreading`): un contexto serializado tras un mutex.

use std::sync::{Arc, Mutex};

use crate::attr::{Attr, DirEntry, StatVfs};
use crate::context::NfsContext;
use crate::error::NfsError;
use nfs_proto::Bytes;

/// Handle asíncrono y clonable a un contexto NFS.
#[derive(Clone)]
pub struct AsyncNfs {
    inner: Arc<Mutex<NfsContext>>,
}

async fn blocking<T, F>(inner: Arc<Mutex<NfsContext>>, f: F) -> Result<T, NfsError>
where
    T: Send + 'static,
    F: FnOnce(&mut NfsContext) -> Result<T, NfsError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut ctx = inner.lock().expect("contexto NFS envenenado");
        f(&mut ctx)
    })
    .await
    .expect("la tarea de bloqueo no debe entrar en pánico")
}

impl AsyncNfs {
    /// Monta a partir de una URL `nfs://...`.
    pub async fn mount_url(url: impl Into<String>) -> Result<Self, NfsError> {
        let url = url.into();
        let ctx = tokio::task::spawn_blocking(move || NfsContext::mount_url(&url))
            .await
            .expect("la tarea de bloqueo no debe entrar en pánico")?;
        Ok(Self {
            inner: Arc::new(Mutex::new(ctx)),
        })
    }

    /// Versión de NFS negociada.
    pub fn version(&self) -> u32 {
        self.inner
            .lock()
            .expect("contexto NFS envenenado")
            .version()
    }

    /// Atributos de `path` (siguiendo enlaces).
    pub async fn stat(&self, path: impl Into<String>) -> Result<Attr, NfsError> {
        let path = path.into();
        blocking(self.inner.clone(), move |c| c.stat(&path)).await
    }

    /// Lee un fichero completo a memoria.
    pub async fn read_whole(&self, path: impl Into<String>) -> Result<Bytes, NfsError> {
        let path = path.into();
        blocking(self.inner.clone(), move |c| c.read_whole(&path)).await
    }

    /// Escribe `data` como contenido completo de `path`.
    pub async fn write_whole(
        &self,
        path: impl Into<String>,
        data: impl Into<Bytes>,
    ) -> Result<(), NfsError> {
        let path = path.into();
        let data = data.into();
        blocking(self.inner.clone(), move |c| c.write_whole(&path, &data)).await
    }

    /// Lista un directorio.
    pub async fn readdir(&self, path: impl Into<String>) -> Result<Vec<DirEntry>, NfsError> {
        let path = path.into();
        blocking(self.inner.clone(), move |c| c.readdir(&path)).await
    }

    /// Crea un directorio.
    pub async fn mkdir(&self, path: impl Into<String>) -> Result<(), NfsError> {
        let path = path.into();
        blocking(self.inner.clone(), move |c| c.mkdir(&path)).await
    }

    /// Borra un directorio vacío.
    pub async fn rmdir(&self, path: impl Into<String>) -> Result<(), NfsError> {
        let path = path.into();
        blocking(self.inner.clone(), move |c| c.rmdir(&path)).await
    }

    /// Borra un fichero.
    pub async fn unlink(&self, path: impl Into<String>) -> Result<(), NfsError> {
        let path = path.into();
        blocking(self.inner.clone(), move |c| c.unlink(&path)).await
    }

    /// Renombra/mueve.
    pub async fn rename(
        &self,
        from: impl Into<String>,
        to: impl Into<String>,
    ) -> Result<(), NfsError> {
        let from = from.into();
        let to = to.into();
        blocking(self.inner.clone(), move |c| c.rename(&from, &to)).await
    }

    /// Estadísticas del sistema de ficheros.
    pub async fn statvfs(&self, path: impl Into<String>) -> Result<StatVfs, NfsError> {
        let path = path.into();
        blocking(self.inner.clone(), move |c| c.statvfs(&path)).await
    }
}
