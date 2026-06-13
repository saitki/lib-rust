//! `NfsContext`: la cara pública síncrona del cliente NFS.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use nfs_proto::connect::{self, MountOptions};
use nfs_proto::nfs3::{Nfs3, ACCESS3_READ};
use nfs_proto::nfs4::Nfs4;
use nfs_proto::{Bytes, Credentials, Protocol};

use crate::attr::{Attr, DirEntry, SetAttr, StatVfs};
use crate::backend::{Backend, LockToken, ObjId, OpenFile, OpenOpts};
use crate::backend_v3::{NlmConfig, V3Backend};
use crate::backend_v4::V4Backend;
use crate::error::NfsError;
use crate::url::NfsUrl;

const MAX_SYMLINK_DEPTH: u32 = 40;

/// Banderas de apertura de fichero.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags {
    /// Abrir para escritura.
    pub write: bool,
    /// Crear si no existe.
    pub create: bool,
    /// Fallar si ya existe (con `create`).
    pub exclusive: bool,
    /// Truncar a 0 al abrir.
    pub truncate: bool,
    /// Modo con el que crear (por defecto 0o644).
    pub mode: u32,
}

impl OpenFlags {
    /// Solo lectura.
    pub fn read_only() -> Self {
        Self::default()
    }
    /// Lectura y escritura.
    pub fn read_write() -> Self {
        Self {
            write: true,
            ..Self::default()
        }
    }
    /// Crear (o truncar) para escritura, modo 0o644.
    pub fn create_write() -> Self {
        Self {
            write: true,
            create: true,
            truncate: true,
            mode: 0o644,
            ..Self::default()
        }
    }
}

/// Un fichero abierto en el contexto NFS.
#[derive(Debug, Clone)]
pub struct NfsFile {
    inner: OpenFile,
}

/// Testigo de un bloqueo activo; se devuelve a [`NfsContext::unlock`] para
/// liberarlo.
#[derive(Debug, Clone)]
pub struct LockHandle {
    token: LockToken,
}

/// Contexto de cliente NFS montado sobre un export.
pub struct NfsContext {
    backend: Box<dyn Backend>,
    root: ObjId,
}

impl NfsContext {
    /// Monta a partir de una URL `nfs://...`.
    pub fn mount_url(url: &str) -> Result<Self, NfsError> {
        Self::mount_parsed(&NfsUrl::parse(url)?)
    }

    /// Monta `export` del `server` con opciones por defecto (NFSv3).
    pub fn mount(server: &str, export: &str) -> Result<Self, NfsError> {
        Self::mount_parsed(&NfsUrl {
            server: server.to_string(),
            path: export.to_string(),
            ..NfsUrl::default()
        })
    }

    fn mount_parsed(url: &NfsUrl) -> Result<Self, NfsError> {
        let cred = Credentials::unix(url.uid, url.gid);
        let timeout = Duration::from_secs(url.timeo);
        if url.version == 4 {
            Self::mount_v4(url, cred, timeout)
        } else {
            Self::mount_v3(url, cred, timeout)
        }
    }

    fn mount_v3(url: &NfsUrl, cred: Credentials, timeout: Duration) -> Result<Self, NfsError> {
        let opts = MountOptions {
            protocol: Protocol::Tcp,
            cred: cred.clone(),
            timeout,
            mount_port: url.mountport,
            nfs_port: url.nfsport,
            ..MountOptions::default()
        };
        let info = connect::mount(&url.server, &url.path, &opts)?;
        let nfs = Nfs3::connect(
            info.server,
            info.nfs_port,
            cred.clone(),
            Protocol::Tcp,
            timeout,
        )?;
        let nlm_config = NlmConfig {
            server: info.server,
            protocol: Protocol::Tcp,
            cred,
            timeout,
            portmap_port: connect::PORTMAP_PORT,
        };
        let backend = V3Backend::new(nfs, &info.root_fh, nlm_config)?;
        Ok(Self {
            backend: Box::new(backend),
            root: info.root_fh,
        })
    }

    fn mount_v4(url: &NfsUrl, cred: Credentials, timeout: Duration) -> Result<Self, NfsError> {
        let port = url.nfsport.unwrap_or(connect::NFS_PORT);
        let ip = resolve_ip(&url.server, port)?;
        let mut nfs = connect_v4(ip, port, cred, timeout, url)?;
        // El export es una ruta dentro del pseudo-sistema de ficheros v4.
        let mut root = nfs.root_fh()?;
        for comp in split_components(&url.path) {
            let (fh, _) = nfs.lookup(&root, &comp)?;
            root = fh;
        }
        let backend = V4Backend::new(nfs);
        Ok(Self {
            backend: Box::new(backend),
            root: root.data,
        })
    }

    /// Versión de NFS negociada (3 o 4).
    pub fn version(&self) -> u32 {
        self.backend.version()
    }

    // --- Resolución de rutas -------------------------------------------------

    /// Resuelve una ruta absoluta (relativa al export) a su file handle.
    /// Si `follow_final` es `true`, sigue un enlace simbólico final.
    fn resolve(&mut self, path: &str, follow_final: bool) -> Result<ObjId, NfsError> {
        let mut cur = self.root.clone();
        let mut comps: VecDeque<String> = split_components(path).into_iter().collect();
        let mut depth = 0u32;
        while let Some(name) = comps.pop_front() {
            if name == "." {
                continue;
            }
            let (fh, attr) = self.backend.lookup(&cur, &name)?;
            let is_last = comps.is_empty();
            if attr.is_symlink() && (!is_last || follow_final) {
                depth += 1;
                if depth > MAX_SYMLINK_DEPTH {
                    return Err(NfsError::TooManySymlinks);
                }
                let target = self.backend.readlink(&fh)?;
                let mut spliced: VecDeque<String> = split_components(&target).into_iter().collect();
                spliced.extend(comps.drain(..));
                comps = spliced;
                if target.starts_with('/') {
                    cur = self.root.clone();
                }
                // si es relativo, `cur` sigue siendo el directorio padre
            } else {
                cur = fh;
            }
        }
        Ok(cur)
    }

    /// Devuelve (fh del directorio padre, nombre final).
    fn resolve_parent(&mut self, path: &str) -> Result<(ObjId, String), NfsError> {
        let comps = split_components(path);
        let name = comps
            .last()
            .cloned()
            .ok_or_else(|| NfsError::InvalidPath(path.to_string()))?;
        let parent_path = format!("/{}", comps[..comps.len() - 1].join("/"));
        let dir = self.resolve(&parent_path, true)?;
        Ok((dir, name))
    }

    // --- Metadatos -----------------------------------------------------------

    /// Atributos de `path` (siguiendo enlaces simbólicos).
    pub fn stat(&mut self, path: &str) -> Result<Attr, NfsError> {
        let fh = self.resolve(path, true)?;
        self.backend.getattr(&fh)
    }

    /// Atributos de `path` (sin seguir un enlace simbólico final).
    pub fn lstat(&mut self, path: &str) -> Result<Attr, NfsError> {
        let fh = self.resolve(path, false)?;
        self.backend.getattr(&fh)
    }

    /// `true` si `path` es accesible para lectura.
    pub fn access(&mut self, path: &str) -> Result<bool, NfsError> {
        let fh = self.resolve(path, true)?;
        let granted = self.backend.access(&fh, ACCESS3_READ)?;
        Ok(granted & ACCESS3_READ != 0)
    }

    // --- Ficheros ------------------------------------------------------------

    /// Abre un fichero existente o lo crea según `flags`.
    pub fn open(&mut self, path: &str, flags: OpenFlags) -> Result<NfsFile, NfsError> {
        let (dir, name) = self.resolve_parent(path)?;
        let mode = if flags.mode == 0 { 0o644 } else { flags.mode };
        let opts = OpenOpts {
            write: flags.write,
            create: flags.create,
            exclusive: flags.exclusive,
            mode,
        };
        let file = self.backend.open(&dir, &name, opts)?;
        let nfsfile = NfsFile { inner: file };
        if flags.truncate && flags.write {
            self.backend.setattr(
                &nfsfile.inner.fh,
                &SetAttr {
                    size: Some(0),
                    ..SetAttr::default()
                },
            )?;
        }
        Ok(nfsfile)
    }

    /// Crea (o trunca) un fichero para escritura.
    pub fn create(&mut self, path: &str) -> Result<NfsFile, NfsError> {
        self.open(path, OpenFlags::create_write())
    }

    /// Cierra un fichero (hace `commit` si era escribible).
    pub fn close(&mut self, file: NfsFile) -> Result<(), NfsError> {
        if file.inner.writable {
            let _ = self.backend.commit(&file.inner);
        }
        self.backend.close(&file.inner)
    }

    /// Fuerza la persistencia de los datos escritos.
    pub fn fsync(&mut self, file: &NfsFile) -> Result<(), NfsError> {
        self.backend.commit(&file.inner)
    }

    /// Lee `count` bytes desde `offset`, troceando según el tamaño preferido.
    pub fn pread(&mut self, file: &NfsFile, offset: u64, count: u64) -> Result<Bytes, NfsError> {
        let chunk = self.backend.pref_read() as u64;
        let mut out = bytes::BytesMut::new();
        let mut pos = offset;
        let mut left = count;
        while left > 0 {
            let want = left.min(chunk) as u32;
            let (data, eof) = self.backend.pread(&file.inner, pos, want)?;
            let got = data.len() as u64;
            out.extend_from_slice(&data);
            pos += got;
            left -= got.min(left);
            if eof || got == 0 {
                break;
            }
        }
        Ok(out.freeze())
    }

    /// Escribe `data` en `offset`, troceando según el tamaño preferido.
    /// Devuelve el total de bytes escritos.
    pub fn pwrite(&mut self, file: &NfsFile, offset: u64, data: &[u8]) -> Result<u64, NfsError> {
        let chunk = self.backend.pref_write() as usize;
        let mut written = 0u64;
        let mut pos = offset;
        for piece in data.chunks(chunk) {
            let n = self
                .backend
                .pwrite(&file.inner, pos, Bytes::copy_from_slice(piece))?;
            written += n as u64;
            pos += n as u64;
            if (n as usize) < piece.len() {
                break;
            }
        }
        Ok(written)
    }

    /// Lee un fichero completo a memoria.
    pub fn read_whole(&mut self, path: &str) -> Result<Bytes, NfsError> {
        let attr = self.stat(path)?;
        let file = self.open(path, OpenFlags::read_only())?;
        let data = self.pread(&file, 0, attr.size);
        let _ = self.close(file);
        data
    }

    /// Escribe `data` como contenido completo de `path` (créalo/trúncalo).
    pub fn write_whole(&mut self, path: &str, data: &[u8]) -> Result<(), NfsError> {
        let file = self.create(path)?;
        let result = self.pwrite(&file, 0, data).map(|_| ());
        self.close(file)?;
        result
    }

    // --- Directorios y nombres ----------------------------------------------

    /// Lista el contenido de un directorio.
    pub fn readdir(&mut self, path: &str) -> Result<Vec<DirEntry>, NfsError> {
        let fh = self.resolve(path, true)?;
        self.backend.readdir(&fh)
    }

    /// Crea un directorio (modo 0o755).
    pub fn mkdir(&mut self, path: &str) -> Result<(), NfsError> {
        let (dir, name) = self.resolve_parent(path)?;
        self.backend.mkdir(&dir, &name, 0o755)?;
        Ok(())
    }

    /// Borra un directorio vacío.
    pub fn rmdir(&mut self, path: &str) -> Result<(), NfsError> {
        let (dir, name) = self.resolve_parent(path)?;
        self.backend.rmdir(&dir, &name)
    }

    /// Borra un fichero.
    pub fn unlink(&mut self, path: &str) -> Result<(), NfsError> {
        let (dir, name) = self.resolve_parent(path)?;
        self.backend.remove(&dir, &name)
    }

    /// Renombra/mueve `from` a `to`.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), NfsError> {
        let (from_dir, from_name) = self.resolve_parent(from)?;
        let (to_dir, to_name) = self.resolve_parent(to)?;
        self.backend
            .rename(&from_dir, &from_name, &to_dir, &to_name)
    }

    /// Crea un enlace simbólico en `linkpath` que apunta a `target`.
    pub fn symlink(&mut self, target: &str, linkpath: &str) -> Result<(), NfsError> {
        let (dir, name) = self.resolve_parent(linkpath)?;
        self.backend.symlink(&dir, &name, target)
    }

    /// Lee el destino de un enlace simbólico.
    pub fn readlink(&mut self, path: &str) -> Result<String, NfsError> {
        let fh = self.resolve(path, false)?;
        self.backend.readlink(&fh)
    }

    /// Crea un enlace duro `newpath` -> `oldpath`.
    pub fn link(&mut self, oldpath: &str, newpath: &str) -> Result<(), NfsError> {
        let fh = self.resolve(oldpath, true)?;
        let (dir, name) = self.resolve_parent(newpath)?;
        self.backend.link(&fh, &dir, &name)
    }

    /// Cambia el modo de `path`.
    pub fn chmod(&mut self, path: &str, mode: u32) -> Result<(), NfsError> {
        let fh = self.resolve(path, true)?;
        self.backend.setattr(
            &fh,
            &SetAttr {
                mode: Some(mode),
                ..SetAttr::default()
            },
        )
    }

    /// Cambia el propietario/grupo de `path`.
    pub fn chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), NfsError> {
        let fh = self.resolve(path, true)?;
        self.backend.setattr(
            &fh,
            &SetAttr {
                uid: Some(uid),
                gid: Some(gid),
                ..SetAttr::default()
            },
        )
    }

    /// Trunca `path` a `size` bytes.
    pub fn truncate(&mut self, path: &str, size: u64) -> Result<(), NfsError> {
        let fh = self.resolve(path, true)?;
        self.backend.setattr(
            &fh,
            &SetAttr {
                size: Some(size),
                ..SetAttr::default()
            },
        )
    }

    /// Estadísticas del sistema de ficheros en `path`.
    pub fn statvfs(&mut self, path: &str) -> Result<StatVfs, NfsError> {
        let fh = self.resolve(path, true)?;
        self.backend.statvfs(&fh)
    }

    // --- Bloqueos byte-range (fcntl) ----------------------------------------

    /// Toma un bloqueo byte-range sobre un fichero abierto. Usa NLM en NFSv3 y
    /// `LOCK` en NFSv4. Devuelve `Err(NfsError::Locked)` si hay conflicto.
    pub fn lock(
        &mut self,
        file: &NfsFile,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<LockHandle, NfsError> {
        let token = self.backend.lock(&file.inner, offset, length, exclusive)?;
        Ok(LockHandle { token })
    }

    /// Libera un bloqueo tomado con [`NfsContext::lock`].
    pub fn unlock(&mut self, file: &NfsFile, lock: LockHandle) -> Result<(), NfsError> {
        self.backend.unlock(&file.inner, &lock.token)
    }

    /// Comprueba si un bloqueo se podría conceder (`true` = disponible).
    pub fn test_lock(
        &mut self,
        file: &NfsFile,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<bool, NfsError> {
        self.backend
            .test_lock(&file.inner, offset, length, exclusive)
    }
}

/// Conecta el cliente NFSv4 (con TLS si la URL lo pide y la feature está activa).
fn connect_v4(
    ip: IpAddr,
    port: u16,
    cred: Credentials,
    timeout: Duration,
    url: &NfsUrl,
) -> Result<Nfs4, NfsError> {
    if url.tls {
        #[cfg(feature = "tls")]
        {
            let params = if url.tls_insecure {
                nfs_rpc::TlsParams::insecure(url.server.clone())
            } else {
                // Montaje por URL: validación con las raíces del sistema operativo
                // pendiente; por ahora sin mTLS (usar la API si se requiere).
                nfs_rpc::TlsParams::with_roots(url.server.clone(), Vec::new())
            };
            let rpc = nfs_rpc::RpcClient::connect_tls(
                SocketAddr::new(ip, port),
                nfs_proto::nfs4::PROGRAM,
                nfs_proto::nfs4::VERSION4,
                cred,
                timeout,
                &params,
            )?;
            return Ok(Nfs4::from_client(rpc, url.minorversion)?);
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = (ip, port, &cred, timeout);
            return Err(NfsError::InvalidUrl(
                "TLS solicitado pero la feature `tls` no está activada".to_string(),
            ));
        }
    }
    Ok(Nfs4::connect_minor(
        ip,
        port,
        cred,
        Protocol::Tcp,
        timeout,
        url.minorversion,
    )?)
}

/// Divide una ruta en componentes no vacíos (ignora `/` repetidos y vacíos).
fn split_components(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|c| !c.is_empty())
        .map(|c| c.to_string())
        .collect()
}

fn resolve_ip(server: &str, port: u16) -> Result<IpAddr, NfsError> {
    let addr: Option<SocketAddr> = (server, port).to_socket_addrs()?.next();
    addr.map(|s| s.ip())
        .ok_or_else(|| NfsError::InvalidUrl(format!("no se pudo resolver «{server}»")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_components_basic() {
        assert_eq!(split_components("/a/b/c"), vec!["a", "b", "c"]);
        assert_eq!(split_components("//a///b/"), vec!["a", "b"]);
        assert!(split_components("/").is_empty());
    }
}
