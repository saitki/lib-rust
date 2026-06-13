//! Abstracción de backend que independiza la API VFS de la versión de NFS.

use nfs_proto::Bytes;

use crate::attr::{Attr, DirEntry, SetAttr, StatVfs};
use crate::error::NfsError;

/// Identificador opaco de un objeto (el file handle, común a v3 y v4).
pub type ObjId = Bytes;

/// Un fichero abierto. En v3 es solo el file handle; en v4 lleva además el
/// `stateid` devuelto por `OPEN`.
#[derive(Debug, Clone)]
pub struct OpenFile {
    /// File handle del objeto.
    pub fh: ObjId,
    /// Stateid de NFSv4 (ausente en v3).
    pub(crate) stateid: Option<nfs_proto::nfs4::Stateid4>,
    /// Si se abrió para escritura.
    pub writable: bool,
}

/// Testigo de un bloqueo activo, devuelto por `lock` y consumido por `unlock`.
#[derive(Debug, Clone)]
pub enum LockToken {
    /// Bloqueo NFSv3 (NLM): basta el rango (el fh/owner los tiene el backend).
    V3 {
        /// Desplazamiento bloqueado.
        offset: u64,
        /// Longitud bloqueada.
        length: u64,
    },
    /// Bloqueo NFSv4: stateid del bloqueo + rango.
    V4 {
        /// Concesión devuelta por `LOCK`.
        grant: nfs_proto::nfs4::LockGrant,
        /// Desplazamiento bloqueado.
        offset: u64,
        /// Longitud bloqueada.
        length: u64,
    },
}

/// Opciones de apertura.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOpts {
    /// Abrir para escritura.
    pub write: bool,
    /// Crear si no existe.
    pub create: bool,
    /// Fallar si existe (junto con `create`).
    pub exclusive: bool,
    /// Modo con el que crear.
    pub mode: u32,
}

/// Operaciones que cada versión de NFS implementa para la capa VFS.
pub trait Backend: Send {
    /// Versión de NFS (3 o 4).
    fn version(&self) -> u32;
    /// Tamaño de lectura preferido (bytes).
    fn pref_read(&self) -> u32;
    /// Tamaño de escritura preferido (bytes).
    fn pref_write(&self) -> u32;

    /// Atributos de un objeto.
    fn getattr(&mut self, fh: &ObjId) -> Result<Attr, NfsError>;
    /// Resuelve `name` dentro de `dir`.
    fn lookup(&mut self, dir: &ObjId, name: &str) -> Result<(ObjId, Attr), NfsError>;
    /// Abre (o crea) `name` dentro de `dir`.
    fn open(&mut self, dir: &ObjId, name: &str, opts: OpenOpts) -> Result<OpenFile, NfsError>;
    /// Cierra un fichero abierto.
    fn close(&mut self, file: &OpenFile) -> Result<(), NfsError>;
    /// Lee hasta `count` bytes desde `offset`. Devuelve (datos, eof).
    fn pread(
        &mut self,
        file: &OpenFile,
        offset: u64,
        count: u32,
    ) -> Result<(Bytes, bool), NfsError>;
    /// Escribe `data` en `offset`. Devuelve los bytes escritos.
    fn pwrite(&mut self, file: &OpenFile, offset: u64, data: Bytes) -> Result<u32, NfsError>;
    /// Fuerza la persistencia de los datos escritos.
    fn commit(&mut self, file: &OpenFile) -> Result<(), NfsError>;

    /// Crea un directorio y devuelve su file handle.
    fn mkdir(&mut self, dir: &ObjId, name: &str, mode: u32) -> Result<ObjId, NfsError>;
    /// Borra un directorio vacío.
    fn rmdir(&mut self, dir: &ObjId, name: &str) -> Result<(), NfsError>;
    /// Borra un fichero.
    fn remove(&mut self, dir: &ObjId, name: &str) -> Result<(), NfsError>;
    /// Renombra/mueve un objeto.
    fn rename(
        &mut self,
        from_dir: &ObjId,
        from_name: &str,
        to_dir: &ObjId,
        to_name: &str,
    ) -> Result<(), NfsError>;
    /// Crea un enlace simbólico.
    fn symlink(&mut self, dir: &ObjId, name: &str, target: &str) -> Result<(), NfsError>;
    /// Lee el destino de un enlace simbólico.
    fn readlink(&mut self, fh: &ObjId) -> Result<String, NfsError>;
    /// Crea un enlace duro.
    fn link(&mut self, fh: &ObjId, dir: &ObjId, name: &str) -> Result<(), NfsError>;
    /// Fija atributos de un objeto.
    fn setattr(&mut self, fh: &ObjId, attr: &SetAttr) -> Result<(), NfsError>;
    /// Lista el contenido de un directorio.
    fn readdir(&mut self, dir: &ObjId) -> Result<Vec<DirEntry>, NfsError>;
    /// Estadísticas del sistema de ficheros.
    fn statvfs(&mut self, fh: &ObjId) -> Result<StatVfs, NfsError>;
    /// Comprueba permisos; devuelve la máscara concedida.
    fn access(&mut self, fh: &ObjId, mask: u32) -> Result<u32, NfsError>;

    /// Toma un bloqueo byte-range sobre un fichero abierto.
    fn lock(
        &mut self,
        file: &OpenFile,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<LockToken, NfsError>;
    /// Libera un bloqueo previamente tomado.
    fn unlock(&mut self, file: &OpenFile, token: &LockToken) -> Result<(), NfsError>;
    /// Comprueba si un bloqueo se podría conceder (`true` = disponible).
    fn test_lock(
        &mut self,
        file: &OpenFile,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<bool, NfsError>;
}

/// Acota un tamaño preferido de read/write a un rango razonable.
pub(crate) fn clamp_pref(value: u32) -> u32 {
    value.clamp(32 * 1024, 1024 * 1024)
}
