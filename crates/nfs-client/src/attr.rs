//! Tipos unificados de atributos, independientes de la versión de NFS.

use nfs_proto::nfs3::{self, Fattr3};
use nfs_proto::nfs4::Fattr4;

/// Tipo de objeto del sistema de ficheros.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Fichero regular.
    Regular,
    /// Directorio.
    Directory,
    /// Enlace simbólico.
    Symlink,
    /// Dispositivo de bloques.
    Block,
    /// Dispositivo de caracteres.
    Char,
    /// Socket.
    Socket,
    /// FIFO.
    Fifo,
    /// Tipo desconocido.
    Unknown,
}

impl FileType {
    fn from_nfs(value: u32) -> Self {
        // NFSv3 y NFSv4 comparten los valores bajos de ftype.
        match value {
            1 => FileType::Regular,
            2 => FileType::Directory,
            3 => FileType::Block,
            4 => FileType::Char,
            5 => FileType::Symlink,
            6 => FileType::Socket,
            7 => FileType::Fifo,
            _ => FileType::Unknown,
        }
    }
}

/// Marca de tiempo (segundos + nanosegundos desde la época Unix).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timestamp {
    /// Segundos.
    pub secs: i64,
    /// Nanosegundos.
    pub nsecs: u32,
}

/// Atributos unificados de un objeto del sistema de ficheros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    /// Tipo de objeto.
    pub file_type: FileType,
    /// Bits de modo/permisos.
    pub mode: u32,
    /// Número de enlaces.
    pub nlink: u32,
    /// UID propietario.
    pub uid: u32,
    /// GID propietario.
    pub gid: u32,
    /// Tamaño en bytes.
    pub size: u64,
    /// Espacio usado en bytes.
    pub used: u64,
    /// Identificador del fichero (inode).
    pub fileid: u64,
    /// Dispositivo (major, minor).
    pub rdev: (u32, u32),
    /// Tiempo de último acceso.
    pub atime: Timestamp,
    /// Tiempo de última modificación.
    pub mtime: Timestamp,
    /// Tiempo de último cambio de metadatos.
    pub ctime: Timestamp,
}

impl Attr {
    /// `true` si el objeto es un directorio.
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }

    /// `true` si el objeto es un fichero regular.
    pub fn is_file(&self) -> bool {
        self.file_type == FileType::Regular
    }

    /// `true` si el objeto es un enlace simbólico.
    pub fn is_symlink(&self) -> bool {
        self.file_type == FileType::Symlink
    }

    pub(crate) fn from_fattr3(a: &Fattr3) -> Self {
        Attr {
            file_type: FileType::from_nfs(a.ftype),
            mode: a.mode,
            nlink: a.nlink,
            uid: a.uid,
            gid: a.gid,
            size: a.size,
            used: a.used,
            fileid: a.fileid,
            rdev: (a.rdev.specdata1, a.rdev.specdata2),
            atime: Timestamp {
                secs: a.atime.seconds as i64,
                nsecs: a.atime.nseconds,
            },
            mtime: Timestamp {
                secs: a.mtime.seconds as i64,
                nsecs: a.mtime.nseconds,
            },
            ctime: Timestamp {
                secs: a.ctime.seconds as i64,
                nsecs: a.ctime.nseconds,
            },
        }
    }

    pub(crate) fn from_fattr4(a: &Fattr4) -> Self {
        let ts = |t: Option<nfs_proto::nfs4::Nfstime4>| {
            t.map(|t| Timestamp {
                secs: t.seconds,
                nsecs: t.nseconds,
            })
            .unwrap_or_default()
        };
        Attr {
            file_type: a.ftype.map(FileType::from_nfs).unwrap_or(FileType::Unknown),
            mode: a.mode.unwrap_or(0),
            nlink: a.numlinks.unwrap_or(1),
            uid: 0, // v4 usa owner string; el mapeo a uid numérico es de la Fase 5+
            gid: 0,
            size: a.size.unwrap_or(0),
            used: a.space_used.unwrap_or(0),
            fileid: a.fileid.unwrap_or(0),
            rdev: a.rawdev.unwrap_or((0, 0)),
            atime: ts(a.time_access),
            mtime: ts(a.time_modify),
            ctime: ts(a.time_metadata),
        }
    }
}

/// Atributos a establecer (chmod/chown/truncate/utimes).
#[derive(Debug, Clone, Default)]
pub struct SetAttr {
    /// Nuevo modo.
    pub mode: Option<u32>,
    /// Nuevo UID.
    pub uid: Option<u32>,
    /// Nuevo GID.
    pub gid: Option<u32>,
    /// Nuevo tamaño.
    pub size: Option<u64>,
    /// Nuevo atime.
    pub atime: Option<Timestamp>,
    /// Nuevo mtime.
    pub mtime: Option<Timestamp>,
}

impl SetAttr {
    pub(crate) fn to_sattr3(&self) -> nfs3::Sattr3 {
        nfs3::Sattr3 {
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            size: self.size,
            atime: self
                .atime
                .map(|t| {
                    nfs3::SetTime::ToClientTime(nfs3::Nfstime3 {
                        seconds: t.secs as u32,
                        nseconds: t.nsecs,
                    })
                })
                .unwrap_or(nfs3::SetTime::DontChange),
            mtime: self
                .mtime
                .map(|t| {
                    nfs3::SetTime::ToClientTime(nfs3::Nfstime3 {
                        seconds: t.secs as u32,
                        nseconds: t.nsecs,
                    })
                })
                .unwrap_or(nfs3::SetTime::DontChange),
        }
    }
}

/// Una entrada de directorio.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Nombre de la entrada.
    pub name: String,
    /// Identificador del fichero.
    pub fileid: u64,
    /// Atributos, si el servidor los devolvió.
    pub attr: Option<Attr>,
}

/// Estadísticas del sistema de ficheros (`statvfs`).
#[derive(Debug, Clone, Copy, Default)]
pub struct StatVfs {
    /// Tamaño de bloque (bytes). Se reporta 1 para que `blocks == bytes`.
    pub block_size: u32,
    /// Bloques totales.
    pub total_blocks: u64,
    /// Bloques libres.
    pub free_blocks: u64,
    /// Bloques disponibles para el usuario.
    pub avail_blocks: u64,
    /// Ficheros (inodos) totales.
    pub total_files: u64,
    /// Ficheros libres.
    pub free_files: u64,
    /// Ficheros disponibles para el usuario.
    pub avail_files: u64,
}
