//! Errores de la API VFS.

use nfs_proto::ProtoError;

/// Error de una operación del cliente NFS de alto nivel.
///
/// Los `nfsstat3`/`nfsstat4` comunes se traducen a variantes semánticas; el
/// resto se conserva en [`NfsError::Proto`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NfsError {
    /// El objeto no existe.
    #[error("no existe el fichero o directorio")]
    NotFound,
    /// Se esperaba un directorio y no lo es.
    #[error("no es un directorio")]
    NotADirectory,
    /// Es un directorio (operación no válida sobre directorios).
    #[error("es un directorio")]
    IsADirectory,
    /// El objeto ya existe.
    #[error("ya existe")]
    AlreadyExists,
    /// Permiso denegado.
    #[error("permiso denegado")]
    PermissionDenied,
    /// El directorio no está vacío.
    #[error("el directorio no está vacío")]
    NotEmpty,
    /// Nombre demasiado largo.
    #[error("nombre demasiado largo")]
    NameTooLong,
    /// Sin espacio en el dispositivo.
    #[error("sin espacio en el dispositivo")]
    NoSpace,
    /// Sistema de ficheros de solo lectura.
    #[error("sistema de ficheros de solo lectura")]
    ReadOnly,
    /// File handle obsoleto.
    #[error("file handle obsoleto")]
    Stale,
    /// Argumento inválido.
    #[error("argumento inválido")]
    InvalidArgument,
    /// Se superó el límite de enlaces simbólicos al resolver la ruta.
    #[error("demasiados enlaces simbólicos al resolver la ruta")]
    TooManySymlinks,
    /// Un bloqueo está en conflicto con otro (lock denegado).
    #[error("recurso bloqueado por otro cliente")]
    Locked,
    /// La ruta es inválida (vacía o mal formada).
    #[error("ruta inválida: {0}")]
    InvalidPath(String),
    /// URL `nfs://` mal formada.
    #[error("URL inválida: {0}")]
    InvalidUrl(String),
    /// Error de E/S al resolver el servidor.
    #[error("E/S: {0}")]
    Io(#[from] std::io::Error),
    /// Otro error de protocolo no traducido a una variante semántica.
    #[error("protocolo: {0}")]
    Proto(ProtoError),
}

impl From<nfs_rpc::RpcError> for NfsError {
    fn from(err: nfs_rpc::RpcError) -> Self {
        NfsError::from(ProtoError::from(err))
    }
}

impl From<ProtoError> for NfsError {
    fn from(err: ProtoError) -> Self {
        match err {
            ProtoError::Nfs3(code) => from_nfsstat3(code),
            ProtoError::Nfs4(code) => from_nfsstat4(code),
            ProtoError::Io(e) => NfsError::Io(e),
            // NLM4_DENIED = 1: bloqueo en conflicto.
            ProtoError::Nlm(1) => NfsError::Locked,
            other => NfsError::Proto(other),
        }
    }
}

fn from_nfsstat3(code: u32) -> NfsError {
    use nfs_proto::nfs3::*;
    match code {
        NFS3ERR_NOENT => NfsError::NotFound,
        NFS3ERR_NOTDIR => NfsError::NotADirectory,
        NFS3ERR_ISDIR => NfsError::IsADirectory,
        NFS3ERR_EXIST => NfsError::AlreadyExists,
        NFS3ERR_PERM | NFS3ERR_ACCES => NfsError::PermissionDenied,
        NFS3ERR_NOTEMPTY => NfsError::NotEmpty,
        NFS3ERR_NAMETOOLONG => NfsError::NameTooLong,
        NFS3ERR_NOSPC => NfsError::NoSpace,
        NFS3ERR_ROFS => NfsError::ReadOnly,
        NFS3ERR_STALE => NfsError::Stale,
        NFS3ERR_INVAL => NfsError::InvalidArgument,
        other => NfsError::Proto(ProtoError::Nfs3(other)),
    }
}

fn from_nfsstat4(code: u32) -> NfsError {
    use nfs_proto::nfs4::*;
    match code {
        NFS4ERR_NOENT => NfsError::NotFound,
        NFS4ERR_NOTDIR => NfsError::NotADirectory,
        NFS4ERR_EXIST => NfsError::AlreadyExists,
        NFS4ERR_ACCESS => NfsError::PermissionDenied,
        NFS4ERR_NOTEMPTY => NfsError::NotEmpty,
        NFS4ERR_STALE => NfsError::Stale,
        NFS4ERR_INVAL => NfsError::InvalidArgument,
        NFS4ERR_DENIED => NfsError::Locked,
        other => NfsError::Proto(ProtoError::Nfs4(other)),
    }
}
