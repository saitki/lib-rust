//! NFSv3 (RFC 1813): tipos XDR y los 22 procedimientos a nivel RAW.
//!
//! Programa RPC 100003, versión 3. Cada procedimiento se expone como un método
//! de [`Nfs3`] que codifica los argumentos, ejecuta la llamada RPC y decodifica
//! el resultado, mapeando los `nfsstat3` de error a [`ProtoError::Nfs3`].

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use nfs_rpc::{Credentials, Protocol, RpcClient};
use nfs_xdr::{Bytes, XdrDecode, XdrEncode, XdrError};

use crate::error::ProtoError;

/// Número de programa de NFS.
pub const PROGRAM: u32 = 100003;
/// Versión 3 de NFS.
pub const VERSION3: u32 = 3;

/// `nfsstat3` de éxito.
pub const NFS3_OK: u32 = 0;

// Números de procedimiento NFSv3 (RFC 1813 §3).
const PROC_GETATTR: u32 = 1;
const PROC_SETATTR: u32 = 2;
const PROC_LOOKUP: u32 = 3;
const PROC_ACCESS: u32 = 4;
const PROC_READLINK: u32 = 5;
const PROC_READ: u32 = 6;
const PROC_WRITE: u32 = 7;
const PROC_CREATE: u32 = 8;
const PROC_MKDIR: u32 = 9;
const PROC_SYMLINK: u32 = 10;
const PROC_MKNOD: u32 = 11;
const PROC_REMOVE: u32 = 12;
const PROC_RMDIR: u32 = 13;
const PROC_RENAME: u32 = 14;
const PROC_LINK: u32 = 15;
const PROC_READDIR: u32 = 16;
const PROC_READDIRPLUS: u32 = 17;
const PROC_FSSTAT: u32 = 18;
const PROC_FSINFO: u32 = 19;
const PROC_PATHCONF: u32 = 20;
const PROC_COMMIT: u32 = 21;

// --- ftype3 ------------------------------------------------------------------

/// Fichero regular.
pub const NF3REG: u32 = 1;
/// Directorio.
pub const NF3DIR: u32 = 2;
/// Dispositivo de bloques.
pub const NF3BLK: u32 = 3;
/// Dispositivo de caracteres.
pub const NF3CHR: u32 = 4;
/// Enlace simbólico.
pub const NF3LNK: u32 = 5;
/// Socket.
pub const NF3SOCK: u32 = 6;
/// FIFO.
pub const NF3FIFO: u32 = 7;

// --- bits de ACCESS ----------------------------------------------------------

/// Permiso de lectura de datos / listado de directorio.
pub const ACCESS3_READ: u32 = 0x0001;
/// Permiso de búsqueda en directorio.
pub const ACCESS3_LOOKUP: u32 = 0x0002;
/// Permiso de modificación de datos existentes.
pub const ACCESS3_MODIFY: u32 = 0x0004;
/// Permiso de extensión (añadir datos / crear entradas).
pub const ACCESS3_EXTEND: u32 = 0x0008;
/// Permiso de borrado de una entrada de directorio.
pub const ACCESS3_DELETE: u32 = 0x0010;
/// Permiso de ejecución.
pub const ACCESS3_EXECUTE: u32 = 0x0020;

// --- stable_how (WRITE) ------------------------------------------------------

/// Escritura sin garantía de persistencia (requiere COMMIT posterior).
pub const UNSTABLE: u32 = 0;
/// Persiste los datos antes de responder.
pub const DATA_SYNC: u32 = 1;
/// Persiste datos y metadatos antes de responder.
pub const FILE_SYNC: u32 = 2;

// --- createmode3 -------------------------------------------------------------

/// Crea sin comprobar si existe.
pub const UNCHECKED: u32 = 0;
/// Falla si el fichero ya existe.
pub const GUARDED: u32 = 1;
/// Creación exclusiva con verifier (semántica exactly-once).
pub const EXCLUSIVE: u32 = 2;

// --- nfsstat3 (subconjunto común) --------------------------------------------

/// No autorizado.
pub const NFS3ERR_PERM: u32 = 1;
/// No existe.
pub const NFS3ERR_NOENT: u32 = 2;
/// Error de E/S.
pub const NFS3ERR_IO: u32 = 5;
/// Acceso denegado.
pub const NFS3ERR_ACCES: u32 = 13;
/// Ya existe.
pub const NFS3ERR_EXIST: u32 = 17;
/// No es un directorio.
pub const NFS3ERR_NOTDIR: u32 = 20;
/// Es un directorio.
pub const NFS3ERR_ISDIR: u32 = 21;
/// Argumento inválido.
pub const NFS3ERR_INVAL: u32 = 22;
/// Sin espacio.
pub const NFS3ERR_NOSPC: u32 = 28;
/// Sistema de ficheros de solo lectura.
pub const NFS3ERR_ROFS: u32 = 30;
/// Nombre demasiado largo.
pub const NFS3ERR_NAMETOOLONG: u32 = 63;
/// Directorio no vacío.
pub const NFS3ERR_NOTEMPTY: u32 = 66;
/// File handle obsoleto.
pub const NFS3ERR_STALE: u32 = 70;
/// Operación no soportada.
pub const NFS3ERR_NOTSUPP: u32 = 10004;

// --- Tipos base --------------------------------------------------------------

/// Instante NFSv3 (`nfstime3`).
#[derive(XdrEncode, XdrDecode, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Nfstime3 {
    /// Segundos.
    pub seconds: u32,
    /// Nanosegundos.
    pub nseconds: u32,
}

/// Datos de dispositivo (`specdata3`).
#[derive(XdrEncode, XdrDecode, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Specdata3 {
    /// Major.
    pub specdata1: u32,
    /// Minor.
    pub specdata2: u32,
}

/// Atributos de un objeto (`fattr3`).
#[derive(XdrEncode, XdrDecode, Clone, Debug, PartialEq, Eq)]
pub struct Fattr3 {
    /// Tipo de objeto (`ftype3`).
    pub ftype: u32,
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
    /// Espacio realmente usado en bytes.
    pub used: u64,
    /// Datos de dispositivo (si aplica).
    pub rdev: Specdata3,
    /// Identificador del sistema de ficheros.
    pub fsid: u64,
    /// Identificador del fichero (inode).
    pub fileid: u64,
    /// Tiempo de último acceso.
    pub atime: Nfstime3,
    /// Tiempo de última modificación.
    pub mtime: Nfstime3,
    /// Tiempo de último cambio de atributos.
    pub ctime: Nfstime3,
}

/// File handle NFSv3 (`nfs_fh3`, opaque<64>).
#[derive(XdrEncode, XdrDecode, Clone, Debug, PartialEq, Eq)]
pub struct NfsFh3 {
    /// Bytes opacos del handle.
    #[xdr(limit = 64)]
    pub data: Bytes,
}

impl NfsFh3 {
    /// Crea un file handle a partir de bytes.
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self { data: data.into() }
    }
}

/// Atributos previos para comprobación débil de coherencia de caché (`wcc_attr`).
#[derive(XdrEncode, XdrDecode, Clone, Copy, Debug, PartialEq, Eq)]
pub struct WccAttr {
    /// Tamaño previo.
    pub size: u64,
    /// mtime previo.
    pub mtime: Nfstime3,
    /// ctime previo.
    pub ctime: Nfstime3,
}

/// Datos de coherencia débil de caché (`wcc_data`).
#[derive(XdrEncode, XdrDecode, Clone, Debug, Default, PartialEq, Eq)]
pub struct WccData {
    /// Atributos antes de la operación.
    pub before: Option<WccAttr>,
    /// Atributos después de la operación.
    pub after: Option<Fattr3>,
}

/// Especificación de cómo fijar un tiempo en `sattr3` (`set_atime`/`set_mtime`).
#[derive(XdrEncode, XdrDecode, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[xdr(union)]
pub enum SetTime {
    /// No cambiar (`DONT_CHANGE`).
    #[default]
    #[xdr(case = 0)]
    DontChange,
    /// Fijar al tiempo del servidor (`SET_TO_SERVER_TIME`).
    #[xdr(case = 1)]
    ToServerTime,
    /// Fijar al tiempo indicado por el cliente (`SET_TO_CLIENT_TIME`).
    #[xdr(case = 2)]
    ToClientTime(Nfstime3),
}

/// Atributos a establecer (`sattr3`); cada campo es opcional.
#[derive(XdrEncode, XdrDecode, Clone, Debug, Default, PartialEq, Eq)]
pub struct Sattr3 {
    /// Nuevo modo/permisos.
    pub mode: Option<u32>,
    /// Nuevo UID.
    pub uid: Option<u32>,
    /// Nuevo GID.
    pub gid: Option<u32>,
    /// Nuevo tamaño (truncado/extendido).
    pub size: Option<u64>,
    /// Cómo fijar atime.
    pub atime: SetTime,
    /// Cómo fijar mtime.
    pub mtime: SetTime,
}

impl Sattr3 {
    /// `sattr3` que no cambia ningún atributo.
    pub fn unchanged() -> Self {
        Self::default()
    }
}

// --- Resultado genérico ok/fail ----------------------------------------------

/// Resultado de un procedimiento NFSv3: éxito con payload `T`, o `nfsstat3` de
/// error. El payload de error (que en el protocolo a veces lleva `wcc_data`) se
/// ignora deliberadamente en esta capa RAW.
#[derive(Debug, Clone)]
pub enum Nfs3Result<T> {
    /// Éxito.
    Ok(T),
    /// Error con su `nfsstat3`.
    Fail(u32),
}

impl<T: XdrDecode> XdrDecode for Nfs3Result<T> {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let status = u32::decode(buf)?;
        if status == NFS3_OK {
            Ok(Nfs3Result::Ok(T::decode(buf)?))
        } else {
            Ok(Nfs3Result::Fail(status))
        }
    }
}

impl<T> Nfs3Result<T> {
    fn into_result(self) -> Result<T, ProtoError> {
        match self {
            Nfs3Result::Ok(value) => Ok(value),
            Nfs3Result::Fail(status) => Err(ProtoError::Nfs3(status)),
        }
    }
}

// --- Argumentos y resultados por procedimiento -------------------------------

/// Argumentos de búsqueda por nombre en un directorio (`diropargs3`).
#[derive(XdrEncode, XdrDecode, Clone, Debug)]
pub struct DirOpArgs3 {
    /// File handle del directorio.
    pub dir: NfsFh3,
    /// Nombre de la entrada.
    pub name: String,
}

/// Resultado OK de `LOOKUP`.
#[derive(XdrDecode, Clone, Debug)]
pub struct LookupOk {
    /// File handle del objeto encontrado.
    pub object: NfsFh3,
    /// Atributos del objeto.
    pub obj_attributes: Option<Fattr3>,
    /// Atributos del directorio.
    pub dir_attributes: Option<Fattr3>,
}

/// Argumentos de `ACCESS`.
#[derive(XdrEncode, Clone, Debug)]
pub struct AccessArgs {
    /// Objeto a consultar.
    pub object: NfsFh3,
    /// Máscara de permisos solicitados (bits `ACCESS3_*`).
    pub access: u32,
}

/// Resultado OK de `ACCESS`.
#[derive(XdrDecode, Clone, Debug)]
pub struct AccessOk {
    /// Atributos del objeto.
    pub obj_attributes: Option<Fattr3>,
    /// Máscara de permisos concedidos.
    pub access: u32,
}

/// Resultado OK de `READLINK`.
#[derive(XdrDecode, Clone, Debug)]
pub struct ReadlinkOk {
    /// Atributos del enlace.
    pub symlink_attributes: Option<Fattr3>,
    /// Ruta destino del enlace.
    pub data: String,
}

/// Argumentos de `READ`.
#[derive(XdrEncode, Clone, Debug)]
pub struct ReadArgs {
    /// Fichero a leer.
    pub file: NfsFh3,
    /// Desplazamiento inicial.
    pub offset: u64,
    /// Número de bytes a leer.
    pub count: u32,
}

/// Resultado OK de `READ`.
#[derive(XdrDecode, Clone, Debug)]
pub struct ReadOk {
    /// Atributos del fichero.
    pub file_attributes: Option<Fattr3>,
    /// Bytes leídos realmente.
    pub count: u32,
    /// Indica si se alcanzó el fin de fichero.
    pub eof: bool,
    /// Datos leídos.
    pub data: Bytes,
}

/// Argumentos de `WRITE`.
#[derive(XdrEncode, Clone, Debug)]
pub struct WriteArgs {
    /// Fichero a escribir.
    pub file: NfsFh3,
    /// Desplazamiento inicial.
    pub offset: u64,
    /// Número de bytes a escribir.
    pub count: u32,
    /// Modo de estabilidad (`UNSTABLE`/`DATA_SYNC`/`FILE_SYNC`).
    pub stable: u32,
    /// Datos a escribir.
    pub data: Bytes,
}

/// Resultado OK de `WRITE`.
#[derive(XdrDecode, Clone, Debug)]
pub struct WriteOk {
    /// Coherencia débil de caché del fichero.
    pub file_wcc: WccData,
    /// Bytes escritos.
    pub count: u32,
    /// Modo de estabilidad efectivo.
    pub committed: u32,
    /// Verifier de escritura (para COMMIT).
    pub verf: [u8; 8],
}

/// Forma de creación de un fichero (`createhow3`).
#[derive(XdrEncode, Clone, Debug)]
#[xdr(union)]
pub enum CreateHow3 {
    /// Crear sin comprobar (`UNCHECKED`).
    #[xdr(case = 0)]
    Unchecked(Sattr3),
    /// Crear fallando si existe (`GUARDED`).
    #[xdr(case = 1)]
    Guarded(Sattr3),
    /// Creación exclusiva con verifier (`EXCLUSIVE`).
    #[xdr(case = 2)]
    Exclusive([u8; 8]),
}

/// Argumentos de `CREATE`.
#[derive(XdrEncode, Clone, Debug)]
pub struct CreateArgs {
    /// Directorio y nombre destino.
    pub where_: DirOpArgs3,
    /// Modo de creación.
    pub how: CreateHow3,
}

/// Resultado OK de operaciones que crean un objeto (CREATE/MKDIR/SYMLINK/MKNOD).
#[derive(XdrDecode, Clone, Debug)]
pub struct CreateOk {
    /// File handle del objeto creado (si el servidor lo devuelve).
    pub obj: Option<NfsFh3>,
    /// Atributos del objeto creado.
    pub obj_attributes: Option<Fattr3>,
    /// Coherencia débil de caché del directorio.
    pub dir_wcc: WccData,
}

/// Argumentos de `MKDIR`.
#[derive(XdrEncode, Clone, Debug)]
pub struct MkdirArgs {
    /// Directorio y nombre destino.
    pub where_: DirOpArgs3,
    /// Atributos del nuevo directorio.
    pub attributes: Sattr3,
}

/// Datos de un enlace simbólico (`symlinkdata3`).
#[derive(XdrEncode, Clone, Debug)]
pub struct SymlinkData3 {
    /// Atributos del enlace.
    pub symlink_attributes: Sattr3,
    /// Ruta destino.
    pub symlink_data: String,
}

/// Argumentos de `SYMLINK`.
#[derive(XdrEncode, Clone, Debug)]
pub struct SymlinkArgs {
    /// Directorio y nombre del enlace.
    pub where_: DirOpArgs3,
    /// Datos del enlace.
    pub symlink: SymlinkData3,
}

/// Datos de dispositivo para `MKNOD` (`devicedata3`).
#[derive(XdrEncode, Clone, Debug)]
pub struct DeviceData3 {
    /// Atributos del dispositivo.
    pub dev_attributes: Sattr3,
    /// Major/minor.
    pub spec: Specdata3,
}

/// Qué crear en `MKNOD` (`mknoddata3`).
#[derive(XdrEncode, Clone, Debug)]
#[xdr(union)]
pub enum MknodData3 {
    /// Dispositivo de bloques.
    #[xdr(case = 3)]
    Blk(DeviceData3),
    /// Dispositivo de caracteres.
    #[xdr(case = 4)]
    Chr(DeviceData3),
    /// Socket.
    #[xdr(case = 6)]
    Sock(Sattr3),
    /// FIFO.
    #[xdr(case = 7)]
    Fifo(Sattr3),
}

/// Argumentos de `MKNOD`.
#[derive(XdrEncode, Clone, Debug)]
pub struct MknodArgs {
    /// Directorio y nombre destino.
    pub where_: DirOpArgs3,
    /// Qué crear.
    pub what: MknodData3,
}

/// Argumentos de `SETATTR`.
#[derive(XdrEncode, Clone, Debug)]
pub struct SetattrArgs {
    /// Objeto a modificar.
    pub object: NfsFh3,
    /// Nuevos atributos.
    pub new_attributes: Sattr3,
    /// Guarda opcional: solo aplicar si el ctime coincide.
    pub guard: Option<Nfstime3>,
}

/// Argumentos de `RENAME`.
#[derive(XdrEncode, Clone, Debug)]
pub struct RenameArgs {
    /// Origen (directorio + nombre).
    pub from: DirOpArgs3,
    /// Destino (directorio + nombre).
    pub to: DirOpArgs3,
}

/// Resultado OK de `RENAME`.
#[derive(XdrDecode, Clone, Debug)]
pub struct RenameOk {
    /// Coherencia del directorio origen.
    pub fromdir_wcc: WccData,
    /// Coherencia del directorio destino.
    pub todir_wcc: WccData,
}

/// Argumentos de `LINK`.
#[derive(XdrEncode, Clone, Debug)]
pub struct LinkArgs {
    /// Fichero existente.
    pub file: NfsFh3,
    /// Directorio + nombre del nuevo enlace.
    pub link: DirOpArgs3,
}

/// Resultado OK de `LINK`.
#[derive(XdrDecode, Clone, Debug)]
pub struct LinkOk {
    /// Atributos del fichero enlazado.
    pub file_attributes: Option<Fattr3>,
    /// Coherencia del directorio del enlace.
    pub linkdir_wcc: WccData,
}

/// Argumentos de `READDIR`.
#[derive(XdrEncode, Clone, Debug)]
pub struct ReaddirArgs {
    /// Directorio a listar.
    pub dir: NfsFh3,
    /// Cookie de continuación (0 para empezar).
    pub cookie: u64,
    /// Verifier de cookie (ceros para empezar).
    pub cookieverf: [u8; 8],
    /// Bytes máximos de la respuesta.
    pub count: u32,
}

/// Una entrada de directorio (`entry3`).
#[derive(Clone, Debug)]
pub struct Entry3 {
    /// Identificador del fichero.
    pub fileid: u64,
    /// Nombre de la entrada.
    pub name: String,
    /// Cookie para continuar tras esta entrada.
    pub cookie: u64,
}

/// Resultado OK de `READDIR`.
#[derive(Clone, Debug)]
pub struct ReaddirOk {
    /// Atributos del directorio.
    pub dir_attributes: Option<Fattr3>,
    /// Verifier de cookie para la siguiente llamada.
    pub cookieverf: [u8; 8],
    /// Entradas devueltas.
    pub entries: Vec<Entry3>,
    /// Indica si se listó hasta el final.
    pub eof: bool,
}

impl XdrDecode for ReaddirOk {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let dir_attributes = Option::<Fattr3>::decode(buf)?;
        let cookieverf = <[u8; 8]>::decode(buf)?;
        let mut entries = Vec::new();
        while bool::decode(buf)? {
            let fileid = u64::decode(buf)?;
            let name = String::decode(buf)?;
            let cookie = u64::decode(buf)?;
            entries.push(Entry3 {
                fileid,
                name,
                cookie,
            });
        }
        let eof = bool::decode(buf)?;
        Ok(ReaddirOk {
            dir_attributes,
            cookieverf,
            entries,
            eof,
        })
    }
}

/// Argumentos de `READDIRPLUS`.
#[derive(XdrEncode, Clone, Debug)]
pub struct ReaddirplusArgs {
    /// Directorio a listar.
    pub dir: NfsFh3,
    /// Cookie de continuación.
    pub cookie: u64,
    /// Verifier de cookie.
    pub cookieverf: [u8; 8],
    /// Bytes máximos solo para nombres/cookies.
    pub dircount: u32,
    /// Bytes máximos totales de la respuesta.
    pub maxcount: u32,
}

/// Una entrada de directorio con atributos (`entryplus3`).
#[derive(Clone, Debug)]
pub struct EntryPlus3 {
    /// Identificador del fichero.
    pub fileid: u64,
    /// Nombre de la entrada.
    pub name: String,
    /// Cookie de continuación.
    pub cookie: u64,
    /// Atributos de la entrada.
    pub name_attributes: Option<Fattr3>,
    /// File handle de la entrada.
    pub name_handle: Option<NfsFh3>,
}

/// Resultado OK de `READDIRPLUS`.
#[derive(Clone, Debug)]
pub struct ReaddirplusOk {
    /// Atributos del directorio.
    pub dir_attributes: Option<Fattr3>,
    /// Verifier de cookie para la siguiente llamada.
    pub cookieverf: [u8; 8],
    /// Entradas devueltas (con atributos y handles).
    pub entries: Vec<EntryPlus3>,
    /// Indica si se listó hasta el final.
    pub eof: bool,
}

impl XdrDecode for ReaddirplusOk {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let dir_attributes = Option::<Fattr3>::decode(buf)?;
        let cookieverf = <[u8; 8]>::decode(buf)?;
        let mut entries = Vec::new();
        while bool::decode(buf)? {
            let fileid = u64::decode(buf)?;
            let name = String::decode(buf)?;
            let cookie = u64::decode(buf)?;
            let name_attributes = Option::<Fattr3>::decode(buf)?;
            let name_handle = Option::<NfsFh3>::decode(buf)?;
            entries.push(EntryPlus3 {
                fileid,
                name,
                cookie,
                name_attributes,
                name_handle,
            });
        }
        let eof = bool::decode(buf)?;
        Ok(ReaddirplusOk {
            dir_attributes,
            cookieverf,
            entries,
            eof,
        })
    }
}

/// Resultado OK de `FSSTAT`.
#[derive(XdrDecode, Clone, Debug)]
pub struct FsstatOk {
    /// Atributos del objeto raíz consultado.
    pub obj_attributes: Option<Fattr3>,
    /// Bytes totales.
    pub tbytes: u64,
    /// Bytes libres.
    pub fbytes: u64,
    /// Bytes disponibles para el usuario.
    pub abytes: u64,
    /// Ficheros totales (inodos).
    pub tfiles: u64,
    /// Ficheros libres.
    pub ffiles: u64,
    /// Ficheros disponibles para el usuario.
    pub afiles: u64,
    /// Segundos de validez estimada de estos datos.
    pub invarsec: u32,
}

/// Resultado OK de `FSINFO`.
#[derive(XdrDecode, Clone, Debug)]
pub struct FsinfoOk {
    /// Atributos del objeto consultado.
    pub obj_attributes: Option<Fattr3>,
    /// Tamaño máximo de lectura.
    pub rtmax: u32,
    /// Tamaño de lectura preferido.
    pub rtpref: u32,
    /// Múltiplo sugerido para lecturas.
    pub rtmult: u32,
    /// Tamaño máximo de escritura.
    pub wtmax: u32,
    /// Tamaño de escritura preferido.
    pub wtpref: u32,
    /// Múltiplo sugerido para escrituras.
    pub wtmult: u32,
    /// Tamaño preferido para lecturas de directorio.
    pub dtpref: u32,
    /// Tamaño máximo de fichero.
    pub maxfilesize: u64,
    /// Resolución temporal del servidor.
    pub time_delta: Nfstime3,
    /// Bits de propiedades del sistema de ficheros.
    pub properties: u32,
}

/// Resultado OK de `PATHCONF`.
#[derive(XdrDecode, Clone, Debug)]
pub struct PathconfOk {
    /// Atributos del objeto consultado.
    pub obj_attributes: Option<Fattr3>,
    /// Número máximo de enlaces.
    pub linkmax: u32,
    /// Longitud máxima de un nombre.
    pub name_max: u32,
    /// `true` si los nombres largos se rechazan en vez de truncarse.
    pub no_trunc: bool,
    /// `true` si `chown` está restringido a root.
    pub chown_restricted: bool,
    /// `true` si el sistema no distingue mayúsculas/minúsculas.
    pub case_insensitive: bool,
    /// `true` si el sistema preserva mayúsculas/minúsculas.
    pub case_preserving: bool,
}

/// Argumentos de `COMMIT`.
#[derive(XdrEncode, Clone, Debug)]
pub struct CommitArgs {
    /// Fichero a confirmar.
    pub file: NfsFh3,
    /// Desplazamiento inicial.
    pub offset: u64,
    /// Bytes a confirmar (0 = hasta el final).
    pub count: u32,
}

/// Resultado OK de `COMMIT`.
#[derive(XdrDecode, Clone, Debug)]
pub struct CommitOk {
    /// Coherencia débil de caché del fichero.
    pub file_wcc: WccData,
    /// Verifier de escritura del servidor.
    pub verf: [u8; 8],
}

// --- Cliente NFSv3 -----------------------------------------------------------

/// Cliente NFSv3 a nivel RAW sobre una conexión RPC.
pub struct Nfs3 {
    rpc: RpcClient,
}

impl Nfs3 {
    /// Envuelve un cliente RPC ya conectado al servicio NFS.
    pub fn new(rpc: RpcClient) -> Self {
        Self { rpc }
    }

    /// Conecta al servicio NFS de `server:port`.
    pub fn connect(
        server: IpAddr,
        port: u16,
        cred: Credentials,
        protocol: Protocol,
        timeout: Duration,
    ) -> Result<Self, ProtoError> {
        let addr = SocketAddr::new(server, port);
        Ok(Self::new(RpcClient::connect(
            addr, protocol, cred, timeout,
        )?))
    }

    /// Acceso mutable al cliente RPC subyacente.
    pub fn rpc_mut(&mut self) -> &mut RpcClient {
        &mut self.rpc
    }

    fn call<R: XdrDecode>(&mut self, proc_: u32, args: &dyn XdrEncode) -> Result<R, ProtoError> {
        Ok(self.rpc.call(PROGRAM, VERSION3, proc_, args)?)
    }

    /// Procedimiento `NULL` (ping).
    pub fn null(&mut self) -> Result<(), ProtoError> {
        self.call(0, &())
    }

    /// `GETATTR`: atributos de un objeto.
    pub fn getattr(&mut self, fh: &NfsFh3) -> Result<Fattr3, ProtoError> {
        self.call::<Nfs3Result<Fattr3>>(PROC_GETATTR, fh)?
            .into_result()
    }

    /// `SETATTR`: fija atributos de un objeto. Devuelve `wcc_data`.
    pub fn setattr(
        &mut self,
        object: &NfsFh3,
        new_attributes: Sattr3,
        guard: Option<Nfstime3>,
    ) -> Result<WccData, ProtoError> {
        let args = SetattrArgs {
            object: object.clone(),
            new_attributes,
            guard,
        };
        self.call::<Nfs3Result<WccData>>(PROC_SETATTR, &args)?
            .into_result()
    }

    /// `LOOKUP`: resuelve `name` dentro de `dir`.
    pub fn lookup(&mut self, dir: &NfsFh3, name: &str) -> Result<LookupOk, ProtoError> {
        let args = DirOpArgs3 {
            dir: dir.clone(),
            name: name.to_string(),
        };
        self.call::<Nfs3Result<LookupOk>>(PROC_LOOKUP, &args)?
            .into_result()
    }

    /// `ACCESS`: comprueba permisos (`ACCESS3_*`).
    pub fn access(&mut self, object: &NfsFh3, access: u32) -> Result<AccessOk, ProtoError> {
        let args = AccessArgs {
            object: object.clone(),
            access,
        };
        self.call::<Nfs3Result<AccessOk>>(PROC_ACCESS, &args)?
            .into_result()
    }

    /// `READLINK`: lee el destino de un enlace simbólico.
    pub fn readlink(&mut self, symlink: &NfsFh3) -> Result<ReadlinkOk, ProtoError> {
        self.call::<Nfs3Result<ReadlinkOk>>(PROC_READLINK, symlink)?
            .into_result()
    }

    /// `READ`: lee `count` bytes desde `offset`.
    pub fn read(&mut self, file: &NfsFh3, offset: u64, count: u32) -> Result<ReadOk, ProtoError> {
        let args = ReadArgs {
            file: file.clone(),
            offset,
            count,
        };
        self.call::<Nfs3Result<ReadOk>>(PROC_READ, &args)?
            .into_result()
    }

    /// `WRITE`: escribe `data` en `offset` con el modo de estabilidad indicado.
    pub fn write(
        &mut self,
        file: &NfsFh3,
        offset: u64,
        stable: u32,
        data: Bytes,
    ) -> Result<WriteOk, ProtoError> {
        let args = WriteArgs {
            file: file.clone(),
            offset,
            count: data.len() as u32,
            stable,
            data,
        };
        self.call::<Nfs3Result<WriteOk>>(PROC_WRITE, &args)?
            .into_result()
    }

    /// `CREATE`: crea un fichero regular.
    pub fn create(
        &mut self,
        dir: &NfsFh3,
        name: &str,
        how: CreateHow3,
    ) -> Result<CreateOk, ProtoError> {
        let args = CreateArgs {
            where_: DirOpArgs3 {
                dir: dir.clone(),
                name: name.to_string(),
            },
            how,
        };
        self.call::<Nfs3Result<CreateOk>>(PROC_CREATE, &args)?
            .into_result()
    }

    /// `MKDIR`: crea un directorio.
    pub fn mkdir(
        &mut self,
        dir: &NfsFh3,
        name: &str,
        attributes: Sattr3,
    ) -> Result<CreateOk, ProtoError> {
        let args = MkdirArgs {
            where_: DirOpArgs3 {
                dir: dir.clone(),
                name: name.to_string(),
            },
            attributes,
        };
        self.call::<Nfs3Result<CreateOk>>(PROC_MKDIR, &args)?
            .into_result()
    }

    /// `SYMLINK`: crea un enlace simbólico `name` -> `target`.
    pub fn symlink(
        &mut self,
        dir: &NfsFh3,
        name: &str,
        target: &str,
        attributes: Sattr3,
    ) -> Result<CreateOk, ProtoError> {
        let args = SymlinkArgs {
            where_: DirOpArgs3 {
                dir: dir.clone(),
                name: name.to_string(),
            },
            symlink: SymlinkData3 {
                symlink_attributes: attributes,
                symlink_data: target.to_string(),
            },
        };
        self.call::<Nfs3Result<CreateOk>>(PROC_SYMLINK, &args)?
            .into_result()
    }

    /// `MKNOD`: crea un nodo especial (dispositivo, socket o FIFO).
    pub fn mknod(
        &mut self,
        dir: &NfsFh3,
        name: &str,
        what: MknodData3,
    ) -> Result<CreateOk, ProtoError> {
        let args = MknodArgs {
            where_: DirOpArgs3 {
                dir: dir.clone(),
                name: name.to_string(),
            },
            what,
        };
        self.call::<Nfs3Result<CreateOk>>(PROC_MKNOD, &args)?
            .into_result()
    }

    /// `REMOVE`: borra el fichero `name` de `dir`. Devuelve `wcc_data` del dir.
    pub fn remove(&mut self, dir: &NfsFh3, name: &str) -> Result<WccData, ProtoError> {
        let args = DirOpArgs3 {
            dir: dir.clone(),
            name: name.to_string(),
        };
        self.call::<Nfs3Result<WccData>>(PROC_REMOVE, &args)?
            .into_result()
    }

    /// `RMDIR`: borra el directorio `name` de `dir`.
    pub fn rmdir(&mut self, dir: &NfsFh3, name: &str) -> Result<WccData, ProtoError> {
        let args = DirOpArgs3 {
            dir: dir.clone(),
            name: name.to_string(),
        };
        self.call::<Nfs3Result<WccData>>(PROC_RMDIR, &args)?
            .into_result()
    }

    /// `RENAME`: renombra/mueve `from` a `to`.
    pub fn rename(
        &mut self,
        from_dir: &NfsFh3,
        from_name: &str,
        to_dir: &NfsFh3,
        to_name: &str,
    ) -> Result<RenameOk, ProtoError> {
        let args = RenameArgs {
            from: DirOpArgs3 {
                dir: from_dir.clone(),
                name: from_name.to_string(),
            },
            to: DirOpArgs3 {
                dir: to_dir.clone(),
                name: to_name.to_string(),
            },
        };
        self.call::<Nfs3Result<RenameOk>>(PROC_RENAME, &args)?
            .into_result()
    }

    /// `LINK`: crea un enlace duro a `file` con nombre `name` en `dir`.
    pub fn link(&mut self, file: &NfsFh3, dir: &NfsFh3, name: &str) -> Result<LinkOk, ProtoError> {
        let args = LinkArgs {
            file: file.clone(),
            link: DirOpArgs3 {
                dir: dir.clone(),
                name: name.to_string(),
            },
        };
        self.call::<Nfs3Result<LinkOk>>(PROC_LINK, &args)?
            .into_result()
    }

    /// `READDIR`: lista entradas de un directorio (solo nombres + cookies).
    pub fn readdir(
        &mut self,
        dir: &NfsFh3,
        cookie: u64,
        cookieverf: [u8; 8],
        count: u32,
    ) -> Result<ReaddirOk, ProtoError> {
        let args = ReaddirArgs {
            dir: dir.clone(),
            cookie,
            cookieverf,
            count,
        };
        self.call::<Nfs3Result<ReaddirOk>>(PROC_READDIR, &args)?
            .into_result()
    }

    /// `READDIRPLUS`: lista entradas con atributos y file handles.
    pub fn readdirplus(
        &mut self,
        dir: &NfsFh3,
        cookie: u64,
        cookieverf: [u8; 8],
        dircount: u32,
        maxcount: u32,
    ) -> Result<ReaddirplusOk, ProtoError> {
        let args = ReaddirplusArgs {
            dir: dir.clone(),
            cookie,
            cookieverf,
            dircount,
            maxcount,
        };
        self.call::<Nfs3Result<ReaddirplusOk>>(PROC_READDIRPLUS, &args)?
            .into_result()
    }

    /// `FSSTAT`: estadísticas de uso del sistema de ficheros.
    pub fn fsstat(&mut self, fh: &NfsFh3) -> Result<FsstatOk, ProtoError> {
        self.call::<Nfs3Result<FsstatOk>>(PROC_FSSTAT, fh)?
            .into_result()
    }

    /// `FSINFO`: parámetros y límites del sistema de ficheros.
    pub fn fsinfo(&mut self, fh: &NfsFh3) -> Result<FsinfoOk, ProtoError> {
        self.call::<Nfs3Result<FsinfoOk>>(PROC_FSINFO, fh)?
            .into_result()
    }

    /// `PATHCONF`: límites de nombres y rutas.
    pub fn pathconf(&mut self, fh: &NfsFh3) -> Result<PathconfOk, ProtoError> {
        self.call::<Nfs3Result<PathconfOk>>(PROC_PATHCONF, fh)?
            .into_result()
    }

    /// `COMMIT`: fuerza la persistencia de datos escritos en modo `UNSTABLE`.
    pub fn commit(
        &mut self,
        file: &NfsFh3,
        offset: u64,
        count: u32,
    ) -> Result<CommitOk, ProtoError> {
        let args = CommitArgs {
            file: file.clone(),
            offset,
            count,
        };
        self.call::<Nfs3Result<CommitOk>>(PROC_COMMIT, &args)?
            .into_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfs_xdr::{from_bytes, to_bytes};

    #[test]
    fn fattr3_roundtrip() {
        let attr = Fattr3 {
            ftype: NF3REG,
            mode: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            size: 123,
            used: 4096,
            rdev: Specdata3::default(),
            fsid: 42,
            fileid: 7,
            atime: Nfstime3 {
                seconds: 1,
                nseconds: 2,
            },
            mtime: Nfstime3 {
                seconds: 3,
                nseconds: 4,
            },
            ctime: Nfstime3 {
                seconds: 5,
                nseconds: 6,
            },
        };
        let bytes = to_bytes(&attr).unwrap();
        // 21 campos de 4 bytes (con los u64 contando 8): tamaño esperado 84 bytes.
        assert_eq!(bytes.len(), 84);
        assert_eq!(from_bytes::<Fattr3>(bytes).unwrap(), attr);
    }

    #[test]
    fn nfs3result_ok_and_fail() {
        // OK: status 0 seguido de un u32 (como si fuera el payload).
        let ok = Bytes::from_static(&[0, 0, 0, 0, 0, 0, 0, 9]);
        match from_bytes::<Nfs3Result<u32>>(ok).unwrap() {
            Nfs3Result::Ok(v) => assert_eq!(v, 9),
            Nfs3Result::Fail(_) => panic!("esperaba Ok"),
        }
        // Fail: status NFS3ERR_NOENT, sin payload.
        let fail = Bytes::from_static(&[0, 0, 0, 2]);
        match from_bytes::<Nfs3Result<u32>>(fail).unwrap() {
            Nfs3Result::Fail(s) => assert_eq!(s, NFS3ERR_NOENT),
            Nfs3Result::Ok(_) => panic!("esperaba Fail"),
        }
    }

    #[test]
    fn settime_union_encoding() {
        // DONT_CHANGE -> solo discriminante 0.
        assert_eq!(&to_bytes(&SetTime::DontChange).unwrap()[..], &[0, 0, 0, 0]);
        // SET_TO_CLIENT_TIME -> disc 2 + nfstime3.
        let t = SetTime::ToClientTime(Nfstime3 {
            seconds: 1,
            nseconds: 2,
        });
        assert_eq!(
            &to_bytes(&t).unwrap()[..],
            &[0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]
        );
    }

    #[test]
    fn sattr3_all_unset() {
        // Cuatro Option::None (mode/uid/gid/size) + dos SetTime::DontChange.
        let bytes = to_bytes(&Sattr3::unchanged()).unwrap();
        assert_eq!(bytes.len(), 6 * 4);
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn readdir_linked_list_decode() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0, 0, 0, 0]); // dir_attributes: None
        wire.extend_from_slice(&[0; 8]); // cookieverf
                                         // entrada 1
        wire.extend_from_slice(&[0, 0, 0, 1]); // present
        wire.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]); // fileid 5
        wire.extend_from_slice(&[0, 0, 0, 1, b'a', 0, 0, 0]); // name "a"
        wire.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // cookie 1
                                                           // fin de entradas + eof true
        wire.extend_from_slice(&[0, 0, 0, 0]); // no más entradas
        wire.extend_from_slice(&[0, 0, 0, 1]); // eof
        let ok: ReaddirOk = from_bytes(Bytes::from(wire)).unwrap();
        assert_eq!(ok.entries.len(), 1);
        assert_eq!(ok.entries[0].fileid, 5);
        assert_eq!(ok.entries[0].name, "a");
        assert!(ok.eof);
    }
}
