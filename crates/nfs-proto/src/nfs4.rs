//! NFSv4.0 (RFC 7530): COMPOUND, `fattr4` con bitmaps y gestión de estado.
//!
//! NFSv4 no usa PORTMAP ni MOUNT: se conecta al puerto 2049 y obtiene el file
//! handle raíz con `PUTROOTFH`. Las operaciones se agrupan en un `COMPOUND`
//! (un viaje de ida y vuelta por operación VFS, como en `lib/nfs_v4.c`).
//!
//! Alcance: v4.0 funcional (handshake `SETCLIENTID`, lease `RENEW`, OPEN/CLOSE
//! con seqids, READ/WRITE/COMMIT, metadatos, directorios). NFSv4.1 (sesiones,
//! `EXCHANGE_ID`/`SEQUENCE`) queda como extensión documentada (ver `FASE-05`).

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::BufMut;
use nfs_rpc::{Credentials, Protocol, RpcClient};
use nfs_xdr::{decode_opaque, Bytes, BytesMut, XdrDecode, XdrEncode, XdrError};

use crate::error::ProtoError;

/// Número de programa de NFS.
pub const PROGRAM: u32 = 100003;
/// Versión 4 de NFS.
pub const VERSION4: u32 = 4;
const COMPOUND_PROC: u32 = 1;

// --- nfs_opnum4 (RFC 7530 §16) -----------------------------------------------

const OP_ACCESS: u32 = 3;
const OP_CLOSE: u32 = 4;
const OP_COMMIT: u32 = 5;
const OP_CREATE: u32 = 6;
const OP_GETATTR: u32 = 9;
const OP_GETFH: u32 = 10;
const OP_LINK: u32 = 11;
const OP_LOCK: u32 = 12;
const OP_LOCKT: u32 = 13;
const OP_LOCKU: u32 = 14;
const OP_LOOKUP: u32 = 15;
const OP_OPEN: u32 = 18;
const OP_OPEN_CONFIRM: u32 = 20;
const OP_PUTFH: u32 = 22;
const OP_PUTROOTFH: u32 = 24;
const OP_READ: u32 = 25;
const OP_READDIR: u32 = 26;
const OP_READLINK: u32 = 27;
const OP_REMOVE: u32 = 28;
const OP_RENAME: u32 = 29;
const OP_RENEW: u32 = 30;
const OP_SAVEFH: u32 = 32;
const OP_SETATTR: u32 = 34;
const OP_SETCLIENTID: u32 = 35;
const OP_SETCLIENTID_CONFIRM: u32 = 36;
const OP_WRITE: u32 = 38;
// NFSv4.1 (minorversion 1)
const OP_EXCHANGE_ID: u32 = 42;
const OP_CREATE_SESSION: u32 = 43;
const OP_DESTROY_SESSION: u32 = 44;
const OP_SEQUENCE: u32 = 53;
const OP_RECLAIM_COMPLETE: u32 = 58;

// --- nfsstat4 (subconjunto) --------------------------------------------------

/// Éxito.
pub const NFS4_OK: u32 = 0;
/// No existe.
pub const NFS4ERR_NOENT: u32 = 2;
/// Acceso denegado.
pub const NFS4ERR_ACCESS: u32 = 13;
/// Ya existe.
pub const NFS4ERR_EXIST: u32 = 17;
/// No es un directorio.
pub const NFS4ERR_NOTDIR: u32 = 20;
/// Argumento inválido.
pub const NFS4ERR_INVAL: u32 = 22;
/// Directorio no vacío.
pub const NFS4ERR_NOTEMPTY: u32 = 66;
/// File handle obsoleto.
pub const NFS4ERR_STALE: u32 = 70;
/// El servidor está en periodo de gracia (reintentar).
pub const NFS4ERR_GRACE: u32 = 10013;
/// El servidor pide reintentar más tarde.
pub const NFS4ERR_DELAY: u32 = 10008;
/// clientid obsoleto (rehacer SETCLIENTID).
pub const NFS4ERR_STALE_CLIENTID: u32 = 10022;
/// seqid de open_owner incorrecto.
pub const NFS4ERR_BAD_SEQID: u32 = 10026;
/// Bloqueo denegado por conflicto (`LOCK`/`LOCKT`).
pub const NFS4ERR_DENIED: u32 = 10010;

/// Tipo de bloqueo de lectura (`READ_LT`).
pub const READ_LT: u32 = 1;
/// Tipo de bloqueo de escritura (`WRITE_LT`).
pub const WRITE_LT: u32 = 2;

// --- nfs_ftype4 --------------------------------------------------------------

/// Fichero regular.
pub const NF4REG: u32 = 1;
/// Directorio.
pub const NF4DIR: u32 = 2;
/// Enlace simbólico.
pub const NF4LNK: u32 = 5;

// --- OPEN: share/deny/flags --------------------------------------------------

/// Acceso de lectura.
pub const OPEN4_SHARE_ACCESS_READ: u32 = 1;
/// Acceso de escritura.
pub const OPEN4_SHARE_ACCESS_WRITE: u32 = 2;
/// Acceso de lectura y escritura.
pub const OPEN4_SHARE_ACCESS_BOTH: u32 = 3;
/// Sin denegación de comparticiones.
pub const OPEN4_SHARE_DENY_NONE: u32 = 0;
const OPEN4_NOCREATE: u32 = 0;
const OPEN4_CREATE: u32 = 1;
const UNCHECKED4: u32 = 0;
const CLAIM_NULL: u32 = 0;
const OPEN4_RESULT_CONFIRM: u32 = 0x0000_0002;

// --- stable_how4 (WRITE/COMMIT) ----------------------------------------------

/// Escritura sin garantía de persistencia.
pub const UNSTABLE4: u32 = 0;
/// Persiste datos y metadatos.
pub const FILE_SYNC4: u32 = 2;

// --- Bits de fattr4 que sabemos (de)codificar --------------------------------

const FATTR4_TYPE: u32 = 1;
const FATTR4_CHANGE: u32 = 3;
const FATTR4_SIZE: u32 = 4;
const FATTR4_FSID: u32 = 8;
const FATTR4_FILEID: u32 = 20;
const FATTR4_FILES_AVAIL: u32 = 21;
const FATTR4_FILES_FREE: u32 = 22;
const FATTR4_FILES_TOTAL: u32 = 23;
const FATTR4_SPACE_AVAIL: u32 = 42;
const FATTR4_SPACE_FREE: u32 = 43;
const FATTR4_SPACE_TOTAL: u32 = 44;
const FATTR4_MODE: u32 = 33;
const FATTR4_NUMLINKS: u32 = 35;
const FATTR4_OWNER: u32 = 36;
const FATTR4_OWNER_GROUP: u32 = 37;
const FATTR4_RAWDEV: u32 = 41;
const FATTR4_SPACE_USED: u32 = 45;
const FATTR4_TIME_ACCESS: u32 = 47;
const FATTR4_TIME_METADATA: u32 = 52;
const FATTR4_TIME_MODIFY: u32 = 53;

/// Atributos que solicita `GETATTR`/`LOOKUP` (los que sabemos decodificar).
const REQUEST_ATTRS: &[u32] = &[
    FATTR4_TYPE,
    FATTR4_CHANGE,
    FATTR4_SIZE,
    FATTR4_FSID,
    FATTR4_FILEID,
    FATTR4_MODE,
    FATTR4_NUMLINKS,
    FATTR4_OWNER,
    FATTR4_OWNER_GROUP,
    FATTR4_RAWDEV,
    FATTR4_SPACE_USED,
    FATTR4_TIME_ACCESS,
    FATTR4_TIME_METADATA,
    FATTR4_TIME_MODIFY,
];

// --- Tipos -------------------------------------------------------------------

/// Identificador de estado (`stateid4`).
#[derive(XdrEncode, XdrDecode, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stateid4 {
    /// Número de secuencia del stateid.
    pub seqid: u32,
    /// Identificador opaco de 12 bytes.
    pub other: [u8; 12],
}

/// File handle NFSv4 (`nfs_fh4`, opaque<128>).
#[derive(XdrEncode, XdrDecode, Clone, Debug, PartialEq, Eq)]
pub struct NfsFh4 {
    /// Bytes opacos del handle.
    #[xdr(limit = 128)]
    pub data: Bytes,
}

impl NfsFh4 {
    /// Crea un file handle a partir de bytes.
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self { data: data.into() }
    }
}

/// Instante NFSv4 (`nfstime4`).
#[derive(XdrEncode, XdrDecode, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Nfstime4 {
    /// Segundos (con signo).
    pub seconds: i64,
    /// Nanosegundos.
    pub nseconds: u32,
}

/// Información de cambio de un directorio (`change_info4`).
#[derive(XdrDecode, Clone, Copy, Debug, Default)]
pub struct ChangeInfo4 {
    /// Si el cambio fue atómico.
    pub atomic: bool,
    /// changeid antes.
    pub before: u64,
    /// changeid después.
    pub after: u64,
}

/// Atributos NFSv4 decodificados de un `fattr4` (solo los soportados).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fattr4 {
    /// Tipo de objeto (`nfs_ftype4`).
    pub ftype: Option<u32>,
    /// changeid (para coherencia de caché).
    pub change: Option<u64>,
    /// Tamaño en bytes.
    pub size: Option<u64>,
    /// Identificador del sistema de ficheros (major, minor).
    pub fsid: Option<(u64, u64)>,
    /// Identificador del fichero.
    pub fileid: Option<u64>,
    /// Bits de modo.
    pub mode: Option<u32>,
    /// Número de enlaces.
    pub numlinks: Option<u32>,
    /// Propietario (`user@domain`).
    pub owner: Option<String>,
    /// Grupo propietario (`group@domain`).
    pub owner_group: Option<String>,
    /// Dispositivo (major, minor).
    pub rawdev: Option<(u32, u32)>,
    /// Espacio usado en bytes.
    pub space_used: Option<u64>,
    /// Ficheros (inodos) disponibles.
    pub files_avail: Option<u64>,
    /// Ficheros libres.
    pub files_free: Option<u64>,
    /// Ficheros totales.
    pub files_total: Option<u64>,
    /// Bytes disponibles para el usuario.
    pub space_avail: Option<u64>,
    /// Bytes libres.
    pub space_free: Option<u64>,
    /// Bytes totales.
    pub space_total: Option<u64>,
    /// Tiempo de acceso.
    pub time_access: Option<Nfstime4>,
    /// Tiempo de cambio de metadatos.
    pub time_metadata: Option<Nfstime4>,
    /// Tiempo de modificación.
    pub time_modify: Option<Nfstime4>,
}

/// Atributos a fijar con `SETATTR` (subconjunto soportado).
#[derive(Clone, Debug, Default)]
pub struct SetAttr4 {
    /// Nuevo modo.
    pub mode: Option<u32>,
    /// Nuevo tamaño.
    pub size: Option<u64>,
}

/// Resultado de OPEN: file handle del fichero y stateid abierto.
#[derive(Clone, Debug)]
pub struct OpenResult {
    /// File handle del fichero abierto.
    pub fh: NfsFh4,
    /// Stateid para READ/WRITE/CLOSE.
    pub stateid: Stateid4,
}

/// Datos leídos por `READ`.
#[derive(Clone, Debug)]
pub struct ReadResult {
    /// `true` si se alcanzó el fin de fichero.
    pub eof: bool,
    /// Datos leídos.
    pub data: Bytes,
}

/// Una entrada de directorio NFSv4 (`entry4`).
#[derive(Clone, Debug)]
pub struct DirEntry4 {
    /// Cookie de continuación.
    pub cookie: u64,
    /// Nombre de la entrada.
    pub name: String,
    /// Atributos de la entrada.
    pub attrs: Fattr4,
}

/// Resultado de `READDIR`.
#[derive(Clone, Debug)]
pub struct ReaddirResult {
    /// Verifier de cookie para la siguiente llamada.
    pub cookieverf: [u8; 8],
    /// Entradas devueltas.
    pub entries: Vec<DirEntry4>,
    /// `true` si se listó hasta el final.
    pub eof: bool,
}

// --- Helpers de bitmap y fattr4 ----------------------------------------------

fn build_bitmap(bits: &[u32]) -> Vec<u32> {
    let max_word = bits.iter().map(|b| (b / 32) as usize).max().unwrap_or(0);
    let mut words = vec![0u32; max_word + 1];
    for &bit in bits {
        words[(bit / 32) as usize] |= 1 << (bit % 32);
    }
    words
}

fn bit_set(bitmap: &[u32], bit: u32) -> bool {
    let word = (bit / 32) as usize;
    word < bitmap.len() && (bitmap[word] >> (bit % 32)) & 1 == 1
}

fn encode_bitmap(buf: &mut BytesMut, bits: &[u32]) -> Result<(), XdrError> {
    build_bitmap(bits).encode(buf)
}

/// Decodifica un `fattr4` (bitmap + attrlist) en sus atributos soportados.
fn decode_fattr4(bitmap: &[u32], mut attrs: Bytes) -> Result<Fattr4, ProtoError> {
    let max_bit = bitmap.len() as u32 * 32;
    let mut out = Fattr4::default();
    for bit in 0..max_bit {
        if !bit_set(bitmap, bit) {
            continue;
        }
        let b = &mut attrs;
        match bit {
            FATTR4_TYPE => out.ftype = Some(u32::decode(b)?),
            FATTR4_CHANGE => out.change = Some(u64::decode(b)?),
            FATTR4_SIZE => out.size = Some(u64::decode(b)?),
            FATTR4_FSID => out.fsid = Some((u64::decode(b)?, u64::decode(b)?)),
            FATTR4_FILEID => out.fileid = Some(u64::decode(b)?),
            FATTR4_MODE => out.mode = Some(u32::decode(b)?),
            FATTR4_NUMLINKS => out.numlinks = Some(u32::decode(b)?),
            FATTR4_OWNER => out.owner = Some(String::decode(b)?),
            FATTR4_OWNER_GROUP => out.owner_group = Some(String::decode(b)?),
            FATTR4_RAWDEV => out.rawdev = Some((u32::decode(b)?, u32::decode(b)?)),
            FATTR4_SPACE_USED => out.space_used = Some(u64::decode(b)?),
            FATTR4_FILES_AVAIL => out.files_avail = Some(u64::decode(b)?),
            FATTR4_FILES_FREE => out.files_free = Some(u64::decode(b)?),
            FATTR4_FILES_TOTAL => out.files_total = Some(u64::decode(b)?),
            FATTR4_SPACE_AVAIL => out.space_avail = Some(u64::decode(b)?),
            FATTR4_SPACE_FREE => out.space_free = Some(u64::decode(b)?),
            FATTR4_SPACE_TOTAL => out.space_total = Some(u64::decode(b)?),
            FATTR4_TIME_ACCESS => out.time_access = Some(Nfstime4::decode(b)?),
            FATTR4_TIME_METADATA => out.time_metadata = Some(Nfstime4::decode(b)?),
            FATTR4_TIME_MODIFY => out.time_modify = Some(Nfstime4::decode(b)?),
            // No alcanzable: solo solicitamos atributos conocidos, así que el
            // servidor solo puede devolver bits de ese conjunto.
            _ => {
                return Err(ProtoError::Protocol(
                    "fattr4 con atributo no soportado en la respuesta",
                ))
            }
        }
    }
    Ok(out)
}

/// Codifica un `fattr4` con los atributos de `SetAttr4` (bits ascendentes).
fn encode_setattr_fattr4(buf: &mut BytesMut, attrs: &SetAttr4) -> Result<(), XdrError> {
    let mut bits = Vec::new();
    let mut values = BytesMut::new();
    // En orden ascendente de bit: size (4) antes que mode (33).
    if let Some(size) = attrs.size {
        bits.push(FATTR4_SIZE);
        size.encode(&mut values)?;
    }
    if let Some(mode) = attrs.mode {
        bits.push(FATTR4_MODE);
        mode.encode(&mut values)?;
    }
    encode_bitmap(buf, &bits)?;
    let values = values.freeze();
    // attrlist4 es un opaque<>.
    (values.len() as u32).encode(buf)?;
    buf.put_slice(&values);
    let pad = (4 - values.len() % 4) % 4;
    buf.put_bytes(0, pad);
    Ok(())
}

// --- COMPOUND ----------------------------------------------------------------

/// Constructor de un `COMPOUND4args`.
struct Compound {
    ops: BytesMut,
    nops: u32,
}

impl Compound {
    fn new() -> Self {
        Self {
            ops: BytesMut::new(),
            nops: 0,
        }
    }

    fn op(&mut self, opcode: u32) -> Result<&mut Self, XdrError> {
        opcode.encode(&mut self.ops)?;
        self.nops += 1;
        Ok(self)
    }

    fn putrootfh(&mut self) -> Result<&mut Self, XdrError> {
        self.op(OP_PUTROOTFH)
    }

    fn putfh(&mut self, fh: &NfsFh4) -> Result<&mut Self, XdrError> {
        self.op(OP_PUTFH)?;
        fh.encode(&mut self.ops)?;
        Ok(self)
    }

    fn getfh(&mut self) -> Result<&mut Self, XdrError> {
        self.op(OP_GETFH)
    }

    fn savefh(&mut self) -> Result<&mut Self, XdrError> {
        self.op(OP_SAVEFH)
    }

    fn getattr(&mut self, bits: &[u32]) -> Result<&mut Self, XdrError> {
        self.op(OP_GETATTR)?;
        encode_bitmap(&mut self.ops, bits)?;
        Ok(self)
    }

    fn lookup(&mut self, name: &str) -> Result<&mut Self, XdrError> {
        self.op(OP_LOOKUP)?;
        name.encode(&mut self.ops)?;
        Ok(self)
    }

    fn access(&mut self, mask: u32) -> Result<&mut Self, XdrError> {
        self.op(OP_ACCESS)?;
        mask.encode(&mut self.ops)?;
        Ok(self)
    }

    fn readlink(&mut self) -> Result<&mut Self, XdrError> {
        self.op(OP_READLINK)
    }

    fn read(&mut self, stateid: &Stateid4, offset: u64, count: u32) -> Result<&mut Self, XdrError> {
        self.op(OP_READ)?;
        stateid.encode(&mut self.ops)?;
        offset.encode(&mut self.ops)?;
        count.encode(&mut self.ops)?;
        Ok(self)
    }

    fn write(
        &mut self,
        stateid: &Stateid4,
        offset: u64,
        stable: u32,
        data: &Bytes,
    ) -> Result<&mut Self, XdrError> {
        self.op(OP_WRITE)?;
        stateid.encode(&mut self.ops)?;
        offset.encode(&mut self.ops)?;
        stable.encode(&mut self.ops)?;
        data.encode(&mut self.ops)?;
        Ok(self)
    }

    fn commit(&mut self, offset: u64, count: u32) -> Result<&mut Self, XdrError> {
        self.op(OP_COMMIT)?;
        offset.encode(&mut self.ops)?;
        count.encode(&mut self.ops)?;
        Ok(self)
    }

    fn remove(&mut self, name: &str) -> Result<&mut Self, XdrError> {
        self.op(OP_REMOVE)?;
        name.encode(&mut self.ops)?;
        Ok(self)
    }

    fn rename(&mut self, old: &str, new: &str) -> Result<&mut Self, XdrError> {
        self.op(OP_RENAME)?;
        old.encode(&mut self.ops)?;
        new.encode(&mut self.ops)?;
        Ok(self)
    }

    fn link(&mut self, newname: &str) -> Result<&mut Self, XdrError> {
        self.op(OP_LINK)?;
        newname.encode(&mut self.ops)?;
        Ok(self)
    }

    fn renew(&mut self, clientid: u64) -> Result<&mut Self, XdrError> {
        self.op(OP_RENEW)?;
        clientid.encode(&mut self.ops)?;
        Ok(self)
    }

    /// CREATE de un directorio (`createtype4 = NF4DIR`, sin atributos).
    fn create_dir(&mut self, name: &str) -> Result<&mut Self, XdrError> {
        self.op(OP_CREATE)?;
        NF4DIR.encode(&mut self.ops)?; // objtype (NF4DIR no lleva datos)
        name.encode(&mut self.ops)?; // objname
        encode_bitmap(&mut self.ops, &[])?; // fattr4: bitmap vacío
        0u32.encode(&mut self.ops)?; // attrlist4: opaque<> vacío
        Ok(self)
    }

    /// CREATE de un enlace simbólico (`createtype4 = NF4LNK`).
    fn create_symlink(&mut self, name: &str, target: &str) -> Result<&mut Self, XdrError> {
        self.op(OP_CREATE)?;
        NF4LNK.encode(&mut self.ops)?;
        target.encode(&mut self.ops)?; // linkdata
        name.encode(&mut self.ops)?; // objname
        encode_bitmap(&mut self.ops, &[])?;
        0u32.encode(&mut self.ops)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    fn open(
        &mut self,
        seqid: u32,
        clientid: u64,
        owner: &Bytes,
        share_access: u32,
        create: bool,
        name: &str,
    ) -> Result<&mut Self, XdrError> {
        self.op(OP_OPEN)?;
        seqid.encode(&mut self.ops)?;
        share_access.encode(&mut self.ops)?;
        OPEN4_SHARE_DENY_NONE.encode(&mut self.ops)?;
        // open_owner4 { clientid; owner<> }
        clientid.encode(&mut self.ops)?;
        owner.encode(&mut self.ops)?;
        // openflag4
        if create {
            OPEN4_CREATE.encode(&mut self.ops)?;
            UNCHECKED4.encode(&mut self.ops)?; // createmode4
            encode_bitmap(&mut self.ops, &[])?; // createattrs fattr4 vacío
            0u32.encode(&mut self.ops)?;
        } else {
            OPEN4_NOCREATE.encode(&mut self.ops)?;
        }
        // open_claim4 = CLAIM_NULL(component)
        CLAIM_NULL.encode(&mut self.ops)?;
        name.encode(&mut self.ops)?;
        Ok(self)
    }

    fn open_confirm(&mut self, stateid: &Stateid4, seqid: u32) -> Result<&mut Self, XdrError> {
        self.op(OP_OPEN_CONFIRM)?;
        stateid.encode(&mut self.ops)?;
        seqid.encode(&mut self.ops)?;
        Ok(self)
    }

    fn close(&mut self, seqid: u32, stateid: &Stateid4) -> Result<&mut Self, XdrError> {
        self.op(OP_CLOSE)?;
        seqid.encode(&mut self.ops)?;
        stateid.encode(&mut self.ops)?;
        Ok(self)
    }

    /// `LOCK` con un lock_owner nuevo (`open_to_lock_owner4`).
    #[allow(clippy::too_many_arguments)]
    fn lock_new(
        &mut self,
        locktype: u32,
        offset: u64,
        length: u64,
        open_seqid: u32,
        open_stateid: &Stateid4,
        lock_seqid: u32,
        clientid: u64,
        lock_owner: &Bytes,
    ) -> Result<&mut Self, XdrError> {
        self.op(OP_LOCK)?;
        locktype.encode(&mut self.ops)?;
        false.encode(&mut self.ops)?; // reclaim
        offset.encode(&mut self.ops)?;
        length.encode(&mut self.ops)?;
        // locker4: new_lock_owner = TRUE -> open_to_lock_owner4
        true.encode(&mut self.ops)?;
        open_seqid.encode(&mut self.ops)?;
        open_stateid.encode(&mut self.ops)?;
        lock_seqid.encode(&mut self.ops)?;
        clientid.encode(&mut self.ops)?;
        lock_owner.encode(&mut self.ops)?;
        Ok(self)
    }

    fn locku(
        &mut self,
        locktype: u32,
        lock_seqid: u32,
        lock_stateid: &Stateid4,
        offset: u64,
        length: u64,
    ) -> Result<&mut Self, XdrError> {
        self.op(OP_LOCKU)?;
        locktype.encode(&mut self.ops)?;
        lock_seqid.encode(&mut self.ops)?;
        lock_stateid.encode(&mut self.ops)?;
        offset.encode(&mut self.ops)?;
        length.encode(&mut self.ops)?;
        Ok(self)
    }

    fn lockt(
        &mut self,
        locktype: u32,
        offset: u64,
        length: u64,
        clientid: u64,
        lock_owner: &Bytes,
    ) -> Result<&mut Self, XdrError> {
        self.op(OP_LOCKT)?;
        locktype.encode(&mut self.ops)?;
        offset.encode(&mut self.ops)?;
        length.encode(&mut self.ops)?;
        clientid.encode(&mut self.ops)?;
        lock_owner.encode(&mut self.ops)?;
        Ok(self)
    }

    fn setattr(&mut self, stateid: &Stateid4, attrs: &SetAttr4) -> Result<&mut Self, XdrError> {
        self.op(OP_SETATTR)?;
        stateid.encode(&mut self.ops)?;
        encode_setattr_fattr4(&mut self.ops, attrs)?;
        Ok(self)
    }

    fn readdir(
        &mut self,
        cookie: u64,
        cookieverf: [u8; 8],
        dircount: u32,
        maxcount: u32,
        attr_bits: &[u32],
    ) -> Result<&mut Self, XdrError> {
        self.op(OP_READDIR)?;
        cookie.encode(&mut self.ops)?;
        cookieverf.encode(&mut self.ops)?;
        dircount.encode(&mut self.ops)?;
        maxcount.encode(&mut self.ops)?;
        encode_bitmap(&mut self.ops, attr_bits)?;
        Ok(self)
    }

    /// Serializa el COMPOUND completo (tag vacío + minorversion + ops).
    fn finish(&self, minor: u32) -> Result<Bytes, XdrError> {
        let mut buf = BytesMut::new();
        "".encode(&mut buf)?; // tag
        minor.encode(&mut buf)?;
        self.nops.encode(&mut buf)?;
        buf.put_slice(&self.ops);
        Ok(buf.freeze())
    }
}

/// Envuelve bytes ya codificados para enviarlos como argumentos RPC crudos.
struct Raw(Bytes);

impl XdrEncode for Raw {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), XdrError> {
        buf.put_slice(&self.0);
        Ok(())
    }
}

/// Lector posicional del array de resultados de un COMPOUND.
struct CompoundReader {
    buf: Bytes,
}

impl CompoundReader {
    fn parse(mut buf: Bytes) -> Result<Self, ProtoError> {
        let status = u32::decode(&mut buf)?;
        let _tag = String::decode(&mut buf)?;
        let _count = u32::decode(&mut buf)?;
        if status != NFS4_OK {
            return Err(ProtoError::Nfs4(status));
        }
        Ok(Self { buf })
    }

    /// Consume la cabecera de la siguiente operación (opcode + status).
    fn begin_op(&mut self, expected: u32) -> Result<(), ProtoError> {
        let opcode = u32::decode(&mut self.buf)?;
        if opcode != expected {
            return Err(ProtoError::Protocol("COMPOUND: opcode inesperado"));
        }
        let status = u32::decode(&mut self.buf)?;
        if status != NFS4_OK {
            return Err(ProtoError::Nfs4(status));
        }
        Ok(())
    }

    fn decode<T: XdrDecode>(&mut self) -> Result<T, ProtoError> {
        Ok(T::decode(&mut self.buf)?)
    }

    fn opaque(&mut self, limit: usize) -> Result<Bytes, ProtoError> {
        Ok(decode_opaque(&mut self.buf, limit)?)
    }

    /// Decodifica un `fattr4` (bitmap + attrlist) ya en el buffer.
    fn fattr4(&mut self) -> Result<Fattr4, ProtoError> {
        let bitmap: Vec<u32> = self.decode()?;
        let attrlist = self.opaque(usize::MAX)?;
        decode_fattr4(&bitmap, attrlist)
    }
}

// --- Cliente NFSv4 -----------------------------------------------------------

/// Cliente NFSv4.0 sobre una conexión RPC, con gestión de estado.
pub struct Nfs4 {
    rpc: RpcClient,
    minor: u32,
    clientid: u64,
    owner: Bytes,
    open_seqid: u32,
    lock_counter: u32,
    /// Sessionid de NFSv4.1 (`None` en v4.0).
    sessionid: Option<[u8; 16]>,
    /// Sequenceid del slot 0 (NFSv4.1).
    seq_id: u32,
}

/// Resultado de un `LOCK` concedido: stateid del bloqueo y tipo.
#[derive(Clone, Debug)]
pub struct LockGrant {
    /// Stateid del bloqueo (para `LOCKU`).
    pub stateid: Stateid4,
    /// Tipo de bloqueo concedido.
    pub locktype: u32,
}

impl Nfs4 {
    /// Conecta al servicio NFSv4.0 de `server:port` (handshake `SETCLIENTID`).
    pub fn connect(
        server: IpAddr,
        port: u16,
        cred: Credentials,
        protocol: Protocol,
        timeout: Duration,
    ) -> Result<Self, ProtoError> {
        Self::connect_minor(server, port, cred, protocol, timeout, 0)
    }

    /// Conecta seleccionando la minorversion (0 = v4.0, 1 = v4.1 con sesiones).
    pub fn connect_minor(
        server: IpAddr,
        port: u16,
        cred: Credentials,
        protocol: Protocol,
        timeout: Duration,
        minor: u32,
    ) -> Result<Self, ProtoError> {
        let addr = SocketAddr::new(server, port);
        let rpc = RpcClient::connect(addr, protocol, cred, timeout)?;
        Self::from_client(rpc, minor)
    }

    /// Construye el cliente sobre un `RpcClient` ya conectado (p. ej. TLS) y
    /// realiza el handshake según la minorversion.
    pub fn from_client(rpc: RpcClient, minor: u32) -> Result<Self, ProtoError> {
        let mut client = Self {
            rpc,
            minor,
            clientid: 0,
            owner: unique_owner(),
            open_seqid: 0,
            lock_counter: 0,
            sessionid: None,
            seq_id: 0,
        };
        if minor >= 1 {
            client.establish_session()?;
        } else {
            client.setclientid()?;
        }
        Ok(client)
    }

    /// Acceso mutable al cliente RPC subyacente.
    pub fn rpc_mut(&mut self) -> &mut RpcClient {
        &mut self.rpc
    }

    /// Ejecuta un COMPOUND. En v4.1 antepone `SEQUENCE` y consume su resultado.
    fn run(&mut self, c: &Compound) -> Result<CompoundReader, ProtoError> {
        // `NFS4ERR_GRACE`/`NFS4ERR_DELAY` significan «nada se aplicó, reintenta»:
        // reenviar el COMPOUND es seguro. Backoff exponencial acotado.
        let mut delay = Duration::from_millis(100);
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let args = self.assemble(c)?;
            let reply: Bytes = self
                .rpc
                .call(PROGRAM, VERSION4, COMPOUND_PROC, &Raw(args))?;
            match CompoundReader::parse(reply) {
                Ok(mut reader) => {
                    if self.minor >= 1 {
                        // Consumir el resultado de SEQUENCE: sessionid + 5 u32.
                        reader.begin_op(OP_SEQUENCE)?;
                        let _sid: [u8; 16] = reader.decode()?;
                        for _ in 0..5 {
                            let _: u32 = reader.decode()?;
                        }
                    }
                    return Ok(reader);
                }
                Err(ProtoError::Nfs4(code))
                    if matches!(code, NFS4ERR_GRACE | NFS4ERR_DELAY) && attempts < 6 =>
                {
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(Duration::from_secs(2));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Ejecuta un COMPOUND sin envolver en `SEQUENCE` (para `EXCHANGE_ID` y
    /// `CREATE_SESSION`, que establecen la sesión y no llevan SEQUENCE).
    fn run_raw(&mut self, c: &Compound) -> Result<CompoundReader, ProtoError> {
        let args = c.finish(self.minor)?;
        let reply: Bytes = self
            .rpc
            .call(PROGRAM, VERSION4, COMPOUND_PROC, &Raw(args))?;
        CompoundReader::parse(reply)
    }

    /// Serializa el COMPOUND a enviar, anteponiendo `SEQUENCE` en v4.1.
    fn assemble(&mut self, c: &Compound) -> Result<Bytes, ProtoError> {
        if self.minor == 0 {
            return Ok(c.finish(0)?);
        }
        let sessionid = self
            .sessionid
            .ok_or(ProtoError::Protocol("sesión NFSv4.1 no establecida"))?;
        let seqid = self.seq_id;
        self.seq_id = self.seq_id.wrapping_add(1);
        let mut buf = BytesMut::new();
        "".encode(&mut buf)?; // tag
        self.minor.encode(&mut buf)?;
        (c.nops + 1).encode(&mut buf)?;
        // SEQUENCE: sessionid, seqid, slotid=0, highest_slotid=0, cachethis=false
        OP_SEQUENCE.encode(&mut buf)?;
        sessionid.encode(&mut buf)?;
        seqid.encode(&mut buf)?;
        0u32.encode(&mut buf)?;
        0u32.encode(&mut buf)?;
        false.encode(&mut buf)?;
        buf.put_slice(&c.ops);
        Ok(buf.freeze())
    }

    /// Handshake de NFSv4.1: `EXCHANGE_ID` → `CREATE_SESSION` → `RECLAIM_COMPLETE`.
    fn establish_session(&mut self) -> Result<(), ProtoError> {
        // EXCHANGE_ID (sin SEQUENCE).
        let mut c = Compound::new();
        c.op(OP_EXCHANGE_ID)?;
        boot_verifier().encode(&mut c.ops)?; // co_verifier
        self.owner.clone().encode(&mut c.ops)?; // co_ownerid
        0u32.encode(&mut c.ops)?; // eia_flags
        0u32.encode(&mut c.ops)?; // state_protect4_a = SP4_NONE
        0u32.encode(&mut c.ops)?; // impl_id<> (vacío)
        let mut r = self.run_raw(&c)?;
        r.begin_op(OP_EXCHANGE_ID)?;
        let clientid: u64 = r.decode()?;
        let create_seqid: u32 = r.decode()?; // eir_sequenceid
        let _flags: u32 = r.decode()?;
        let _state_protect: u32 = r.decode()?; // SP4_NONE
        let _server_minor_id: u64 = r.decode()?;
        let _server_major_id = r.opaque(usize::MAX)?;
        let _server_scope = r.opaque(usize::MAX)?;
        let _impl_id_count: u32 = r.decode()?; // normalmente 0
        self.clientid = clientid;

        // CREATE_SESSION (sin SEQUENCE).
        let mut c2 = Compound::new();
        c2.op(OP_CREATE_SESSION)?;
        clientid.encode(&mut c2.ops)?;
        create_seqid.encode(&mut c2.ops)?; // csa_sequence
        0u32.encode(&mut c2.ops)?; // csa_flags
        encode_channel_attrs(&mut c2.ops)?; // fore
        encode_channel_attrs(&mut c2.ops)?; // back
        0u32.encode(&mut c2.ops)?; // cb_program
        1u32.encode(&mut c2.ops)?; // csa_sec_parms<> : 1 entrada
        0u32.encode(&mut c2.ops)?; // flavor AUTH_NONE (brazo void)
        let mut r2 = self.run_raw(&c2)?;
        r2.begin_op(OP_CREATE_SESSION)?;
        let sessionid: [u8; 16] = r2.decode()?;
        let csr_seq: u32 = r2.decode()?; // csr_sequence
        let _csr_flags: u32 = r2.decode()?;
        skip_channel_attrs(&mut r2)?; // fore
        skip_channel_attrs(&mut r2)?; // back
        self.sessionid = Some(sessionid);
        self.seq_id = csr_seq;

        // RECLAIM_COMPLETE (ya con SEQUENCE).
        let mut c3 = Compound::new();
        c3.op(OP_RECLAIM_COMPLETE)?;
        false.encode(&mut c3.ops)?; // rca_one_fs
        let mut r3 = self.run(&c3)?;
        r3.begin_op(OP_RECLAIM_COMPLETE)?;
        Ok(())
    }

    /// `DESTROY_SESSION` + `DESTROY_CLIENTID` (cierre ordenado de v4.1).
    pub fn destroy_session(&mut self) -> Result<(), ProtoError> {
        let Some(sessionid) = self.sessionid else {
            return Ok(());
        };
        let mut c = Compound::new();
        c.op(OP_DESTROY_SESSION)?;
        sessionid.encode(&mut c.ops)?;
        let mut r = self.run_raw(&c)?;
        r.begin_op(OP_DESTROY_SESSION)?;
        self.sessionid = None;
        Ok(())
    }

    fn setclientid(&mut self) -> Result<(), ProtoError> {
        let verifier = boot_verifier();
        let id = unique_owner();
        // SETCLIENTID: no es una operación COMPOUND con PUTFH; va directa.
        let mut c = Compound::new();
        c.op(OP_SETCLIENTID)?;
        verifier.encode(&mut c.ops)?; // client.verifier
        id.encode(&mut c.ops)?; // client.id
        0u32.encode(&mut c.ops)?; // cb_program
        "".encode(&mut c.ops)?; // r_netid
        "".encode(&mut c.ops)?; // r_addr
        0u32.encode(&mut c.ops)?; // callback_ident
        let mut r = self.run(&c)?;
        r.begin_op(OP_SETCLIENTID)?;
        let clientid: u64 = r.decode()?;
        let confirm: [u8; 8] = r.decode()?;

        let mut c2 = Compound::new();
        c2.op(OP_SETCLIENTID_CONFIRM)?;
        clientid.encode(&mut c2.ops)?;
        confirm.encode(&mut c2.ops)?;
        let mut r2 = self.run(&c2)?;
        r2.begin_op(OP_SETCLIENTID_CONFIRM)?;

        self.clientid = clientid;
        Ok(())
    }

    /// Renueva el lease del cliente (`RENEW`).
    pub fn renew(&mut self) -> Result<(), ProtoError> {
        let mut c = Compound::new();
        c.renew(self.clientid)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_RENEW)
    }

    /// Devuelve el file handle raíz del servidor (`PUTROOTFH` + `GETFH`).
    pub fn root_fh(&mut self) -> Result<NfsFh4, ProtoError> {
        let mut c = Compound::new();
        c.putrootfh()?.getfh()?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTROOTFH)?;
        r.begin_op(OP_GETFH)?;
        r.decode()
    }

    /// `GETATTR` de un objeto.
    pub fn getattr(&mut self, fh: &NfsFh4) -> Result<Fattr4, ProtoError> {
        self.getattr_bits(fh, REQUEST_ATTRS)
    }

    fn getattr_bits(&mut self, fh: &NfsFh4, bits: &[u32]) -> Result<Fattr4, ProtoError> {
        let mut c = Compound::new();
        c.putfh(fh)?.getattr(bits)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_GETATTR)?;
        r.fattr4()
    }

    /// `GETATTR` de los atributos de espacio del sistema de ficheros (statvfs).
    pub fn statvfs(&mut self, fh: &NfsFh4) -> Result<Fattr4, ProtoError> {
        const STATVFS_ATTRS: &[u32] = &[
            FATTR4_FILES_AVAIL,
            FATTR4_FILES_FREE,
            FATTR4_FILES_TOTAL,
            FATTR4_SPACE_AVAIL,
            FATTR4_SPACE_FREE,
            FATTR4_SPACE_TOTAL,
        ];
        self.getattr_bits(fh, STATVFS_ATTRS)
    }

    /// `LOOKUP` de `name` en `dir`; devuelve fh y atributos.
    pub fn lookup(&mut self, dir: &NfsFh4, name: &str) -> Result<(NfsFh4, Fattr4), ProtoError> {
        let mut c = Compound::new();
        c.putfh(dir)?
            .lookup(name)?
            .getfh()?
            .getattr(REQUEST_ATTRS)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_LOOKUP)?;
        r.begin_op(OP_GETFH)?;
        let fh: NfsFh4 = r.decode()?;
        r.begin_op(OP_GETATTR)?;
        let attrs = r.fattr4()?;
        Ok((fh, attrs))
    }

    /// `ACCESS`: comprueba permisos. Devuelve la máscara concedida.
    pub fn access(&mut self, fh: &NfsFh4, mask: u32) -> Result<u32, ProtoError> {
        let mut c = Compound::new();
        c.putfh(fh)?.access(mask)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_ACCESS)?;
        let _supported: u32 = r.decode()?;
        r.decode()
    }

    /// `READLINK`: destino de un enlace simbólico.
    pub fn readlink(&mut self, fh: &NfsFh4) -> Result<String, ProtoError> {
        let mut c = Compound::new();
        c.putfh(fh)?.readlink()?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_READLINK)?;
        r.decode()
    }

    /// `OPEN` de un fichero (creándolo si `create`). Confirma si hace falta.
    pub fn open(
        &mut self,
        dir: &NfsFh4,
        name: &str,
        share_access: u32,
        create: bool,
    ) -> Result<OpenResult, ProtoError> {
        let seqid = self.open_seqid;
        let owner = self.owner.clone();
        let clientid = self.clientid;
        let mut c = Compound::new();
        c.putfh(dir)?
            .open(seqid, clientid, &owner, share_access, create, name)?
            .getfh()?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_OPEN)?;
        let mut stateid: Stateid4 = r.decode()?;
        let _cinfo: ChangeInfo4 = r.decode()?;
        let rflags: u32 = r.decode()?;
        let _attrset: Vec<u32> = r.decode()?;
        let delegation_type: u32 = r.decode()?;
        if delegation_type != 0 {
            return Err(ProtoError::Protocol(
                "el servidor concedió una delegación (no soportado)",
            ));
        }
        r.begin_op(OP_GETFH)?;
        let fh: NfsFh4 = r.decode()?;
        self.open_seqid = self.open_seqid.wrapping_add(1);

        if rflags & OPEN4_RESULT_CONFIRM != 0 {
            let confirm_seqid = self.open_seqid;
            let mut cc = Compound::new();
            cc.putfh(&fh)?.open_confirm(&stateid, confirm_seqid)?;
            let mut rr = self.run(&cc)?;
            rr.begin_op(OP_PUTFH)?;
            rr.begin_op(OP_OPEN_CONFIRM)?;
            stateid = rr.decode()?;
            self.open_seqid = self.open_seqid.wrapping_add(1);
        }

        Ok(OpenResult { fh, stateid })
    }

    /// `CLOSE` de un fichero abierto.
    pub fn close(&mut self, fh: &NfsFh4, stateid: &Stateid4) -> Result<(), ProtoError> {
        let seqid = self.open_seqid;
        let mut c = Compound::new();
        c.putfh(fh)?.close(seqid, stateid)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_CLOSE)?;
        let _stateid: Stateid4 = r.decode()?;
        self.open_seqid = self.open_seqid.wrapping_add(1);
        Ok(())
    }

    fn fresh_lock_owner(&mut self) -> Bytes {
        self.lock_counter = self.lock_counter.wrapping_add(1);
        let mut owner = self.owner.to_vec();
        owner.extend_from_slice(format!(":lock:{}", self.lock_counter).as_bytes());
        Bytes::from(owner)
    }

    /// `LOCK`: solicita un bloqueo byte-range sobre un fichero abierto. Crea un
    /// lock_owner nuevo por bloqueo (un par LOCK/LOCKU por owner). Devuelve el
    /// stateid del bloqueo; `Err(Nfs4(NFS4ERR_DENIED))` si hay conflicto.
    pub fn lock(
        &mut self,
        fh: &NfsFh4,
        open_stateid: &Stateid4,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<LockGrant, ProtoError> {
        let locktype = if exclusive { WRITE_LT } else { READ_LT };
        let lock_owner = self.fresh_lock_owner();
        let open_seqid = self.open_seqid;
        let clientid = self.clientid;
        let mut c = Compound::new();
        c.putfh(fh)?.lock_new(
            locktype,
            offset,
            length,
            open_seqid,
            open_stateid,
            0,
            clientid,
            &lock_owner,
        )?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_LOCK)?;
        let stateid: Stateid4 = r.decode()?;
        // `open_to_lock_owner` consume un seqid del open_owner.
        self.open_seqid = self.open_seqid.wrapping_add(1);
        Ok(LockGrant { stateid, locktype })
    }

    /// `LOCKU`: libera el bloqueo concedido por [`Nfs4::lock`].
    pub fn unlock(
        &mut self,
        fh: &NfsFh4,
        grant: &LockGrant,
        offset: u64,
        length: u64,
    ) -> Result<Stateid4, ProtoError> {
        // El lock_owner se creó con LOCK (lock_seqid 0); este es su segundo uso.
        let mut c = Compound::new();
        c.putfh(fh)?
            .locku(grant.locktype, 1, &grant.stateid, offset, length)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_LOCKU)?;
        r.decode()
    }

    /// `LOCKT`: comprueba si un bloqueo se podría conceder. `Ok(true)` si está
    /// disponible, `Ok(false)` si hay un bloqueo en conflicto.
    pub fn test_lock(
        &mut self,
        fh: &NfsFh4,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<bool, ProtoError> {
        let locktype = if exclusive { WRITE_LT } else { READ_LT };
        let lock_owner = self.fresh_lock_owner();
        let clientid = self.clientid;
        let mut c = Compound::new();
        c.putfh(fh)?
            .lockt(locktype, offset, length, clientid, &lock_owner)?;
        match self.run(&c) {
            Ok(mut r) => {
                r.begin_op(OP_PUTFH)?;
                r.begin_op(OP_LOCKT)?;
                Ok(true)
            }
            Err(ProtoError::Nfs4(NFS4ERR_DENIED)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `READ` desde un fichero abierto.
    pub fn read(
        &mut self,
        fh: &NfsFh4,
        stateid: &Stateid4,
        offset: u64,
        count: u32,
    ) -> Result<ReadResult, ProtoError> {
        let mut c = Compound::new();
        c.putfh(fh)?.read(stateid, offset, count)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_READ)?;
        let eof: bool = r.decode()?;
        let data = r.opaque(usize::MAX)?;
        Ok(ReadResult { eof, data })
    }

    /// `WRITE` en un fichero abierto. Devuelve los bytes escritos.
    pub fn write(
        &mut self,
        fh: &NfsFh4,
        stateid: &Stateid4,
        offset: u64,
        stable: u32,
        data: Bytes,
    ) -> Result<u32, ProtoError> {
        let mut c = Compound::new();
        c.putfh(fh)?.write(stateid, offset, stable, &data)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_WRITE)?;
        let count: u32 = r.decode()?;
        let _committed: u32 = r.decode()?;
        let _verf: [u8; 8] = r.decode()?;
        Ok(count)
    }

    /// `COMMIT`: fuerza la persistencia de datos escritos en modo `UNSTABLE4`.
    pub fn commit(&mut self, fh: &NfsFh4, offset: u64, count: u32) -> Result<(), ProtoError> {
        let mut c = Compound::new();
        c.putfh(fh)?.commit(offset, count)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_COMMIT)?;
        let _verf: [u8; 8] = r.decode()?;
        Ok(())
    }

    /// `SETATTR`: fija atributos (modo/tamaño) de un objeto.
    pub fn setattr(&mut self, fh: &NfsFh4, attrs: &SetAttr4) -> Result<(), ProtoError> {
        let mut c = Compound::new();
        c.putfh(fh)?.setattr(&Stateid4::default(), attrs)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_SETATTR)?;
        let _attrsset: Vec<u32> = r.decode()?;
        Ok(())
    }

    /// `CREATE` de un directorio; devuelve su file handle.
    pub fn mkdir(&mut self, dir: &NfsFh4, name: &str) -> Result<NfsFh4, ProtoError> {
        let mut c = Compound::new();
        c.putfh(dir)?.create_dir(name)?.getfh()?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_CREATE)?;
        let _cinfo: ChangeInfo4 = r.decode()?;
        let _attrset: Vec<u32> = r.decode()?;
        r.begin_op(OP_GETFH)?;
        r.decode()
    }

    /// `CREATE` de un enlace simbólico; devuelve su file handle.
    pub fn symlink(
        &mut self,
        dir: &NfsFh4,
        name: &str,
        target: &str,
    ) -> Result<NfsFh4, ProtoError> {
        let mut c = Compound::new();
        c.putfh(dir)?.create_symlink(name, target)?.getfh()?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_CREATE)?;
        let _cinfo: ChangeInfo4 = r.decode()?;
        let _attrset: Vec<u32> = r.decode()?;
        r.begin_op(OP_GETFH)?;
        r.decode()
    }

    /// `REMOVE`: borra `name` de `dir`.
    pub fn remove(&mut self, dir: &NfsFh4, name: &str) -> Result<(), ProtoError> {
        let mut c = Compound::new();
        c.putfh(dir)?.remove(name)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_REMOVE)?;
        let _cinfo: ChangeInfo4 = r.decode()?;
        Ok(())
    }

    /// `LINK`: crea un enlace duro a `file` con nombre `name` en `dir`.
    pub fn link(&mut self, file: &NfsFh4, dir: &NfsFh4, name: &str) -> Result<(), ProtoError> {
        // PUTFH(file), SAVEFH, PUTFH(dir), LINK(name)
        let mut c = Compound::new();
        c.putfh(file)?.savefh()?.putfh(dir)?.link(name)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_SAVEFH)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_LINK)?;
        let _cinfo: ChangeInfo4 = r.decode()?;
        Ok(())
    }

    /// `RENAME`: mueve `from_name` de `from_dir` a `to_name` en `to_dir`.
    pub fn rename(
        &mut self,
        from_dir: &NfsFh4,
        from_name: &str,
        to_dir: &NfsFh4,
        to_name: &str,
    ) -> Result<(), ProtoError> {
        let mut c = Compound::new();
        c.putfh(from_dir)?
            .savefh()?
            .putfh(to_dir)?
            .rename(from_name, to_name)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_SAVEFH)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_RENAME)?;
        let _source: ChangeInfo4 = r.decode()?;
        let _target: ChangeInfo4 = r.decode()?;
        Ok(())
    }

    /// `READDIR`: lista entradas de un directorio (con atributos).
    pub fn readdir(
        &mut self,
        dir: &NfsFh4,
        cookie: u64,
        cookieverf: [u8; 8],
        maxcount: u32,
    ) -> Result<ReaddirResult, ProtoError> {
        let mut c = Compound::new();
        c.putfh(dir)?
            .readdir(cookie, cookieverf, maxcount / 2, maxcount, REQUEST_ATTRS)?;
        let mut r = self.run(&c)?;
        r.begin_op(OP_PUTFH)?;
        r.begin_op(OP_READDIR)?;
        let cookieverf: [u8; 8] = r.decode()?;
        let mut entries = Vec::new();
        let mut present: bool = r.decode()?;
        while present {
            let cookie: u64 = r.decode()?;
            let name: String = r.decode()?;
            let attrs = r.fattr4()?;
            entries.push(DirEntry4 {
                cookie,
                name,
                attrs,
            });
            present = r.decode()?;
        }
        let eof: bool = r.decode()?;
        Ok(ReaddirResult {
            cookieverf,
            entries,
            eof,
        })
    }
}

/// Codifica un `channel_attrs4` con valores por defecto (1 slot, 1 MiB).
fn encode_channel_attrs(buf: &mut BytesMut) -> Result<(), XdrError> {
    0u32.encode(buf)?; // ca_headerpad_size
    1_048_576u32.encode(buf)?; // ca_maxrequestsize
    1_048_576u32.encode(buf)?; // ca_maxresponsesize
    0u32.encode(buf)?; // ca_maxresponsesize_cached
    8u32.encode(buf)?; // ca_maxoperations
    1u32.encode(buf)?; // ca_maxrequests (1 slot)
    0u32.encode(buf)?; // ca_rdma_ird<> (vacío)
    Ok(())
}

/// Descarta un `channel_attrs4` de la respuesta de `CREATE_SESSION`.
fn skip_channel_attrs(r: &mut CompoundReader) -> Result<(), ProtoError> {
    for _ in 0..6 {
        let _: u32 = r.decode()?;
    }
    let _rdma_ird: Vec<u32> = r.decode()?;
    Ok(())
}

fn boot_verifier() -> [u8; 8] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos.to_be_bytes()
}

fn unique_owner() -> Bytes {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id();
    Bytes::from(format!("libnfs-rs:{pid}:{nanos}").into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfs_xdr::to_bytes;

    #[test]
    fn bitmap_build_and_check() {
        let bm = build_bitmap(&[FATTR4_TYPE, FATTR4_SIZE, FATTR4_MODE, FATTR4_TIME_MODIFY]);
        assert_eq!(bm.len(), 2);
        assert!(bit_set(&bm, FATTR4_TYPE));
        assert!(bit_set(&bm, FATTR4_SIZE));
        assert!(bit_set(&bm, FATTR4_MODE));
        assert!(bit_set(&bm, FATTR4_TIME_MODIFY));
        assert!(!bit_set(&bm, FATTR4_FILEID));
    }

    #[test]
    fn fattr4_roundtrip_subset() {
        // Construye un attrlist con type(1), size(4), mode(33) en orden de bit.
        let bits = [FATTR4_TYPE, FATTR4_SIZE, FATTR4_MODE];
        let mut values = BytesMut::new();
        NF4REG.encode(&mut values).unwrap(); // type
        1234u64.encode(&mut values).unwrap(); // size
        0o644u32.encode(&mut values).unwrap(); // mode
        let bitmap = build_bitmap(&bits);
        let attrs = decode_fattr4(&bitmap, values.freeze()).unwrap();
        assert_eq!(attrs.ftype, Some(NF4REG));
        assert_eq!(attrs.size, Some(1234));
        assert_eq!(attrs.mode, Some(0o644));
        assert_eq!(attrs.fileid, None);
    }

    #[test]
    fn setattr_fattr4_encoding() {
        let mut buf = BytesMut::new();
        encode_setattr_fattr4(
            &mut buf,
            &SetAttr4 {
                mode: Some(0o600),
                size: Some(0),
            },
        )
        .unwrap();
        // bitmap: 2 words (mode está en el bit 33). size(4) y mode(33) activos.
        let mut b = buf.freeze();
        let bitmap = Vec::<u32>::decode(&mut b).unwrap();
        assert!(bit_set(&bitmap, FATTR4_SIZE));
        assert!(bit_set(&bitmap, FATTR4_MODE));
        // attrlist: size (8 bytes) + mode (4 bytes) = 12 bytes.
        let attrlist = decode_opaque(&mut b, usize::MAX).unwrap();
        assert_eq!(attrlist.len(), 12);
    }

    #[test]
    fn compound_header_layout() {
        let mut c = Compound::new();
        c.putrootfh().unwrap().getfh().unwrap();
        let bytes = c.finish(0).unwrap();
        let mut b = bytes.clone();
        assert_eq!(String::decode(&mut b).unwrap(), ""); // tag
        assert_eq!(u32::decode(&mut b).unwrap(), 0); // minorversion
        assert_eq!(u32::decode(&mut b).unwrap(), 2); // nops
        assert_eq!(u32::decode(&mut b).unwrap(), OP_PUTROOTFH);
        assert_eq!(u32::decode(&mut b).unwrap(), OP_GETFH);
    }

    #[test]
    fn raw_appends_without_length_prefix() {
        let raw = Raw(Bytes::from_static(&[1, 2, 3, 4]));
        assert_eq!(&to_bytes(&raw).unwrap()[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn lock_compound_layout() {
        let mut c = Compound::new();
        let stateid = Stateid4 {
            seqid: 1,
            other: [7u8; 12],
        };
        c.lock_new(
            WRITE_LT,
            0,
            100,
            5,
            &stateid,
            0,
            0xABCD,
            &Bytes::from_static(b"owner"),
        )
        .unwrap();
        let bytes = c.finish(0).unwrap();
        let mut b = bytes;
        assert_eq!(String::decode(&mut b).unwrap(), ""); // tag
        assert_eq!(u32::decode(&mut b).unwrap(), 0); // minor
        assert_eq!(u32::decode(&mut b).unwrap(), 1); // nops
        assert_eq!(u32::decode(&mut b).unwrap(), OP_LOCK);
        assert_eq!(u32::decode(&mut b).unwrap(), WRITE_LT);
        assert!(!bool::decode(&mut b).unwrap()); // reclaim
        assert_eq!(u64::decode(&mut b).unwrap(), 0); // offset
        assert_eq!(u64::decode(&mut b).unwrap(), 100); // length
        assert!(bool::decode(&mut b).unwrap()); // new_lock_owner
        assert_eq!(u32::decode(&mut b).unwrap(), 5); // open_seqid
    }
}
