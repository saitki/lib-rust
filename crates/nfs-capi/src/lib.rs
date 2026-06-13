//! API C (FFI) sobre [`nfs_client`].
//!
//! Compila a `nfs_client.dll` (+ import lib) y `nfs_client.lib`, consumibles
//! desde C/C++ o desde Rust vía FFI (como hace la app Tauri con libnfs).
//!
//! Convenciones:
//! - El contexto es un puntero opaco `NfsHandle*` (de `nfs_rs_mount`), que se
//!   libera con `nfs_rs_unmount`.
//! - Las funciones que devuelven datos estructurados (stat, readdir) devuelven
//!   una cadena JSON (`char*`) que el llamante libera con `nfs_rs_free_string`.
//! - `nfs_rs_read` devuelve un buffer que se libera con `nfs_rs_free_bytes`.
//! - Las funciones que devuelven `int` usan `0` = OK, `-1` = error (consultar
//!   `nfs_rs_last_error`).
//!
//! Este es el único crate del workspace que usa `unsafe` (es FFI; justificado).

use std::ffi::{c_char, c_int, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use nfs_client::NfsContext;
use serde_json::json;

/// Contexto NFS opaco para el llamante C.
pub struct NfsHandle {
    ctx: NfsContext,
    last_error: CString,
}

impl NfsHandle {
    fn set_error(&mut self, msg: impl Into<String>) {
        self.last_error = CString::new(msg.into()).unwrap_or_default();
    }
}

// --- Helpers internos --------------------------------------------------------

unsafe fn as_handle<'a>(h: *mut NfsHandle) -> Option<&'a mut NfsHandle> {
    if h.is_null() {
        None
    } else {
        Some(&mut *h)
    }
}

unsafe fn as_str(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok().map(str::to_owned)
}

/// Ejecuta `f` capturando pánicos; en error devuelve `-1` y fija `last_error`.
fn guard_int(
    h: &mut NfsHandle,
    what: &str,
    f: impl FnOnce(&mut NfsHandle) -> Result<(), String>,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| f(h))) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            h.set_error(e);
            -1
        }
        Err(_) => {
            h.set_error(format!("pánico en {what}"));
            -1
        }
    }
}

fn into_json_ptr(value: serde_json::Value) -> *mut c_char {
    match CString::new(value.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

// --- Montaje -----------------------------------------------------------------

/// Monta una URL `nfs://...`. Devuelve un handle o `NULL` si falla.
///
/// # Safety
/// `url` debe ser un puntero C válido y terminado en NUL.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_mount(url: *const c_char) -> *mut NfsHandle {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let url = as_str(url)?;
        NfsContext::mount_url(&url).ok().map(|ctx| NfsHandle {
            ctx,
            last_error: CString::default(),
        })
    }));
    match result {
        Ok(Some(handle)) => Box::into_raw(Box::new(handle)),
        _ => ptr::null_mut(),
    }
}

/// Libera un handle de montaje.
///
/// # Safety
/// `h` debe provenir de `nfs_rs_mount` y no usarse después.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_unmount(h: *mut NfsHandle) {
    if !h.is_null() {
        drop(Box::from_raw(h));
    }
}

/// Último mensaje de error del handle (válido hasta la siguiente llamada).
///
/// # Safety
/// `h` debe provenir de `nfs_rs_mount`.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_last_error(h: *mut NfsHandle) -> *const c_char {
    match as_handle(h) {
        Some(handle) => handle.last_error.as_ptr(),
        None => ptr::null(),
    }
}

// --- Metadatos y directorios -------------------------------------------------

/// Atributos de `path` como JSON, o `NULL` en error. Liberar con
/// `nfs_rs_free_string`.
///
/// # Safety
/// Punteros C válidos terminados en NUL.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_stat(h: *mut NfsHandle, path: *const c_char) -> *mut c_char {
    let Some(handle) = as_handle(h) else {
        return ptr::null_mut();
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let path = as_str(path).ok_or_else(|| "ruta inválida".to_string())?;
        let a = handle.ctx.stat(&path).map_err(|e| e.to_string())?;
        Ok::<_, String>(json!({
            "type": format!("{:?}", a.file_type),
            "mode": a.mode,
            "nlink": a.nlink,
            "uid": a.uid,
            "gid": a.gid,
            "size": a.size,
            "fileid": a.fileid,
            "mtime": a.mtime.secs,
            "atime": a.atime.secs,
            "ctime": a.ctime.secs,
        }))
    }));
    match result {
        Ok(Ok(value)) => into_json_ptr(value),
        Ok(Err(e)) => {
            handle.set_error(e);
            ptr::null_mut()
        }
        Err(_) => {
            handle.set_error("pánico en nfs_rs_stat");
            ptr::null_mut()
        }
    }
}

/// Lista `path` como JSON (array de {name,type,size,fileid}), o `NULL` en error.
/// Liberar con `nfs_rs_free_string`.
///
/// # Safety
/// Punteros C válidos terminados en NUL.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_readdir(h: *mut NfsHandle, path: *const c_char) -> *mut c_char {
    let Some(handle) = as_handle(h) else {
        return ptr::null_mut();
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let path = as_str(path).ok_or_else(|| "ruta inválida".to_string())?;
        let entries = handle.ctx.readdir(&path).map_err(|e| e.to_string())?;
        let arr: Vec<_> = entries
            .iter()
            .map(|e| {
                json!({
                    "name": e.name,
                    "fileid": e.fileid,
                    "type": e.attr.as_ref().map(|a| format!("{:?}", a.file_type)),
                    "size": e.attr.as_ref().map(|a| a.size),
                })
            })
            .collect();
        Ok::<_, String>(json!(arr))
    }));
    match result {
        Ok(Ok(value)) => into_json_ptr(value),
        Ok(Err(e)) => {
            handle.set_error(e);
            ptr::null_mut()
        }
        Err(_) => {
            handle.set_error("pánico en nfs_rs_readdir");
            ptr::null_mut()
        }
    }
}

// --- Lectura / escritura -----------------------------------------------------

/// Lee `path` completo. Escribe `*out_buf`/`*out_len` y devuelve `0`, o `-1` en
/// error. Liberar el buffer con `nfs_rs_free_bytes`.
///
/// # Safety
/// Punteros C válidos; `out_buf`/`out_len` deben apuntar a memoria escribible.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_read(
    h: *mut NfsHandle,
    path: *const c_char,
    out_buf: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    let Some(handle) = as_handle(h) else {
        return -1;
    };
    if out_buf.is_null() || out_len.is_null() {
        handle.set_error("punteros de salida nulos");
        return -1;
    }
    let path_owned = as_str(path);
    guard_int(handle, "nfs_rs_read", |handle| {
        let path = path_owned.ok_or_else(|| "ruta inválida".to_string())?;
        let data = handle.ctx.read_whole(&path).map_err(|e| e.to_string())?;
        let mut boxed = data.to_vec().into_boxed_slice();
        let len = boxed.len();
        let ptr = boxed.as_mut_ptr();
        std::mem::forget(boxed);
        *out_buf = ptr;
        *out_len = len;
        Ok(())
    })
}

/// Escribe `data`/`len` como contenido completo de `path`. `0` OK, `-1` error.
///
/// # Safety
/// `data` debe ser válido para `len` bytes; punteros C terminados en NUL.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_write(
    h: *mut NfsHandle,
    path: *const c_char,
    data: *const u8,
    len: usize,
) -> c_int {
    let Some(handle) = as_handle(h) else {
        return -1;
    };
    let path_owned = as_str(path);
    let slice: &[u8] = if data.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, len)
    };
    guard_int(handle, "nfs_rs_write", |handle| {
        let path = path_owned.ok_or_else(|| "ruta inválida".to_string())?;
        handle
            .ctx
            .write_whole(&path, slice)
            .map_err(|e| e.to_string())
    })
}

// --- Operaciones de nombres --------------------------------------------------

macro_rules! path_op {
    ($name:ident, $what:literal, $method:ident) => {
        /// # Safety
        /// Punteros C válidos terminados en NUL.
        #[no_mangle]
        pub unsafe extern "C" fn $name(h: *mut NfsHandle, path: *const c_char) -> c_int {
            let Some(handle) = as_handle(h) else {
                return -1;
            };
            let path_owned = as_str(path);
            guard_int(handle, $what, |handle| {
                let path = path_owned.ok_or_else(|| "ruta inválida".to_string())?;
                handle.ctx.$method(&path).map_err(|e| e.to_string())
            })
        }
    };
}

path_op!(nfs_rs_mkdir, "nfs_rs_mkdir", mkdir);
path_op!(nfs_rs_rmdir, "nfs_rs_rmdir", rmdir);
path_op!(nfs_rs_unlink, "nfs_rs_unlink", unlink);

/// Renombra/mueve `from` a `to`. `0` OK, `-1` error.
///
/// # Safety
/// Punteros C válidos terminados en NUL.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_rename(
    h: *mut NfsHandle,
    from: *const c_char,
    to: *const c_char,
) -> c_int {
    let Some(handle) = as_handle(h) else {
        return -1;
    };
    let from_owned = as_str(from);
    let to_owned = as_str(to);
    guard_int(handle, "nfs_rs_rename", |handle| {
        let from = from_owned.ok_or_else(|| "ruta origen inválida".to_string())?;
        let to = to_owned.ok_or_else(|| "ruta destino inválida".to_string())?;
        handle.ctx.rename(&from, &to).map_err(|e| e.to_string())
    })
}

/// `true` si `path` es accesible para lectura (1) o no (0); `-1` en error.
///
/// # Safety
/// Punteros C válidos terminados en NUL.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_access(h: *mut NfsHandle, path: *const c_char) -> c_int {
    let Some(handle) = as_handle(h) else {
        return -1;
    };
    let path_owned = as_str(path);
    match catch_unwind(AssertUnwindSafe(|| {
        let path = path_owned.ok_or_else(|| "ruta inválida".to_string())?;
        handle.ctx.access(&path).map_err(|e| e.to_string())
    })) {
        Ok(Ok(true)) => 1,
        Ok(Ok(false)) => 0,
        Ok(Err(e)) => {
            handle.set_error(e);
            -1
        }
        Err(_) => {
            handle.set_error("pánico en nfs_rs_access");
            -1
        }
    }
}

// --- Liberación de memoria ---------------------------------------------------

/// Libera una cadena devuelta por la librería (stat/readdir).
///
/// # Safety
/// `s` debe provenir de esta librería y no usarse después.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Libera un buffer devuelto por `nfs_rs_read`.
///
/// # Safety
/// `buf`/`len` deben provenir de `nfs_rs_read` y no usarse después.
#[no_mangle]
pub unsafe extern "C" fn nfs_rs_free_bytes(buf: *mut u8, len: usize) {
    if !buf.is_null() && len > 0 {
        drop(Vec::from_raw_parts(buf, len, len));
    }
}

/// Versión de la librería (cadena estática, no liberar).
#[no_mangle]
pub extern "C" fn nfs_rs_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}
