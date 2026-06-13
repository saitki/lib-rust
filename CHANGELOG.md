# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/).
Versionado semántico. Fechas en formato ISO.

## [Sin publicar]

Recreación de [libnfs](https://github.com/sahlberg/libnfs) en Rust puro.

### Añadido

- **`nfs-xdr`** — códec XDR (RFC 4506) con derive `#[derive(XdrEncode, XdrDecode)]`
  (structs, `enum32`, uniones, `limit`); decodificación robusta sin pánicos/OOM.
- **`nfs-rpc`** — ONC-RPC (RFC 5531): CALL/REPLY, record marking, AUTH_NONE/AUTH_SYS,
  cliente síncrono (TCP/UDP) y asíncrono (tokio), transporte por stream para TLS.
- **`nfs-proto`** — PORTMAP/rpcbind, MOUNT v3, NFSv3 (22 procedimientos),
  NFSv4.0 y NFSv4.1 (COMPOUND, fattr4, estado, sesiones, locks byte-range), NLM, NSM, RQUOTA.
- **`nfs-client`** — API VFS sync/async (`NfsContext`, `AsyncNfs`), parser de URLs
  `nfs://` (incl. `version=4.1`, `tls`), resolución de rutas con symlinks, chunking de
  read/write, statvfs, locks (`lock`/`unlock`/`test_lock`), idmap NFSv4 (uid/gid).
- **TLS (RFC 9289)** — probe `AUTH_TLS` + STARTTLS sobre `rustls` (feature `tls`),
  con **mTLS** (`TlsParams::with_client_auth`) y validación contra raíces DER.
- **NFSv4** — recuperación automática ante `GRACE`/`DELAY` con backoff.
- Ejemplos `nfs-ls`, `nfs-cp`, `nfs-cat`, `nfs-async-ls`; harness de fuzzing; CI multiplataforma.
- **Release** — workflow que publica binarios (Linux/macOS/Windows) en GitHub Releases.

### Pendiente para 1.0

- Parseo PEM de certificados/clave y exposición de mTLS/raíces vía URL.
- `fcntl` sobre NLM con registro NSM (statd) para recuperación tras reinicio.
- Automount de exports anidados (`autotraverse`) y caché de atributos.
- Servidor NFS de prueba propio para integración en Windows; interoperabilidad
  contra NFS-Ganesha/unfs3; publicación `1.0.0` en crates.io.
