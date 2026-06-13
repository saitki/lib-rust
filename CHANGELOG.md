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
  NFSv4.0 (COMPOUND, fattr4, estado), NLM, NSM, RQUOTA.
- **`nfs-client`** — API VFS sync/async (`NfsContext`, `AsyncNfs`), parser de URLs
  `nfs://`, resolución de rutas con symlinks, chunking de read/write, statvfs.
- Ejemplos `nfs-ls` y `nfs-cp`; harness de fuzzing; CI multiplataforma.

### Pendiente para 1.0

- NFSv4.1 (sesiones: `EXCHANGE_ID`/`CREATE_SESSION`/`SEQUENCE`).
- TLS extremo a extremo con RFC 9289 (AUTH_TLS + STARTTLS) cableado en el montaje.
- Servidor NFS de prueba propio para integración en Windows.
- Mapeo idmap (`user@domain` ↔ uid/gid) en NFSv4.
