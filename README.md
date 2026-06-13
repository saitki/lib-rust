# libnfs-rs

Recreación en **Rust puro** de [libnfs](https://github.com/sahlberg/libnfs), el
cliente NFS en espacio de usuario. Objetivo: 100% funcional y multiplataforma
(**Windows, macOS y Linux**), con API síncrona y asíncrona.

> Estado del proyecto y plan completo: [`docs/ESTADO-FASES.md`](docs/ESTADO-FASES.md).
> Decisiones de arquitectura: [`docs/DECISIONES.md`](docs/DECISIONES.md).

## Workspace

| Crate | Rol | Equivalente en libnfs (C) |
|---|---|---|
| [`nfs-xdr`](crates/nfs-xdr) | Códec XDR (RFC 4506) + derive | `rpcgen`, `lib/libnfs-zdr.c` |
| [`nfs-xdr-derive`](crates/nfs-xdr-derive) | Macros `#[derive(XdrEncode, XdrDecode)]` | salida de `rpcgen` |
| [`nfs-rpc`](crates/nfs-rpc) | Motor ONC-RPC (RFC 5531) sans-IO | `lib/pdu.c`, `lib/socket.c` |
| [`nfs-proto`](crates/nfs-proto) | PORTMAP, MOUNT, NFSv3/4, NLM, NSM, RQUOTA | `portmap/`, `mount/`, `nfs/`, … |
| [`nfs-client`](crates/nfs-client) | API VFS sync/async, URLs, automount | `lib/libnfs.c`, `lib/libnfs-sync.c` |

## Inicio rápido

Síncrono:

```rust
use nfs_client::{NfsContext, OpenFlags};

let mut nfs = NfsContext::mount_url("nfs://servidor/export?uid=1000&gid=1000")?;
let datos = nfs.read_whole("/dir/fichero.txt")?;
nfs.write_whole("/dir/copia.txt", &datos)?;
for e in nfs.readdir("/dir")? {
    println!("{}", e.name);
}
# Ok::<(), nfs_client::NfsError>(())
```

Asíncrono (feature `tokio`), clonable entre tareas:

```rust,ignore
let nfs = nfs_client::AsyncNfs::mount_url("nfs://servidor/export").await?;
let datos = nfs.read_whole("/dir/fichero.txt").await?;
```

NFSv4: añade `?version=4` a la URL. Migración desde libnfs (C):
[`docs/MIGRACION.md`](docs/MIGRACION.md). Interoperabilidad y portabilidad:
[`docs/INTEROP.md`](docs/INTEROP.md).

## Descargas

Los binarios de los ejemplos CLI (`nfs-ls`, `nfs-cp`, `nfs-cat`, `nfs-async-ls`)
se publican en cada *release* para **Linux**, **macOS** (x86_64 y arm64) y
**Windows**, compilados con todas las features (incluido TLS). Descárgalos desde
la pestaña **Releases** del repositorio (o como artefactos del workflow
[`release.yml`](.github/workflows/release.yml), que también se puede lanzar a mano
con *workflow_dispatch*).

```sh
# Ejemplo de uso de un binario descargado:
./nfs-ls nfs://servidor/export /ruta
./nfs-cat nfs://servidor/export /ruta/fichero.txt
```

## Desarrollo

```sh
cargo build --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
cargo fmt --all -- --check
cargo test --workspace            # tests unitarios
cargo test --workspace -- --ignored   # integración: requiere NFS_TEST_URL
```

> **Entorno local Windows:** `cargo test` no arranca en la máquina de
> desarrollo; en local se valida con `cargo build` + `cargo clippy` y la
> ejecución de tests se delega a CI (ver [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Licencia

`MIT OR Apache-2.0`. Es código nuevo: el código C de libnfs se usa solo como
referencia de comportamiento, no se traduce línea a línea (ver
[`docs/DECISIONES.md`](docs/DECISIONES.md) §licencia).
