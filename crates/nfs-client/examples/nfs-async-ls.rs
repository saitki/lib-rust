//! Lista un directorio NFS usando la API asíncrona (feature `tokio`).
//!
//! Uso: `cargo run --features tokio --example nfs-async-ls -- nfs://servidor/export [/ruta]`

#[cfg(feature = "tokio")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nfs_client::AsyncNfs;

    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .ok_or("uso: nfs-async-ls nfs://servidor/export [/ruta]")?;
    let path = args.next().unwrap_or_else(|| "/".to_string());

    // El feature `tokio` de nfs-client no activa la macro `#[tokio::main]`, así
    // que construimos un runtime current-thread a mano.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let nfs = AsyncNfs::mount_url(url).await?;
        for entry in nfs.readdir(path).await? {
            println!("{}", entry.name);
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!("Recompila con `--features tokio` para usar este ejemplo.");
}
