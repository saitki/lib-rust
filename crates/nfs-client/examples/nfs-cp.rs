//! Copia un fichero desde NFS a disco local. Inspirado en `examples/nfs-cp.c`.
//!
//! Uso: `nfs-cp nfs://servidor/export /ruta/remota /destino/local`

use nfs_client::NfsContext;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .ok_or("uso: nfs-cp nfs://servidor/export /ruta/remota /destino/local")?;
    let remote = args.next().ok_or("falta la ruta remota")?;
    let dest = args.next().ok_or("falta el destino local")?;

    let mut nfs = NfsContext::mount_url(&url)?;
    let data = nfs.read_whole(&remote)?;
    std::fs::write(&dest, &data)?;
    println!("copiados {} bytes a {dest}", data.len());
    Ok(())
}
