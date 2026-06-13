//! Vuelca el contenido de un fichero NFS a la salida estándar.
//!
//! Uso: `nfs-cat nfs://servidor/export /ruta/remota`

use std::io::Write;

use nfs_client::NfsContext;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .ok_or("uso: nfs-cat nfs://servidor/export /ruta/remota")?;
    let remote = args.next().ok_or("falta la ruta remota")?;

    let mut nfs = NfsContext::mount_url(&url)?;
    let data = nfs.read_whole(&remote)?;
    std::io::stdout().write_all(&data)?;
    Ok(())
}
