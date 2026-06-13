//! Lista un directorio NFS. Equivalente a `examples/nfs-ls.c` de libnfs.
//!
//! Uso: `nfs-ls nfs://servidor/export [/ruta]`

use nfs_client::{FileType, NfsContext};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .ok_or("uso: nfs-ls nfs://servidor/export [/ruta]")?;
    let path = args.next().unwrap_or_else(|| "/".to_string());

    let mut nfs = NfsContext::mount_url(&url)?;
    println!("# NFSv{} {}", nfs.version(), path);
    for entry in nfs.readdir(&path)? {
        let (kind, size) = match &entry.attr {
            Some(a) => (type_char(a.file_type), a.size),
            None => ('?', 0),
        };
        println!("{kind} {size:>12}  {}", entry.name);
    }
    Ok(())
}

fn type_char(t: FileType) -> char {
    match t {
        FileType::Regular => '-',
        FileType::Directory => 'd',
        FileType::Symlink => 'l',
        FileType::Block => 'b',
        FileType::Char => 'c',
        FileType::Socket => 's',
        FileType::Fifo => 'p',
        FileType::Unknown => '?',
    }
}
