//! Test de integración de la API VFS contra un servidor NFS real.
//!
//! Gated con `NFS_TEST_URL` (v3) y `NFS4_TEST_URL` (v4); `#[ignore]`. Se ejecuta
//! en CI con `cargo test -- --ignored`.

use nfs_client::{NfsContext, OpenFlags};

fn run_sweep(url: &str) {
    let mut nfs = NfsContext::mount_url(url).expect("mount");
    let base = "/libnfs_rs_vfs";

    // Limpieza previa.
    let _ = cleanup(&mut nfs, base);

    nfs.mkdir(base).expect("mkdir");
    let attr = nfs.stat(base).expect("stat dir");
    assert!(attr.is_dir());

    // Escribir y releer (troceado por el tamaño preferido).
    let payload = vec![0x5Au8; 300 * 1024];
    let file = format!("{base}/data.bin");
    nfs.write_whole(&file, &payload).expect("write_whole");
    let read = nfs.read_whole(&file).expect("read_whole");
    assert_eq!(read.len(), payload.len());
    assert_eq!(&read[..], &payload[..]);

    // pread parcial.
    let f = nfs.open(&file, OpenFlags::read_only()).expect("open");
    let chunk = nfs.pread(&f, 1024, 256).expect("pread");
    assert_eq!(chunk.len(), 256);
    nfs.close(f).expect("close");

    // readdir contiene el fichero.
    let entries = nfs.readdir(base).expect("readdir");
    assert!(entries.iter().any(|e| e.name == "data.bin"));

    // chmod + stat.
    nfs.chmod(&file, 0o600).expect("chmod");
    assert_eq!(nfs.stat(&file).expect("stat").mode & 0o777, 0o600);

    // rename + unlink.
    let renamed = format!("{base}/data2.bin");
    nfs.rename(&file, &renamed).expect("rename");
    nfs.unlink(&renamed).expect("unlink");

    // statvfs.
    let vfs = nfs.statvfs(base).expect("statvfs");
    assert!(vfs.total_blocks > 0);

    cleanup(&mut nfs, base).expect("cleanup final");
}

fn cleanup(nfs: &mut NfsContext, base: &str) -> Result<(), nfs_client::NfsError> {
    if let Ok(entries) = nfs.readdir(base) {
        for e in entries {
            if e.name == "." || e.name == ".." {
                continue;
            }
            let _ = nfs.unlink(&format!("{base}/{}", e.name));
        }
        nfs.rmdir(base)?;
    }
    Ok(())
}

#[test]
#[ignore = "requiere NFS_TEST_URL y servidor NFSv3 real (CI)"]
fn vfs_sweep_v3() {
    let Ok(url) = std::env::var("NFS_TEST_URL") else {
        eprintln!("NFS_TEST_URL no definida; omitiendo");
        return;
    };
    run_sweep(&url);
}

#[test]
#[ignore = "requiere NFS4_TEST_URL y servidor NFSv4 real (CI)"]
fn vfs_sweep_v4() {
    let Ok(url) = std::env::var("NFS4_TEST_URL") else {
        eprintln!("NFS4_TEST_URL no definida; omitiendo");
        return;
    };
    run_sweep(&url);
}
