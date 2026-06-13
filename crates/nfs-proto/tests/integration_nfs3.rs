//! Test de integración de NFSv3 contra un servidor real.
//!
//! Requiere la variable de entorno `NFS_TEST_URL` (p. ej.
//! `nfs://127.0.0.1/export/test`) y está marcado `#[ignore]`: se ejecuta en CI
//! (job `integration-linux`) con `cargo test -- --ignored`, no en el build
//! normal. Recorre los 22 procedimientos NFSv3 sobre un export real.

use std::time::Duration;

use nfs_proto::connect::{mount, MountOptions};
use nfs_proto::nfs3::{
    self, CreateHow3, MknodData3, Nfs3, NfsFh3, Sattr3, ACCESS3_READ, NF3DIR, NF3REG, UNSTABLE,
};
use nfs_proto::Bytes;

/// Divide `nfs://host[:port]/export/path` en (host, "/export/path").
fn parse_url(url: &str) -> (String, String) {
    let rest = url
        .strip_prefix("nfs://")
        .expect("URL debe empezar por nfs://");
    match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    }
}

fn connect() -> Option<(Nfs3, NfsFh3)> {
    let url = std::env::var("NFS_TEST_URL").ok()?;
    let (server, export) = parse_url(&url);
    let opts = MountOptions {
        timeout: Duration::from_secs(15),
        ..Default::default()
    };
    let info = mount(&server, &export, &opts).expect("mount del export de prueba");
    assert!(!info.root_fh.is_empty(), "el fh raíz no puede estar vacío");
    let nfs = Nfs3::connect(
        info.server,
        info.nfs_port,
        opts.cred.clone(),
        opts.protocol,
        opts.timeout,
    )
    .expect("conectar a NFS");
    Some((nfs, NfsFh3::new(info.root_fh)))
}

#[test]
#[ignore = "requiere NFS_TEST_URL y un servidor NFS real (CI)"]
fn full_procedure_sweep() {
    let Some((mut nfs, root)) = connect() else {
        eprintln!("NFS_TEST_URL no definida; omitiendo");
        return;
    };

    // NULL
    nfs.null().expect("NULL");

    // Atributos / info del sistema de ficheros.
    let root_attr = nfs.getattr(&root).expect("GETATTR raíz");
    assert_eq!(root_attr.ftype, NF3DIR);
    let fsinfo = nfs.fsinfo(&root).expect("FSINFO");
    assert!(fsinfo.wtpref > 0);
    nfs.fsstat(&root).expect("FSSTAT");
    nfs.pathconf(&root).expect("PATHCONF");
    let acc = nfs.access(&root, ACCESS3_READ).expect("ACCESS");
    assert!(acc.access & ACCESS3_READ != 0);

    let dirname = "libnfs_rs_it";
    // Limpieza de una ejecución previa (ignorar errores).
    let _ = cleanup(&mut nfs, &root, dirname);

    // MKDIR
    let dir = nfs
        .mkdir(&root, dirname, Sattr3::unchanged())
        .expect("MKDIR")
        .obj
        .expect("MKDIR debe devolver fh");

    // CREATE + WRITE + READ + COMMIT
    let file = nfs
        .create(&dir, "data.bin", CreateHow3::Unchecked(Sattr3::unchanged()))
        .expect("CREATE")
        .obj
        .expect("CREATE debe devolver fh");
    let payload = Bytes::from(vec![0xABu8; 64 * 1024]);
    let w = nfs
        .write(&file, 0, UNSTABLE, payload.clone())
        .expect("WRITE");
    assert_eq!(w.count as usize, payload.len());
    nfs.commit(&file, 0, 0).expect("COMMIT");
    let r = nfs.read(&file, 0, payload.len() as u32).expect("READ");
    assert_eq!(r.data, payload, "los datos leídos deben coincidir");

    // SETATTR (chmod 600)
    nfs.setattr(
        &file,
        Sattr3 {
            mode: Some(0o600),
            ..Sattr3::unchanged()
        },
        None,
    )
    .expect("SETATTR");
    let attr = nfs.getattr(&file).expect("GETATTR fichero");
    assert_eq!(attr.ftype, NF3REG);
    assert_eq!(attr.mode & 0o777, 0o600);

    // LOOKUP
    let looked = nfs.lookup(&dir, "data.bin").expect("LOOKUP");
    assert_eq!(looked.object.data, file.data);

    // SYMLINK + READLINK
    nfs.symlink(&dir, "link", "data.bin", Sattr3::unchanged())
        .expect("SYMLINK");
    let link_fh = nfs.lookup(&dir, "link").expect("LOOKUP link").object;
    let target = nfs.readlink(&link_fh).expect("READLINK");
    assert_eq!(target.data, "data.bin");

    // LINK (enlace duro)
    nfs.link(&file, &dir, "hardlink").expect("LINK");

    // MKNOD (FIFO)
    nfs.mknod(&dir, "fifo", MknodData3::Fifo(Sattr3::unchanged()))
        .expect("MKNOD fifo");

    // READDIR / READDIRPLUS
    let listing = nfs.readdir(&dir, 0, [0; 8], 8192).expect("READDIR");
    let names: Vec<_> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"data.bin"));
    let listing_plus = nfs
        .readdirplus(&dir, 0, [0; 8], 8192, 32768)
        .expect("READDIRPLUS");
    assert!(listing_plus.entries.iter().any(|e| e.name == "data.bin"));

    // RENAME
    nfs.rename(&dir, "data.bin", &dir, "renamed.bin")
        .expect("RENAME");
    assert!(nfs.lookup(&dir, "renamed.bin").is_ok());

    // REMOVE (todos los ficheros) + RMDIR
    cleanup(&mut nfs, &root, dirname).expect("limpieza final");
}

/// Borra el árbol de prueba `dirname` bajo `root`.
fn cleanup(nfs: &mut Nfs3, root: &NfsFh3, dirname: &str) -> Result<(), nfs_proto::ProtoError> {
    let dir = match nfs.lookup(root, dirname) {
        Ok(l) => l.object,
        Err(nfs_proto::ProtoError::Nfs3(nfs3::NFS3ERR_NOENT)) => return Ok(()),
        Err(e) => return Err(e),
    };
    let entries = nfs.readdir(&dir, 0, [0; 8], 16384)?.entries;
    for entry in entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let _ = nfs.remove(&dir, &entry.name);
    }
    nfs.rmdir(root, dirname)?;
    Ok(())
}
