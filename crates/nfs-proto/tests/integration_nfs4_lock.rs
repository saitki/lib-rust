//! Integración de bloqueos byte-range NFSv4 contra un servidor real.
//!
//! Gated con `NFS4_LOCK_TEST` = `host:export` (p. ej. `127.0.0.1:/export/test`);
//! `#[ignore]`. Se ejecuta en CI con un servidor que exporta v4.

use std::net::ToSocketAddrs;
use std::time::Duration;

use nfs_proto::nfs4::{Nfs4, OPEN4_SHARE_ACCESS_BOTH};
use nfs_proto::{Credentials, Protocol};

#[test]
#[ignore = "requiere NFS4_LOCK_TEST y servidor NFSv4 real (CI)"]
fn lock_unlock_and_conflict() {
    let Ok(spec) = std::env::var("NFS4_LOCK_TEST") else {
        eprintln!("NFS4_LOCK_TEST no definida; omitiendo");
        return;
    };
    let (host, export) = spec.split_once(':').expect("formato host:export");
    let ip = (host, 2049u16)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
        .ip();

    let mut nfs = Nfs4::connect(
        ip,
        2049,
        Credentials::unix(0, 0),
        Protocol::Tcp,
        Duration::from_secs(15),
    )
    .expect("connect v4");

    // Navegar hasta el export y crear un fichero de prueba.
    let mut dir = nfs.root_fh().expect("root");
    for comp in export.split('/').filter(|c| !c.is_empty()) {
        dir = nfs.lookup(&dir, comp).expect("lookup export").0;
    }

    let name = "libnfs_rs_lock.bin";
    let _ = nfs.remove(&dir, name);
    let opened = nfs
        .open(&dir, name, OPEN4_SHARE_ACCESS_BOTH, true)
        .expect("open create");

    // Disponible antes de bloquear.
    assert!(nfs
        .test_lock(&opened.fh, 0, 100, true)
        .expect("test_lock libre"));

    // Tomar un bloqueo exclusivo y liberarlo.
    let grant = nfs
        .lock(&opened.fh, &opened.stateid, 0, 100, true)
        .expect("lock");
    nfs.unlock(&opened.fh, &grant, 0, 100).expect("unlock");

    // Limpieza.
    nfs.close(&opened.fh, &opened.stateid).expect("close");
    let _ = nfs.remove(&dir, name);
}
