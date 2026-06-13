//! Fuzz de los decodificadores de protocolo (NFSv3, MOUNT): respuestas
//! arbitrarias del servidor nunca deben hacer entrar en pánico al cliente.
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use nfs_xdr::from_bytes;

fuzz_target!(|data: &[u8]| {
    let b = Bytes::copy_from_slice(data);
    use nfs_proto::mount::Mountres3;
    use nfs_proto::nfs3::{Fattr3, Nfs3Result, ReaddirOk};
    use nfs_proto::portmap::PortmapList;

    let _ = from_bytes::<Fattr3>(b.clone());
    let _ = from_bytes::<Nfs3Result<Fattr3>>(b.clone());
    let _ = from_bytes::<ReaddirOk>(b.clone());
    let _ = from_bytes::<Mountres3>(b.clone());
    let _ = from_bytes::<PortmapList>(b);
});
