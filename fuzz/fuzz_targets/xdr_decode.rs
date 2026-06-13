//! Fuzz del códec XDR: decodificar bytes arbitrarios nunca debe entrar en
//! pánico ni provocar OOM.
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use nfs_xdr::from_bytes;

fuzz_target!(|data: &[u8]| {
    let b = Bytes::copy_from_slice(data);
    let _ = from_bytes::<u64>(b.clone());
    let _ = from_bytes::<bool>(b.clone());
    let _ = from_bytes::<String>(b.clone());
    let _ = from_bytes::<Vec<u32>>(b.clone());
    let _ = from_bytes::<Option<u64>>(b.clone());
    let _ = from_bytes::<Bytes>(b);
});
