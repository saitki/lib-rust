//! Fuzz del reensamblado de record marking: un flujo arbitrario nunca debe
//! entrar en pánico ni reservar memoria sin acotar.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nfs_rpc::RecordReassembler;

fuzz_target!(|data: &[u8]| {
    let mut reassembler = RecordReassembler::with_max(1 << 20);
    // Alimentar en trozos para ejercitar la fragmentación arbitraria.
    for chunk in data.chunks(7) {
        reassembler.push(chunk);
        loop {
            match reassembler.next_record() {
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
    }
});
