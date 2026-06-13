//! Garantías de concurrencia y thread-safety.
//!
//! Las aserciones `Send`/`Sync` son en tiempo de compilación: si dejaran de
//! cumplirse, este archivo no compilaría. El estrés real multihilo contra un
//! servidor está gated con `NFS_TEST_URL`.

use nfs_client::NfsContext;

fn assert_send<T: Send>() {}

#[test]
fn context_is_send() {
    // `NfsContext` debe ser `Send` para poder compartirse tras un `Mutex`
    // entre hilos (modelo de `README.multithreading` de libnfs).
    assert_send::<NfsContext>();
}

#[cfg(feature = "tokio")]
#[test]
fn async_handle_is_send_sync_clone() {
    fn assert_send_sync<T: Send + Sync + Clone>() {}
    assert_send_sync::<nfs_client::AsyncNfs>();
}

#[test]
#[ignore = "requiere NFS_TEST_URL y servidor NFS real (CI)"]
fn multithread_stress() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let Ok(url) = std::env::var("NFS_TEST_URL") else {
        eprintln!("NFS_TEST_URL no definida; omitiendo");
        return;
    };
    let mut ctx = NfsContext::mount_url(&url).expect("mount");
    let base = "/libnfs_rs_mt";
    let _ = ctx.mkdir(base);
    let shared = Arc::new(Mutex::new(ctx));

    let mut handles = Vec::new();
    for t in 0..8 {
        let shared = Arc::clone(&shared);
        let base = base.to_string();
        handles.push(thread::spawn(move || {
            let path = format!("{base}/file_{t}.bin");
            let payload = vec![t as u8; 64 * 1024];
            {
                let mut c = shared.lock().unwrap();
                c.write_whole(&path, &payload).expect("write");
            }
            let read = {
                let mut c = shared.lock().unwrap();
                c.read_whole(&path).expect("read")
            };
            assert_eq!(read.len(), payload.len());
            assert!(read.iter().all(|&b| b == t as u8));
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // Limpieza.
    let mut c = shared.lock().unwrap();
    for t in 0..8 {
        let _ = c.unlink(&format!("{base}/file_{t}.bin"));
    }
    let _ = c.rmdir(base);
}
