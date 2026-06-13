//! Test de extremo a extremo del cliente RPC síncrono contra un servidor RPC
//! de juguete (en el propio test) sobre TCP y UDP en loopback.
//!
//! El servidor responde a dos procedimientos del programo ficticio 0x20000001
//! versión 1:
//!   - proc 0 (NULL): respuesta vacía.
//!   - proc 1 (ECHO): devuelve el `u32` recibido.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use nfs_rpc::{Credentials, Protocol, RpcClient};

const PROG: u32 = 0x2000_0001;
const VERS: u32 = 1;

/// Lee el args (un `u32`) de la cola del mensaje CALL y construye un REPLY
/// MSG_ACCEPTED/SUCCESS. `call` es el mensaje RPC completo (sin record marking).
fn build_reply(call: &[u8]) -> Vec<u8> {
    // Cabecera CALL: xid(4) CALL(4) rpcvers(4) prog(4) vers(4) proc(4)
    // cred(flavor4+len4+body) verf(flavor4+len4+body) [args...]
    let be = |o: usize| u32::from_be_bytes([call[o], call[o + 1], call[o + 2], call[o + 3]]);
    let xid = be(0);
    let proc_ = be(20);
    let mut off = 24;
    // cred
    off += 4; // flavor
    let cred_len = be(off) as usize;
    off += 4 + cred_len + ((4 - cred_len % 4) % 4);
    // verf
    off += 4; // flavor
    let verf_len = be(off) as usize;
    off += 4 + verf_len + ((4 - verf_len % 4) % 4);

    let mut reply = Vec::new();
    reply.extend_from_slice(&xid.to_be_bytes());
    reply.extend_from_slice(&1u32.to_be_bytes()); // REPLY
    reply.extend_from_slice(&0u32.to_be_bytes()); // MSG_ACCEPTED
    reply.extend_from_slice(&0u32.to_be_bytes()); // verf flavor AUTH_NONE
    reply.extend_from_slice(&0u32.to_be_bytes()); // verf body len 0
    reply.extend_from_slice(&0u32.to_be_bytes()); // accept_stat SUCCESS
    if proc_ == 1 {
        // ECHO: devolver el u32 de args.
        let arg = be(off);
        reply.extend_from_slice(&arg.to_be_bytes());
    }
    reply
}

#[test]
fn tcp_call_reply_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // Atender dos llamadas (NULL y ECHO).
        for _ in 0..2 {
            // Leer cabecera de record marking (4 bytes) + el registro.
            let mut hdr = [0u8; 4];
            stream.read_exact(&mut hdr).unwrap();
            let len = (u32::from_be_bytes(hdr) & 0x7FFF_FFFF) as usize;
            let mut call = vec![0u8; len];
            stream.read_exact(&mut call).unwrap();

            let reply = build_reply(&call);
            let mut framed = Vec::new();
            framed.extend_from_slice(&((0x8000_0000u32) | reply.len() as u32).to_be_bytes());
            framed.extend_from_slice(&reply);
            stream.write_all(&framed).unwrap();
        }
    });

    let mut client = RpcClient::connect(
        addr,
        Protocol::Tcp,
        Credentials::unix(1000, 1000),
        Duration::from_secs(5),
    )
    .unwrap();

    client.null(PROG, VERS).expect("NULL debe responder");
    let echoed: u32 = client.call(PROG, VERS, 1, &0xABCD_1234u32).expect("ECHO");
    assert_eq!(echoed, 0xABCD_1234);

    server.join().unwrap();
}

#[test]
fn stream_transport_roundtrip() {
    // Valida la ruta de transporte genérica (Socket::Stream) que habilita TLS:
    // aquí el "stream" es un TcpStream plano; con TLS solo cambia el tipo.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        for _ in 0..2 {
            let mut hdr = [0u8; 4];
            stream.read_exact(&mut hdr).unwrap();
            let len = (u32::from_be_bytes(hdr) & 0x7FFF_FFFF) as usize;
            let mut call = vec![0u8; len];
            stream.read_exact(&mut call).unwrap();
            let reply = build_reply(&call);
            let mut framed = Vec::new();
            framed.extend_from_slice(&((0x8000_0000u32) | reply.len() as u32).to_be_bytes());
            framed.extend_from_slice(&reply);
            stream.write_all(&framed).unwrap();
        }
    });

    let tcp = TcpStream::connect(addr).unwrap();
    let mut client = RpcClient::from_stream(
        Box::new(tcp),
        Credentials::unix(0, 0),
        Duration::from_secs(5),
    );
    client.null(PROG, VERS).expect("NULL vía stream");
    let echoed: u32 = client.call(PROG, VERS, 1, &7u32).expect("ECHO vía stream");
    assert_eq!(echoed, 7);

    server.join().unwrap();
}

#[test]
fn udp_call_reply_roundtrip() {
    let server_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = server_sock.local_addr().unwrap();

    let server = thread::spawn(move || {
        let mut buf = [0u8; 65536];
        for _ in 0..2 {
            let (n, peer) = server_sock.recv_from(&mut buf).unwrap();
            let reply = build_reply(&buf[..n]);
            server_sock.send_to(&reply, peer).unwrap();
        }
    });

    let mut client = RpcClient::connect(
        addr,
        Protocol::Udp,
        Credentials::None,
        Duration::from_secs(5),
    )
    .unwrap();

    client.null(PROG, VERS).expect("NULL UDP");
    let echoed: u32 = client.call(PROG, VERS, 1, &42u32).expect("ECHO UDP");
    assert_eq!(echoed, 42);

    server.join().unwrap();
}
