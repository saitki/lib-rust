//! Cliente RPC síncrono sobre `std::net` (TCP y UDP).
//!
//! Empareja respuestas por XID, aplica record marking en TCP, reintenta con
//! reconexión ante caídas y aplica un timeout por llamada. Es la base sobre la
//! que se montan PORTMAP, MOUNT y NFS (`nfs-proto`).

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use nfs_xdr::{Bytes, BytesMut, XdrDecode, XdrEncode};

use crate::auth::Credentials;
use crate::error::RpcError;
use crate::message::{encode_call, parse_reply, NULL_PROC};
use crate::record::{frame, RecordReassembler};

/// Protocolo de transporte para la conexión RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP con record marking.
    Tcp,
    /// UDP (un datagrama por mensaje).
    Udp,
}

/// Timeout por defecto de una llamada RPC.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// Número total de intentos por llamada (1 inicial + reintentos).
const MAX_ATTEMPTS: u32 = 3;

/// Un transporte de flujo bidireccional (TCP, TLS, …) sobre el que correr RPC
/// con record marking. Permite usar TLS pasando un stream de `rustls` o
/// `native-tls` sin que el núcleo dependa de una librería TLS concreta.
pub trait ReadWriteStream: Read + Write + Send {
    /// Fija el timeout de lectura, si el transporte lo soporta.
    fn set_read_timeout(&mut self, _dur: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

impl ReadWriteStream for TcpStream {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }
}

enum Socket {
    Tcp(TcpStream),
    Udp(UdpSocket),
    Stream(Box<dyn ReadWriteStream>),
}

/// Cliente ONC-RPC síncrono.
pub struct RpcClient {
    addr: SocketAddr,
    protocol: Protocol,
    cred: Credentials,
    timeout: Duration,
    socket: Socket,
    reassembler: RecordReassembler,
    pending: VecDeque<Bytes>,
    next_xid: u32,
    auto_reconnect: bool,
}

impl RpcClient {
    /// Conecta a `addr` por el protocolo indicado con las credenciales dadas.
    pub fn connect(
        addr: SocketAddr,
        protocol: Protocol,
        cred: Credentials,
        timeout: Duration,
    ) -> Result<Self, RpcError> {
        let socket = open_socket(addr, protocol, timeout)?;
        Ok(Self {
            addr,
            protocol,
            cred,
            timeout,
            socket,
            reassembler: RecordReassembler::new(),
            pending: VecDeque::new(),
            next_xid: seed_xid(),
            auto_reconnect: true,
        })
    }

    /// Construye un cliente sobre un transporte de flujo ya establecido (p. ej.
    /// una conexión TLS). El record marking se aplica igual que en TCP. La
    /// reconexión automática queda desactivada (el stream no se puede recrear).
    pub fn from_stream(
        stream: Box<dyn ReadWriteStream>,
        cred: Credentials,
        timeout: Duration,
    ) -> Self {
        Self {
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            protocol: Protocol::Tcp,
            cred,
            timeout,
            socket: Socket::Stream(stream),
            reassembler: RecordReassembler::new(),
            pending: VecDeque::new(),
            next_xid: seed_xid(),
            auto_reconnect: false,
        }
    }

    /// Activa o desactiva la reconexión automática ante caídas de TCP.
    pub fn set_auto_reconnect(&mut self, enabled: bool) {
        self.auto_reconnect = enabled;
    }

    /// Cambia las credenciales usadas en las siguientes llamadas.
    pub fn set_credentials(&mut self, cred: Credentials) {
        self.cred = cred;
    }

    /// Dirección remota a la que está conectado el cliente.
    pub fn peer_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Invoca el procedimiento `NULL` (proc 0) del programa: un *ping* RPC.
    pub fn null(&mut self, prog: u32, vers: u32) -> Result<(), RpcError> {
        self.call(prog, vers, NULL_PROC, &())
    }

    /// Invoca un procedimiento RPC y decodifica su resultado.
    ///
    /// Empareja por XID (ignora respuestas con XID que no coincide), aplica el
    /// timeout configurado y reintenta con reconexión si la conexión cae.
    pub fn call<R: XdrDecode>(
        &mut self,
        prog: u32,
        vers: u32,
        proc_: u32,
        args: &dyn XdrEncode,
    ) -> Result<R, RpcError> {
        let (xid, message) = self.build_call(prog, vers, proc_, args)?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.attempt_call::<R>(xid, &message) {
                Ok(value) => return Ok(value),
                Err(err) if attempt < MAX_ATTEMPTS && self.is_retryable(&err) => {
                    // UDP: retransmitir; TCP: reconectar y reenviar.
                    if matches!(self.protocol, Protocol::Tcp) {
                        self.reconnect()?;
                    }
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn is_retryable(&self, err: &RpcError) -> bool {
        match err {
            RpcError::Timeout if matches!(self.protocol, Protocol::Udp) => true,
            RpcError::Io(_) | RpcError::ConnectionClosed => self.auto_reconnect,
            _ => false,
        }
    }

    fn build_call(
        &mut self,
        prog: u32,
        vers: u32,
        proc_: u32,
        args: &dyn XdrEncode,
    ) -> Result<(u32, Bytes), RpcError> {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        let mut message = BytesMut::new();
        encode_call(&mut message, xid, prog, vers, proc_, &self.cred)?;
        args.encode(&mut message)?;
        Ok((xid, message.freeze()))
    }

    fn attempt_call<R: XdrDecode>(&mut self, xid: u32, message: &Bytes) -> Result<R, RpcError> {
        self.send(message)?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let reply = self.recv_message(deadline)?;
            let (reply_xid, result) = parse_reply(reply)?;
            if reply_xid != xid {
                continue; // respuesta vieja o duplicada: descartar
            }
            let mut body = result?;
            return Ok(R::decode(&mut body)?);
        }
    }

    fn send(&mut self, message: &Bytes) -> Result<(), RpcError> {
        match &mut self.socket {
            Socket::Tcp(stream) => {
                let framed = frame(message)?;
                stream.write_all(&framed)?;
                stream.flush()?;
            }
            Socket::Udp(socket) => {
                socket.send(message)?;
            }
            Socket::Stream(stream) => {
                let framed = frame(message)?;
                stream.write_all(&framed)?;
                stream.flush()?;
            }
        }
        Ok(())
    }

    fn recv_message(&mut self, deadline: Instant) -> Result<Bytes, RpcError> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(message);
        }
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(RpcError::Timeout);
            }
            let remaining = deadline - now;
            match &mut self.socket {
                Socket::Tcp(stream) => {
                    stream.set_read_timeout(Some(remaining)).ok();
                    let mut buf = [0u8; 16384];
                    match stream.read(&mut buf) {
                        Ok(0) => return Err(RpcError::ConnectionClosed),
                        Ok(n) => {
                            self.reassembler.push(&buf[..n]);
                            while let Some(record) = self.reassembler.next_record()? {
                                self.pending.push_back(record);
                            }
                            if let Some(message) = self.pending.pop_front() {
                                return Ok(message);
                            }
                        }
                        Err(e) if is_timeout(&e) => return Err(RpcError::Timeout),
                        Err(e) if e.kind() == ErrorKind::Interrupted => {}
                        Err(e) => return Err(RpcError::Io(e)),
                    }
                }
                Socket::Udp(socket) => {
                    socket.set_read_timeout(Some(remaining)).ok();
                    let mut buf = [0u8; 65536];
                    match socket.recv(&mut buf) {
                        Ok(n) => return Ok(Bytes::copy_from_slice(&buf[..n])),
                        Err(e) if is_timeout(&e) => return Err(RpcError::Timeout),
                        Err(e) if e.kind() == ErrorKind::Interrupted => {}
                        Err(e) => return Err(RpcError::Io(e)),
                    }
                }
                Socket::Stream(stream) => {
                    stream.set_read_timeout(Some(remaining)).ok();
                    let mut buf = [0u8; 16384];
                    match stream.read(&mut buf) {
                        Ok(0) => return Err(RpcError::ConnectionClosed),
                        Ok(n) => {
                            self.reassembler.push(&buf[..n]);
                            while let Some(record) = self.reassembler.next_record()? {
                                self.pending.push_back(record);
                            }
                            if let Some(message) = self.pending.pop_front() {
                                return Ok(message);
                            }
                        }
                        Err(e) if is_timeout(&e) => return Err(RpcError::Timeout),
                        Err(e) if e.kind() == ErrorKind::Interrupted => {}
                        Err(e) => return Err(RpcError::Io(e)),
                    }
                }
            }
        }
    }

    fn reconnect(&mut self) -> Result<(), RpcError> {
        self.socket = open_socket(self.addr, self.protocol, self.timeout)?;
        self.reassembler = RecordReassembler::new();
        self.pending.clear();
        Ok(())
    }
}

fn open_socket(
    addr: SocketAddr,
    protocol: Protocol,
    timeout: Duration,
) -> Result<Socket, RpcError> {
    match protocol {
        Protocol::Tcp => {
            let stream = TcpStream::connect_timeout(&addr, timeout)?;
            stream.set_nodelay(true).ok();
            Ok(Socket::Tcp(stream))
        }
        Protocol::Udp => {
            let bind: SocketAddr = if addr.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let socket = UdpSocket::bind(bind)?;
            socket.connect(addr)?;
            Ok(Socket::Udp(socket))
        }
    }
}

fn is_timeout(err: &std::io::Error) -> bool {
    // En Unix el timeout de lectura es WouldBlock; en Windows, TimedOut.
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn seed_xid() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos ^ std::process::id()
}
