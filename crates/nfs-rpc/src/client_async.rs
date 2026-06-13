//! Cliente RPC asíncrono sobre `tokio` (TCP y UDP). Disponible con la *feature*
//! `tokio`. Comparte códec, autenticación y record marking con el cliente
//! síncrono.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use nfs_xdr::{Bytes, BytesMut, XdrDecode, XdrEncode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::auth::Credentials;
use crate::client::Protocol;
use crate::error::RpcError;
use crate::message::{encode_call, parse_reply, NULL_PROC};
use crate::record::{frame, RecordReassembler};

/// Número total de intentos por llamada (1 inicial + reintentos).
const MAX_ATTEMPTS: u32 = 3;

enum Socket {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

/// Cliente ONC-RPC asíncrono basado en tokio.
pub struct AsyncRpcClient {
    addr: SocketAddr,
    protocol: Protocol,
    cred: Credentials,
    timeout: Duration,
    socket: Socket,
    reassembler: RecordReassembler,
    pending: VecDeque<Bytes>,
    next_xid: u32,
}

impl AsyncRpcClient {
    /// Conecta a `addr` por el protocolo indicado.
    pub async fn connect(
        addr: SocketAddr,
        protocol: Protocol,
        cred: Credentials,
        call_timeout: Duration,
    ) -> Result<Self, RpcError> {
        let socket = open_socket(addr, protocol).await?;
        Ok(Self {
            addr,
            protocol,
            cred,
            timeout: call_timeout,
            socket,
            reassembler: RecordReassembler::new(),
            pending: VecDeque::new(),
            next_xid: seed_xid(),
        })
    }

    /// Cambia las credenciales usadas en las siguientes llamadas.
    pub fn set_credentials(&mut self, cred: Credentials) {
        self.cred = cred;
    }

    /// Invoca el procedimiento `NULL` (proc 0): un *ping* RPC.
    pub async fn null(&mut self, prog: u32, vers: u32) -> Result<(), RpcError> {
        self.call(prog, vers, NULL_PROC, &()).await
    }

    /// Invoca un procedimiento RPC y decodifica su resultado.
    pub async fn call<R: XdrDecode>(
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
            let result = match timeout(self.timeout, self.exchange::<R>(xid, &message)).await {
                Ok(result) => result,
                Err(_elapsed) => Err(RpcError::Timeout),
            };
            match result {
                Ok(value) => return Ok(value),
                Err(err) if attempt < MAX_ATTEMPTS && self.is_retryable(&err) => {
                    if matches!(self.protocol, Protocol::Tcp) {
                        self.reconnect().await?;
                    }
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn is_retryable(&self, err: &RpcError) -> bool {
        matches!(
            err,
            RpcError::Io(_) | RpcError::ConnectionClosed | RpcError::Timeout
        )
    }

    async fn reconnect(&mut self) -> Result<(), RpcError> {
        self.socket = open_socket(self.addr, self.protocol).await?;
        self.reassembler = RecordReassembler::new();
        self.pending.clear();
        Ok(())
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

    async fn exchange<R: XdrDecode>(&mut self, xid: u32, message: &Bytes) -> Result<R, RpcError> {
        self.send(message).await?;
        loop {
            let reply = self.recv_message().await?;
            let (reply_xid, result) = parse_reply(reply)?;
            if reply_xid != xid {
                continue;
            }
            let mut body = result?;
            return Ok(R::decode(&mut body)?);
        }
    }

    async fn send(&mut self, message: &Bytes) -> Result<(), RpcError> {
        match &mut self.socket {
            Socket::Tcp(stream) => {
                let framed = frame(message)?;
                stream.write_all(&framed).await?;
                stream.flush().await?;
            }
            Socket::Udp(socket) => {
                socket.send(message).await?;
            }
        }
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<Bytes, RpcError> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(message);
        }
        loop {
            match &mut self.socket {
                Socket::Tcp(stream) => {
                    let mut buf = [0u8; 16384];
                    let n = stream.read(&mut buf).await?;
                    if n == 0 {
                        return Err(RpcError::ConnectionClosed);
                    }
                    self.reassembler.push(&buf[..n]);
                    while let Some(record) = self.reassembler.next_record()? {
                        self.pending.push_back(record);
                    }
                    if let Some(message) = self.pending.pop_front() {
                        return Ok(message);
                    }
                }
                Socket::Udp(socket) => {
                    let mut buf = [0u8; 65536];
                    let n = socket.recv(&mut buf).await?;
                    return Ok(Bytes::copy_from_slice(&buf[..n]));
                }
            }
        }
    }
}

async fn open_socket(addr: SocketAddr, protocol: Protocol) -> Result<Socket, RpcError> {
    match protocol {
        Protocol::Tcp => {
            let stream = TcpStream::connect(addr).await?;
            stream.set_nodelay(true).ok();
            Ok(Socket::Tcp(stream))
        }
        Protocol::Udp => {
            let bind = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(addr).await?;
            Ok(Socket::Udp(socket))
        }
    }
}

fn seed_xid() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos ^ std::process::id()
}
