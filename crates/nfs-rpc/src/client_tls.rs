//! Transporte TLS para ONC-RPC (RFC 9289): probe `AUTH_TLS` + STARTTLS sobre
//! `rustls`. Disponible con la *feature* `tls`.
//!
//! Flujo: se abre TCP, se envía un `NULL` con credencial `AUTH_TLS` (probe); si
//! el servidor responde con verificador `AUTH_TLS` (soporta RPC-with-TLS), se
//! hace el handshake TLS sobre la misma conexión y el resto del RPC viaja
//! cifrado (vía [`RpcClient::from_stream`]).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use nfs_xdr::{decode_opaque, Bytes, BytesMut, XdrDecode, XdrEncode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::auth::Credentials;
use crate::client::{ReadWriteStream, RpcClient};
use crate::error::RpcError;
use crate::record::frame;

/// `flavor` de autenticación `AUTH_TLS` (RFC 9289).
pub const AUTH_TLS: u32 = 7;

/// Configuración del transporte TLS.
pub struct TlsParams {
    /// Nombre del servidor para SNI y validación de certificado.
    pub server_name: String,
    /// Si `true`, acepta cualquier certificado (solo para pruebas / self-signed).
    pub danger_accept_invalid: bool,
    /// Certificados raíz de confianza en formato DER (si no se usa el modo
    /// inseguro).
    pub root_certs_der: Vec<Vec<u8>>,
    /// Cadena de certificados del cliente en DER (mTLS). Vacío = sin mTLS.
    pub client_cert_der: Vec<Vec<u8>>,
    /// Clave privada del cliente en DER (mTLS). Requerida si hay `client_cert_der`.
    pub client_key_der: Option<Vec<u8>>,
}

impl TlsParams {
    /// Parámetros que aceptan cualquier certificado (útil para CI/self-signed).
    pub fn insecure(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            danger_accept_invalid: true,
            root_certs_der: Vec::new(),
            client_cert_der: Vec::new(),
            client_key_der: None,
        }
    }

    /// Parámetros que validan contra `roots` (DER), sin mTLS.
    pub fn with_roots(server_name: impl Into<String>, roots: Vec<Vec<u8>>) -> Self {
        Self {
            server_name: server_name.into(),
            danger_accept_invalid: false,
            root_certs_der: roots,
            client_cert_der: Vec::new(),
            client_key_der: None,
        }
    }

    /// Añade un certificado de cliente para mTLS (cadena + clave, en DER).
    pub fn with_client_auth(mut self, cert_chain: Vec<Vec<u8>>, key: Vec<u8>) -> Self {
        self.client_cert_der = cert_chain;
        self.client_key_der = Some(key);
        self
    }
}

impl ReadWriteStream for StreamOwned<ClientConnection, TcpStream> {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        self.sock.set_read_timeout(dur)
    }
}

impl RpcClient {
    /// Conecta por TLS (RFC 9289) al servicio `(prog, vers)` en `addr`.
    pub fn connect_tls(
        addr: SocketAddr,
        prog: u32,
        vers: u32,
        cred: Credentials,
        timeout: Duration,
        params: &TlsParams,
    ) -> Result<Self, RpcError> {
        let mut tcp = TcpStream::connect_timeout(&addr, timeout)?;
        tcp.set_nodelay(true).ok();

        // 1. Probe AUTH_TLS sobre texto plano.
        starttls_probe(&mut tcp, prog, vers, timeout)?;

        // 2. Handshake TLS sobre la misma conexión.
        let config = build_config(params)?;
        let server_name = ServerName::try_from(params.server_name.clone())
            .map_err(|_| tls_err("nombre de servidor TLS inválido"))?;
        let conn = ClientConnection::new(Arc::new(config), server_name).map_err(tls_err)?;
        let stream = StreamOwned::new(conn, tcp);

        // 3. El resto del RPC viaja por el stream TLS.
        Ok(RpcClient::from_stream(Box::new(stream), cred, timeout))
    }
}

fn build_config(params: &TlsParams) -> Result<ClientConfig, RpcError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(tls_err)?;

    // Verificación del servidor: insegura (self-signed) o contra raíces DER.
    let wants_client_cert = if params.danger_accept_invalid {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoVerify))
    } else {
        let mut roots = RootCertStore::empty();
        for der in &params.root_certs_der {
            roots
                .add(CertificateDer::from(der.clone()))
                .map_err(tls_err)?;
        }
        builder.with_root_certificates(roots)
    };

    // Autenticación del cliente: mTLS si se aportó cadena + clave.
    let config = match &params.client_key_der {
        Some(key) if !params.client_cert_der.is_empty() => {
            let chain: Vec<CertificateDer<'static>> = params
                .client_cert_der
                .iter()
                .map(|d| CertificateDer::from(d.clone()))
                .collect();
            let key = PrivateKeyDer::try_from(key.clone()).map_err(tls_err)?;
            wants_client_cert
                .with_client_auth_cert(chain, key)
                .map_err(tls_err)?
        }
        _ => wants_client_cert.with_no_client_auth(),
    };
    Ok(config)
}

/// Envía el `NULL` de probe con credencial `AUTH_TLS` y verifica que el servidor
/// responde con verificador `AUTH_TLS` (soporta RPC-with-TLS).
fn starttls_probe(
    tcp: &mut TcpStream,
    prog: u32,
    vers: u32,
    timeout: Duration,
) -> Result<(), RpcError> {
    let mut msg = BytesMut::new();
    0x5454_4c53u32.encode(&mut msg)?; // xid arbitrario ("TTLS")
    0u32.encode(&mut msg)?; // msg_type = CALL
    2u32.encode(&mut msg)?; // rpcvers
    prog.encode(&mut msg)?;
    vers.encode(&mut msg)?;
    0u32.encode(&mut msg)?; // proc = NULL
    AUTH_TLS.encode(&mut msg)?; // cred flavor = AUTH_TLS
    0u32.encode(&mut msg)?; // cred body len 0
    0u32.encode(&mut msg)?; // verf flavor = AUTH_NONE
    0u32.encode(&mut msg)?; // verf body len 0

    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.write_all(&frame(&msg.freeze())?)?;
    tcp.flush()?;

    // Leer un registro (la respuesta a un NULL cabe en un fragmento).
    let mut header = [0u8; 4];
    tcp.read_exact(&mut header)?;
    let len = (u32::from_be_bytes(header) & 0x7FFF_FFFF) as usize;
    let mut record = vec![0u8; len];
    tcp.read_exact(&mut record)?;

    let mut reply = Bytes::from(record);
    let _xid = u32::decode(&mut reply)?;
    if u32::decode(&mut reply)? != 1 {
        return Err(RpcError::MalformedReply); // REPLY
    }
    if u32::decode(&mut reply)? != 0 {
        return Err(RpcError::MalformedReply); // MSG_ACCEPTED
    }
    let verf_flavor = u32::decode(&mut reply)?;
    let _verf_body = decode_opaque(&mut reply, 400)?;
    if verf_flavor != AUTH_TLS {
        return Err(tls_err("el servidor no soporta RPC-with-TLS (RFC 9289)"));
    }
    Ok(())
}

fn tls_err<E: std::fmt::Display>(err: E) -> RpcError {
    RpcError::Io(std::io::Error::other(err.to_string()))
}

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    /// Verificador que acepta cualquier certificado (solo pruebas/self-signed).
    #[derive(Debug)]
    pub struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            use SignatureScheme::*;
            vec![
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                ECDSA_NISTP256_SHA256,
                ECDSA_NISTP384_SHA384,
                RSA_PSS_SHA256,
                RSA_PSS_SHA384,
                RSA_PSS_SHA512,
                ED25519,
            ]
        }
    }
}
