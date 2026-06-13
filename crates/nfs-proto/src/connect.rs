//! Flujo de conexión de alto nivel: portmap → mount → descubrimiento del
//! puerto NFS, replicando la secuencia de `lib/libnfs.c`.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use nfs_rpc::{Credentials, Protocol, RpcClient};

use crate::error::ProtoError;
use crate::{mount, portmap};

/// Número de programa de NFS.
pub const NFS_PROGRAM: u32 = 100003;
/// Versión 3 de NFS.
pub const NFS_VERSION3: u32 = 3;
/// Puerto estándar del portmapper.
pub const PORTMAP_PORT: u16 = 111;
/// Puerto estándar de NFS.
pub const NFS_PORT: u16 = 2049;

/// Opciones del flujo de montaje.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Protocolo de transporte.
    pub protocol: Protocol,
    /// Credenciales RPC.
    pub cred: Credentials,
    /// Timeout por llamada.
    pub timeout: Duration,
    /// Puerto del portmapper (por defecto 111).
    pub portmap_port: u16,
    /// Si se fija, se salta el portmapper para el mountd y se usa este puerto.
    pub mount_port: Option<u16>,
    /// Si se fija, se salta el portmapper para NFS y se usa este puerto.
    pub nfs_port: Option<u16>,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            protocol: Protocol::Tcp,
            cred: Credentials::unix(0, 0),
            timeout: nfs_rpc::DEFAULT_TIMEOUT,
            portmap_port: PORTMAP_PORT,
            mount_port: None,
            nfs_port: None,
        }
    }
}

/// Resultado del montaje: datos necesarios para hablar NFS con el servidor.
#[derive(Debug, Clone)]
pub struct MountInfo {
    /// Dirección IP resuelta del servidor.
    pub server: IpAddr,
    /// File handle raíz del export.
    pub root_fh: nfs_xdr::Bytes,
    /// Flavors de autenticación aceptados.
    pub auth_flavors: Vec<u32>,
    /// Puerto donde escucha el servicio NFS.
    pub nfs_port: u16,
}

fn ipproto(protocol: Protocol) -> u32 {
    match protocol {
        Protocol::Tcp => portmap::IPPROTO_TCP,
        Protocol::Udp => portmap::IPPROTO_UDP,
    }
}

fn resolve(server: &str, port: u16) -> Result<SocketAddr, ProtoError> {
    (server, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| ProtoError::Unresolvable(server.to_string()))
}

/// Conecta a un puerto concreto del servidor con las opciones dadas.
fn connect(ip: IpAddr, port: u16, opts: &MountOptions) -> Result<RpcClient, ProtoError> {
    let addr = SocketAddr::new(ip, port);
    Ok(RpcClient::connect(
        addr,
        opts.protocol,
        opts.cred.clone(),
        opts.timeout,
    )?)
}

/// Ejecuta el flujo completo: descubre el mountd (vía portmap salvo que se fije
/// `mount_port`), monta `export`, y descubre el puerto NFS (vía portmap salvo
/// que se fije `nfs_port`).
pub fn mount(server: &str, export: &str, opts: &MountOptions) -> Result<MountInfo, ProtoError> {
    let server_addr = resolve(server, opts.portmap_port)?;
    let ip = server_addr.ip();

    // 1. Puerto del mountd.
    let mount_port = match opts.mount_port {
        Some(p) => p,
        None => {
            let mut pm = connect(ip, opts.portmap_port, opts)?;
            portmap::getport(
                &mut pm,
                mount::PROGRAM,
                mount::VERSION3,
                ipproto(opts.protocol),
            )?
        }
    };

    // 2. MNT(export) -> file handle raíz.
    let mut mountd = connect(ip, mount_port, opts)?;
    let mount_ok = mount::mnt(&mut mountd, export)?;

    // 3. Puerto del servicio NFS.
    let nfs_port = match opts.nfs_port {
        Some(p) => p,
        None => {
            let mut pm = connect(ip, opts.portmap_port, opts)?;
            portmap::getport(&mut pm, NFS_PROGRAM, NFS_VERSION3, ipproto(opts.protocol))?
        }
    };

    Ok(MountInfo {
        server: ip,
        root_fh: mount_ok.fhandle,
        auth_flavors: mount_ok.auth_flavors,
        nfs_port,
    })
}
