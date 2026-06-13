//! Parser de URLs `nfs://` (RFC 2224 + parámetros de libnfs, `nfs-url.5`).

use crate::error::NfsError;

/// URL NFS parseada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsUrl {
    /// Host del servidor.
    pub server: String,
    /// Ruta del export (y subruta) tras el host.
    pub path: String,
    /// Versión de NFS (3 por defecto).
    pub version: u32,
    /// UID para AUTH_SYS.
    pub uid: u32,
    /// GID para AUTH_SYS.
    pub gid: u32,
    /// Puerto NFS fijo (salta portmap).
    pub nfsport: Option<u16>,
    /// Puerto del mountd fijo (salta portmap).
    pub mountport: Option<u16>,
    /// Timeout por llamada en segundos.
    pub timeo: u64,
    /// Cruce automático de exports anidados.
    pub autotraverse: bool,
}

impl Default for NfsUrl {
    fn default() -> Self {
        Self {
            server: String::new(),
            path: "/".to_string(),
            version: 3,
            uid: 0,
            gid: 0,
            nfsport: None,
            mountport: None,
            timeo: 60,
            autotraverse: false,
        }
    }
}

impl NfsUrl {
    /// Parsea `nfs://server[:port]/export/path?param=valor&...`.
    pub fn parse(url: &str) -> Result<Self, NfsError> {
        let rest = url
            .strip_prefix("nfs://")
            .ok_or_else(|| NfsError::InvalidUrl(format!("falta el esquema nfs:// en «{url}»")))?;

        let (location, query) = match rest.split_once('?') {
            Some((loc, q)) => (loc, Some(q)),
            None => (rest, None),
        };

        let (authority, path) = match location.find('/') {
            Some(i) => (&location[..i], location[i..].to_string()),
            None => (location, "/".to_string()),
        };
        if authority.is_empty() {
            return Err(NfsError::InvalidUrl("falta el servidor".to_string()));
        }

        let mut parsed = NfsUrl {
            path,
            ..Default::default()
        };

        // authority = host o [ipv6] con :port opcional.
        if let Some(stripped) = authority.strip_prefix('[') {
            // [ipv6]:port
            let (host, after) = stripped
                .split_once(']')
                .ok_or_else(|| NfsError::InvalidUrl("IPv6 sin cierre ]".to_string()))?;
            parsed.server = host.to_string();
            if let Some(p) = after.strip_prefix(':') {
                parsed.nfsport = Some(parse_port(p)?);
            }
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            parsed.server = host.to_string();
            parsed.nfsport = Some(parse_port(port)?);
        } else {
            parsed.server = authority.to_string();
        }

        if let Some(query) = query {
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                match key {
                    "version" | "vers" | "nfsvers" => {
                        parsed.version = parse_u32(value, key)?;
                    }
                    "uid" => parsed.uid = parse_u32(value, key)?,
                    "gid" => parsed.gid = parse_u32(value, key)?,
                    "nfsport" => parsed.nfsport = Some(parse_port(value)?),
                    "mountport" => parsed.mountport = Some(parse_port(value)?),
                    "timeo" => parsed.timeo = parse_u32(value, key)? as u64,
                    "autotraverse" | "auto-traverse" => {
                        parsed.autotraverse = value != "0" && !value.eq_ignore_ascii_case("false");
                    }
                    // Parámetros conocidos pero aún no usados: se aceptan sin error.
                    "dircache" | "readahead" | "auto-mount" | "rsize" | "wsize" | "retrans" => {}
                    other => {
                        return Err(NfsError::InvalidUrl(format!(
                            "parámetro de URL desconocido: {other}"
                        )))
                    }
                }
            }
        }

        Ok(parsed)
    }
}

fn parse_u32(value: &str, key: &str) -> Result<u32, NfsError> {
    value
        .parse()
        .map_err(|_| NfsError::InvalidUrl(format!("valor inválido para {key}: «{value}»")))
}

fn parse_port(value: &str) -> Result<u16, NfsError> {
    value
        .parse()
        .map_err(|_| NfsError::InvalidUrl(format!("puerto inválido: «{value}»")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_url() {
        let u = NfsUrl::parse("nfs://server/export/dir").unwrap();
        assert_eq!(u.server, "server");
        assert_eq!(u.path, "/export/dir");
        assert_eq!(u.version, 3);
    }

    #[test]
    fn url_with_params() {
        let u =
            NfsUrl::parse("nfs://10.0.0.1/data?version=4&uid=1000&gid=1000&nfsport=2049").unwrap();
        assert_eq!(u.server, "10.0.0.1");
        assert_eq!(u.path, "/data");
        assert_eq!(u.version, 4);
        assert_eq!(u.uid, 1000);
        assert_eq!(u.gid, 1000);
        assert_eq!(u.nfsport, Some(2049));
    }

    #[test]
    fn url_ipv6() {
        let u = NfsUrl::parse("nfs://[::1]:2049/export").unwrap();
        assert_eq!(u.server, "::1");
        assert_eq!(u.nfsport, Some(2049));
        assert_eq!(u.path, "/export");
    }

    #[test]
    fn url_host_port() {
        let u = NfsUrl::parse("nfs://nas.local:20490/vol1?autotraverse=1").unwrap();
        assert_eq!(u.server, "nas.local");
        assert_eq!(u.nfsport, Some(20490));
        assert!(u.autotraverse);
    }

    #[test]
    fn rejects_missing_scheme() {
        assert!(NfsUrl::parse("http://x/y").is_err());
    }

    #[test]
    fn rejects_unknown_param() {
        assert!(NfsUrl::parse("nfs://s/e?bogus=1").is_err());
    }
}
