use crate::async_socks5::SocksDatagram as Socks5Datagram;
use std::{
    fmt::{Display, Write},
    io,
    net::{AddrParseError, SocketAddr},
    ops::Deref,
    str::FromStr,
};
pub use tokio::net::TcpStream;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket as TokioUdpSocket;

use thiserror::Error;
use url::{ParseError, Url};

// 🌟 解耦：传入已经由上层配置好 SO_MARK 和绑定网卡的纯净 Stream，这里只做业务层握手
pub async fn handshake_tcp(
    mut stream: TokioTcpStream,
    server_addr: SocketAddr,
    proxy: Option<&ProxyConfig>,
) -> io::Result<TcpStream> {
    let target_addr = server_addr.ip().to_string();
    let target_port = server_addr.port();

    match proxy {
        Some(proxy) => match proxy.proto {
            ProxyProtocol::Socks5 => {
                use crate::async_socks5::Auth;

                let auth = if proxy.username.is_some() {
                    let username = proxy.username.as_deref().unwrap_or_default();
                    let password = proxy.password.as_deref().unwrap_or_default();

                    Some(Auth {
                        username: username.to_string(),
                        password: password.to_string(),
                    })
                } else {
                    None
                };

                let _ = crate::async_socks5::connect(&mut stream, server_addr, auth)
                    .await
                    .map_err(from_socks5_err)?;

                Ok(stream)
            }
            ProxyProtocol::Http => {
                use async_http_proxy::{http_connect_tokio, http_connect_tokio_with_basic_auth};

                if let Some(user) = proxy.username.as_deref() {
                    http_connect_tokio_with_basic_auth(
                        &mut stream,
                        &target_addr,
                        target_port,
                        user,
                        proxy.password.as_deref().unwrap_or_default(),
                    )
                    .await
                } else {
                    http_connect_tokio(&mut stream, &target_addr, target_port).await
                }
                .map_err(from_http_err)?;

                Ok(stream)
            }
        },
        None => Ok(stream),
    }
}

// 🌟 解耦：同理，代理 UDP 流量所需的控制流 TCP Stream，也必须在外部打好防漏流补丁后传进来
pub async fn handshake_udp(
    stream: Option<TokioTcpStream>,
    socket: TokioUdpSocket,
    proxy: Option<&ProxyConfig>,
) -> io::Result<UdpSocket> {
    match proxy {
        Some(proxy) => match proxy.proto {
            ProxyProtocol::Socks5 => {
                use crate::async_socks5::{AddrKind, Auth};
                let stream = stream.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TCP stream required for SOCKS5 UDP associate",
                    )
                })?;

                let auth = if proxy.username.is_some() {
                    let username = proxy.username.as_deref().unwrap_or_default();
                    let password = proxy.password.as_deref().unwrap_or_default();

                    Some(Auth {
                        username: username.to_string(),
                        password: password.to_string(),
                    })
                } else {
                    None
                };

                let socket = Socks5Datagram::associate(stream, socket, auth, None::<AddrKind>)
                    .await
                    .map_err(from_socks5_err)?;

                Ok(UdpSocket::Proxy(socket))
            }
            ProxyProtocol::Http => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP proxy does not support UDP",
            )),
        },
        None => Ok(UdpSocket::Tokio(socket)),
    }
}

fn from_socks5_err(err: crate::async_socks5::Error) -> io::Error {
    match err {
        crate::async_socks5::Error::Io(io) => io,
        err => io::Error::new(io::ErrorKind::ConnectionRefused, err),
    }
}

fn from_http_err(err: async_http_proxy::HttpError) -> io::Error {
    match err {
        async_http_proxy::HttpError::IoError(io) => io,
        err => io::Error::new(io::ErrorKind::ConnectionRefused, err),
    }
}

pub enum UdpSocket {
    Tokio(TokioUdpSocket),
    Proxy(Socks5Datagram<TokioTcpStream>),
}

impl Deref for UdpSocket {
    type Target = TokioUdpSocket;

    fn deref(&self) -> &Self::Target {
        match self {
            UdpSocket::Tokio(s) => s,
            UdpSocket::Proxy(s) => s.get_ref(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProxyConfig {
    pub proto: ProxyProtocol,
    pub server: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// 按名字取代理配置；名字没在 `proxy-server ... -name <名>` 里定义时**明确告警**并返回 `None`。
///
/// 为什么必须说出来：写错代理名（或忘了写 `proxy-server` 那行）时，原行为是**静默改直连** ——
/// 用户以为流量走了代理，实际没走；在"必须经代理才能出去"的网络里，症状就是
/// "名单/上游连不上，但日志里看不出为什么"。告警用 `warn_once` 去重，不刷屏。
///
/// 拿到 `None` 的调用方**仍然直连**（行为不变，只是不再无声）。
pub fn resolve_proxy<'a>(
    proxies: &'a std::collections::HashMap<String, ProxyConfig>,
    name: &str,
) -> Option<&'a ProxyConfig> {
    match proxies.get(name) {
        Some(proxy) => Some(proxy),
        None => {
            if crate::log::warn_once(&format!("unknown-proxy:{name}")) {
                crate::log::warn!(
                    "代理名 {name} 未在 `proxy-server ... -name {name}` 里定义，本次改为直连（请检查拼写）"
                );
            }
            None
        }
    }
}

/// 🌟 安全修复：手写 Debug，口令属于敏感信息，不得出现在任何日志/错误输出中。
impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("proto", &self.proto)
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .finish()
    }
}

impl Display for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.proto {
            ProxyProtocol::Socks5 => "socks5://",
            ProxyProtocol::Http => "http://",
        })?;

        if let Some(user) = self.username.as_deref() {
            f.write_str(user)?;

            // 🌟 安全修复：口令不参与展示。
            // 本 Display 会被启动横幅（dns_conf.rs 的 summary）以及 NameServerInfo 的 Display 使用，
            // 原实现直接输出明文，导致 `socks5://user:password@host` 被持久化进磁盘日志文件。
            // 注意：连接与认证路径读取的是 self.password 字段本身（见本文件 handshake_tcp/handshake_udp），
            // 不经过 Display，因此打码不会影响代理可用性。
            if self.password.is_some() {
                f.write_str(":***")?;
            }
            f.write_char('@')?;
        }

        write!(f, "{}", self.server)?;

        Ok(())
    }
}

impl FromStr for ProxyConfig {
    type Err = ProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::from_str(s)?;

        let proto = match url.scheme() {
            "socks5" => ProxyProtocol::Socks5,
            "http" => ProxyProtocol::Http,
            scheme => return Err(ProxyParseError::UnexpectedSchema(scheme.to_string())),
        };

        let server = match url
            .socket_addrs(|| match proto {
                ProxyProtocol::Socks5 => Some(1080),
                _ => None,
            })
            .into_iter()
            .flatten()
            .next()
        {
            Some(s) => s,
            None => return Err(ParseError::InvalidDomainCharacter.into()),
        };

        let mut username = Some(url.username());
        if matches!(username, Some("")) {
            username = None;
        }

        let password = url.password();

        Ok(Self {
            proto,
            server,
            username: username.map(|s| s.to_owned()),
            password: password.map(|s| s.to_owned()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyProtocol {
    Socks5,
    Http,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProxyParseError {
    #[error("UnexpectedSchema {0:?}")]
    UnexpectedSchema(String),
    #[error(" address parse error {0:?}")]
    Addr(#[from] AddrParseError),
    #[error("{0:?}")]
    Parse(#[from] ParseError),
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;

    #[test]
    fn test_resolve_proxy_by_name() {
        use std::collections::HashMap;

        let mut proxies: HashMap<String, ProxyConfig> = HashMap::new();
        proxies.insert(
            "ok".to_string(),
            ProxyConfig::from_str("socks5://1.2.3.4:1080").unwrap(),
        );

        // 名字对得上：拿到配置
        assert!(resolve_proxy(&proxies, "ok").is_some());
        // 名字对不上：返回 None（调用方直连）+ 告警；重复调用不会 panic（warn_once 去重）
        assert!(resolve_proxy(&proxies, "typo").is_none());
        assert!(resolve_proxy(&proxies, "typo").is_none());
    }

    #[test]
    fn test_parse_socks5() {
        assert_eq!(
            ProxyConfig::from_str("socks5://1.2.3.4:1080"),
            Ok(ProxyConfig {
                proto: ProxyProtocol::Socks5,
                server: "1.2.3.4:1080".parse().unwrap(),
                username: None,
                password: None
            })
        );
    }

    #[test]
    fn test_parse_socks5_with_user() {
        assert_eq!(
            ProxyConfig::from_str("socks5://user123@1.2.3.4:1080"),
            Ok(ProxyConfig {
                proto: ProxyProtocol::Socks5,
                server: "1.2.3.4:1080".parse().unwrap(),
                username: Some("user123".to_string()),
                password: None
            })
        );

        let url = Url::from_str("abc://user123@1.2.3.4:1080").unwrap();

        assert_eq!(url.username(), "user123");
        assert_eq!(url.password(), None);
    }

    #[test]
    fn test_parse_socks5_with_user_pass() {
        assert_eq!(
            ProxyConfig::from_str("socks5://user123:pass456@1.2.3.4:1080"),
            Ok(ProxyConfig {
                proto: ProxyProtocol::Socks5,
                server: "1.2.3.4:1080".parse().unwrap(),
                username: Some("user123".to_string()),
                password: Some("pass456".to_string())
            })
        );
    }

    #[test]
    fn test_parse_http() {
        assert_eq!(
            ProxyConfig::from_str("http://1.2.3.4:8080"),
            Ok(ProxyConfig {
                proto: ProxyProtocol::Http,
                server: "1.2.3.4:8080".parse().unwrap(),
                username: None,
                password: None
            })
        );
    }
}
