//! An `async`/`.await` [SOCKS5] implementation.
//!
//! [SOCKS5]: https://tools.ietf.org/html/rfc1928

#![deny(missing_debug_implementations)]

use std::{
    fmt::Debug,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    string::FromUtf8Error,
};
use tokio::{
    io,
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

// Error and Result
// *****************************************************************************

/// The library's error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),
    #[error("{0}")]
    FromUtf8(
        #[from]
        #[source]
        FromUtf8Error,
    ),
    #[error("Invalid SOCKS version: {0:x}")]
    InvalidVersion(u8),
    #[error("Invalid command: {0:x}")]
    InvalidCommand(u8),
    #[error("Invalid address type: {0:x}")]
    InvalidAtyp(u8),
    #[error("Invalid reserved bytes: {0:x}")]
    InvalidReserved(u8),
    #[error("Invalid authentication status: {0:x}")]
    InvalidAuthStatus(u8),
    #[error("Invalid authentication version of subnegotiation: {0:x}")]
    InvalidAuthSubnegotiation(u8),
    #[error("Invalid fragment id: {0:x}")]
    InvalidFragmentId(u8),
    #[error("Invalid authentication method: {0:?}")]
    InvalidAuthMethod(AuthMethod),
    #[error("SOCKS version is 4 when 5 is expected")]
    WrongVersion,
    #[error("No acceptable methods")]
    NoAcceptableMethods,
    #[error("Unsuccessful reply: {0:?}")]
    Response(UnsuccessfulReply),
    #[error("{0:?} length is more than 255 bytes")]
    TooLongString(StringKind),
}

/// Required to mark which string is too long.
/// See [`Error::TooLongString`].
///
/// [`Error::TooLongString`]: enum.Error.html#variant.TooLongString
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum StringKind {
    Domain,
    Username,
    Password,
}

/// The library's `Result` type alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

// Utilities
// *****************************************************************************

trait ReadExt: AsyncReadExt + Unpin {
    async fn read_version(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        match value {
            0x04 => Err(Error::WrongVersion),
            0x05 => Ok(()),
            _ => Err(Error::InvalidVersion(value)),
        }
    }

    async fn read_method(&mut self) -> Result<AuthMethod> {
        let value = self.read_u8().await?;

        let method = match value {
            0x00 => AuthMethod::None,
            0x01 => AuthMethod::GssApi,
            0x02 => AuthMethod::UsernamePassword,
            0x03..=0x7f => AuthMethod::IanaReserved(value),
            0x80..=0xfe => AuthMethod::Private(value),
            0xff => return Err(Error::NoAcceptableMethods),
        };

        Ok(method)
    }

    async fn read_command(&mut self) -> Result<Command> {
        let value = self.read_u8().await?;

        let command = match value {
            0x01 => Command::Connect,
            0x02 => Command::Bind,
            0x03 => Command::UdpAssociate,
            _ => return Err(Error::InvalidCommand(value)),
        };

        Ok(command)
    }

    async fn read_atyp(&mut self) -> Result<Atyp> {
        let value = self.read_u8().await?;
        let atyp = match value {
            0x01 => Atyp::V4,
            0x03 => Atyp::Domain,
            0x04 => Atyp::V6,
            _ => return Err(Error::InvalidAtyp(value)),
        };
        Ok(atyp)
    }

    async fn read_reserved(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        match value {
            0x00 => Ok(()),
            _ => Err(Error::InvalidReserved(value)),
        }
    }

    async fn read_fragment_id(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        if value == 0x00 {
            Ok(())
        } else {
            Err(Error::InvalidFragmentId(value))
        }
    }

    async fn read_reply(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        let reply = match value {
            0x00 => return Ok(()),
            0x01 => UnsuccessfulReply::GeneralFailure,
            0x02 => UnsuccessfulReply::ConnectionNotAllowedByRules,
            0x03 => UnsuccessfulReply::NetworkUnreachable,
            0x04 => UnsuccessfulReply::HostUnreachable,
            0x05 => UnsuccessfulReply::ConnectionRefused,
            0x06 => UnsuccessfulReply::TtlExpired,
            0x07 => UnsuccessfulReply::CommandNotSupported,
            0x08 => UnsuccessfulReply::AddressTypeNotSupported,
            _ => UnsuccessfulReply::Unassigned(value),
        };

        Err(Error::Response(reply))
    }

    async fn read_target_addr(&mut self) -> Result<AddrKind> {
        let atyp: Atyp = self.read_atyp().await?;

        let addr = match atyp {
            Atyp::V4 => {
                let mut ip = [0; 4];
                self.read_exact(&mut ip).await?;
                let port = self.read_u16().await?;
                AddrKind::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            Atyp::V6 => {
                let mut ip = [0; 16];
                self.read_exact(&mut ip).await?;
                let port = self.read_u16().await?;
                AddrKind::Ip(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                )))
            }
            Atyp::Domain => {
                let str = self.read_string().await?;
                let port = self.read_u16().await?;
                AddrKind::Domain(str, port)
            }
        };

        Ok(addr)
    }

    async fn read_string(&mut self) -> Result<String> {
        let len = self.read_u8().await?;
        let mut str = vec![0; len as usize];
        self.read_exact(&mut str).await?;
        let str = String::from_utf8(str)?;
        Ok(str)
    }

    async fn read_auth_version(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        if value != 0x01 {
            return Err(Error::InvalidAuthSubnegotiation(value));
        }

        Ok(())
    }

    async fn read_auth_status(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        if value != 0x00 {
            return Err(Error::InvalidAuthStatus(value));
        }

        Ok(())
    }

    async fn read_selection_msg(&mut self) -> Result<AuthMethod> {
        self.read_version().await?;
        self.read_method().await
    }

    async fn read_final(&mut self) -> Result<AddrKind> {
        self.read_version().await?;
        self.read_reply().await?;
        self.read_reserved().await?;
        let addr = self.read_target_addr().await?;
        Ok(addr)
    }
}

impl<T: AsyncReadExt + Unpin> ReadExt for T {}

trait WriteExt: AsyncWriteExt + Unpin {
    async fn write_version(&mut self) -> Result<()> {
        self.write_u8(0x05).await?;
        Ok(())
    }

    async fn write_method(&mut self, method: AuthMethod) -> Result<()> {
        let value = match method {
            AuthMethod::None => 0x00,
            AuthMethod::GssApi => 0x01,
            AuthMethod::UsernamePassword => 0x02,
            AuthMethod::IanaReserved(value) => value,
            AuthMethod::Private(value) => value,
        };
        self.write_u8(value).await?;
        Ok(())
    }

    async fn write_command(&mut self, command: Command) -> Result<()> {
        self.write_u8(command as u8).await?;
        Ok(())
    }

    async fn write_atyp(&mut self, atyp: Atyp) -> Result<()> {
        self.write_u8(atyp as u8).await?;
        Ok(())
    }

    async fn write_reserved(&mut self) -> Result<()> {
        self.write_u8(0x00).await?;
        Ok(())
    }

    async fn write_fragment_id(&mut self) -> Result<()> {
        self.write_u8(0x00).await?;
        Ok(())
    }

    async fn write_target_addr(&mut self, target_addr: &AddrKind) -> Result<()> {
        match target_addr {
            AddrKind::Ip(SocketAddr::V4(addr)) => {
                self.write_atyp(Atyp::V4).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            AddrKind::Ip(SocketAddr::V6(addr)) => {
                self.write_atyp(Atyp::V6).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            AddrKind::Domain(domain, port) => {
                self.write_atyp(Atyp::Domain).await?;
                self.write_string(domain, StringKind::Domain).await?;
                self.write_u16(*port).await?;
            }
        }
        Ok(())
    }

    async fn write_string(&mut self, string: &str, kind: StringKind) -> Result<()> {
        let bytes = string.as_bytes();
        if bytes.len() > 255 {
            return Err(Error::TooLongString(kind));
        }
        self.write_u8(bytes.len() as u8).await?;
        self.write_all(bytes).await?;
        Ok(())
    }

    async fn write_auth_version(&mut self) -> Result<()> {
        self.write_u8(0x01).await?;
        Ok(())
    }

    async fn write_methods(&mut self, methods: &[AuthMethod]) -> Result<()> {
        self.write_u8(methods.len() as u8).await?;
        for method in methods {
            self.write_method(*method).await?;
        }
        Ok(())
    }

    async fn write_selection_msg(&mut self, methods: &[AuthMethod]) -> Result<()> {
        self.write_version().await?;
        self.write_methods(methods).await?;
        self.flush().await?;
        Ok(())
    }

    async fn write_final(&mut self, command: Command, addr: &AddrKind) -> Result<()> {
        self.write_version().await?;
        self.write_command(command).await?;
        self.write_reserved().await?;
        self.write_target_addr(addr).await?;
        self.flush().await?;
        Ok(())
    }
}

impl<T: AsyncWriteExt + Unpin> WriteExt for T {}

async fn username_password_auth<S>(stream: &mut S, auth: Auth) -> Result<()>
where
    S: WriteExt + ReadExt + Send,
{
    stream.write_auth_version().await?;
    stream
        .write_string(&auth.username, StringKind::Username)
        .await?;
    stream
        .write_string(&auth.password, StringKind::Password)
        .await?;
    stream.flush().await?;

    stream.read_auth_version().await?;
    stream.read_auth_status().await
}

async fn init<S, A>(
    stream: &mut S,
    command: Command,
    addr: A,
    auth: Option<Auth>,
) -> Result<AddrKind>
where
    S: WriteExt + ReadExt + Send,
    A: Into<AddrKind>,
{
    let addr: AddrKind = addr.into();

    let mut methods = Vec::with_capacity(2);
    methods.push(AuthMethod::None);
    if auth.is_some() {
        methods.push(AuthMethod::UsernamePassword);
    }
    stream.write_selection_msg(&methods).await?;

    let method: AuthMethod = stream.read_selection_msg().await?;
    match method {
        AuthMethod::None => {}
        // FIXME: until if let in match is stabilized
        AuthMethod::UsernamePassword if auth.is_some() => {
            username_password_auth(stream, auth.unwrap()).await?;
        }
        _ => return Err(Error::InvalidAuthMethod(method)),
    }

    stream.write_final(command, &addr).await?;
    stream.read_final().await
}

// Types
// *****************************************************************************

/// Required for a username + password authentication.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Auth {
    pub username: String,
    pub password: String,
}

impl Auth {
    /// Constructs `Auth` with the specified username and a password.
    pub fn new<U, P>(username: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// A proxy authentication method.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum AuthMethod {
    /// No authentication required.
    None,
    /// GSS API.
    GssApi,
    /// A username + password authentication.
    UsernamePassword,
    /// IANA reserved.
    IanaReserved(u8),
    /// A private authentication method.
    Private(u8),
}

enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

enum Atyp {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x4,
}

/// An unsuccessful reply from a proxy server.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum UnsuccessfulReply {
    GeneralFailure,
    ConnectionNotAllowedByRules,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Unassigned(u8),
}

/// Either [`SocketAddr`] or a domain and a port.
///
/// [`SocketAddr`]: https://doc.rust-lang.org/std/net/enum.SocketAddr.html
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum AddrKind {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl AddrKind {
    const MAX_SIZE: usize = 1 // atyp
        + 1 // domain len
        + 255 // domain
        + 2; // port

    // FIXME: until ToSocketAddrs is allowed to implement
    fn to_socket_addr(&self) -> String {
        match self {
            AddrKind::Ip(addr) => addr.to_string(),
            AddrKind::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }

    fn size(&self) -> usize {
        1 + // atyp
            2 + // port
            match self {
                AddrKind::Ip(SocketAddr::V4(_)) => 4,
                AddrKind::Ip(SocketAddr::V6(_)) => 16,
                AddrKind::Domain(domain, _) =>
                    1 // string len
                        + domain.len(),
            }
    }
}

impl From<(IpAddr, u16)> for AddrKind {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for AddrKind {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for AddrKind {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(String, u16)> for AddrKind {
    fn from((domain, port): (String, u16)) -> Self {
        Self::Domain(domain, port)
    }
}

impl From<(&'_ str, u16)> for AddrKind {
    fn from((domain, port): (&'_ str, u16)) -> Self {
        Self::Domain(domain.to_owned(), port)
    }
}

impl From<SocketAddr> for AddrKind {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<SocketAddrV4> for AddrKind {
    fn from(value: SocketAddrV4) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddrV6> for AddrKind {
    fn from(value: SocketAddrV6) -> Self {
        Self::Ip(value.into())
    }
}

// Public API
// *****************************************************************************

/// Proxifies a TCP connection. Performs the [`CONNECT`] command under the hood.
///
/// [`CONNECT`]: https://tools.ietf.org/html/rfc1928#page-6
///
/// ```no_run
/// # use async_socks5::Result;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<()> {
/// use async_socks5::connect;
/// use tokio::{io::BufStream, net::TcpStream};
///
/// let stream = TcpStream::connect("my-proxy-server.com:54321").await?;
/// let mut stream = BufStream::new(stream);
/// connect(&mut stream, ("google.com", 80), None).await?;
///
/// # Ok(())
/// # }
/// ```
pub async fn connect<S, A>(socket: &mut S, addr: A, auth: Option<Auth>) -> Result<AddrKind>
where
    S: AsyncWriteExt + AsyncReadExt + Send + Unpin,
    A: Into<AddrKind>,
{
    init(socket, Command::Connect, addr, auth).await
}

/// A listener that accepts TCP connections through a proxy.
///
/// ```no_run
/// # use async_socks5::Result;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<()> {
/// use async_socks5::SocksListener;
/// use tokio::{io::BufStream, net::TcpStream};
///
/// let stream = TcpStream::connect("my-proxy-server.com:54321").await?;
/// let mut stream = BufStream::new(stream);
/// let (stream, addr) = SocksListener::bind(stream, ("ftp-server.org", 21), None)
///     .await?
///     .accept()
///     .await?;
///
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct SocksListener<S> {
    stream: S,
    proxy_addr: AddrKind,
}

impl<S> SocksListener<S>
where
    S: AsyncWriteExt + AsyncReadExt + Send + Unpin,
{
    /// Creates `SocksListener`. Performs the [`BIND`] command under the hood.
    ///
    /// [`BIND`]: https://tools.ietf.org/html/rfc1928#page-6
    pub async fn bind<A>(mut stream: S, addr: A, auth: Option<Auth>) -> Result<Self>
    where
        A: Into<AddrKind>,
    {
        let addr = init(&mut stream, Command::Bind, addr, auth).await?;
        Ok(Self {
            stream,
            proxy_addr: addr,
        })
    }

    pub fn proxy_addr(&self) -> &AddrKind {
        &self.proxy_addr
    }

    pub async fn accept(mut self) -> Result<(S, AddrKind)> {
        let addr = self.stream.read_final().await?;
        Ok((self.stream, addr))
    }
}

/// A UDP socket that sends packets through a proxy.
#[derive(Debug)]
pub struct SocksDatagram<S> {
    socket: UdpSocket,
    proxy_addr: AddrKind,
    stream: S,
    /// 期望的应答来源（= 我们查询的上游地址）；未设置时不做来源过滤。
    expected_source: std::sync::OnceLock<SocketAddr>,
}

/// 因"数据报头部来源地址"与我们所查询的上游不符而被丢弃的数量（P1-9 投毒防护的可观测项）。
///
/// 注意：直连路径由内核丢弃来源不符的报文，那一层我们看不到、也无法计数；
/// 这个计数只反映**代理路径**上被用户态校验拦下的数据报。
pub static UDP_SOURCE_REJECTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 读取被丢弃的"来源不符"数据报数（供管理接口展示）。
pub fn rejected_by_source() -> u64 {
    UDP_SOURCE_REJECTED.load(std::sync::atomic::Ordering::Relaxed)
}

impl<S> SocksDatagram<S>
where
    S: AsyncWriteExt + AsyncReadExt + Send + Unpin,
{
    /// Creates `SocksDatagram`. Performs [`UDP ASSOCIATE`] under the hood.
    ///
    /// [`UDP ASSOCIATE`]: https://tools.ietf.org/html/rfc1928#page-7
    pub async fn associate<A>(
        mut proxy_stream: S,
        socket: UdpSocket,
        auth: Option<Auth>,
        association_addr: Option<A>,
    ) -> Result<Self>
    where
        A: Into<AddrKind>,
    {
        let addr = association_addr
            .map(Into::into)
            .unwrap_or_else(|| AddrKind::Ip(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0)));
        let proxy_addr = init(&mut proxy_stream, Command::UdpAssociate, addr, auth).await?;
        socket.connect(proxy_addr.to_socket_addr()).await?;
        Ok(Self {
            socket,
            proxy_addr,
            stream: proxy_stream,
            expected_source: std::sync::OnceLock::new(),
        })
    }

    /// 仅供测试：跳过 SOCKS5 握手直接组装，用于验证来源校验这条生产代码路径。
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(socket: UdpSocket, proxy_addr: AddrKind, stream: S) -> Self {
        Self {
            socket,
            proxy_addr,
            stream,
            expected_source: std::sync::OnceLock::new(),
        }
    }

    /// 登记"期望的应答来源"，此后头部来源不符的数据报会被丢弃并计数（RFC 1928 §7）。
    pub fn set_expected_source(&self, addr: SocketAddr) {
        let _ = self.expected_source.set(addr);
    }

    /// 该数据报的来源是否为我们查询的那个上游？
    /// 未登记期望来源时（例如单独使用本类型）不做过滤，保持原有行为。
    fn source_is_expected(&self, addr: &AddrKind) -> bool {
        match (self.expected_source.get(), addr) {
            (None, _) => true,
            (Some(expected), AddrKind::Ip(got)) => got == expected,
            // 我们配置的上游是 IP，来源报域名的数据报一律不接受
            (Some(_), _) => false,
        }
    }

    pub fn proxy_addr(&self) -> &AddrKind {
        &self.proxy_addr
    }

    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn get_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    pub fn into_inner(self) -> (S, UdpSocket) {
        (self.stream, self.socket)
    }

    async fn write_request(buf: &[u8], addr: AddrKind) -> Result<(Vec<u8>, usize)> {
        let header_size = Self::get_header_size(addr.size());
        let bytes = Vec::with_capacity(header_size + buf.len());

        let mut cursor = Cursor::new(bytes);
        cursor.write_reserved().await?;
        cursor.write_reserved().await?;
        cursor.write_fragment_id().await?;
        cursor.write_target_addr(&addr).await?;
        cursor.write_all(buf).await?;

        let bytes = cursor.into_inner();
        Ok((bytes, header_size))
    }

    // ======= 🌟 下面是为 smartdns 同步轮询机制补充的底层方法 =======

    fn write_header_sync(bytes: &mut [u8], addr: &AddrKind) -> usize {
        bytes[0] = 0x00; // RSV
        bytes[1] = 0x00; // RSV
        bytes[2] = 0x00; // FRAG
        let mut offset = 3;
        match addr {
            AddrKind::Ip(SocketAddr::V4(addr)) => {
                bytes[offset] = 0x01; // ATYP: V4
                offset += 1;
                bytes[offset..offset + 4].copy_from_slice(&addr.ip().octets());
                offset += 4;
                bytes[offset..offset + 2].copy_from_slice(&addr.port().to_be_bytes());
                offset += 2;
            }
            AddrKind::Ip(SocketAddr::V6(addr)) => {
                bytes[offset] = 0x04; // ATYP: V6
                offset += 1;
                bytes[offset..offset + 16].copy_from_slice(&addr.ip().octets());
                offset += 16;
                bytes[offset..offset + 2].copy_from_slice(&addr.port().to_be_bytes());
                offset += 2;
            }
            AddrKind::Domain(domain, port) => {
                bytes[offset] = 0x03; // ATYP: Domain
                offset += 1;
                let domain_bytes = domain.as_bytes();
                let len = domain_bytes.len();
                bytes[offset] = len as u8;
                offset += 1;
                bytes[offset..offset + len].copy_from_slice(domain_bytes);
                offset += len;
                bytes[offset..offset + 2].copy_from_slice(&port.to_be_bytes());
                offset += 2;
            }
        }
        offset
    }

    fn parse_header_sync(bytes: &[u8]) -> Result<(usize, AddrKind)> {
        if bytes.len() < 4 {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Packet too short",
            )));
        }
        if bytes[0] != 0x00 || bytes[1] != 0x00 {
            return Err(Error::InvalidReserved(bytes[0]));
        }
        if bytes[2] != 0x00 {
            return Err(Error::InvalidFragmentId(bytes[2]));
        }

        let atyp = bytes[3];
        let mut offset = 4;

        let addr = match atyp {
            0x01 => {
                if bytes.len() < offset + 6 {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Packet too short for IPv4",
                    )));
                }
                let mut ip_bytes = [0u8; 4];
                ip_bytes.copy_from_slice(&bytes[offset..offset + 4]);
                offset += 4;
                let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                offset += 2;
                AddrKind::Ip(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(ip_bytes),
                    port,
                )))
            }
            0x04 => {
                if bytes.len() < offset + 18 {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Packet too short for IPv6",
                    )));
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&bytes[offset..offset + 16]);
                offset += 16;
                let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                offset += 2;
                AddrKind::Ip(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip_bytes),
                    port,
                    0,
                    0,
                )))
            }
            0x03 => {
                if bytes.len() < offset + 1 {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Packet too short for Domain len",
                    )));
                }
                let len = bytes[offset] as usize;
                offset += 1;
                if bytes.len() < offset + len + 2 {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Packet too short for Domain",
                    )));
                }
                let domain = String::from_utf8(bytes[offset..offset + len].to_vec())
                    .map_err(Error::FromUtf8)?;
                offset += len;
                let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                offset += 2;
                AddrKind::Domain(domain, port)
            }
            _ => return Err(Error::InvalidAtyp(atyp)),
        };

        Ok((offset, addr))
    }

    pub fn poll_send_to<A>(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        addr: A,
    ) -> std::task::Poll<Result<usize>>
    where
        A: Into<AddrKind>,
    {
        let addr = addr.into();
        let total_len = buf.len() + 262; // 负载长度 + SOCKS5最大头部长度

        // 🌟 核心优化：99% 的 DNS 请求都小于 4096，使用极速栈内存，真正实现 0 Malloc 分配！
        let mut stack_buf = [0u8; 4096];
        let mut heap_buf = Vec::new();

        let target_buf = if total_len <= 4096 {
            &mut stack_buf[..total_len]
        } else {
            heap_buf.resize(total_len, 0); // 仅在遇到怪兽级巨型数据包时退化为堆分配
            &mut heap_buf[..]
        };

        let header_len = Self::write_header_sync(target_buf, &addr);
        let packet_len = header_len + buf.len();
        target_buf[header_len..packet_len].copy_from_slice(buf);

        match self.socket.poll_send(cx, &target_buf[..packet_len]) {
            std::task::Poll::Ready(Ok(n)) => {
                if n >= header_len {
                    std::task::Poll::Ready(Ok(n - header_len))
                } else {
                    std::task::Poll::Ready(Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Sent bytes shorter than SOCKS5 header",
                    ))))
                }
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(Error::Io(e))),
        }
    }

    pub fn poll_recv_from(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<Result<(usize, AddrKind)>> {
        let total_len = buf.len() + 262;

        let mut stack_buf = [0u8; 4096];
        let mut heap_buf = Vec::new();

        let target_buf = if total_len <= 4096 {
            &mut stack_buf[..total_len]
        } else {
            heap_buf.resize(total_len, 0);
            &mut heap_buf[..]
        };

        // 🌟 P1-9 修复：来源校验循环 —— 只接受"我们查询的那个上游"回来的数据报。
        // 遇到来源不符的：计数后丢弃，继续读下一个（最多 32 个，避免长时间占住执行器）。
        const MAX_SKIPPED: usize = 32;
        for _ in 0..=MAX_SKIPPED {
            let mut read_buf = tokio::io::ReadBuf::new(&mut target_buf[..]);

            match self.socket.poll_recv(cx, &mut read_buf) {
                std::task::Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        return std::task::Poll::Ready(Err(Error::Io(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "Empty packet",
                        ))));
                    }

                    match Self::parse_header_sync(filled) {
                        Ok((header_len, addr)) => {
                            if !self.source_is_expected(&addr) {
                                UDP_SOURCE_REJECTED
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                continue;
                            }
                            let payload_len = filled.len() - header_len;
                            if payload_len > buf.len() {
                                return std::task::Poll::Ready(Err(Error::Io(
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidInput,
                                        "User buffer too small for UDP payload",
                                    ),
                                )));
                            }
                            buf[..payload_len].copy_from_slice(&filled[header_len..]);
                            return std::task::Poll::Ready(Ok((payload_len, addr)));
                        }
                        Err(e) => return std::task::Poll::Ready(Err(e)),
                    }
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(Error::Io(e))),
            }
        }

        // 连续丢弃达到上限：让出执行权，但必须保证被再次唤醒，否则可能永久卡住。
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    }

    // 🌟 核心优化：直接复用 poll 方法，极大地瘦身协程体积，删除了原来慢速臃肿的 Cursor/Vec 逻辑
    pub async fn send_to<A>(&self, buf: &[u8], addr: A) -> Result<usize>
    where
        A: Into<AddrKind>,
    {
        let addr: AddrKind = addr.into();
        std::future::poll_fn(|cx| self.poll_send_to(cx, buf, addr.clone())).await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, AddrKind)> {
        std::future::poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }

    fn get_buf_size(addr_size: usize, buf_len: usize) -> usize {
        Self::get_header_size(addr_size) + buf_len
    }
    #[inline]
    fn get_header_size(addr_size: usize) -> usize {
        2 // reserved
                + 1 // fragment id
                + addr_size
    }
}

// Tests
// *****************************************************************************

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpStream;

    use crate::proxy::{
        ProxyConfig, ProxyProtocol, UdpSocket as ProxyUdpSocket, handshake_tcp, handshake_udp,
    };

    const DATA: &[u8] = b"Hello, world!";

    /// 测试用代理一律从环境变量读取，不硬编码到某台机器/某个人的本地环境。
    ///
    /// | 环境变量 | 含义 | 回退顺序 |
    /// | --- | --- | --- |
    /// | `SMARTDNS_TEST_SOCKS5_PROXY` | 普通 SOCKS5 代理（无需认证） | `ALL_PROXY`/`all_proxy` → `HTTP_PROXY`/`HTTPS_PROXY`（含小写）｜**无默认值**：都没有就跳过 |
    /// | `SMARTDNS_TEST_SOCKS5_PROXY_AUTH` | 需要用户名/口令认证的 SOCKS5 代理 | 同上 ｜ **无默认值**：都没有就跳过 |
    /// | `SMARTDNS_TEST_SOCKS5_USER` | 认证用户名 | `hyper` |
    /// | `SMARTDNS_TEST_SOCKS5_PASSWORD` | 认证口令 | `proxy` |
    /// | `SMARTDNS_TEST_SOCKS5_TARGET` | CONNECT 的探测目标（`IP:端口`） | `1.1.1.1:443` |
    ///
    /// 取值既可以是 `主机:端口`，也可以是 `socks5://用户:口令@主机:端口` 或
    /// `http://主机:端口` 这类 URL（会自动取出主机与端口），
    /// 因此可以直接复用系统里已有的代理环境变量。
    ///
    /// ⚠️ 这里**刻意经过生产入口** `crate::proxy::handshake_tcp` / `handshake_udp`
    /// 来驱动本模块的实现，而不是直接调 `connect` / `associate`：
    /// 这样测到的就是生产真正走的链路——协议选择、认证参数组装，以及下面这一层协议实现。
    ///
    /// 生产不使用 SOCKS5 `BIND`（`handshake_tcp` 只发 CONNECT、`handshake_udp` 只发
    /// UDP ASSOCIATE），所以这里不再保留 BIND 的测试。
    /// `connect_no_auth_panic` 需要一台强制认证的代理，故用 `#[ignore]` 标注。
    ///
    /// 代理地址**只从环境变量读取，不设任何硬编码默认值**；环境里没有代理时这些测试会打印说明并跳过。
    fn env_first(names: &[&str]) -> Option<String> {
        names
            .iter()
            .find_map(|name| std::env::var(name).ok())
            .filter(|value| !value.trim().is_empty())
    }

    /// 从 `主机:端口` / `scheme://[用户:口令@]主机:端口[/路径]` 中取出 `主机:端口`
    fn host_port(raw: &str) -> String {
        let s = raw.trim();
        let s = s.split_once("://").map(|(_, rest)| rest).unwrap_or(s);
        let s = s.split(['/', '?', '#']).next().unwrap_or(s);
        s.rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(s)
            .to_string()
    }

    /// 普通（无认证）测试代理地址
    fn proxy_addr() -> Option<String> {
        env_first(&[
            "SMARTDNS_TEST_SOCKS5_PROXY",
            "ALL_PROXY",
            "all_proxy",
            // 系统里常见的代理变量（如 Windows 上的 HTTP_PROXY=http://127.0.0.1:10808）
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
        ])
        .map(|value| host_port(&value))
    }

    /// 需要认证的测试代理地址；未单独指定时退回普通代理地址
    fn proxy_auth_addr() -> Option<String> {
        env_first(&[
            "SMARTDNS_TEST_SOCKS5_PROXY_AUTH",
            "SMARTDNS_TEST_SOCKS5_PROXY",
            "ALL_PROXY",
            "all_proxy",
            // 系统里常见的代理变量（如 Windows 上的 HTTP_PROXY=http://127.0.0.1:10808）
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
        ])
        .map(|value| host_port(&value))
    }

    /// 环境里没配置代理时跳过：本模块测的就是「经代理走 SOCKS5」，没有代理就无从测起。
    /// 这里刻意不回退到任何硬编码地址——硬编码的 127.0.0.1:1080 只对写它的人那台机器有意义，
    /// 换一台机器就变成一条假命题（既可能误报通过，也可能误报失败）。
    fn skip_no_proxy(test: &str) {
        eprintln!(
            "跳过 {test}：环境变量里没有可用代理（可设 SMARTDNS_TEST_SOCKS5_PROXY；也认 ALL_PROXY / HTTP_PROXY / HTTPS_PROXY）"
        );
    }

    /// 组装生产使用的代理配置；`with_auth` 决定是否带上用户名/口令
    /// （与生产一致：`proxy.rs` 只在 `username` 存在时才发认证）。
    fn proxy_config(addr: &str, with_auth: bool) -> ProxyConfig {
        let (username, password) = if with_auth {
            (
                Some(
                    std::env::var("SMARTDNS_TEST_SOCKS5_USER")
                        .unwrap_or_else(|_| "hyper".to_string()),
                ),
                Some(
                    std::env::var("SMARTDNS_TEST_SOCKS5_PASSWORD")
                        .unwrap_or_else(|_| "proxy".to_string()),
                ),
            )
        } else {
            (None, None)
        };

        ProxyConfig {
            proto: ProxyProtocol::Socks5,
            server: addr
                .parse()
                .unwrap_or_else(|_| panic!("代理地址必须是 主机:端口 形式，当前为 {addr:?}")),
            username,
            password,
        }
    }

    /// CONNECT 的探测目标
    fn target_addr() -> SocketAddr {
        std::env::var("SMARTDNS_TEST_SOCKS5_TARGET")
            .unwrap_or_else(|_| "1.1.1.1:443".to_string())
            .parse()
            .unwrap_or_else(|_| panic!("SMARTDNS_TEST_SOCKS5_TARGET 必须是 IP:端口 形式"))
    }

    /// 与生产一致：先连上代理的 TCP，再交给 `handshake_tcp` 完成协议握手与认证
    async fn connect(addr: &str, with_auth: bool) {
        let cfg = proxy_config(addr, with_auth);
        let stream = TcpStream::connect(cfg.server).await.unwrap();
        handshake_tcp(stream, target_addr(), Some(&cfg))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn connect_auth() {
        let Some(addr) = proxy_auth_addr() else {
            return skip_no_proxy("connect_auth");
        };
        connect(&addr, true).await;
    }

    #[tokio::test]
    async fn connect_no_auth() {
        let Some(addr) = proxy_addr() else {
            return skip_no_proxy("connect_no_auth");
        };
        connect(&addr, false).await;
    }

    #[ignore = "需要一台强制用户名/口令认证的 SOCKS5 代理（普通代理不具备该行为）；用 SMARTDNS_TEST_SOCKS5_PROXY_AUTH 指定地址后加 --ignored 运行"]
    #[should_panic = "ConnectionNotAllowedByRules"]
    #[tokio::test]
    async fn connect_no_auth_panic() {
        // 生产行为：未配置用户名时不发认证，遇到强制认证的代理即被拒绝
        let Some(addr) = proxy_auth_addr() else {
            return skip_no_proxy("connect_no_auth_panic");
        };
        connect(&addr, false).await;
    }

    type TestDatagram = SocksDatagram<TcpStream>;
    type TestHalves = (Arc<TestDatagram>, Arc<TestDatagram>);

    trait UdpClient {
        async fn send_to<A>(&self, buf: &[u8], addr: A) -> Result<usize>
        where
            A: Into<AddrKind> + Send;

        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, AddrKind)>;
    }

    impl UdpClient for TestDatagram {
        async fn send_to<A>(&self, buf: &[u8], addr: A) -> Result<usize, Error>
        where
            A: Into<AddrKind> + Send,
        {
            SocksDatagram::send_to(self, buf, addr).await
        }

        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, AddrKind), Error> {
            SocksDatagram::recv_from(self, buf).await
        }
    }

    impl UdpClient for TestHalves {
        async fn send_to<A>(&self, buf: &[u8], addr: A) -> Result<usize, Error>
        where
            A: Into<AddrKind> + Send,
        {
            self.1.send_to(buf, addr).await
        }

        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, AddrKind), Error> {
            self.0.recv_from(buf).await
        }
    }

    /// 客户端与"服务器"都绑随机端口：原来硬编码 127.0.0.1:2345 / :23456，
    /// 两个 UDP 测试并行时会抢同一个端口，导致其中一个 bind 失败。
    const EPHEMERAL_ADDR: &str = "127.0.0.1:0";

    /// 与生产一致：先连上代理的 TCP 控制连接，再交给 `handshake_udp` 完成 UDP ASSOCIATE
    async fn create_client(addr: &str) -> TestDatagram {
        let cfg = proxy_config(addr, false);
        let stream = TcpStream::connect(cfg.server).await.unwrap();
        let socket = UdpSocket::bind(EPHEMERAL_ADDR).await.unwrap();

        match handshake_udp(Some(stream), socket, Some(&cfg))
            .await
            .unwrap()
        {
            ProxyUdpSocket::Proxy(datagram) => datagram,
            ProxyUdpSocket::Tokio(_) => panic!("配置了代理，却拿到直连的 UDP socket"),
        }
    }

    struct UdpTest<C> {
        client: C,
        server: UdpSocket,
        server_addr: AddrKind,
    }

    impl<C: UdpClient> UdpTest<C> {
        async fn test(&self) {
            let mut buf = vec![0; DATA.len()];
            self.client
                .send_to(DATA, self.server_addr.clone())
                .await
                .unwrap();
            let (len, addr) = self.server.recv_from(&mut buf).await.unwrap();
            assert_eq!(len, buf.len());
            assert_eq!(buf.as_slice(), DATA);

            let mut buf = vec![0; DATA.len()];
            self.server.send_to(DATA, addr).await.unwrap();
            let (len, _) = self.client.recv_from(&mut buf).await.unwrap();
            assert_eq!(len, buf.len());
            assert_eq!(buf.as_slice(), DATA);
        }
    }

    impl UdpTest<TestDatagram> {
        async fn datagram(addr: &str) -> Self {
            let client = create_client(addr).await;

            let server = UdpSocket::bind(EPHEMERAL_ADDR).await.unwrap();
            let server_addr = AddrKind::Ip(server.local_addr().unwrap());

            Self {
                client,
                server,
                server_addr,
            }
        }
    }

    impl UdpTest<TestHalves> {
        async fn halves(addr: &str) -> Self {
            let this = UdpTest::<TestDatagram>::datagram(addr).await;
            let client = Arc::new(this.client);
            Self {
                client: (client.clone(), client),
                server: this.server,
                server_addr: this.server_addr,
            }
        }
    }

    /// 与生产一致：经 `handshake_udp` 拿到的 datagram 转发 UDP 报文
    #[tokio::test]
    async fn udp_associate() {
        let Some(addr) = proxy_addr() else {
            return skip_no_proxy("udp_associate");
        };
        UdpTest::datagram(&addr).await.test().await
    }

    /// 生产会把同一个 datagram 共享出去（读写分离），这里验证共享后收发互不干扰
    #[tokio::test]
    async fn udp_datagram_halves() {
        let Some(addr) = proxy_addr() else {
            return skip_no_proxy("udp_datagram_halves");
        };
        UdpTest::halves(&addr).await.test().await
    }
}

#[cfg(test)]
mod p1_9_source_validation_tests {
    use super::*;
    use std::time::Duration;

    /// 造一条 SOCKS5 UDP 数据报：头部声明来源为 src，负载为 payload。
    fn build_datagram(src: &str, payload: &[u8]) -> Vec<u8> {
        let addr = AddrKind::Ip(src.parse().unwrap());
        let mut buf = vec![0u8; payload.len() + 262];
        let header_len =
            SocksDatagram::<tokio::io::DuplexStream>::write_header_sync(&mut buf, &addr);
        buf[header_len..header_len + payload.len()].copy_from_slice(payload);
        buf.truncate(header_len + payload.len());
        buf
    }

    #[tokio::test]
    async fn test_udp_source_validation_drops_spoofed_datagram() {
        // 直接驱动生产代码路径：SocksDatagram::poll_recv_from 里的来源校验（P1-9）
        let before = UDP_SOURCE_REJECTED.load(std::sync::atomic::Ordering::Relaxed);

        let (stream, _keep) = tokio::io::duplex(64);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let dgram = SocksDatagram::from_parts_for_test(
            socket,
            AddrKind::Ip(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 1080)),
            stream,
        );
        dgram.set_expected_source("1.1.1.1:53".parse().unwrap());

        // 第三方套接字发来一条头部声明来源为 9.9.9.9:53 的伪造应答
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(&build_datagram("9.9.9.9:53", b"forged"), local)
            .await
            .unwrap();

        let mut buf = [0u8; 512];
        let res = tokio::time::timeout(Duration::from_millis(300), dgram.recv_from(&mut buf)).await;
        assert!(
            res.is_err(),
            "来源不符的数据报必须被丢弃，实际收到了 {res:?}"
        );
        assert_eq!(
            UDP_SOURCE_REJECTED.load(std::sync::atomic::Ordering::Relaxed) - before,
            1,
            "被丢弃的来源不符数据报必须计数（管理接口要靠它可观测）"
        );

        // 再来一条来源正确的 → 必须正常收到
        peer.send_to(&build_datagram("1.1.1.1:53", b"legit"), local)
            .await
            .unwrap();
        let (n, addr) = tokio::time::timeout(Duration::from_millis(300), dgram.recv_from(&mut buf))
            .await
            .expect("来源正确的数据报必须被接收")
            .unwrap();
        assert_eq!(&buf[..n], b"legit");
        assert_eq!(
            addr,
            AddrKind::Ip("1.1.1.1:53".parse::<SocketAddr>().unwrap())
        );
    }

    #[tokio::test]
    async fn test_no_expected_source_keeps_old_behaviour() {
        // 未登记期望来源时不做过滤（单独使用本类型时的向后兼容）
        let (stream, _keep) = tokio::io::duplex(64);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let dgram = SocksDatagram::from_parts_for_test(
            socket,
            AddrKind::Ip(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 1080)),
            stream,
        );

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(&build_datagram("8.8.8.8:53", b"whatever"), local)
            .await
            .unwrap();

        let mut buf = [0u8; 512];
        let (n, addr) = tokio::time::timeout(Duration::from_millis(300), dgram.recv_from(&mut buf))
            .await
            .expect("未设置期望来源时不应过滤")
            .unwrap();
        assert_eq!(&buf[..n], b"whatever");
        assert_eq!(
            addr,
            AddrKind::Ip("8.8.8.8:53".parse::<SocketAddr>().unwrap())
        );
    }
}
