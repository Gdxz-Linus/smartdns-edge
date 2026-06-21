use crate::log;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::{io, net::SocketAddr};
use tokio::net::{TcpListener, UdpSocket};

pub fn bind_to<T: LocalAddr>(
    new_socket: impl Fn(SocketAddr, Option<&str>) -> io::Result<T>,
    bind_addr: SocketAddr,
    bind_device: Option<&str>,
    bind_type: &str,
) -> io::Result<T> { // 🌟 修复：返回 io::Result
    let device_note = bind_device
        .map(|device| format!("@{device}"))
        .unwrap_or_default();

    crate::log::debug!("binding {} to {:?}{}", bind_type, bind_addr, device_note);

    match new_socket(bind_addr, bind_device) {
        Ok(socket) => {
            let local_addr = socket.local_addr().unwrap_or(bind_addr); // 降级处理，不 expect
            crate::log::info!(
                "listening for {} on {:?}{}",
                bind_type,
                local_addr,
                device_note
            );
            Ok(socket) // 🌟 成功则包装在 Ok 中
        }
        Err(err) => {
            // 🌟 修复：用 Error 打印日志并向上抛出，绝对不 Panic 杀进程！
            crate::log::error!("could not bind to {bind_type}: {bind_addr}, {err}");
            Err(err)
        }
    }
}

pub fn setup_tcp_socket(
    bind_addr: SocketAddr,
    bind_device: Option<&str>,
) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(bind_addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;

    setup_socket(&socket, bind_device, bind_addr)?;

    socket.listen(128)?;

    let tcp_listener = std::net::TcpListener::from(socket);

    let tcp_listener = TcpListener::from_std(tcp_listener)?;

    Ok(tcp_listener)
}

pub fn setup_udp_socket(bind_addr: SocketAddr, bind_device: Option<&str>) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;

    // 🌟 终极物理层提速：暴力突破系统 UDP 收发缓冲区极限！
    // 默认内核通常只有 64KB~212KB，遇到瞬时高并发或泛洪极易在内核层静默丢包。
    // 我们强行向系统申请 4MB 的超级大信箱（尽最大努力申请，忽略 OS 权限拒绝，能扩多少扩多少）
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);

    setup_socket(&socket, bind_device, bind_addr)?;

    let udp_socket = std::net::UdpSocket::from(socket);

    #[cfg(all(target_os = "windows", target_env = "msvc"))]
    fix_windows_udp(&udp_socket);

    let udp_socket = UdpSocket::from_std(udp_socket)?;

    Ok(udp_socket)
}

#[allow(unused_variables)]
fn setup_socket<'a, T: Into<SockRef<'a>>>(
    socket: T,
    bind_device: Option<&str>,
    bind_addr: SocketAddr,
) -> io::Result<()> {
    let sock_ref: SockRef<'a> = socket.into();
    sock_ref.set_nonblocking(true)?;
    let sock_typ = sock_ref.r#type()?;

    if bind_addr.is_ipv6() {
        sock_ref.set_only_v6(false)?;
    }

    // https://github.com/pymumu/smartdns/blob/e26ecf6a52851f88e2937448019f74b753c0e6dc/src/dns_server/server_socket.c#L111
    if sock_typ == Type::STREAM {
        // enable TCP_FASTOPEN
        sock_ref.set_tcp_nodelay(true)?;
    }

    // 🌟 核心修复 3：严禁 Windows 系统开启端口复用，把防多开的最后一道底线交还给操作系统内核！
    #[cfg(not(windows))]
    sock_ref.set_reuse_address(true)?;

    #[cfg(not(any(
        target_os = "solaris",
        target_os = "illumos",
        target_os = "cygwin",
        target_os = "windows"
    )))]
    sock_ref.set_reuse_port(true)?;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(device) = bind_device {
        sock_ref.bind_device(Some(device.as_bytes()))?;
    }

    sock_ref.bind(&bind_addr.into())?;

    Ok(())
}

/// set UDP_CONNRESET off to ignore UdpSocket's WSAECONNRESET error
#[cfg(all(target_os = "windows", target_env = "msvc"))]
fn fix_windows_udp<T: std::os::windows::io::AsRawSocket>(udp_socket: &T) {
    // https://github.com/mokeyish/smartdns-rs/issues/391
    // https://github.com/shadowsocks/shadowsocks-rust/blob/3b47fa67fac6c2bded73616a284f26c6159cbe9a/src/relay/sys/windows/mod.rs#L17
    use std::ffi::c_void;
    use std::{mem, ptr};
    use windows::Win32::Foundation::FALSE;
    use windows::Win32::Networking::WinSock::{
        SIO_UDP_CONNRESET, SOCKET, SOCKET_ERROR, WSAGetLastError, WSAIoctl,
    };

    let handle = SOCKET(udp_socket.as_raw_socket() as usize);
    let mut bytes_returned: u32 = 0;
    let enable = FALSE;
    unsafe {
        let ret = WSAIoctl(
            handle,
            SIO_UDP_CONNRESET,
            Some(&enable as *const _ as *const c_void),
            mem::size_of_val(&enable) as u32,
            Some(ptr::null_mut()),
            0,
            &mut bytes_returned,
            Some(ptr::null_mut()),
            None,
        );

        if ret == SOCKET_ERROR {
            // ignore the error here, just warn and continue
            let err_code = WSAGetLastError();
            log::warn!("WSAIoctl failed with error code {:?}", err_code);
            // return Err(td::io::Error::from_raw_os_error(err_code.0));
        }
    };
}

pub trait LocalAddr {
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl LocalAddr for TcpListener {
    #[inline]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr()
    }
}

impl LocalAddr for UdpSocket {
    #[inline]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr()
    }
}
