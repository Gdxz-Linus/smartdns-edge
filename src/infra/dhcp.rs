use crate::log;
use anyhow::{Result, anyhow};
use cfg_if::cfg_if;
use dhcproto::{Decodable, Encodable, v4};
use netdev::{Interface as NetworkInterface, MacAddr};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

const TIMEOUT: Duration = Duration::from_secs(3);

pub fn find_interface_by_name(name: Option<&str>) -> Result<NetworkInterface> {
    match name {
        Some(name) => netdev::get_interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or(anyhow!("Interface {} not found", name)),
        None => netdev::get_default_interface().map_err(|err| anyhow::anyhow!(err)),
    }
}

async fn send_message(
    mut bind_addr: SocketAddr,
    dst_addr: SocketAddr,
    message: v4::Message,
) -> Result<v4::Message> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;

    socket.set_nonblocking(true)?;

    socket.set_reuse_address(true)?;

    if socket.bind(&bind_addr.into()).is_err() {
        bind_addr.set_port(0);
        socket.bind(&bind_addr.into())?;
    }

    let udp_socket = std::net::UdpSocket::from(socket);

    let udp_socket = UdpSocket::from_std(udp_socket)?;

    if matches!(dst_addr.ip(), IpAddr::V4(ip) if ip.is_broadcast()) {
        udp_socket.set_broadcast(true)?;
    }

    let expected_xid = message.xid();

    udp_socket.send_to(&message.to_vec()?, dst_addr).await?;

    let mut buf = vec![0; 1024];

    // P1-3 / R-P2-12 修复：循环收包并逐包核验，丢弃一切不属于本次事务的包，
    // 直到 3 秒外层超时（discover_v4 的 timeout 包裹）或拿到合法应答为止。
    // 依据 RFC 2131 §4.1：客户端必须用 xid 匹配应答；广播应答的源 IP 可能不是
    // 服务器单播地址，因此只核验来源端口与事务号，不校验来源 IP。
    loop {
        let (n, src) = udp_socket.recv_from(&mut buf[..]).await?;
        match verify_reply(&buf[..n], src, expected_xid) {
            Ok(res) => break Ok(res),
            Err(reason) => {
                log::debug!("dhcp: ignoring packet from {src}: {reason}");
                continue;
            }
        }
    }
}

/// 校验收到的包是否为本次事务的合法 DHCP 应答。
/// 依据 RFC 2131 第 4.1 节：事务号必须匹配；应答必须来自服务器端口 67；包类型必须为 BootReply。
/// 广播应答的源地址可能不是服务器单播地址，因此不校验来源 IP。
fn verify_reply(packet: &[u8], src: SocketAddr, expected_xid: u32) -> Result<v4::Message> {
    if src.port() != 67 {
        return Err(anyhow!("non-server port {}", src.port()));
    }
    if packet.len() < 240 {
        // DHCPv4 报文固定头 + magic cookie 共 240 字节，更短的不可能是合法应答
        return Err(anyhow!("packet too short ({} bytes)", packet.len()));
    }
    let res = v4::Message::from_bytes(packet).map_err(|e| anyhow!("malformed packet: {e}"))?;
    if res.opcode() != v4::Opcode::BootReply {
        return Err(anyhow!("not a BootReply (opcode {:?})", res.opcode()));
    }
    if res.xid() != expected_xid {
        return Err(anyhow!(
            "xid mismatch (got {:x}, want {:x})",
            res.xid(),
            expected_xid
        ));
    }
    Ok(res)
}

fn create_dhcp_v4_discover(mac_addr: MacAddr, broadcast: bool) -> Result<v4::Message> {
    use v4::{DhcpOption, Message, MessageType, OptionCode};
    let mut msg = Message::default();
    msg.set_chaddr(&mac_addr.octets());

    if broadcast {
        msg.set_flags(msg.flags().set_broadcast());
    }

    let mut opts = vec![DhcpOption::MessageType(MessageType::Discover)];

    if let Ok(Ok(host)) = hostname::get().map(|s| s.into_string()) {
        opts.push(DhcpOption::Hostname(host));
    }

    let mut client_identifier = vec![msg.htype().into()];

    client_identifier.extend(mac_addr.octets());

    opts.push(DhcpOption::ClientIdentifier(client_identifier));

    opts.push(DhcpOption::ParameterRequestList(vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::DomainName,
        OptionCode::PerformRouterDiscovery,
        OptionCode::StaticRoutingTable,
        OptionCode::NetBiosNameServers,
        OptionCode::NetBiosNodeType,
        OptionCode::NetBiosScope,
        OptionCode::DomainSearch,
        OptionCode::ClasslessStaticRoute,
        OptionCode::BroadcastAddr,
        OptionCode::TimeOffset,
        OptionCode::Hostname,
    ]));

    opts.push(DhcpOption::End);

    msg.set_opts(opts.into_iter().collect());

    Ok(msg)
}

pub async fn discover_v4(eth_name: Option<&str>) -> Result<v4::Message> {
    let interface = find_interface_by_name(eth_name)?;
    let mac_addr = interface
        .mac_addr
        .ok_or_else(|| anyhow!("No MAC address found for interface"))?;

    let gateway = interface
        .gateway
        .iter()
        .flat_map(|x| x.ipv4.iter())
        .next()
        .cloned()
        .unwrap_or(Ipv4Addr::BROADCAST);

    let mut retry_count = 3;
    while retry_count > 0 {
        match send_discover_v4(mac_addr, gateway).await {
            Ok(msg) => return Ok(msg),
            Err(e) => {
                log::error!("Failed to discover DHCPv4 server: {}", e);
                retry_count -= 1;
                if retry_count == 0 {
                    return Err(e);
                }
                sleep(Duration::from_secs(1)).await; // Wait for a second before retrying
            }
        }
    }
    Err(anyhow!("Failed to discover DHCPv4 server after retries"))
}

cfg_if! {
    if #[cfg(target_os = "macos")] {
        pub async fn send_discover_v4(mac_addr: MacAddr, dst: Ipv4Addr) -> Result<v4::Message> {
            let msg = create_dhcp_v4_discover(mac_addr, false).unwrap();
            let src = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 68);
            let dst = SocketAddr::new(dst.into(), 67);
            let res = timeout(
                TIMEOUT,
                send_message(src,dst,msg),
            )
            .await??;
            Ok(res)
        }
    } else {
        pub async fn send_discover_v4(mac_addr: MacAddr, dst: Ipv4Addr) -> Result<v4::Message> {
            let msg = create_dhcp_v4_discover(mac_addr, false).unwrap();
            let src = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 68);
            let dst = SocketAddr::new(dst.into(), 67);
            let res = timeout(
                TIMEOUT,
                send_message(src,dst,msg),
            )
            .await??;
            Ok(res)
        }
    }
}

pub trait DhcpMessageExt {
    fn nameservers(&self) -> Vec<IpAddr>;
}

impl DhcpMessageExt for v4::Message {
    fn nameservers(&self) -> Vec<IpAddr> {
        use v4::{DhcpOption, OptionCode};
        if let Some(DhcpOption::DomainNameServer(ns)) =
            self.opts().get(OptionCode::DomainNameServer)
        {
            return ns.iter().map(|&ip| ip.into()).collect();
        }
        if let Some(DhcpOption::NameServer(ns)) = self.opts().get(OptionCode::NameServer) {
            return ns.iter().map(|&ip| ip.into()).collect();
        }
        vec![]
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[ignore = "需要局域网内存在真实 DHCP 服务器：本测试会在本机网段实际发出 DHCP DISCOVER"]
    #[tokio::test]
    async fn test_dhcp_get_dns() -> anyhow::Result<()> {
        let msg = discover_v4(None).await?;
        assert!(!msg.nameservers().is_empty());
        Ok(())
    }

    // ── verify_reply 的过滤逻辑单元测试（P1-3 / R-P2-12 修复）──

    use std::net::SocketAddr;

    /// 构造一个最小的合法 DHCP 应答（BootReply + 指定事务号 + Offer）。
    fn valid_reply(xid: u32) -> Vec<u8> {
        let mut msg = v4::Message::default();
        msg.set_opcode(v4::Opcode::BootReply);
        msg.set_xid(xid);
        msg.set_opts(
            vec![v4::DhcpOption::MessageType(v4::MessageType::Offer)]
                .into_iter()
                .collect(),
        );
        msg.to_vec().unwrap()
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn verify_reply_accepts_valid() {
        let packet = valid_reply(0x1234);
        assert!(verify_reply(&packet, loopback(67), 0x1234).is_ok());
    }

    #[test]
    fn verify_reply_rejects_wrong_port() {
        let packet = valid_reply(0x1234);
        assert!(verify_reply(&packet, loopback(68), 0x1234).is_err());
    }

    #[test]
    fn verify_reply_rejects_short_packet() {
        assert!(verify_reply(&[0u8; 100], loopback(67), 0x1234).is_err());
    }

    #[test]
    fn verify_reply_rejects_garbage() {
        // opcode 字节合法，其余全零（magic cookie 不合法）
        let mut packet = vec![0u8; 300];
        packet[0] = 2;
        assert!(verify_reply(&packet, loopback(67), 0x1234).is_err());
    }

    #[test]
    fn verify_reply_rejects_wrong_opcode() {
        // BootRequest 类型的包不应被当作应答
        let mut msg = v4::Message::default();
        msg.set_xid(0x1234);
        let packet = msg.to_vec().unwrap();
        assert!(verify_reply(&packet, loopback(67), 0x1234).is_err());
    }

    #[test]
    fn verify_reply_rejects_mismatched_xid() {
        let packet = valid_reply(0xaaaa);
        assert!(verify_reply(&packet, loopback(67), 0x1234).is_err());
    }
}
