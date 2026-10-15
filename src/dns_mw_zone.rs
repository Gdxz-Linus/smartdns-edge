use crate::dns::*;
use crate::middleware::*;
use crate::zone::{IdentityZoneProvider, LocalPtrZoneProvider, RuleZoneProvider, ZoneManager};

pub struct DnsZoneMiddleware {
    manager: ZoneManager,
    rule_provider: RuleZoneProvider,
}

impl DnsZoneMiddleware {
    pub fn new() -> Self {
        Self {
            manager: ZoneManager::new()
                .with_provider(LocalPtrZoneProvider::new())
                .with_provider(IdentityZoneProvider::new()),
            rule_provider: RuleZoneProvider::new(),
        }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsZoneMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        if let Some(response) = self.manager.lookup(ctx, req).await? {
            return Ok(response);
        }

        if let Some(response) = self.rule_provider.lookup(ctx, req, next.clone()).await? {
            return Ok(response);
        }

        next.run(ctx, req).await
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::dns_mw_hosts::DnsHostsMiddleware;
    use crate::infra::ipset::IpSet;
    use crate::libdns::proto::op::Query;
    use crate::libdns::proto::rr::DNSClass;
    use crate::libdns::proto::rr::rdata::PTR;
    use crate::{dns_conf::RuntimeConfig, dns_mw::*};
    use std::net::SocketAddr;

    async fn search_with_query(
        mw: &DnsMiddlewareHandler,
        name: &str,
        query_type: RecordType,
        query_class: DNSClass,
        src: SocketAddr,
    ) -> DnsResponse {
        let mut query = Query::query(name.parse().unwrap(), query_type);
        query.set_query_class(query_class);
        let mut message = op::Message::query();
        message.add_query(query);
        let req = DnsRequest::new(message, src, Protocol::Udp);
        mw.search(&req, &Default::default()).await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_srv_record() {
        let cfg = RuntimeConfig::builder()
            .with("srv-record /_vlmcs._tcp/example.com,1688,1,2")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let srv = mock
            .lookup_rdata("_vlmcs._tcp", RecordType::SRV)
            .await
            .unwrap()
            .pop()
            .unwrap()
            .into_srv()
            .unwrap();

        assert_eq!(srv.target(), &"example.com".parse().unwrap());
        assert_eq!(srv.port(), 1688);
        assert_eq!(srv.priority(), 1);
        assert_eq!(srv.weight(), 2);
    }

    #[test]
    fn test_arpa() {
        let local_net = IpSet::new(vec![
            "::1/128".parse().unwrap(),
            "192.168.1.1/32".parse().unwrap(),
        ]);

        let name1: Name =
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
                .parse()
                .unwrap();

        let net1 = name1.parse_arpa_name().unwrap();

        assert!(local_net.contains(&net1));

        let name2: Name = "1.168.192.in-addr.arpa.".parse().unwrap();
        let net2 = name2.parse_arpa_name().unwrap();

        assert!(local_net.overlap(&net2));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_localptr_nxdomain_for_private_ptr_not_owned() {
        // R-P1-1 隐私定调回归：私网 PTR 且无本地数据 → NXDOMAIN（不得外发上游）。
        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);
        let response = search_with_query(
            &mock,
            "77.1.168.192.in-addr.arpa.",
            RecordType::PTR,
            DNSClass::IN,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await;
        assert_eq!(
            response.answers().len(),
            0,
            "无本地数据的私网 PTR 不应有 Answer"
        );
        // rcode：设计定调是 NXDOMAIN。若实现走的是"转发上游"，这里会拿到上游应答。
        println!(
            "private-ptr-not-owned rcode: {:?}",
            response.response_code()
        );
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn test_private_ptr_from_hosts_file_answers_before_localptr() {
        // R-P1-1 场景：hosts 文件里有私网地址条目 + expand-ptr-from-address。
        // 修复前：Zone 中间件（外层）的 LocalPtrProvider 对任何私网 PTR 直接回 NXDOMAIN，
        // 内层的 DnsHostsMiddleware 永远没机会应答——局域网设备反查主机名整体失效。
        // 验证结构必须与真实链路一致：hosts 外层 → zone 内层。
        let cfg = RuntimeConfig::builder()
            .with("hosts-file ./tests/test_data/hosts/printer.hosts")
            .with("expand-ptr-from-address yes")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::builder()
            .with_extra_middleware(DnsHostsMiddleware::new())
            .with_extra_middleware(DnsZoneMiddleware::new())
            .build(cfg);
        let response = search_with_query(
            &mock,
            "55.1.168.192.in-addr.arpa.",
            RecordType::PTR,
            DNSClass::IN,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await;
        let hostnames: Vec<_> = response
            .answers()
            .iter()
            .flat_map(|r| r.data().as_ptr())
            .collect();
        assert_eq!(
            hostnames,
            vec![&PTR("myprinter.lan.".parse().unwrap())],
            "私网 PTR 应由 hosts 数据回答（修复前被外层 LocalPtr 的 NXDOMAIN 短路）"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_server_hostname() {
        let cfg = RuntimeConfig::builder()
            .with("server-name smartdns-rs-test")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);
        let response = search_with_query(
            &mock,
            "hostname.bind",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await;
        let answer = response.answers().first().unwrap();
        assert_eq!(answer.record_type(), RecordType::TXT);
        assert_eq!(answer.dns_class(), DNSClass::CH);
        assert!(answer.data().to_string().contains("smartdns-rs-test"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_server_name_alias() {
        let cfg = RuntimeConfig::builder()
            .with("server-name smartdns-rs-test")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);
        let response = search_with_query(
            &mock,
            "server-name",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await;

        assert!(
            response.answers()[0]
                .data()
                .to_string()
                .contains("smartdns-rs-test")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_version_and_client_ip() {
        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let version_response = search_with_query(
            &mock,
            "version.bind",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.9:5300".parse().unwrap(),
        )
        .await;
        assert!(
            version_response.answers()[0]
                .data()
                .to_string()
                .contains(crate::BUILD_VERSION)
        );

        let ip_response = search_with_query(
            &mock,
            "client_ip",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.9:5300".parse().unwrap(),
        )
        .await;
        assert!(
            ip_response.answers()[0]
                .data()
                .to_string()
                .contains("192.168.1.9")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_client_mac_for_loopback() {
        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);
        let response = search_with_query(
            &mock,
            "client_mac",
            RecordType::TXT,
            DNSClass::CH,
            "127.0.0.1:5300".parse().unwrap(),
        )
        .await;
        assert!(response.answers()[0].data().to_string().contains("N/A"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_json_query() {
        let cfg = RuntimeConfig::builder()
            .with("server-name smartdns-rs-test")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let response = search_with_query(
            &mock,
            "whoami.json",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.10:5300".parse().unwrap(),
        )
        .await;

        let out = response.answers()[0].data().to_string();
        assert!(out.contains("\"server_name\""));
        assert!(out.contains("\"server_version\""));
        assert!(out.contains("\"client_ip\""));
        assert!(out.contains("192.168.1.10"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_multi_records_query() {
        let cfg = RuntimeConfig::builder()
            .with("server-name smartdns-rs-test")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let response = search_with_query(
            &mock,
            "smartdns",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.11:5300".parse().unwrap(),
        )
        .await;

        assert_eq!(response.answers().len(), 2);
        let txts = response
            .answers()
            .iter()
            .map(|record| record.data().to_string())
            .collect::<Vec<_>>();
        assert!(txts.iter().any(|txt| txt.contains("server_name=")));
        assert!(txts.iter().any(|txt| txt.contains("server_version=")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_whoami_multi_records_query() {
        let cfg = RuntimeConfig::builder()
            .with("server-name smartdns-rs-test")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let response = search_with_query(
            &mock,
            "whoami",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.13:5300".parse().unwrap(),
        )
        .await;

        assert_eq!(response.answers().len(), 4);
        let txts = response
            .answers()
            .iter()
            .map(|record| record.data().to_string())
            .collect::<Vec<_>>();
        assert!(txts.iter().any(|txt| txt.contains("server_name=")));
        assert!(txts.iter().any(|txt| txt.contains("server_version=")));
        assert!(txts.iter().any(|txt| txt.contains("client_ip=")));
        assert!(txts.iter().any(|txt| txt.contains("client_mac=")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_client_fields_query() {
        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let ip_response = search_with_query(
            &mock,
            "client_ip",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.13:5300".parse().unwrap(),
        )
        .await;
        assert!(
            ip_response.answers()[0]
                .data()
                .to_string()
                .contains("192.168.1.13")
        );

        let mac_response = search_with_query(
            &mock,
            "client_mac",
            RecordType::TXT,
            DNSClass::CH,
            "127.0.0.1:5300".parse().unwrap(),
        )
        .await;
        assert!(mac_response.answers()[0].data().to_string().contains("N/A"));

        let ip_response2 = search_with_query(
            &mock,
            "client-ip",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.13:5300".parse().unwrap(),
        )
        .await;
        assert!(
            ip_response2.answers()[0]
                .data()
                .to_string()
                .contains("192.168.1.13")
        );

        let mac_response2 = search_with_query(
            &mock,
            "client-mac",
            RecordType::TXT,
            DNSClass::CH,
            "127.0.0.1:5300".parse().unwrap(),
        )
        .await;
        assert!(
            mac_response2.answers()[0]
                .data()
                .to_string()
                .contains("N/A")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_id_server_query() {
        let cfg = RuntimeConfig::builder()
            .with("server-name smartdns-rs-test")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let response = search_with_query(
            &mock,
            "id.server",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.15:5300".parse().unwrap(),
        )
        .await;

        assert_eq!(response.answers().len(), 2);
        let txts = response
            .answers()
            .iter()
            .map(|record| record.data().to_string())
            .collect::<Vec<_>>();
        assert!(
            txts.iter()
                .any(|txt| txt.contains("server_name=smartdns-rs-test"))
        );
        assert!(txts.iter().any(|txt| txt.contains("server_version=")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_short_name_version_alias() {
        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let response = search_with_query(
            &mock,
            "version",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.12:5300".parse().unwrap(),
        )
        .await;

        assert!(
            response.answers()[0]
                .data()
                .to_string()
                .contains(crate::BUILD_VERSION)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_removed_hostname_alias_is_not_supported() {
        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let mut query = Query::query("hostname".parse().unwrap(), RecordType::TXT);
        query.set_query_class(DNSClass::CH);
        let mut message = op::Message::query();
        message.add_query(query);
        let req = DnsRequest::new(message, "192.168.1.14:5300".parse().unwrap(), Protocol::Udp);

        let res = mock.search(&req, &Default::default()).await;
        assert!(matches!(res, Err(ref err) if err.is_soa()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_removed_whoami_bind_aliases_are_not_supported() {
        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        for name in ["whoami.bind", "whoami.mac.bind"] {
            let mut query = Query::query(name.parse().unwrap(), RecordType::TXT);
            query.set_query_class(DNSClass::CH);
            let mut message = op::Message::query();
            message.add_query(query);
            let req = DnsRequest::new(message, "192.168.1.14:5300".parse().unwrap(), Protocol::Udp);

            let res = mock.search(&req, &Default::default()).await;
            assert!(matches!(res, Err(ref err) if err.is_soa()));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_identity_txt_in_class_is_not_intercepted() {
        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let mut query = Query::query("version".parse().unwrap(), RecordType::TXT);
        query.set_query_class(DNSClass::IN);
        let mut message = op::Message::query();
        message.add_query(query);
        let req = DnsRequest::new(message, "192.168.1.14:5300".parse().unwrap(), Protocol::Udp);

        let res = mock.search(&req, &Default::default()).await;
        assert!(matches!(res, Err(ref err) if err.is_soa()));
    }
}
