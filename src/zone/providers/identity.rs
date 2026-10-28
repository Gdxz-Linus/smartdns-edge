use std::net::IpAddr;
use std::sync::Arc;

use crate::dns::{DnsContext, DnsError, DnsRequest, DnsResponse, RData, Record};
use crate::infra::arp::ArpResolver;
use crate::libdns::proto::op::Query;
use crate::libdns::proto::rr::rdata::TXT;
use crate::libdns::proto::rr::{DNSClass, Name, RecordType};

use crate::zone::ZoneProvider;

const UNKNOWN_CLIENT_MAC: &str = "N/A";

/// 🔐 P3-9：身份类 TXT（server-name / version / client-ip / client-mac / whoami 等）
/// 的应答 TTL。原先沿用 `MAX_TTL`（86400 秒）：这些应答是**随客户端与时间变化的
/// 动态数据**（client-ip、client-mac、whoami 随查询方不同而不同），缓存一天意味着
/// 漫游设备换网络后拿到陈旧答案。外部基准：BIND9 的 hostname.bind / version.bind
/// 应答用 TTL 0；这里取 60 秒，动态类得到合理缓存时长，静态类损失一天缓存但无功能影响。
/// C 版没有这组应答（identity 为本项目增强功能），无对照语义可抄。
const IDENTITY_TXT_TTL: u32 = 60;

pub struct IdentityZoneProvider {
    arp_resolver: Arc<ArpResolver>,
}

impl IdentityZoneProvider {
    pub fn new() -> Self {
        Self::with_resolver(Arc::new(ArpResolver::new()))
    }

    pub fn with_resolver(resolver: Arc<ArpResolver>) -> Self {
        Self {
            arp_resolver: resolver,
        }
    }

    async fn get_client_mac(&self, client_ip: IpAddr) -> String {
        self.arp_resolver
            .lookup(client_ip)
            .await
            .unwrap_or_else(|| UNKNOWN_CLIENT_MAC.to_string())
    }
}

#[async_trait::async_trait]
impl ZoneProvider for IdentityZoneProvider {
    async fn lookup(
        &self,
        ctx: &DnsContext,
        req: &DnsRequest,
    ) -> Result<Option<DnsResponse>, DnsError> {
        let query = req.query().original().to_owned();

        if query.query_type() != RecordType::TXT {
            return Ok(None);
        }

        if query.query_class() != DNSClass::CH {
            return Ok(None);
        }

        let query_name = normalize_query_name(query.name());
        let Some(canonical) = translate_query_name(&query_name) else {
            return Ok(None);
        };

        let client_ip = normalize_client_ip(req.src().ip());
        let server_name = trim_fqdn_dot(ctx.cfg().server_name().to_string());

        let res = match canonical {
            CanonicalIdentityQuery::ServerName => txt_response(query, server_name.clone()),
            CanonicalIdentityQuery::ServerVersion => {
                txt_response(query, crate::BUILD_VERSION.to_string())
            }
            CanonicalIdentityQuery::ClientIp => txt_response(query, client_ip.to_string()),

            // 🌟 安全接入：只有在真正需要查 MAC 的记录时，才去触发带有阵列防御的异步引擎！
            CanonicalIdentityQuery::ClientMac => {
                txt_response(query, self.get_client_mac(client_ip).await)
            }
            CanonicalIdentityQuery::WhoAmIJson => txt_response(
                query,
                build_info_json_text(
                    &server_name,
                    crate::BUILD_VERSION,
                    &client_ip,
                    &self.get_client_mac(client_ip).await,
                ),
            ),
            CanonicalIdentityQuery::WhoAmIRecords => txt_records_response(
                query,
                build_info_records_text(
                    &server_name,
                    crate::BUILD_VERSION,
                    &client_ip,
                    &self.get_client_mac(client_ip).await,
                ),
            ),
            CanonicalIdentityQuery::ServerRecords => txt_records_response(
                query,
                build_server_records_text(&server_name, crate::BUILD_VERSION),
            ),
            CanonicalIdentityQuery::ServerJson => txt_response(
                query,
                build_server_json_text(&server_name, crate::BUILD_VERSION),
            ),
        };

        Ok(Some(res))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanonicalIdentityQuery {
    ServerName,
    ServerVersion,
    ClientIp,
    ClientMac,
    WhoAmIRecords,
    WhoAmIJson,
    ServerRecords,
    ServerJson,
}

fn translate_query_name(name: &str) -> Option<CanonicalIdentityQuery> {
    use CanonicalIdentityQuery::*;
    Some(match name {
        // server name
        "server-name." | "hostname.bind." => ServerName,
        // server version
        "version." | "version.bind." => ServerVersion,
        // client ip
        "client_ip." | "client-ip." => ClientIp,
        // client mac
        "client_mac." | "client-mac." => ClientMac,
        // full identity
        "whoami." => WhoAmIRecords,
        "whoami.json." => WhoAmIJson,
        // server identity
        "smartdns." | "id.server." => ServerRecords,
        "smartdns.json." => ServerJson,
        _ => return None,
    })
}

fn normalize_query_name(name: &Name) -> String {
    let mut normalized = name.clone();
    normalized.set_fqdn(true);
    normalized.to_string().to_ascii_lowercase()
}

fn trim_fqdn_dot(name: String) -> String {
    name.trim_end_matches('.').to_string()
}

fn normalize_client_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(addr) => addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4),
        IpAddr::V4(addr) => IpAddr::V4(addr),
    }
}

fn txt_response(query: Query, value: String) -> DnsResponse {
    let mut record = Record::from_rdata(
        query.name().to_owned(),
        IDENTITY_TXT_TTL,
        RData::TXT(TXT::new(vec![value])),
    );
    record.set_dns_class(query.query_class());
    DnsResponse::new_with_max_ttl(query, vec![record])
}

fn txt_records_response(query: Query, values: Vec<String>) -> DnsResponse {
    let records = values
        .into_iter()
        .map(|value| {
            let mut record = Record::from_rdata(
                query.name().to_owned(),
                IDENTITY_TXT_TTL,
                RData::TXT(TXT::new(vec![value])),
            );
            record.set_dns_class(query.query_class());
            record
        })
        .collect::<Vec<_>>();

    DnsResponse::new_with_max_ttl(query, records)
}

fn build_info_records_text(
    server_name: &str,
    version: &str,
    client_ip: &IpAddr,
    client_mac: &str,
) -> Vec<String> {
    vec![
        format!("server_name={server_name}"),
        format!("server_version={version}"),
        format!("client_ip={client_ip}"),
        format!("client_mac={client_mac}"),
    ]
}

fn build_server_records_text(server_name: &str, version: &str) -> Vec<String> {
    vec![
        format!("server_name={server_name}"),
        format!("server_version={version}"),
    ]
}

fn build_info_json_text(
    server_name: &str,
    version: &str,
    client_ip: &IpAddr,
    client_mac: &str,
) -> String {
    serde_json::json!({
        "server_name": server_name,
        "server_version": version,
        "client_ip": client_ip.to_string(),
        "client_mac": client_mac,
    })
    .to_string()
}

fn build_server_json_text(server_name: &str, version: &str) -> String {
    serde_json::json!({
        "server_name": server_name,
        "server_version": version,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn test_translate_query_name_aliases() {
        assert_eq!(
            translate_query_name("hostname.bind."),
            Some(CanonicalIdentityQuery::ServerName)
        );
        assert_eq!(
            translate_query_name("server-name."),
            Some(CanonicalIdentityQuery::ServerName)
        );
        assert_eq!(
            translate_query_name("version.bind."),
            Some(CanonicalIdentityQuery::ServerVersion)
        );
        assert_eq!(
            translate_query_name("client-ip."),
            Some(CanonicalIdentityQuery::ClientIp)
        );
        assert_eq!(
            translate_query_name("client-mac."),
            Some(CanonicalIdentityQuery::ClientMac)
        );
        assert_eq!(
            translate_query_name("whoami."),
            Some(CanonicalIdentityQuery::WhoAmIRecords)
        );
        assert_eq!(
            translate_query_name("smartdns."),
            Some(CanonicalIdentityQuery::ServerRecords)
        );
        assert_eq!(
            translate_query_name("smartdns.json."),
            Some(CanonicalIdentityQuery::ServerJson)
        );
        assert_eq!(translate_query_name("whoami.bind."), None);
        assert_eq!(translate_query_name("whoami.mac.bind."), None);
        assert_eq!(translate_query_name("whoami-mac.smartdns."), None);
        assert_eq!(translate_query_name("unknown."), None);
    }

    #[test]
    fn test_json_output_is_valid() {
        let client_ip: IpAddr = "192.168.1.10".parse().unwrap();
        let info_json =
            build_info_json_text("smartdns '测试'", "v1.0", &client_ip, "aa:bb:cc:dd:ee:ff");
        let info: Value = serde_json::from_str(&info_json).unwrap();
        assert_eq!(info["server_name"], "smartdns '测试'");
        assert_eq!(info["server_version"], "v1.0");
        assert_eq!(info["client_ip"], "192.168.1.10");
        assert_eq!(info["client_mac"], "aa:bb:cc:dd:ee:ff");

        let server_json = build_server_json_text("smartdns '测试'", "v1.0");
        let server: Value = serde_json::from_str(&server_json).unwrap();
        assert_eq!(server["server_name"], "smartdns '测试'");
        assert_eq!(server["server_version"], "v1.0");
    }

    /// 🔐 P3-9：身份类 TXT 的 TTL 必须是短 TTL（60 秒），不得沿用 MAX_TTL（86400）。
    /// 这些应答随客户端与时间变化（client-ip / client-mac / whoami），
    /// 缓存一天会让漫游设备拿到陈旧答案。
    #[test]
    fn test_identity_txt_ttl_is_short() {
        assert_eq!(
            IDENTITY_TXT_TTL, 60,
            "身份类 TXT 的 TTL 固定在 60 秒；改这个值需要显式说明理由"
        );

        // 走一遍真实构造路径验证 TTL 落地（生产同一条代码路径）
        let query = Query::query(Name::from_utf8("hostname.bind.").unwrap(), RecordType::TXT);
        let resp = txt_response(query, "test-server".to_string());
        let answers = resp.answers();
        assert!(!answers.is_empty(), "TXT 应答至少要有一条记录");
        for record in answers {
            assert_eq!(
                record.ttl(),
                IDENTITY_TXT_TTL,
                "TXT 应答的 TTL 必须等于 IDENTITY_TXT_TTL"
            );
        }
    }
}
