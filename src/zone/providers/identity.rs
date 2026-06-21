use std::net::IpAddr;
use std::sync::Arc;

use crate::dns::{DnsContext, DnsError, DnsRequest, DnsResponse, RData, Record};
use crate::infra::arp::lookup_client_mac_from_arp;
use crate::libdns::proto::op::Query;
use crate::libdns::proto::rr::rdata::TXT;
use crate::libdns::proto::rr::{DNSClass, Name, RecordType};

use crate::zone::ZoneProvider;

const UNKNOWN_CLIENT_MAC: &str = "N/A";

pub struct IdentityZoneProvider {
    // 🌟 一级防御：全局 LRU 缓存，容量 4096，生存期 60 秒
    arp_cache: Arc<std::sync::Mutex<lru::LruCache<IpAddr, (String, std::time::Instant)>>>,
    // 🌟 二级防御：基于 IP 的 Single-Flight 并发折叠状态表，彻底消除全局锁
    inflight_arp: Arc<std::sync::Mutex<std::collections::HashMap<IpAddr, tokio::sync::broadcast::Sender<String>>>>,
}

impl IdentityZoneProvider {
    pub fn new() -> Self {
        Self {
            arp_cache: Arc::new(std::sync::Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(4096).unwrap(),
            ))),
            inflight_arp: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    // 🌟 核心防御引擎：Single-Flight 并发请求折叠
    async fn get_client_mac(&self, client_ip: IpAddr) -> String {
        let now = std::time::Instant::now();
        
        // 1. 无锁光速尝试读取缓存
        {
            let mut cache = self.arp_cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((mac, expire_at)) = cache.get(&client_ip) {
                if now < *expire_at {
                    return mac.clone();
                }
            }
        }

        // 2. 缓存穿透，准备请求操作系统。
        // 🚨 核心拦截：按 IP 分离的底层收费站！查询相同 IP 的兄弟发对讲机并挂起，查询不同 IP 的直接放行！
        let rx = {
            let mut map = self.inflight_arp.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.get(&client_ip) {
                Some(tx.subscribe()) // 已经有人去查这个 IP 了，领个对讲机坐板凳等结果
            } else {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                map.insert(client_ip, tx);
                None // 我是第一个到的，我负责去执行耗时的 OS 命令
            }
        };

        if let Some(mut receiver) = rx {
            // 坐在板凳上等待复印件，绝对不发起系统调用！
            return match receiver.recv().await {
                Ok(mac) => mac,
                Err(_) => UNKNOWN_CLIENT_MAC.to_string(), // 意外兜底
            };
        }

        // 🌟 3. 给天选之子发放生命周期智能工牌，防止中途异常 panic 导致对讲机永远不响应
        struct InflightArpGuard {
            inflight: Arc<std::sync::Mutex<std::collections::HashMap<IpAddr, tokio::sync::broadcast::Sender<String>>>>,
            ip: IpAddr,
            done: bool,
        }
        impl Drop for InflightArpGuard {
            fn drop(&mut self) {
                if !self.done {
                    let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(tx) = map.remove(&self.ip) {
                        let _ = tx.send(UNKNOWN_CLIENT_MAC.to_string());
                    }
                }
            }
        }

        let mut inflight_guard = InflightArpGuard {
            inflight: self.inflight_arp.clone(),
            ip: client_ip,
            done: false,
        };

        // 4. 扔到 blocking 线程池，绝不挂起 Tokio 主线程！
        let fetched_mac = tokio::task::spawn_blocking(move || {
            lookup_client_mac_from_arp(client_ip)
        })
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| UNKNOWN_CLIENT_MAC.to_string());

        // 5. 拿到结果，先存入冰柜造福后续请求
        {
            let mut cache = self.arp_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.put(client_ip, (fetched_mac.clone(), std::time::Instant::now() + std::time::Duration::from_secs(60)));
        }

        // 6. 用对讲机广播复印件给所有坐在板凳上等待的兄弟，并销毁频道
        {
            let mut map = self.inflight_arp.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.remove(&client_ip) {
                let _ = tx.send(fetched_mac.clone());
            }
        }
        inflight_guard.done = true; // 宣告安全下班

        fetched_mac
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
            CanonicalIdentityQuery::ClientMac => txt_response(query, self.get_client_mac(client_ip).await),
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
        crate::dns_client::MAX_TTL,
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
                crate::dns_client::MAX_TTL,
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
}
