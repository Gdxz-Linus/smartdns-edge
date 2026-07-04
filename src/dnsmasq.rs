use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use std::io::BufRead;

use crate::collections::DomainMap;
use crate::dns::{Name, RData};
use crate::libdns::proto::rr::RecordType;

pub struct LanClientStore {
    zone: Option<Name>,
    file: PathBuf,
    cache: RwLock<Option<LeaseCache>>,
}

struct LeaseCache {
    clients: Arc<DomainMap<ClientInfo>>,
    modified_at: Option<SystemTime>,
    checked_at: Instant,
}

const LEASE_FILE_STAT_INTERVAL: Duration = Duration::from_secs(2);

impl LanClientStore {
    pub fn new<P: AsRef<Path>>(file: P, zone: Option<Name>) -> Self {
        Self {
            zone,
            file: file.as_ref().to_owned(),
            cache: Default::default(),
        }
    }

    async fn cached_clients(&self) -> Option<Arc<DomainMap<ClientInfo>>> {
        let now = Instant::now();

        {
            let cache = self.cache.read().unwrap_or_else(|err| err.into_inner());
            if let Some(cache) = cache.as_ref()
                && now.duration_since(cache.checked_at) < LEASE_FILE_STAT_INTERVAL
            {
                return Some(cache.clients.clone());
            }
        }

        // 🌟 核心修复：把读取硬盘元数据的阻塞操作踢给外包线程池
        let file_path = self.file.clone();
        let modified_at = tokio::task::spawn_blocking(move || {
            std::fs::metadata(&file_path).ok().and_then(|meta| meta.modified().ok())
        }).await.unwrap_or(None);

        {
            let mut cache = self.cache.write().unwrap_or_else(|err| err.into_inner());
            if let Some(cache) = cache.as_mut() {
                if now.duration_since(cache.checked_at) < LEASE_FILE_STAT_INTERVAL {
                    return Some(cache.clients.clone());
                }

                if cache.modified_at == modified_at {
                    cache.checked_at = now;
                    return Some(cache.clients.clone());
                }
            }
        }

        // 🌟 核心修复：把打开文件解析的大量 I/O 操作踢给外包线程池
        let file_path = self.file.clone();
        let zone = self.zone.clone();
        let refreshed = tokio::task::spawn_blocking(move || {
            read_lease_file(&file_path, zone.as_ref()).ok().map(Arc::new)
        }).await.unwrap_or(None);

        let mut cache = self.cache.write().unwrap_or_else(|err| err.into_inner());
        if let Some(clients) = refreshed {
            *cache = Some(LeaseCache {
                clients: clients.clone(),
                modified_at,
                checked_at: now,
            });
            Some(clients)
        } else if let Some(cache) = cache.as_mut() {
            // read failed, keep existing cache and avoid hot-loop retries.
            cache.checked_at = now;
            Some(cache.clients.clone())
        } else {
            None
        }
    }

    // 🌟 返回值改成了 Option<Vec<RData>>，这样就能名正言顺地返回空包了
    pub async fn lookup(&self, name: &Name, record_type: RecordType) -> Option<Vec<RData>> {
        match record_type {
            RecordType::A | RecordType::AAAA => {
                let store = match self.cached_clients().await {
                    Some(v) => v,
                    None => return None,
                };

                let mut name = name.clone();

                if !name.is_fqdn() {
                    if let Some(zone) = self.zone.as_ref() {
                        if let Ok(n) = name.clone().append_name(zone) {
                            name = n;
                        }
                    }
                    name.set_fqdn(true);
                }

                if let Some(client_info) = store.find(&name).or_else(|| match self.zone.as_ref() {
                    Some(z) if !z.zone_of(&name) => {
                        if let Ok(n) = name.append_domain(z) {
                            name = n;
                            store.find(&name)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }) {
                    match client_info.ip {
                        IpAddr::V4(v) if record_type == RecordType::A => Some(vec![RData::A(v.into())]),
                        IpAddr::V6(v) if record_type == RecordType::AAAA => {
                            Some(vec![RData::AAAA(v.into())])
                        }
                        // 🌟 修复炸弹一：设备在这，但你要找的 IP 类型不对（比如内网电脑没有 IPv6）。
                        // 绝对不能返回 None（会流向外网泄露），而是返回空数组 vec![]（原地生成空包）！
                        _ => Some(vec![]),
                    }
                } else {
                    // 内网根本没叫这个名字的设备，安全放行给外网
                    None
                }
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ClientInfo {
    id: String,
    ip: IpAddr,
    host: Name,
    mac: String,
    expires_at: i64, // 🌟 修复时区Bug：直接存最纯粹的 UNIX 时间戳
}

impl ClientInfo {
    #[inline]
    fn is_expired(&self, now_ts: i64) -> bool {
        // 🌟 过期判断：只要大于0 且比当前时间戳小，就是过期了！
        self.expires_at > 0 && self.expires_at < now_ts
    }
}

impl FromStr for ClientInfo {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // skip comments and empty line.
        if matches!(s.chars().next(), Some('#') | None) {
            return Err(());
        }

        let mut parts = s.split(' ').filter(|p| !p.is_empty());

        let timestamp = parts
            .next()
            .and_then(|timestamp| i64::from_str(timestamp).ok())
            .unwrap_or(0); // 🌟 直接用原始时间戳，干干净净

        let mac = match parts.next() {
            Some(v) => v.to_string(),
            None => return Err(()),
        };

        let ip = match parts.next().map(IpAddr::from_str) {
            Some(Ok(v)) => v,
            _ => return Err(()),
        };
        let host = match parts.next().map(Name::from_str) {
            Some(Ok(v)) => v,
            _ => return Err(()),
        };
        let id = match parts.next() {
            Some(v) => v.to_string(),
            None => return Err(()),
        };

        Ok(Self {
            id,
            ip,
            host,
            mac,
            expires_at: timestamp,
        })
    }
}

fn read_lease_file<P: AsRef<Path>>(
    path: P,
    zone: Option<&Name>,
) -> std::io::Result<DomainMap<ClientInfo>> {
    let file = File::open(path.as_ref())?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

    // 🌟 1. 获取当前的时间戳，准备作为“生死审判”的标准
    let now_ts = chrono::Utc::now().timestamp(); 

    for line in reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => continue,
        };

        let line = line.trim_start();

        if matches!(line.chars().next(), Some('#') | None) {
            continue;
        }

        if let Ok(mut client_info) = ClientInfo::from_str(line) {
            // 🌟 2. 核心修复：发现是过期的历史设备，直接忽略（continue），绝不进冰柜！
            if client_info.is_expired(now_ts) { 
                continue; 
            }
			
            if let Some(z) = zone {
                if let Ok(host) = client_info.host.clone().append_name(z) {
                    client_info.host = host;
                }
            }
            client_info.host.set_fqdn(true);
            map.insert(client_info.host.clone().into(), client_info);
        }
    }

    Ok(map.into())
}

#[cfg(test)]
mod tests {

    use crate::libdns::resolver::IntoName;

    use super::*;

    #[test]
    fn parse_client_info() {
        let client_info = ClientInfo::from_str(
            "1702763919 c5:65:92:0b:b5:72 192.168.100.16 Andy-PC 01:c5:65:92:0b:b5:72",
        )
        .unwrap();

        assert_eq!(client_info.expires_at.and_utc().timestamp(), 1702763919);
        assert_eq!(client_info.host, Name::from_str("andy-pc").unwrap());
        assert_eq!(client_info.ip, "192.168.100.16".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_read_dnsmasq_lease_file() {
        let host_ips = read_lease_file("tests/test_data/dhcp.leases", None).unwrap();
        assert_eq!(
            host_ips
                .find(&Name::from_str("Andy-PC").unwrap())
                .map(|x| x.ip),
            Some("192.168.100.16".parse::<IpAddr>().unwrap())
        );

        assert_eq!(
            host_ips
                .find(&Name::from_str("andy-pc").unwrap())
                .map(|x| x.ip),
            Some("192.168.100.16".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            host_ips
                .find(&Name::from_str("iphone-abc").unwrap())
                .map(|x| x.ip),
            Some(
                "2402:4e00:1013:e500:0:9671:f018:4947"
                    .parse::<IpAddr>()
                    .unwrap()
            )
        );
    }

    #[tokio::test]
    async fn test_lan_client_store_lookup() {
        let store = LanClientStore::new("tests/test_data/dhcp.leases", Default::default());

        assert_eq!(
            store.lookup(&"iphone-abc".parse().unwrap(), RecordType::AAAA).await,
            "2402:4e00:1013:e500:0:9671:f018:4947"
                .to_ip()
                .map(|s| s.into())
        );

        assert_eq!(
            store.lookup(&"iphone-abc".parse().unwrap(), RecordType::A).await,
            None
        );
    }

    #[tokio::test]
    async fn test_lan_client_store_lookup_fqdn() {
        let store = LanClientStore::new("tests/test_data/dhcp.leases", Default::default());

        assert_eq!(
            store.lookup(&"iphone-abc.".parse().unwrap(), RecordType::AAAA).await,
            "2402:4e00:1013:e500:0:9671:f018:4947"
                .to_ip()
                .map(|s| s.into())
        );

        assert_eq!(
            store.lookup(&"iphone-abc.".parse().unwrap(), RecordType::A).await, 
            None
        );
    }

    #[tokio::test]
    async fn test_lan_client_store_lookup_zone() {
        let store = LanClientStore::new("tests/test_data/dhcp.leases", Name::from_str("xyz").ok());

        assert_eq!(
            store.lookup(&"iphone-abc.xyz.".parse().unwrap(), RecordType::AAAA).await,
            "2402:4e00:1013:e500:0:9671:f018:4947"
                .to_ip()
                .map(|s| s.into())
        );

        assert_eq!(
            store.lookup(&"iphone-abc.xyz.".parse().unwrap(), RecordType::A).await,
            None
        );
    }
}
