use std::sync::Arc;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use crate::libdns::proto::op::Query;
use tokio::sync::RwLock;

use crate::libdns::resolver::Hosts;
use crate::middleware::*;
use crate::{dns::*, log};

pub struct DnsHostsMiddleware(RwLock<Option<HostsCache>>);

struct HostsCache {
    hosts: Arc<Hosts>,
    signature: HostsFileSignature,
    checked_at: Instant,
    /// 🔐 P2：这份缓存是不是"读到了非空白内容"。用来识别"文件正在被原子替换时读到的空结果"。
    has_content: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostsFileSignature {
    files: Vec<HostsFileMeta>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostsFileMeta {
    path: PathBuf,
    modified_at: Option<SystemTime>,
}

impl DnsHostsMiddleware {
    pub fn new() -> Self {
        Self(Default::default())
    }

    async fn cached_hosts(&self, hosts_file_pattern: Option<&glob::Pattern>) -> Arc<Hosts> {
        let now = Instant::now();

        {
            let cache = self.0.read().await;
            if let Some(cache) = cache.as_ref()
                && now.duration_since(cache.checked_at) < HOSTS_FILE_STAT_INTERVAL
            {
                return cache.hosts.clone();
            }
        }

        // 把 pattern 转换为字符串，用于跨线程传递
        let pattern_str = hosts_file_pattern.map(|p| p.as_str().to_string());

        // 🌟 核心修复：外包签名收集（含阻塞的 fs::metadata）
        let signature = tokio::task::spawn_blocking({
            let p_str = pattern_str.clone();
            move || collect_hosts_signature(p_str.as_deref())
        })
        .await
        .unwrap();

        {
            let mut cache = self.0.write().await;
            if let Some(cache) = cache.as_mut() {
                if now.duration_since(cache.checked_at) < HOSTS_FILE_STAT_INTERVAL {
                    return cache.hosts.clone();
                }
                if cache.signature == signature {
                    cache.checked_at = now;
                    return cache.hosts.clone();
                }
            }
        }

        // 🔐 P2：hosts 文件被"原子替换"（写新文件 + rename）的瞬间，轮询恰好读到的是空文件。
        // 原实现直接拿它覆盖缓存 → 内网域名突然全部转去公网解析。
        // 现在的处理（同目录 dnsmasq 的实现也是保守的）：读到空内容而旧缓存是有内容的，
        // 就稍等 200ms 再读一次；两次都空才认账 —— 这样"用户真的清空了 hosts"依然能生效。
        let prev_has_content = self.0.read().await.as_ref().is_some_and(|c| c.has_content);

        let (mut refreshed, mut has_content) = read_hosts_blocking(pattern_str.clone()).await;

        if !has_content && prev_has_content {
            log::debug!("the hosts file read as empty this time; it will be read once more shortly (the file may be mid-replacement)");
            tokio::time::sleep(Duration::from_millis(200)).await;
            let (hosts2, content2) = read_hosts_blocking(pattern_str.clone()).await;
            refreshed = hosts2;
            has_content = content2;

            if !has_content {
                log::warn!(
                    "the hosts file read as empty twice in a row and is treated as empty (check the hosts-file setting if this is unexpected)"
                );
            }
        }

        let refreshed_hosts = Arc::new(refreshed);
        let mut cache = self.0.write().await;
        *cache = Some(HostsCache {
            hosts: refreshed_hosts.clone(),
            signature,
            checked_at: now,
            has_content,
        });
        refreshed_hosts
    }
}

/// 在阻塞线程里读 hosts（`read_hosts` 里有文件 IO）。
async fn read_hosts_blocking(pattern: Option<String>) -> (Hosts, bool) {
    tokio::task::spawn_blocking(move || match pattern {
        Some(ref pattern) => read_hosts(pattern),
        None => (Hosts::default(), false),
    })
    .await
    .unwrap()
}

const HOSTS_FILE_STAT_INTERVAL: Duration = Duration::from_secs(2);

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsHostsMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query = req.query().original();
        let is_ptr = query.query_type() == RecordType::PTR && ctx.cfg().expand_ptr_from_address();
        if query.query_type().is_ip_addr() || is_ptr {
            let hosts = self.cached_hosts(ctx.cfg().hosts_file()).await;

            if let Some(lookup) = hosts.lookup_static_host(query).or_else(|| {
                let mut name = query.name().clone();
                name.set_fqdn(!name.is_fqdn());
                hosts.lookup_static_host(&Query::query(name, query.query_type()))
            }) {
                return Ok(DnsResponse::new_with_deadline(
                    query.clone(),
                    lookup.records().to_vec(),
                    lookup.valid_until(),
                ));
            }
        }

        next.run(ctx, req).await
    }
}

fn collect_hosts_signature(hosts_file_pattern: Option<&str>) -> HostsFileSignature {
    let mut files = Vec::new();

    if let Some(pattern) = hosts_file_pattern {
        match glob::glob(pattern) {
            Ok(paths) => {
                for entry in paths {
                    match entry {
                        Ok(path) => {
                            append_hosts_file_meta(path.as_path(), &mut files);
                        }
                        Err(err) => {
                            log::error!("{}", err);
                        }
                    }
                }
            }
            Err(err) => {
                log::error!("{}", err);
            }
        }
    }

    for path in system_hosts_paths() {
        append_hosts_file_meta(Path::new(&path), &mut files);
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));
    files.dedup_by(|a, b| a.path == b.path);
    HostsFileSignature { files }
}

fn append_hosts_file_meta(path: &Path, files: &mut Vec<HostsFileMeta>) {
    if !path.is_file() {
        return;
    }

    let modified_at = std::fs::metadata(path)
        .ok()
        .and_then(|meta| meta.modified().ok());

    files.push(HostsFileMeta {
        path: path.to_path_buf(),
        modified_at,
    });
}

#[cfg(unix)]
fn system_hosts_paths() -> Vec<String> {
    vec!["/etc/hosts".to_string()]
}

#[cfg(windows)]
fn system_hosts_paths() -> Vec<String> {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    vec![format!("{}\\System32\\drivers\\etc\\hosts", sys_root)]
}

#[cfg(not(any(unix, windows)))]
fn system_hosts_paths() -> Vec<String> {
    Vec::new()
}

fn read_hosts(pattern: &str) -> (Hosts, bool) {
    let mut hosts = Hosts::default();
    // 🔐 P2：是否读到过非空白内容（用来识别"原子替换瞬间读到的空文件"）
    let mut has_content = false;
    match glob::glob(pattern) {
        Ok(paths) => {
            for entry in paths {
                let path = match entry {
                    Ok(path) => {
                        if !path.is_file() {
                            continue;
                        }
                        path
                    }
                    Err(err) => {
                        log::error!("{}", err);
                        continue;
                    }
                };

                let content = match std::fs::read(&path) {
                    Ok(content) => content,
                    Err(err) => {
                        log::error!("{}", err);
                        continue;
                    }
                };

                if content.iter().any(|b| !b.is_ascii_whitespace()) {
                    has_content = true;
                }

                if let Err(err) = hosts.read_hosts_conf(&content[..]) {
                    log::error!("{}", err);
                }
            }
        }
        Err(err) => {
            log::error!("{}", err);
        }
    }
    (hosts, has_content)
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        path::{Path, PathBuf},
        str::FromStr,
        time::Duration,
    };

    use crate::libdns::proto::rr::rdata::PTR;

    use super::*;

    use crate::{dns_conf::RuntimeConfig, dns_mw::*};

    /// 🔐 P2：空 hosts 文件必须能被识别出来 —— 它是"文件正在被原子替换时读到空结果"
    /// 这套保守处理的判据。
    #[test]
    fn test_read_hosts_reports_content() -> anyhow::Result<()> {
        let dir = TempDirGuard::new("hosts-content")?;

        let empty = dir.path.join("empty.hosts");
        std::fs::write(&empty, b"\n   \n")?;
        let (_, has_content) = read_hosts(empty.to_str().unwrap());
        assert!(
            !has_content,
            "只有空白的 hosts 文件应报告 has_content=false"
        );

        let filled = dir.path.join("filled.hosts");
        std::fs::write(&filled, b"127.0.0.1  p2-test.local\n")?;
        let (_, has_content) = read_hosts(filled.to_str().unwrap());
        assert!(has_content, "有内容的 hosts 文件应报告 has_content=true");

        Ok(())
    }

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(prefix: &str) -> anyhow::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "{}-{}-{}",
                prefix,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[tokio::test()]
    async fn test_query_ip() -> anyhow::Result<()> {
        let cfg = RuntimeConfig::builder()
            .with("hosts-file ./tests/test_data/hosts/a*.hosts")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(DnsHostsMiddleware::new()).build(cfg);

        let lookup = mock.lookup("hi.a1", RecordType::A).await?;
        let ip_addrs = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().ip_addr())
            .collect::<Vec<_>>();
        assert_eq!(ip_addrs, vec![IpAddr::from_str("1.1.1.1").unwrap()]);

        let lookup = mock.lookup("hi.a2", RecordType::A).await?;
        let ip_addrs = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().ip_addr())
            .collect::<Vec<_>>();
        assert_eq!(ip_addrs, vec![IpAddr::from_str("2.2.2.2").unwrap()]);

        Ok(())
    }

    #[tokio::test()]
    async fn test_query_ptr() -> anyhow::Result<()> {
        let cfg = RuntimeConfig::builder()
            .with("hosts-file ./tests/test_data/hosts/a*.hosts")
            .with("expand-ptr-from-address yes")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(DnsHostsMiddleware::new()).build(cfg);

        let lookup = mock
            .lookup("1.1.1.1.in-addr.arpa.", RecordType::PTR)
            .await?;
        let hostnames = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().as_ptr())
            .collect::<Vec<_>>();
        assert_eq!(hostnames, vec![&PTR("hi.a1.".parse().unwrap())]);

        let lookup = mock
            .lookup("2.2.2.2.in-addr.arpa.", RecordType::PTR)
            .await?;
        let hostnames = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().as_ptr())
            .collect::<Vec<_>>();
        assert_eq!(hostnames, vec![&PTR("hi.a2.".parse().unwrap())]);

        Ok(())
    }

    #[tokio::test()]
    async fn test_hosts_cache_refresh_on_file_change() -> anyhow::Result<()> {
        let temp_dir = TempDirGuard::new("smartdns-hosts-refresh-test")?;
        let hosts_file = temp_dir.path().join("hosts");
        std::fs::write(&hosts_file, "1.1.1.1 host-refresh\n")?;

        let config_line = format!("hosts-file {}", hosts_file.display());
        let cfg = RuntimeConfig::builder()
            .with(config_line.as_str())
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(DnsHostsMiddleware::new()).build(cfg);

        let lookup = mock.lookup("host-refresh", RecordType::A).await?;
        let ip_addrs = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().ip_addr())
            .collect::<Vec<_>>();
        assert_eq!(ip_addrs, vec![IpAddr::from_str("1.1.1.1").unwrap()]);

        tokio::time::sleep(HOSTS_FILE_STAT_INTERVAL + Duration::from_secs(1)).await;
        std::fs::write(&hosts_file, "2.2.2.2 host-refresh\n")?;
        tokio::time::sleep(HOSTS_FILE_STAT_INTERVAL + Duration::from_secs(1)).await;

        let lookup = mock.lookup("host-refresh", RecordType::A).await?;
        let ip_addrs = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().ip_addr())
            .collect::<Vec<_>>();
        assert_eq!(ip_addrs, vec![IpAddr::from_str("2.2.2.2").unwrap()]);
        Ok(())
    }
}
