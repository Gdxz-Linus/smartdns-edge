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

/// hosts 文件的"签名"：一组文件的路径 + 修改时间。
///
/// `Default`（空列表）用于"签名任务失败且尚无缓存"时的退化值 ——
/// 见 `cached_hosts` 里问题 27-5 的处理。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
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
        //
        // 🔐 问题 27-5：**不能把后台任务的失败 unwrap 给请求任务**。
        //
        // 原来这里是 `.await.unwrap()`：`spawn_blocking` 的任务一旦 panic
        // （例如正则回溯、被取消、或将来有人往 `collect_hosts_signature` 里加了会 panic 的东西），
        // `unwrap` 就会把 panic **抛进正在处理客户端查询的任务** ——
        // 表现是"这个客户端超时/被兜底成 SERVFAIL"，而真正的原因在后台线程，日志里对不上。
        //
        // 注意 `collect_hosts_signature` **自身已经吞掉了所有 IO 错误**
        // （glob 失败、metadata 失败都只记日志），所以走到这里的 `Err` 只可能是
        // 任务 panic 或被取消 —— 这两种情况都应当"保持现状"，而不是让请求失败。
        //
        // 处理：拿不到新签名就**沿用缓存里已有的签名**（继续用上次的 hosts 内容），
        // 没有缓存则退化为"空签名"，并限流告警一次让人知道 hosts 刷新出了问题。
        let signature = match tokio::task::spawn_blocking({
            let p_str = pattern_str.clone();
            move || collect_hosts_signature(p_str.as_deref())
        })
        .await
        {
            Ok(sig) => sig,
            Err(err) => {
                if crate::log::warn_once("hosts-signature-task-failed") {
                    crate::log::warn!(
                        "the hosts-file signature task failed ({}); keeping the previously loaded hosts content. \
                         If this repeats, check the hosts file pattern and the log for a task panic",
                        err
                    );
                }
                // 沿用已有签名，让后续比较不会误判成"文件变了"而触发无谓的重新读取
                match self.0.read().await.as_ref() {
                    Some(cache) => cache.signature.clone(),
                    None => HostsFileSignature::default(),
                }
            }
        };

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
            log::debug!(
                "the hosts file read as empty this time; it will be read once more shortly (the file may be mid-replacement)"
            );
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
///
/// 🔐 问题 27-5：任务失败时**退回"没有 hosts"**，而不是把 panic 抛给请求任务。
/// 语义上这是安全的降级：hosts 读不出来时，查询照常走上游解析
/// （`handle` 里 `hosts.lookup_static_host(...)` 返回 `None` 就会 `next.run(...)`），
/// 比"让客户端超时"好得多；同时限流告警，让人知道 hosts 没生效。
async fn read_hosts_blocking(pattern: Option<String>) -> (Hosts, bool) {
    match tokio::task::spawn_blocking(move || match pattern {
        Some(ref pattern) => read_hosts(pattern),
        None => (Hosts::default(), false),
    })
    .await
    {
        Ok(v) => v,
        Err(err) => {
            if crate::log::warn_once("hosts-read-task-failed") {
                crate::log::warn!(
                    "the hosts-file read task failed ({}); falling back to no static hosts for now \
                     (queries still go to the upstreams). If this repeats, check the log for a task panic",
                    err
                );
            }
            (Hosts::default(), false)
        }
    }
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
                            log::error!("cannot read hosts file metadata: {}", err);
                        }
                    }
                }
            }
            Err(err) => {
                log::error!("cannot enumerate hosts file paths: {}", err);
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
                        log::error!("cannot resolve a path matched by {}: {}", pattern, err);
                        continue;
                    }
                };

                let content = match std::fs::read(&path) {
                    Ok(content) => content,
                    Err(err) => {
                        log::error!("cannot read hosts file {}: {}", path.display(), err);
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
            log::error!("cannot list the hosts file directory: {}", err);
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
