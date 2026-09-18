use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use url::Url;

use anyhow::Result;

use super::{IpNet, NomParser, set_cache::SetCache};

/// IP 集合的取用缓存（与域名集合共用同一套语义，见 `set_cache`）。
static IP_SET_CACHE: SetCache<Vec<IpNet>> = SetCache::new();

/// 一条 IP 集合来源。
///
/// 与域名集合（`domain-set`）保持同样的能力：本地文件 / 远程 URL、可选专用代理、可选自动刷新周期。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpSetProvider {
    File(IpSetFileProvider),
    Http(IpSetHttpProvider),
}

impl IpSetProvider {
    pub fn name(&self) -> &str {
        match self {
            IpSetProvider::File(p) => &p.name,
            IpSetProvider::Http(p) => &p.name,
        }
    }

    /// `-interval`（秒）—— 定时刷新任务按它判断该集合多久重新取一次。
    pub fn interval(&self) -> Option<usize> {
        match self {
            IpSetProvider::File(p) => p.interval,
            IpSetProvider::Http(p) => p.interval,
        }
    }

    /// 把本地文件路径解析成绝对路径后的副本（`-url` 来源原样返回）。
    ///
    /// 为什么要这一步：配置里写 `ip-set -file list.txt` 是相对**当前配置文件所在目录**的，
    /// 与域名集合一致；解析放在"取用"之前，缓存键才是稳定的绝对路径（否则同一份名单
    /// 在不同工作目录下拉起来会被当成两个来源，各下一份）。
    pub fn with_resolved_file(&self, resolve: impl Fn(&Path) -> PathBuf) -> Self {
        match self {
            IpSetProvider::File(p) => IpSetProvider::File(IpSetFileProvider {
                name: p.name.clone(),
                file: resolve(&p.file),
                interval: p.interval,
            }),
            IpSetProvider::Http(p) => IpSetProvider::Http(p.clone()),
        }
    }

    /// 不带缓存的取用：本地文件每次都重读、远程每次都重新下载。
    pub fn get_ip_set(
        &self,
        proxies: &HashMap<String, crate::proxy::ProxyConfig>,
    ) -> Result<Vec<IpNet>> {
        match self {
            IpSetProvider::File(p) => read_ip_set_file(&p.file),
            IpSetProvider::Http(p) => p.download(proxies),
        }
    }

    /// 带 `-interval` 语义的取用（判断逻辑见 `config::set_cache`）：
    /// 未到期直接用缓存、到期才重新取、`force` 强制重新取、取用失败退回上一次的名单。
    pub fn get_ip_set_cached(
        &self,
        proxies: &HashMap<String, crate::proxy::ProxyConfig>,
        force: bool,
    ) -> Result<Vec<IpNet>> {
        match self {
            IpSetProvider::File(p) => {
                let source = p.file.to_string_lossy().into_owned();
                IP_SET_CACHE.get("IpSet", &p.name, &source, p.interval, force, || {
                    read_ip_set_file(&p.file)
                })
            }
            IpSetProvider::Http(p) => {
                IP_SET_CACHE.get("IpSet", &p.name, p.url.as_str(), p.interval, force, || {
                    p.download(proxies)
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSetFileProvider {
    pub name: String,
    pub file: PathBuf,
    /// 自动重新读取该文件的周期（秒）；不配则不自动刷新。
    pub interval: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSetHttpProvider {
    pub name: String,
    pub url: Url,
    /// 自动重新下载的周期（秒）；不配则不自动刷新。
    pub interval: Option<usize>,
    /// 下载该名单时使用的代理名（指向 `proxy-server ... -name <名>` 定义好的代理）。
    pub proxy: Option<String>,
}

impl IpSetHttpProvider {
    fn download(&self, proxies: &HashMap<String, crate::proxy::ProxyConfig>) -> Result<Vec<IpNet>> {
        use crate::infra::http_client::{self, HttpResponse};

        // 只匹配用户显式指定的 proxy 名称（与 ip-set 同款：不偷拿）；
        // 名字写错会**明确告警**并改直连，而不是无声直连（见 `proxy::resolve_proxy`）
        let proxy_str = self
            .proxy
            .as_ref()
            .and_then(|proxy_name| crate::proxy::resolve_proxy(proxies, proxy_name))
            .map(|p| p.to_string());

        let res = http_client::get(self.url.to_string(), proxy_str.as_deref())?;
        let text = res.text()?;
        Ok(parse_ip_set_file(&text).collect())
    }
}

fn read_ip_set_file(file: &Path) -> Result<Vec<IpNet>> {
    let text = std::fs::read_to_string(file)?;
    Ok(parse_ip_set_file(&text).collect())
}

pub fn parse_ip_set_file(text: &str) -> impl Iterator<Item = IpNet> + '_ {
    text.lines()
        .filter_map(|line| Some(IpNet::parse(line.trim_start()).ok()?.1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 名单文本的解析规则：逐行取 IP / 网段，行内多余内容（如 `2.3.4.5/16qwerty`）截到网段为止，
    /// 认不出来的行直接跳过。
    #[test]
    fn test_parse_ip_set_file() {
        let file = "
1.2.3.4
asdfghjkl

2.3.4.5/16qwertyuiop
";

        let mut nets: Vec<String> = parse_ip_set_file(file).map(|net| net.to_string()).collect();
        nets.sort();
        assert_eq!(nets, ["1.2.3.4/32", "2.3.4.5/16"]);
    }

    /// 域名集合那套"带 `-interval` 的取用"语义对 IP 集合同样成立（共用 `set_cache`）。
    /// 这里只验最关键的几条，逻辑本身由 `domain_set` 的用例覆盖。
    #[test]
    fn test_http_provider_fetch_and_interval() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = hits.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                hits_srv.fetch_add(1, Ordering::SeqCst);
                let body = "1.2.3.0/24\n203.0.113.9\n# 注释\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        let provider = IpSetProvider::Http(IpSetHttpProvider {
            name: "ipset-http-test".to_string(),
            url: Url::parse(&format!("http://127.0.0.1:{port}/list.txt")).unwrap(),
            interval: Some(3600),
            proxy: None,
        });
        let proxies: HashMap<String, crate::proxy::ProxyConfig> = Default::default();

        // 第一次：真的去下载，内容按行解析为 IP 网段
        let set = provider.get_ip_set_cached(&proxies, false).unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1, "第一次应发起请求");
        assert!(set.contains(&"1.2.3.0/24".parse().unwrap()));
        assert!(set.contains(&"203.0.113.9/32".parse().unwrap()));
        assert_eq!(set.len(), 2, "注释行不该被当成网段");

        // 未到期：直接用缓存
        provider.get_ip_set_cached(&proxies, false).unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1, "未到期不该再发请求");

        // force（启动 / 手动重载）：强制重新下载
        provider.get_ip_set_cached(&proxies, true).unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2, "force 应强制重新下载");
    }

    /// 本地文件来源：`-interval` 生效时未到期不重读，`force` 时重读；
    /// 文件不存在要如实报错（不能凭空造出空名单）。
    #[test]
    fn test_file_provider_interval_and_missing_file() {
        let dir = std::env::temp_dir().join(format!("ipset-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("list.txt");
        std::fs::write(&file, "10.0.0.0/8\n").unwrap();

        let provider = IpSetProvider::File(IpSetFileProvider {
            name: "ipset-file-test".to_string(),
            file: file.clone(),
            interval: Some(3600),
        });
        let proxies: HashMap<String, crate::proxy::ProxyConfig> = Default::default();

        let set = provider.get_ip_set_cached(&proxies, false).unwrap();
        assert!(set.contains(&"10.0.0.0/8".parse().unwrap()));

        // 未到期：文件改了也先不重读（等 `-interval` 到点）
        std::fs::write(&file, "10.0.0.0/8\n192.168.0.0/16\n").unwrap();
        let cached = provider.get_ip_set_cached(&proxies, false).unwrap();
        assert_eq!(cached.len(), 1, "未到期应沿用上次的结果");

        // force：立刻重读
        let refreshed = provider.get_ip_set_cached(&proxies, true).unwrap();
        assert_eq!(refreshed.len(), 2, "force 应立即重读文件");

        // 文件缺失：如实报错
        let missing = IpSetProvider::File(IpSetFileProvider {
            name: "ipset-file-missing".to_string(),
            file: dir.join("nope.txt"),
            interval: None,
        });
        assert!(missing.get_ip_set_cached(&proxies, true).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
