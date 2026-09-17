use enum_dispatch::enum_dispatch;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
};
use url::Url;

use anyhow::Result;

use super::{WildcardName, set_cache::SetCache};

/// 域名集合的取用缓存（与 IP 集合共用同一套语义，见 `set_cache`）。
static DOMAIN_SET_CACHE: SetCache<HashSet<WildcardName>> = SetCache::new();

#[enum_dispatch(IDomainSetProvider)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainSetProvider {
    File(DomainSetFileProvider),
    Http(DomainSetHttpProvider),
}

#[enum_dispatch]
pub trait IDomainSetProvider {
    fn name(&self) -> &str;

    // 🌟 核心修复 1：打通参数管道，允许传入代理池
    fn get_domain_set(
        &self,
        proxies: &HashMap<String, crate::proxy::ProxyConfig>,
    ) -> Result<HashSet<WildcardName>>;

    /// 带 `-interval` 语义的取名单（判断逻辑见 `config::set_cache`）。
    /// `force` = 忽略内存缓存、强制重新取（启动与手动重载用）。
    fn get_domain_set_cached(
        &self,
        proxies: &HashMap<String, crate::proxy::ProxyConfig>,
        force: bool,
    ) -> Result<HashSet<WildcardName>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSetFileProvider {
    pub name: String,
    pub file: PathBuf,
    /// 🔐 P2：自动重新读取该文件的周期（秒）。本项内容同样是在配置构建时展开进规则树的，
    /// 所以"文件变了要生效"同样需要定期重建配置 —— 与 HTTP 名单同一套机制。
    pub interval: Option<usize>,
    pub content_type: DomainSetContentType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSetHttpProvider {
    pub name: String,
    pub url: Url,
    pub interval: Option<usize>,
    pub content_type: DomainSetContentType,
    pub proxy: Option<String>, // 🌟 新增：专属代理参数
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DomainSetContentType {
    #[default]
    List,
}

impl IDomainSetProvider for DomainSetFileProvider {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn get_domain_set(
        &self,
        _proxies: &HashMap<String, crate::proxy::ProxyConfig>,
    ) -> Result<HashSet<WildcardName>> {
        let mut domain_set = HashSet::new();
        let text = std::fs::read_to_string(&self.file)?;
        read_to_domain_set(&text, &mut domain_set);
        Ok(domain_set)
    }

    fn get_domain_set_cached(
        &self,
        proxies: &HashMap<String, crate::proxy::ProxyConfig>,
        force: bool,
    ) -> Result<HashSet<WildcardName>> {
        let path = self.file.to_string_lossy().into_owned();
        DOMAIN_SET_CACHE.get("DomainSet", &self.name, &path, self.interval, force, || {
            self.get_domain_set(proxies)
        })
    }
}

impl IDomainSetProvider for DomainSetHttpProvider {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn get_domain_set(
        &self,
        proxies: &HashMap<String, crate::proxy::ProxyConfig>,
    ) -> Result<HashSet<WildcardName>> {
        use crate::infra::http_client::{self, HttpResponse};
        let mut domain_set = HashSet::new();

        // 🌟 核心修复：坚决不偷拿！只匹配用户显式指定的 proxy 名称
        let proxy_str = self
            .proxy
            .as_ref()
            // 名字写错会**明确告警**并改直连，而不是无声直连（见 `proxy::resolve_proxy`）
            .and_then(|proxy_name| crate::proxy::resolve_proxy(proxies, proxy_name))
            .map(|p| p.to_string());

        let res = http_client::get(self.url.to_string(), proxy_str.as_deref())?;

        let text = res.text()?;
        read_to_domain_set(&text, &mut domain_set);
        Ok(domain_set)
    }

    fn get_domain_set_cached(
        &self,
        proxies: &HashMap<String, crate::proxy::ProxyConfig>,
        force: bool,
    ) -> Result<HashSet<WildcardName>> {
        DOMAIN_SET_CACHE.get("DomainSet", &self.name, self.url.as_str(), self.interval, force, || {
            self.get_domain_set(proxies)
        })
    }
}

fn read_to_domain_set(s: &str, domain_set: &mut HashSet<WildcardName>) {
    for line in s.lines() {
        let line = line.trim_start();
        if line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(' ');

        if let Some(n) = parts.next().and_then(|n| WildcardName::from_str(n).ok()) {
            domain_set.insert(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::Duration;

    /// 迷你 HTTP 名单服务器：返回 `list` 里的内容，`hits` 记请求次数，
    /// `stop` 置位后一律不应答（模拟"刷新时取用失败"）。
    fn spawn_list_server(
        list: Arc<Mutex<String>>,
        hits: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
    ) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                if stop.load(Ordering::SeqCst) {
                    // 直接关掉连接：客户端拿不到响应，按"取用失败"处理
                    continue;
                }
                hits.fetch_add(1, Ordering::SeqCst);
                let body = list.lock().unwrap().clone();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        port
    }

    fn http_provider(name: &str, port: u16, interval: Option<usize>) -> DomainSetHttpProvider {
        DomainSetHttpProvider {
            name: name.to_string(),
            url: Url::parse(&format!("http://127.0.0.1:{port}/list.txt")).unwrap(),
            interval,
            content_type: Default::default(),
            proxy: None,
        }
    }

    /// 🔐 P2：`-interval` 的取用语义 —— 未到期用缓存、到期重新取、force 强制重新取、
    /// 没配 interval 保持"每次都取"的原行为。
    #[test]
    fn test_interval_cache_semantics() {
        let list = Arc::new(Mutex::new("a.example.com\n".to_string()));
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let port = spawn_list_server(list.clone(), hits.clone(), stop);
        let proxies: HashMap<String, crate::proxy::ProxyConfig> = Default::default();

        let p = http_provider("cache-semantics-test", port, Some(1));

        // ① 第一次：必须真的去下载
        let first = p.get_domain_set_cached(&proxies, false).unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1, "第一次应发起请求");
        assert!(first.contains(&"a.example.com".parse().unwrap()));

        // ② 还没到期：直接用缓存，不再发请求
        p.get_domain_set_cached(&proxies, false).unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1, "未到期不该再发请求");

        // ③ force（启动 / 手动重载）：没到期也要重新下载
        p.get_domain_set_cached(&proxies, true).unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2, "force 应强制重新下载");

        // ④ 到期后：自动重新下载，并拿到新名单
        *list.lock().unwrap() = "b.example.com\n".to_string();
        std::thread::sleep(Duration::from_millis(1100));
        let refreshed = p.get_domain_set_cached(&proxies, false).unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 3, "到期应重新下载");
        assert!(refreshed.contains(&"b.example.com".parse().unwrap()));

        // ⑤ 没配 `-interval`：每次都取（与改动前一致）
        let plain = http_provider("no-interval-test", port, None);
        let base = hits.load(Ordering::SeqCst);
        plain.get_domain_set_cached(&proxies, false).unwrap();
        plain.get_domain_set_cached(&proxies, false).unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            base + 2,
            "没配 interval 的名单应每次都取"
        );

        // ⑥ `-interval 0`：等同于不配（关掉定时刷新）
        let zero = http_provider("zero-interval-test", port, Some(0));
        let base = hits.load(Ordering::SeqCst);
        zero.get_domain_set_cached(&proxies, false).unwrap();
        zero.get_domain_set_cached(&proxies, false).unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), base + 2, "-interval 0 应视为关闭");
    }

    /// 🔐 P2：刷新失败时**保留上一次的名单**，不能让规则因为一次网络抖动集体消失。
    #[test]
    fn test_interval_refresh_failure_keeps_last_list() {
        let list = Arc::new(Mutex::new("keep.example.com\n".to_string()));
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let port = spawn_list_server(list.clone(), hits.clone(), stop.clone());
        let proxies: HashMap<String, crate::proxy::ProxyConfig> = Default::default();

        let p = http_provider("failure-fallback-test", port, Some(1));

        let first = p.get_domain_set_cached(&proxies, false).unwrap();
        assert!(first.contains(&"keep.example.com".parse().unwrap()));

        // 让服务器彻底不应答，并等到期
        stop.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(1100));

        let after = p
            .get_domain_set_cached(&proxies, false)
            .expect("刷新失败时必须退回上一次的名单，而不是报错让规则消失");
        assert!(after.contains(&"keep.example.com".parse().unwrap()));

        // 从来没取到过任何名单时，失败仍然是失败（不能凭空造出空名单）
        let never = http_provider("never-loaded-test", port, Some(1));
        assert!(
            never.get_domain_set_cached(&proxies, false).is_err(),
            "没有任何可用旧名单时，取用失败应如实报错"
        );
    }
}
