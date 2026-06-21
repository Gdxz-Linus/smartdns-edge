use enum_dispatch::enum_dispatch;
use std::{collections::HashSet, path::PathBuf, str::FromStr};
use url::Url;

use anyhow::Result;

use super::WildcardName;

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
    fn get_domain_set(&self, proxies: &std::collections::HashMap<String, crate::proxy::ProxyConfig>) -> Result<HashSet<WildcardName>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSetFileProvider {
    pub name: String,
    pub file: PathBuf,
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

    fn get_domain_set(&self, _proxies: &std::collections::HashMap<String, crate::proxy::ProxyConfig>) -> Result<HashSet<WildcardName>> {
        let mut domain_set = HashSet::new();
        let text = std::fs::read_to_string(&self.file)?;
        read_to_domain_set(&text, &mut domain_set);
        Ok(domain_set)
    }
}

impl IDomainSetProvider for DomainSetHttpProvider {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn get_domain_set(&self, proxies: &std::collections::HashMap<String, crate::proxy::ProxyConfig>) -> Result<HashSet<WildcardName>> {
        use crate::infra::http_client::{self, HttpResponse};
        let mut domain_set = HashSet::new();
        
        // 🌟 核心修复：坚决不偷拿！只匹配用户显式指定的 proxy 名称
        let proxy_str = self.proxy.as_ref()
            .and_then(|proxy_name| proxies.get(proxy_name))
            .map(|p| p.to_string());

        let res = http_client::get(self.url.to_string(), proxy_str.as_deref())?;

        let text = res.text()?;
        read_to_domain_set(&text, &mut domain_set);
        Ok(domain_set)
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
