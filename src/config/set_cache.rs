//! 「名单类」资源的取用缓存 —— domain-set（域名集合）与 ip-set（IP 集合）共用同一套语义。
//!
//! 为什么必须有它：名单在配置构建时被**展开进规则树**，所以"刷新某个名单"必然连带重建
//! 配置，而重建配置会把**所有**名单都取一遍。有了缓存，没到自己 `-interval` 的名单直接用
//! 上次的结果，不会被别的名单的刷新顺带重下 —— 各自的周期才真的说了算。
//!
//! key = `标签|名字|来源`（HTTP 用 URL、文件用路径）。

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::Result;

/// 一类名单的缓存。每种名单各自持有一个静态实例（静态量不能是泛型，所以按具体类型各建一个）。
pub(crate) struct SetCache<T> {
    entries: OnceLock<Mutex<HashMap<String, (Instant, T)>>>,
}

impl<T: Clone> SetCache<T> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: OnceLock::new(),
        }
    }

    fn entries(&self) -> &Mutex<HashMap<String, (Instant, T)>> {
        self.entries.get_or_init(Default::default)
    }

    fn lookup(&self, key: &str) -> Option<(Instant, T)> {
        self.entries()
            .lock()
            .ok()
            .and_then(|cache| cache.get(key).cloned())
    }

    fn store(&self, key: &str, value: &T) {
        if let Ok(mut cache) = self.entries().lock() {
            cache.insert(key.to_string(), (Instant::now(), value.clone()));
        }
    }

    /// 带 `-interval` 语义的取用：
    ///
    /// 1. **没配 `-interval`（或配 0）** → 每次都要最新的，与改动前完全一致；
    /// 2. **配了** → 未到自己周期直接用缓存（不重新下载 / 不重读文件），到期才重新取；
    /// 3. **`force`**（启动、手动重载）→ 忽略缓存，强制重新取 —— 用户手动按重载就该拿最新的；
    /// 4. **取用失败但手里有上一份** → 用旧的并告警：一次网络抖动不该让规则集体消失。
    ///
    /// `label` 只用于日志和缓存键（如 `DomainSet` / `IpSet`）。
    pub(crate) fn get<F>(
        &self,
        label: &str,
        name: &str,
        source: &str,
        interval: Option<usize>,
        force: bool,
        fetch: F,
    ) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        // 只有明确配了正数的 `-interval` 才走"定时刷新"这条路。
        let Some(secs) = interval.filter(|secs| *secs > 0) else {
            return fetch();
        };

        let key = format!("{label}|{name}|{source}");

        if !force
            && let Some((fetched_at, value)) = self.lookup(&key)
            && fetched_at.elapsed() < Duration::from_secs(secs as u64)
        {
            crate::log::debug!("{label} {name} 未到 -interval {secs} 秒，沿用上次的名单");
            return Ok(value);
        }

        match fetch() {
            Ok(value) => {
                crate::log::info!("{label} {name} 取到名单（-interval {secs} 秒）");
                self.store(&key, &value);
                Ok(value)
            }
            Err(err) => match self.lookup(&key) {
                Some((_, value)) => {
                    crate::log::warn!("{label} {name} 取用失败（{err}），继续用上一次的名单");
                    Ok(value)
                }
                None => Err(err),
            },
        }
    }
}
