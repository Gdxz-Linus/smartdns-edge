use cfg_if::cfg_if;
use ipnet::IpNet;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use crate::config::*;
use crate::dns::DomainRuleGetter;
use crate::infra::ipset::IpMap;
use crate::log;
use crate::{
    dns_rule::{DomainRuleMap, DomainRuleTreeNode},
    infra::ipset::IpSet,
    libdns::proto::rr::{Name, RecordType},
    log::{debug, info, warn},
    proxy::ProxyConfig,
};

const DEFAULT_GROUP: &str = "default";

/// 配置文件相关错误（文件不存在 / 解析失败）导致启动失败时使用的退出码。
///
/// 单独使用 2 而不是笼统的 1，是为了让脚本与服务管理器能一眼区分
/// “配置写错了”（需要人工改配置）和“其它运行期错误”（如 PID 锁获取失败）。
/// 以 Windows 服务方式运行时 stderr 不可见，此时退出码是唯一可被记录的线索。
pub const EXIT_CODE_CONFIG_ERROR: i32 = 2;

#[cfg(target_os = "windows")]
pub const DEFAULT_CONF_DIR: &str = r"C:\ProgramData\smartdns";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub const DEFAULT_CONF_DIR: &str = "/usr/local/etc/smartdns";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const DEFAULT_CONF_DIR: &str = "/opt/homebrew/etc/smartdns";
#[cfg(target_os = "android")]
pub const DEFAULT_CONF_DIR: &str = "/data/data/com.termux/files/usr/etc/smartdns";
#[cfg(target_os = "linux")]
pub const DEFAULT_CONF_DIR: &str = "/etc/smartdns";

#[derive(Default)]
pub struct RuntimeConfig {
    conf_dir: Option<PathBuf>,
    conf_file: Option<PathBuf>,
    managed_dir: Option<PathBuf>,
    inner: Config,

    rule_groups: HashMap<String, RuleGroup>,

    domain_rule_group_map: HashMap<String, DomainRuleMap>,

    proxy_servers: Arc<HashMap<String, ProxyConfig>>,

    /// List of hosts that supply bogus NX domain results
    bogus_nxdomain: Arc<IpSet>,

    /// List of IPs that will be filtered when nameserver is configured -blacklist-ip parameter
    blacklist_ip: Arc<IpSet>,

    /// List of IPs that will be accepted when nameserver is configured -whitelist-ip parameter
    whitelist_ip: Arc<IpSet>,

    /// List of IPs that will be ignored
    ignore_ip: Arc<IpSet>,

    ip_alias: Arc<IpMap<Arc<[IpAddr]>>>,
}

impl RuntimeConfig {
	// 🌟 新增：专门用于清洗输出文件（日志/缓存/审计）的绝对路径锚定器！
    #[inline]
    fn anchor_path(&self, raw_path: PathBuf) -> PathBuf {
        // 1. 绝对路径保持原样，相对路径基于配置文件所在目录拼接
        let joined = if raw_path.is_absolute() {
            raw_path // 👈 请放心，绝对路径就在这里安全着陆，绝无错误拼接！
        } else {
            let base_dir = self.conf_file.as_ref().and_then(|f| f.parent())
                .or(self.conf_dir.as_deref())
                .unwrap_or_else(|| std::path::Path::new("."));
            base_dir.join(&raw_path)
        };

        // 🌟 核心绝杀：Cargo 官方级别的纯内存词法路径清洗 (Lexical Normalization)
        let mut normalized = std::path::PathBuf::new();
        for comp in joined.components() {
            match comp {
                std::path::Component::CurDir => continue, // 遇到 '.' 直接丢弃
                std::path::Component::ParentDir => {
                    // 遇到 '..' 时，只有上一级是普通文件夹才安全退格（防误删盘符或根目录）
                    if let Some(std::path::Component::Normal(_)) = normalized.components().next_back() {
                        normalized.pop();
                    } else {
                        normalized.push(comp);
                    }
                }
                _ => normalized.push(comp), // 盘符、根目录、普通名字统统装入
            }
        }

        normalized
    }
    
	
    pub fn load<P: AsRef<Path>>(conf_dir: Option<PathBuf>, path: Option<P>) -> Arc<Self> {
        let mut builder = Self::builder();

        if let Some(conf_dir) = conf_dir.as_deref() {
            builder = builder.with_conf_dir(conf_dir);
        }

        let path = if let Some(ref conf) = path {
            let mut path = Cow::Borrowed(conf.as_ref());
            if path.is_dir() {
                path = Cow::Owned(path.join(format!("{}.conf", crate::NAME.to_lowercase())));
            }
            if conf_dir.is_none()
                && let Some(dir) = path.parent()
                && dir
                    .file_stem()
                    .map(|s| s.eq_ignore_ascii_case(crate::NAME))
                    .unwrap_or_default()
            {
                builder = builder.with_conf_dir(dir);
            }
            path
        } else {
            #[cfg(feature = "service")]
            let conf_path: &str = crate::service::CONF_PATH;
            #[cfg(not(feature = "service"))]
            let conf_path: &str = "./smartdns.conf";
            cfg_if! {
                if #[cfg(target_os = "android")] {
                    let candidate_path = [
                        conf_path,
                        "/data/data/com.termux/files/usr/etc/smartdns.conf",
                        "/data/data/com.termux/files/usr/etc/smartdns/smartdns.conf"
                    ];

                } else if #[cfg(target_os = "windows")] {
                    let candidate_path = [conf_path];
                } else {
                    let candidate_path = [
                        conf_path,
                        "/etc/smartdns.conf",
                        "/etc/smartdns/smartdns.conf",
                        "/usr/local/etc/smartdns.conf",
                        "/usr/local/etc/smartdns/smartdns.conf"
                    ];
                }
            }

            let mut candidate_paths = candidate_path.iter().map(Path::new).filter(|p| p.exists());

            let Some(path) = candidate_paths.next() else {
                // 🌟 修复：原为 std::process::exit(1)。
                // 提示信息本身是清楚的，问题在于退出码与其它错误（如 PID 锁失败）混用 1，
                // 服务方式运行时 stderr 不可见，只剩退出码可被服务管理器记录，
                // 因此这里改用专门的“配置错误”退出码，让"配置没找到"可被区分出来。
                eprintln!("\n❌ [ERROR] Configuration file not found!");
                eprintln!("💡 Hint: Please specify the config file using '-c' (e.g., smartdns run -c ./smartdns.conf).");
                eprintln!("   Or use 'smartdns service install' to generate a default config.");
                eprintln!(
                    "   Searched the following locations: {}",
                    candidate_path.join(", ")
                );
                eprintln!("   Exit code: {EXIT_CODE_CONFIG_ERROR} (configuration error)\n");
                std::process::exit(EXIT_CODE_CONFIG_ERROR);
            };
            Cow::Owned(path.to_path_buf())
        };

        match builder.with_conf_file(&path).build() {
            Ok(cfg) => cfg.into(),
            Err(err) => {
                // 🌟 修复：原为 panic!()，整个进程以 Rust panic 方式摔死，
                // 屏幕上只有一句 "Failed to load configuration file..." 加一大段调用栈，
                // 既难阅读，也让 `smartdns test` 这个"只检查配置"的子命令跟着崩溃。
                // 改为「清晰错误 + 明确退出码」：打印文件路径与完整错误链（{err:#} 会带出因果链），
                // 并以专用的配置错误码退出，便于脚本与服务管理器区分。
                eprintln!(
                    "\n❌ [ERROR] Failed to load configuration file: {}",
                    path.display()
                );
                eprintln!("💡 Reason: {err:#}");
                eprintln!("💡 Hint: 请检查该文件是否存在语法错误、非法参数或不可读的引用路径。");
                eprintln!("   You can validate a config standalone with: smartdns test -c <file>");
                eprintln!("   Exit code: {EXIT_CODE_CONFIG_ERROR} (configuration error)\n");
                std::process::exit(EXIT_CODE_CONFIG_ERROR);
            }
        }
    }

    pub fn builder() -> RuntimeConfigBuilder {
        RuntimeConfigBuilder {
            conf_dir: Default::default(),
            conf_file: Default::default(),
            managed_dir: Default::default(),
            config: Default::default(),
            loaded_files: Default::default(),
            rule_groups: Default::default(),
            rule_group_stack: Default::default(),
            dirs: Default::default(),
            // 默认强制重新取用名单：启动与手动重载都该拿到最新的。
            // 只有 `-interval` 触发的定时刷新才把它设成 false（见 reload_new_reusing_set_cache）。
            force_set_refresh: true,
        }
    }
}

impl RuntimeConfig {
    /// Print the config summary.
    pub fn summary(&self) {
        if let Some(user) = self.user() {
            info!("whoami 👉 {user}");
        }

        info!("DNS Engine activated {} concurrent worker threads.", self.num_workers());

        for server in self.nameservers.iter() {
            if !server.exclude_default_group && server.group.is_empty() {
                continue;
            }
            let proxy = server
                .proxy
                .as_deref()
                .map(|n| self.proxies().get(n))
                .unwrap_or_default();

            // 🌟 修复：优雅地拼接组名，剥离 [""]
            let group_str = if server.group.is_empty() {
                "default".to_string()
            } else {
                server.group.join(", ")
            };

            info!(
                "upstream server: {}[Group: {}] {}", // <--- 换回清爽的 {}
                server.server.to_string(),
                group_str,
                match proxy {
                    Some(s) => format!("over {s}"),
                    None => "".to_string(),
                }
            );
        }

        for server in self.nameservers.iter().filter(|s| !s.exclude_default_group) {
            info!(
                "upstream server: {} [Group: {}]",
                server.server.to_string(),
                DEFAULT_GROUP
            );
        }

        info!(
            "cache: {}",
            if self.cache_size() > 0 {
                format!("size({})", self.cache_size())
            } else {
                "OFF".to_string()
            }
        );

        if self.cache_size() > 0 {
            info!(
                "cache persist: {}",
                if self.cache_persist() { "YES" } else { "NO" }
            );

            info!(
                "domain prefetch: {}",
                if self.prefetch_domain() { "ON" } else { "OFF" }
            );
        }

        info!(
            "speed check mode: {}",
            match self.speed_check_mode() {
                Some(mode) => format!("{mode:?}"),
                None => "OFF".to_string(),
            }
        );
    }

    pub fn server_name(&self) -> Name {
        match self.server_name {
            Some(ref server_name) => Some(server_name.clone()),
            None => match hostname::get() {
                Ok(name) => match name.to_str() {
                    Some(s) => s.parse().ok(),
                    None => None,
                },
                Err(_) => None,
            },
        }
        .unwrap_or_else(|| crate::NAME.parse().unwrap())
    }

    /// The number of worker threads
    #[inline]
    pub fn num_workers(&self) -> usize {
        use std::num::NonZeroUsize;
        self.num_workers
            .unwrap_or(std::thread::available_parallelism().map_or(1, NonZeroUsize::get))
    }

    pub fn binds(&self) -> &[BindAddrConfig] {
        &self.binds
    }

    /// SSL Certificate file path
    #[inline]
    pub fn bind_cert_file(&self) -> Option<&Path> {
        self.bind_cert_file.as_deref()
    }
    /// SSL Certificate key file path
    #[inline]
    pub fn bind_cert_key_file(&self) -> Option<&Path> {
        self.bind_cert_key_file.as_deref()
    }
    /// bind_cert_key_pass
    #[inline]
    pub fn bind_cert_key_pass(&self) -> Option<&str> {
        self.bind_cert_key_pass.as_deref()
    }

    /// whether resolv local hostname to ip address
    #[inline]
    pub fn resolv_hostanme(&self) -> bool {
        self.resolv_hostname.unwrap_or(self.hosts_file.is_some())
    }

    /// hosts file path
    #[inline]
    pub fn hosts_file(&self) -> Option<&glob::Pattern> {
        self.hosts_file.as_ref()
    }

    /// Whether to expand the address record corresponding to PTR record
    #[inline]
    pub fn expand_ptr_from_address(&self) -> bool {
        self.expand_ptr_from_address.unwrap_or_default()
    }

    /// whether resolv mdns
    #[inline]
    pub fn mdns_lookup(&self) -> bool {
        self.mdns_lookup.unwrap_or_default()
    }

    /// dns server run user
    #[inline]
    /// 管理后台口令：配置 `api-token` 优先，其次是环境变量（见 crate::api::api_token）
    pub fn api_token(&self) -> Option<&str> {
        self.api_token.as_deref()
    }

    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    #[inline]
    pub fn domain(&self) -> Option<&Name> {
        self.domain.as_ref()
    }

    /// tcp connection idle timeout
    #[inline]
    pub fn tcp_idle_time(&self) -> u64 {
        self.tcp_idle_time.unwrap_or(120)
    }

    /// 同时连接数上限；None 表示按物理内存自动推算（见 server::limit）
    pub fn max_connections(&self) -> Option<usize> {
        self.max_connections
    }

    /// 单一来源连接数上限；None 表示自动
    pub fn max_connections_per_ip(&self) -> Option<usize> {
        self.max_connections_per_ip
    }

    /// 连接建立后等待"第一个完整报文"的秒数；0 表示不限制。
    /// 默认 5 秒：正常客户端握手完成后会立刻发查询，5 秒足够宽裕；
    /// 而"只发长度前缀不发正文"的慢速攻击会被迅速断开。
    pub fn first_packet_timeout(&self) -> Option<std::time::Duration> {
        match self.first_packet_timeout {
            Some(0) => None,
            Some(secs) => Some(std::time::Duration::from_secs(secs)),
            None => Some(std::time::Duration::from_secs(5)),
        }
    }

    #[inline]
    pub fn cache_config(&self) -> &CacheConfig {
        &self.cache
    }

    /// dns cache size
    #[inline]
    pub fn cache_size(&self) -> usize {
        self.cache.size.unwrap_or(512)
    }

    /// enable persist cache when restart
    #[inline]
    pub fn cache_persist(&self) -> bool {
        self.cache.persist.unwrap_or(false)
    }

    /// cache save interval
    #[inline]
    pub fn cache_checkpoint_time(&self) -> u64 {
        self.cache.checkpoint_time.unwrap_or(24 * 60 * 60)
    }

    /// cache persist file
    #[inline]
    pub fn cache_file(&self) -> PathBuf {
        let f = self.cache
            .file
            .to_owned()
            .unwrap_or_else(|| std::env::temp_dir().join("smartdns.cache"));
        self.anchor_path(f) // 🌟 套上盾牌！
    }

    /// prefetch domain
    #[inline]
    pub fn prefetch_domain(&self) -> bool {
        self.cache.prefetch_domain.unwrap_or_default()
    }

    #[inline]
    pub fn dnsmasq_lease_file(&self) -> Option<&Path> {
        self.dnsmasq_lease_file.as_deref()
    }

    /// cache serve expired
    #[inline]
    pub fn serve_expired(&self) -> bool {
        self.cache.serve_expired.unwrap_or(true)
    }

    /// cache serve expired TTL
    #[inline]
    pub fn serve_expired_ttl(&self) -> u64 {
        self.cache.serve_expired_ttl.unwrap_or(86400)
    }

    /// reply TTL value to use when replying with expired data
    #[inline]
    pub fn serve_expired_reply_ttl(&self) -> u64 {
        self.cache.serve_expired_reply_ttl.unwrap_or(5)
    }
	
	// 👇 【新增这一段】：提供读取接口，官方默认值为 21600 秒 (6小时)
    #[inline]
    pub fn serve_expired_prefetch_time(&self) -> u64 {
        self.cache.serve_expired_prefetch_time.unwrap_or(21600)
    }

    /// List of hosts that supply bogus NX domain results
    #[inline]
    pub fn bogus_nxdomain(&self) -> &Arc<IpSet> {
        &self.bogus_nxdomain
    }
    /// List of IPs that will be filtered when nameserver is configured -blacklist-ip parameter
    #[inline]
    pub fn blacklist_ip(&self) -> &Arc<IpSet> {
        &self.blacklist_ip
    }
    /// List of IPs that will be accepted when nameserver is configured -whitelist-ip parameter
    #[inline]
    pub fn whitelist_ip(&self) -> &Arc<IpSet> {
        &self.whitelist_ip
    }
    /// List of IPs that will be ignored
    #[inline]
    pub fn ignore_ip(&self) -> &Arc<IpSet> {
        &self.ignore_ip
    }

    pub fn ip_alias(&self) -> &Arc<IpMap<Arc<[IpAddr]>>> {
        &self.ip_alias
    }

    /// speed check mode
    #[inline]
    pub fn speed_check_mode(&self) -> Option<&SpeedCheckModeList> {
        self.speed_check_mode.as_ref()
    }

    /// force AAAA query return SOA
    #[inline]
    pub fn force_aaaa_soa(&self) -> bool {
        self.force_aaaa_soa.unwrap_or_default()
    }

    /// force HTTPS query return SOA
    #[inline]
    pub fn force_https_soa(&self) -> bool {
        self.force_https_soa.unwrap_or_default()
    }

    /// force specific qtype return soa
    #[inline]
    pub fn force_qtype_soa(&self) -> &HashSet<RecordType> {
        &self.force_qtype_soa
    }

    /// Enable IPV4, IPV6 dual stack IP optimization selection strategy
    #[inline]
    pub fn dualstack_ip_selection(&self) -> bool {
        self.dualstack_ip_selection.unwrap_or(true)
    }
    /// dualstack-ip-selection-threshold [num] (0~1000)
    #[inline]
    pub fn dualstack_ip_selection_threshold(&self) -> u64 {
        self.dualstack_ip_selection_threshold.unwrap_or(10)
    }

    /// dualstack-ip-allow-force-AAAA
    #[inline]
    pub fn dualstack_ip_allow_force_aaaa(&self) -> bool {
        self.dualstack_ip_allow_force_aaaa.unwrap_or_default()
    }
    /// edns client subnet
    #[inline]
    pub fn edns_client_subnet(&self) -> Option<IpNet> {
        self.edns_client_subnet
    }

    /// ttl for all resource record
    #[inline]
    pub fn rr_ttl(&self) -> Option<u64> {
        self.rr_ttl
    }
    /// minimum ttl for resource record
    #[inline]
    pub fn rr_ttl_min(&self) -> Option<u64> {
        self.rr_ttl_min.or_else(|| self.rr_ttl())
    }
    /// maximum ttl for resource record
    #[inline]
    pub fn rr_ttl_max(&self) -> Option<u64> {
        self.rr_ttl_max.or_else(|| self.rr_ttl())
    }
    #[inline]
    pub fn rr_ttl_reply_max(&self) -> Option<u64> {
        self.rr_ttl_reply_max
    }

    #[inline]
    pub fn local_ttl(&self) -> u64 {
        self.local_ttl.or_else(|| self.rr_ttl_min()).unwrap_or(60)
    }

    /// Maximum number of IPs returned to the client|8|number of IPs, 1~16
    #[inline]
    pub fn max_reply_ip_num(&self) -> Option<u8> {
        self.max_reply_ip_num
    }

    /// response mode
    #[inline]
    pub fn response_mode(&self) -> ResponseMode {
        self.response_mode.unwrap_or(ResponseMode::FirstPing)
    }

    #[inline]
    pub fn log_config(&self) -> &LogConfig {
        &self.log
    }

    #[inline]
    pub fn log_enabled(&self) -> bool {
        self.log_num() > 0
    }

    pub fn log_level(&self) -> Option<crate::log::Level> {
        self.log.level
    }

    pub fn log_file(&self) -> PathBuf {
        let f = match self.log.file.as_ref() {
            Some(e) => e.to_owned(),
            None => {
                cfg_if! {
                    if #[cfg(target_os="windows")] {
                        let mut path = std::env::temp_dir();
                        path.push("smartdns");
                        path.push("smartdns.log");
                        path
                    } else {
                        PathBuf::from(r"/var/log/smartdns/smartdns.log")
                    }
                }
            }
        };
        self.anchor_path(f) // 🌟 套上盾牌！
    }

    #[inline]
    pub fn log_size(&self) -> u64 {
        use byte_unit::{Byte, Unit};
        self.log
            .size
            .unwrap_or_else(|| Byte::from_u64_with_unit(128, Unit::KB).unwrap())
            .as_u64()
    }
    #[inline]
    pub fn log_num(&self) -> u64 {
        self.log.num.unwrap_or(2)
    }

    #[inline]
    pub fn log_file_mode(&self) -> u32 {
        self.log.file_mode.map(|m| *m).unwrap_or(0o640)
    }

    #[inline]
    pub fn log_filter(&self) -> Option<&str> {
        self.log.filter.as_deref()
    }

    #[inline]
    pub fn audit_config(&self) -> &AuditConfig {
        &self.audit
    }

    /// 访问控制总开关（`acl-enable`）。默认关闭 —— 不开就是"谁都能查"，与改动前行为一致。
    ///
    /// 语义见 `src/config/acl.rs` 与 `src/dns_mw.rs` 里的落地：开启后**没匹配到任何
    /// `client-rules` 的客户端一律 REFUSED**（不缓存）；监听级 `bind ... -acl` 是"或"的关系。
    #[inline]
    pub fn acl_enable(&self) -> bool {
        self.acl.enable.unwrap_or(false)
    }

    pub fn audit_enable(&self) -> bool {
        self.audit.enable.unwrap_or_default()
    }

    #[inline]
    pub fn audit_file(&self) -> Option<PathBuf> {
        self.audit.file.as_ref().map(|f| self.anchor_path(f.clone())) // 🌟 套上盾牌！
    }

    #[inline]
    pub fn audit_num(&self) -> usize {
        self.audit.num.unwrap_or(2)
    }

    #[inline]
    pub fn audit_size(&self) -> u64 {
        use byte_unit::{Byte, Unit};
        self.audit
            .size
            .unwrap_or_else(|| Byte::from_u64_with_unit(128, Unit::KB).unwrap())
            .as_u64()
    }

    #[inline]
    pub fn audit_file_mode(&self) -> u32 {
        self.audit.file_mode.map(|m| *m).unwrap_or(0o640)
    }
    /// certificate file
    #[inline]
    pub fn ca_file(&self) -> Option<&Path> {
        self.ca_file.as_deref()
    }

    /// certificate path
    #[inline]
    pub fn ca_path(&self) -> Option<&Path> {
        self.ca_path.as_deref()
    }

    /// remote dns server list
    #[inline]
    pub fn servers(&self) -> &[NameServerInfo] {
        &self.nameservers
    }

    #[inline]
    pub fn proxies(&self) -> &Arc<HashMap<String, ProxyConfig>> {
        &self.proxy_servers
    }

    #[inline]
    pub fn resolv_file(&self) -> Option<&Path> {
        self.resolv_file.as_deref()
    }

    pub fn valid_nftsets(&self) -> Vec<&ConfigForIP<NFTsetConfig>> {
        self.nftsets
            .iter()
            .flat_map(|x| &x.config)
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|x| !matches!(x, ConfigForIP::None))
            .collect()
    }

    pub fn rule_groups(&self) -> &HashMap<String, RuleGroup> {
        &self.rule_groups
    }

    pub fn rule_group(&self, name: &str) -> &RuleGroup {
        self.rule_groups.get(name).unwrap_or(RuleGroup::empty())
    }

    /// 🔐 P2（用户定策）：这个**规则组**名字在配置里真的存在吗？
    ///
    /// 用于"组不存在 → 走默认组 + 点名告警"：必须能区分"这个组确实定义了"和"名字根本没见过"
    /// （拼错、改名后忘了同步、或者内部代码传了别的名字）。
    pub fn has_rule_group(&self, name: &str) -> bool {
        name.is_empty()
            || name == DEFAULT_GROUP
            || self.rule_groups.contains_key(name)
            || self.client_rules.iter().any(|r| r.group == name)
    }

    /// 🔐 P2（用户定策）：这个**服务器组**名字在配置里真的存在吗？
    ///
    /// 已知来源：`server`/`nameserver` 行上的 `-group <名>`。默认组与空名恒为"存在"。
    pub fn has_server_group(&self, name: &str) -> bool {
        name.is_empty()
            || name.eq_ignore_ascii_case(DEFAULT_GROUP)
            || self
                .servers()
                .iter()
                .any(|s| s.group.iter().any(|g| g == name))
    }

    pub fn client_rules(&self) -> &[ClientRule] {
        &self.client_rules
    }

    #[inline]
    pub fn domain_rule_group(&self, name: &str) -> &DomainRuleMap {
        let name = if name.is_empty() { DEFAULT_GROUP } else { name };
        self.domain_rule_group_map
            .get(name)
            .unwrap_or(DomainRuleMap::empty())
    }

    #[inline]
    pub fn find_domain_rule(&self, domain: &Name, group: &str) -> Option<Arc<DomainRuleTreeNode>> {
        self.domain_rule_group(group)
            .find(domain)
            .or_else(|| self.domain_rule_group(DEFAULT_GROUP).find(domain))
            .cloned()
    }

    fn get_server_group(&self, group: &str) -> Vec<&NameServerInfo> {
        if group == DEFAULT_GROUP {
            self.servers()
                .iter()
                .filter(|s| s.group.iter().any(|g| g == DEFAULT_GROUP) || !s.exclude_default_group)
                .collect::<Vec<_>>()
        } else {
            self.servers()
                .iter()
                .filter(|s| s.group.iter().any(|g| g == group))
                .collect::<Vec<_>>()
        }
    }

    pub fn conf_dir(&self) -> Option<&Path> {
        self.conf_dir.as_deref()
    }

    pub fn managed_dir(&self) -> Option<&Path> {
        self.managed_dir.as_deref()
    }

    pub fn reload_new(&self) -> anyhow::Result<Arc<RuntimeConfig>> {
        let builder = RuntimeConfigBuilder {
            conf_dir: self.conf_dir.clone(),
            conf_file: self.conf_file.clone(),
            ..Self::builder()
        };

        Ok(Arc::new(builder.build()?))
    }

    /// 🔐 P2：`domain-set -interval` 触发的定时刷新走这条路。
    ///
    /// 与 `reload_new`（启动 / 手动重载）的唯一区别：**未到自己 `-interval` 的名单直接用内存缓存**。
    /// 否则一次定时刷新会把所有名单都重新下载一遍 —— 别的名单配的周期就白配了。
    pub fn reload_new_reusing_set_cache(&self) -> anyhow::Result<Arc<RuntimeConfig>> {
        let builder = RuntimeConfigBuilder {
            conf_dir: self.conf_dir.clone(),
            conf_file: self.conf_file.clone(),
            force_set_refresh: false,
            ..Self::builder()
        };

        Ok(Arc::new(builder.build()?))
    }
}

impl std::ops::Deref for RuntimeConfig {
    type Target = Config;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct RuntimeConfigBuilder {
    conf_dir: Option<PathBuf>,
    conf_file: Option<PathBuf>,
    managed_dir: Option<PathBuf>,
    config: Config,
    rule_groups: HashMap<String, RuleGroup>,
    rule_group_stack: Vec<(String, RuleGroup)>,
    loaded_files: HashSet<PathBuf>,
    dirs: HashSet<PathBuf>,
    /// 🔐 P2：构建时是否**强制重新取用** domain-set 名单（忽略内存缓存）。
    /// 启动与手动重载 = true；`-interval` 触发的定时刷新 = false。
    force_set_refresh: bool,
}

impl RuntimeConfigBuilder {
    pub fn build(mut self) -> anyhow::Result<RuntimeConfig> {
        if let Some(conf_file) = self.conf_file.clone() {
            // 🌟 修复：主配置文件必须真实存在。
            // 原先若 -c 指定的路径解析后并不存在（例如 -c 给了一个目录、而该目录下
            // 并没有 smartdns.conf），load_file 只会打一条 warning 然后按“成功”返回，
            // 于是 build() 成功 → `smartdns test` 会对着一个根本没读到的配置打印
            // “✅ Configuration test passed successfully!” 并以退出码 0 退出。
            // 对 include 进来的文件容忍缺失是合理的（见 load_file 的 warn 分支），
            // 但对用户指定的主配置绝不可以——这等于用退出码告诉用户“配置没问题”。
            if !conf_file.exists() {
                anyhow::bail!("configuration file does not exist: {}", conf_file.display());
            }

            let loaded = self.loaded_files.contains(&conf_file);
            if !loaded {
                self.load_file(&conf_file)?;
            }
        }

        let conf_file = self.conf_file;
        let conf_dir = self.conf_dir;
        let mut cfg = self.config;

        if !self.rule_group_stack.is_empty() {
            while let Some((name, group)) = self.rule_group_stack.pop() {
                self.rule_groups.entry(name).or_default().merge(group);
            }
        }

        if cfg.binds.is_empty() {
            cfg.binds.push(UdpBindAddrConfig::default().into())
        }

        fn get_ip_set<'a>(ip: &'a IpOrSet, cfg: &'a Config) -> &'a [IpNet] {
            match ip {
                IpOrSet::Net(net) => std::slice::from_ref(net),
                IpOrSet::Set(name) => match cfg.ip_sets.get(name) {
                    Some(net) => net,
                    None => {
                        warn!("unknown ip-set:{name}");
                        &[]
                    }
                },
            }
        }

        let make_ip_set = |set: &[IpOrSet]| {
            let iter = set.iter().flat_map(|ip| get_ip_set(ip, &cfg));
            Arc::new(IpSet::new(iter.copied()))
        };

        let bogus_nxdomain = make_ip_set(&cfg.bogus_nxdomain);
        let blacklist_ip = make_ip_set(&cfg.blacklist_ip);
        let whitelist_ip = make_ip_set(&cfg.whitelist_ip);
        let ignore_ip = make_ip_set(&cfg.ignore_ip);

        let ip_alias = cfg.ip_alias.iter().flat_map(|alias| {
            let to = std::iter::repeat(alias.to.clone());
            get_ip_set(&alias.ip, &cfg).iter().copied().zip(to)
        });
        let ip_alias = Arc::new(IpMap::from_iter(ip_alias));

        for rule in self.rule_groups.values_mut() {
            if !rule.cnames.is_empty() {
                rule.cnames.dedup_by(|a, b| a.domain == b.domain);
            }
        }

        let mut domain_sets: HashMap<String, HashSet<WildcardName>> = HashMap::new();

        for (set_name, providers) in &cfg.domain_set_providers {
            let set = domain_sets.entry(set_name.to_string()).or_default();
            for p in providers.iter() {
                // 🌟 核心修复 2：将从配置文件里提取好的全部代理池 (proxy_servers)
                // 传给底层下载器！打破次元壁！
                //
                // 🔐 P2：走"带 `-interval` 语义"的取用 —— 配了周期的名单未到期就用内存缓存，
                // 不会被别人的刷新顺带重下；取用失败时保留上一次的名单（见 `get_with_cache`）。
                match p.get_domain_set_cached(&cfg.proxy_servers, self.force_set_refresh) {
                    Ok(s) => {
                        log::info!("DomainSet {} 生效 {} 条规则", s.len(), p.name());
                        set.extend(s);
                    }
                    Err(err) => {
                        log::error!("DomainSet load failed {} {}", p.name(), err);
                    }
                }
            }
        }

        let mut domain_rule_group_map = HashMap::new();

        let mut rule_map = Default::default();

        for (group_name, rule_group) in &self.rule_groups {
            let domain_rule_map = DomainRuleMap::create(
                &mut rule_map,
                &rule_group.domain_rules,
                &rule_group.address_rules,
                &rule_group.forward_rules,
                &domain_sets,
                &rule_group.cnames,
                &rule_group.srv_records,
                &rule_group.https_records,
                &cfg.nftsets,
            );
            domain_rule_group_map.insert(group_name.to_string(), domain_rule_map);
        }

        let domain_rule_map = domain_rule_group_map
            .get(DEFAULT_GROUP)
            .unwrap_or(DomainRuleMap::empty());

        // set nameserver group for bootstraping
        for server in cfg.nameservers.iter_mut() {
            if server.server.ip().is_none() {
                let host = server.server.host().to_string();
                if let Ok(Some(rule)) = host
                    .as_str()
                    .parse()
                    .map(|domain| domain_rule_map.find(&domain))
                {
                    server.resolve_group = rule.get(|r| r.nameserver.clone());
                }
            }
        }

        // find device address
        {
            if !cfg.binds.is_empty() {
                use local_ip_address::list_afinet_netifas;
                match list_afinet_netifas() {
                    Ok(network_interfaces) => {
                        for listener in &mut cfg.binds {
                            let device = match listener.device() {
                                Some(v) => v,
                                None => continue,
                            };

                            let ips = network_interfaces
                                .iter()
                                .filter(|(dev, _ip)| dev == device)
                                .map(|(_, ip)| *ip)
                                .collect::<Vec<_>>();

                            if ips.is_empty() {
                                warn!("network device {} not found.", device);
                            }

                            let ip = ips.into_iter().find(|ip| match listener.addr() {
                                BindAddr::Localhost => true,
                                BindAddr::All => true,
                                BindAddr::V4(_) => ip.is_ipv4(),
                                BindAddr::V6(_) => ip.is_ipv6() && !matches!(ip, IpAddr::V6(ipv6) if (ipv6.segments()[0] & 0xffc0) == 0xfe80),
                            });

                            match ip {
                                Some(ip) => *listener.mut_addr() = ip.into(),
                                None => {
                                    warn!("no ip address on device {}", device)
                                }
                            }
                        }
                    }
                    Err(err) => {
                        warn!("bind device failed, {}", err);
                    }
                }
            }
        }

        // dedup bind address
        {
            let mut udp_addr = HashSet::new();
            let mut tcp_addr = HashSet::new();

            let mut remove_idx = vec![];
            for (idx, listener) in cfg.binds.iter().enumerate().rev() {
                let addr = listener.sock_addr();
                if matches!(
                    listener,
                    BindAddrConfig::Udp(_) | BindAddrConfig::Quic(_) | BindAddrConfig::H3(_)
                ) {
                    if !udp_addr.insert(addr) {
                        remove_idx.push(idx)
                    }
                } else if !tcp_addr.insert(addr) {
                    remove_idx.push(idx)
                }
            }

            for idx in remove_idx {
                let listener = cfg.binds.remove(idx);
                warn!("remove duplicated listener {:?}", listener);
            }
        }

        let mut proxy_servers = HashMap::with_capacity(0);

        std::mem::swap(&mut proxy_servers, &mut cfg.proxy_servers);

        let managed_dir = conf_dir.as_deref().map(|dir| {
            let dir = dir.join("managed");
            if !dir.exists() {
                let _ = std::fs::create_dir_all(&dir);
            }
            dir
        });

        Ok(RuntimeConfig {
            conf_dir,
            conf_file,
            managed_dir,
            inner: cfg,
            rule_groups: self.rule_groups,
            domain_rule_group_map,
            bogus_nxdomain,
            blacklist_ip,
            whitelist_ip,
            ignore_ip,
            ip_alias,
            proxy_servers: Arc::new(proxy_servers),
        })
    }
}

impl std::ops::Deref for RuntimeConfigBuilder {
    type Target = Config;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl std::ops::DerefMut for RuntimeConfigBuilder {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

impl RuntimeConfigBuilder {
    pub fn with(mut self, config: &str) -> Self {
        self.config(config.trim());
        self
    }

    pub fn with_conf_file<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.conf_file = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn with_conf_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.conf_dir = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let path = self.resolve_filepath(path);

        // 🌟 核心修复（治理 conf-file 无限递归）：
        // 必须在进入递归之前就把路径登记进 loaded_files。
        // 原实现在递归返回之后才 insert，而 load_file 自身从不登记，
        // 因此 "conf-file 指向自己" 或 a↔b 互相包含时会无限递归直至栈溢出，进程直接崩溃。
        //
        // 去重键使用 canonicalize 之后的真实文件身份：resolve_filepath 只做"找到文件"的
        // 相对/绝对拼接，并不规范化，同一个文件写 `inc.conf`、`./inc.conf`、
        // `C:/abs/inc.conf` 会得到三个不同的字符串，导致被重复解析。canonicalize 失败
        // （文件不存在等）时退回 resolve 后的路径。
        let key = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());

        if !self.loaded_files.insert(key) {
            warn!(
                "configuration file {:?} has already been loaded, skip to avoid recursion",
                path
            );
            return Ok(());
        }

        if path.exists() {
            debug!("loading extra configuration from {:?}", path);

            let file = File::open(&path)?;
            let reader = BufReader::new(file);

            if self.conf_file.is_none() {
                self.conf_file = Some(path.clone());
            }
            // 🔐 P2：原实现是 `reader.lines().map_while(Result::ok)` ——
            // 配置文件里只要有一行不是合法 UTF-8，**这一行之后的全部配置就静默不加载**，
            // 用户只会看到"我明明配了却不起作用"。
            // 改成按字节读行 + 有损转换：坏字节只影响它自己那一行，并且明确告警。
            let mut reader = reader;
            let mut buf: Vec<u8> = Vec::new();
            let mut lineno = 0usize;
            loop {
                buf.clear();
                if reader.read_until(b'\n', &mut buf)? == 0 {
                    break;
                }
                lineno += 1;

                if std::str::from_utf8(&buf).is_err() {
                    warn!(
                        "配置文件 {:?} 第 {} 行含有非 UTF-8 字节，已按替换字符解析（该行之后照常加载）",
                        path, lineno
                    );
                }

                let line = String::from_utf8_lossy(&buf);
                self.config_at(line.trim_end_matches(['\r', '\n']), Some(lineno));
            }
        } else {
            warn!("configuration file {:?} does not exist", path);
        }

        Ok(())
    }

    /// 解析一行配置（对外接口，行为与从前一致）。
    pub fn config(&mut self, line: &str) {
        self.config_at(line, None);
    }

    /// 🔐 P2：解析一行配置，并把"这行有没有我们没认出来的内容"明确说出来。
    ///
    /// 背景：`parse_config` 的语法里有 `space0`（零宽）兜底分支 —— 任何一行至少都能被
    /// 解析成"空行"，所以它**永远不会返回 Err**，原来那句
    /// `Err(err) => warn!("unknown conf: ...")` 根本执行不到：关键字拼错的一整行就这样
    /// 静默消失（服务照常起来、零提示）。这里改用"剩余输入是否为空"来判定，并把剩余内容报出来。
    ///
    /// 注：这里多解析一次（只为拿到剩余输入）。配置加载只发生在启动/配置重载，代价可忽略。
    fn config_at(&mut self, line: &str, lineno: Option<usize>) {
        if let Ok((rest, item)) = parser::parse_config(line) {
            let rest = rest.trim();
            if !rest.is_empty() {
                // 剩下来的就是"我们没认出来的东西"：
                // item 为 None = 整行谁都不认（例如关键字拼错）；
                // item 有值 = 配置项认出来了，但后面还粘着多余内容（例如行尾粘了别的东西）。
                // 🔐 A1：这两条告警曾是"把整行原文写进日志"的口子 —— 用户写
                // `proxy-server socks5://user:pass@…` 时只要行尾多一个字，代理密码（乃至
                // `api-token` 的口令、`bind-cert-key-pass` 的私钥口令）就会明文落盘。
                // 日志的目的是帮他找到拼写错误，不需要看到口令，所以统一先脱敏。
                let shown_line = redact_config_line(line);
                let shown_rest = redact_config_line(rest);
                let detail = if item.is_none() {
                    format!("未识别的配置行（已原样忽略）：{shown_line:?}，请检查关键字拼写")
                } else {
                    format!("配置行尾部有无法识别的内容（已忽略）：{shown_rest:?} —— 整行：{shown_line:?}")
                };
                match lineno {
                    Some(no) => warn!("配置文件第 {no} 行：{detail}"),
                    None => warn!("{detail}"),
                }
            }
        }
        self.config_unchecked(line);
    }

    fn config_unchecked(&mut self, line: &str) {
        use crate::config::parser::ConfigItem::*;
        let rule_group = match self.rule_group_stack.last_mut() {
            Some((_, rule_group)) => rule_group,
            None => {
                self.rule_group_stack
                    .push((DEFAULT_GROUP.to_string(), RuleGroup::default()));
                &mut self.rule_group_stack.last_mut().unwrap().1
            }
        };

        match parser::parse_config(line) {
            Ok((_, Some(config_item))) => match config_item {
                AuditEnable(v) => self.audit.enable = Some(v),
                AclEnable(v) => self.acl.enable = Some(v),
                AuditFile(v) => self.audit.file = Some(self.resolve_filepath(v)),
                AuditFileMode(v) => self.audit.file_mode = Some(v),
                AuditNum(v) => self.audit.num = Some(v),
                AuditSize(v) => self.audit.size = Some(v),
                BindCertFile(v) => self.bind_cert_file = Some(self.resolve_filepath(v)),
                BindCertKeyFile(v) => self.bind_cert_key_file = Some(self.resolve_filepath(v)),
                ApiToken(v) => self.api_token = Some(v),
                BindCertKeyPass(v) => self.bind_cert_key_pass = Some(v),
                CacheFile(v) => self.cache.file = Some(self.resolve_filepath(v)),
                CachePersist(v) => self.cache.persist = Some(v),
                CacheCheckpointTime(v) => self.cache.checkpoint_time = Some(v),
                CNAME(v) => rule_group.cnames.push(v),
                Dns64(v) => self.dns64_prefix = Some(v),
                ExpandPtrFromAddress(v) => self.expand_ptr_from_address = Some(v),
                NftSet(v) => self.nftsets.push(v),
                HttpsRecord(v) => rule_group.https_records.push(v),
                Server(server) => self.nameservers.push(server),
                ResponseMode(mode) => self.response_mode = Some(mode),
                ResolvHostname(v) => self.resolv_hostname = Some(v),
                ServeExpired(v) => self.cache.serve_expired = Some(v),
                PrefetchDomain(v) => self.cache.prefetch_domain = Some(v),
                ForceAAAASOA(v) => self.force_aaaa_soa = Some(v),
                ForceHTTPSSOA(v) => self.force_https_soa = Some(v),
                DualstackIpAllowForceAAAA(v) => self.dualstack_ip_allow_force_aaaa = Some(v),
                DualstackIpSelection(v) => self.dualstack_ip_selection = Some(v),
                ServerName(v) => self.server_name = Some(v),
                // 🔐 P2：`num-workers 0` 会让 tokio 一个工作线程都没有 —— 进程活着、端口也开着，
                // 但一个查询都不会被解析，而且没有任何报错（用户只会以为"DNS 彻底坏了"）。
                // 0 显然是笔误，这里忽略它、改用自动值，并把这件事明确说出来。
                NumWorkers(0) => {
                    crate::log::warn!(
                        "配置项 num-workers 0 无意义（会让服务完全不解析），已忽略该值并改用自动计算的工作线程数"
                    );
                    self.num_workers = None;
                }
                NumWorkers(v) => self.num_workers = Some(v),
                Domain(v) => self.domain = Some(v),
                SpeedMode(v) => self.speed_check_mode = v,
                ServeExpiredTtl(v) => self.cache.serve_expired_ttl = Some(v),
                ServeExpiredReplyTtl(v) => self.cache.serve_expired_reply_ttl = Some(v),
				// 【新增这一行】：将解析器翻译出来的值装入容器
                ServeExpiredPrefetchTime(v) => self.cache.serve_expired_prefetch_time = Some(v),
                CacheSize(v) => self.cache.size = Some(v),
                ForceQtypeSoa(v) => {
                    self.force_qtype_soa.insert(v);
                }
                DualstackIpSelectionThreshold(v) => self.dualstack_ip_selection_threshold = Some(v),
                RrTtl(v) => self.rr_ttl = Some(v),
                RrTtlMin(v) => self.rr_ttl_min = Some(v),
                RrTtlMax(v) => self.rr_ttl_max = Some(v),
                RrTtlReplyMax(v) => self.rr_ttl_reply_max = Some(v),
                Listener(listener) => {
                    // 🔐 P2：证书相对路径先锚定到配置文件所在目录，再入列表
                    let listener = self.anchor_tls_cert_paths(listener);
                    self.binds.push(listener);
                }
                LocalTtl(v) => self.local_ttl = Some(v),
                LogConsole(v) => self.log.console = Some(v),
                LogNum(v) => self.log.num = Some(v),
                LogLevel(v) => self.log.level = Some(v),
                LogFile(v) => self.log.file = Some(self.resolve_filepath(v)),
                LogFileMode(v) => self.log.file_mode = Some(v),
                LogFilter(v) => self.log.filter = Some(v),
                LogSize(v) => self.log.size = Some(v),
                MaxReplyIpNum(v) => self.max_reply_ip_num = Some(v),
                BlacklistIp(v) => self.blacklist_ip.push(v),
                BogusNxDomain(v) => self.bogus_nxdomain.push(v),
                WhitelistIp(v) => self.whitelist_ip.push(v),
                IgnoreIp(v) => self.ignore_ip.push(v),
                CaFile(v) => self.ca_file = Some(v),
                CaPath(v) => self.ca_path = Some(v),
                ConfFile(v) => {
                    // 去重与递归保护统一由 load_file 内部处理（它在递归之前就登记路径），
                    // 此处不再自行 contains/insert：原先这里用的是未 resolve 的原始路径，
                    // 与 load_file 内部 resolve 后的路径不是同一个键，判断必然失效。
                    //
                    // 🌟 修复：原为 .expect("load_file failed")。
                    // 只要 include 的文件存在但打不开（权限不足、路径指向目录、被占用等），
                    // 就会 panic 直接中止整个进程，用户只能看到一句 "load_file failed" 和栈回溯。
                    // 改为打印"哪个文件、什么原因"并跳过该文件、继续加载其余配置。
                    //
                    // 🔐 新增：路径支持通配符（`conf-file /etc/smartdns/conf.d/*.conf`），
                    // 并可写 `-g|-group <组名>` 把这一段被包含进来的配置整体挂到该规则组。
                    let files = self.expand_conf_files(&v.path);
                    if files.is_empty() {
                        warn!(
                            "conf-file {:?} 没有匹配到任何文件（通配符没命中或路径不存在）",
                            v.path
                        );
                    }

                    for file in files {
                        // 用与 group-begin / group-end 完全相同的机制：压栈 → 加载 → 出栈合并。
                        // 必须在 load_file **之前**压栈：文件里那些没写组名的规则要落到这个组里。
                        if let Some(group) = v.group.as_ref() {
                            self.rule_group_stack
                                .push((group.clone(), RuleGroup::default()));
                        }

                        if let Err(err) = self.load_file(file.clone()) {
                            log::error!(
                                "failed to load extra configuration file {:?}: {err}; this file is skipped",
                                file
                            );
                        }

                        if v.group.is_some()
                            && let Some((name, rule_group)) = self.rule_group_stack.pop()
                        {
                            self.rule_groups
                                .entry(name)
                                .or_default()
                                .merge(rule_group);
                        }

                        if let Some(dir) = file.parent() {
                            self.dirs.insert(dir.to_path_buf());
                        }
                    }
                }
                DnsmasqLeaseFile(v) => self.dnsmasq_lease_file = Some(self.resolve_filepath(v)),
                ResolvFile(v) => self.resolv_file = Some(self.resolve_filepath(v)),
                SrvRecord(v) => rule_group.srv_records.push(v),
                DomainRule(v) => rule_group.domain_rules.push(v),
                ForwardRule(v) => rule_group.forward_rules.push(v),
                User(v) => self.user = Some(v),
                TcpIdleTime(v) => self.tcp_idle_time = Some(v),
                FirstPacketTimeout(v) => self.first_packet_timeout = Some(v),
                MaxConnections(v) => self.max_connections = Some(v),
                MaxConnectionsPerIp(v) => self.max_connections_per_ip = Some(v),
                EdnsClientSubnet(v) => self.edns_client_subnet = Some(v),
                Address(v) => rule_group.address_rules.push(v),
                DomainSetProvider(mut v) => {
                    use crate::config::DomainSetProvider;
                    if let DomainSetProvider::File(provider) = &mut v {
                        provider.file = self.resolve_filepath(&provider.file);
                    }
                    self.domain_set_providers
                        .entry(v.name().to_string())
                        .or_default()
                        .push(v);
                }
                ProxyConfig(v) => {
                    self.proxy_servers.insert(v.name.clone(), v.config);
                }
                HostsFile(file) => self.hosts_file = Some(file),
                IpSetProvider(p) => {
                    // 🔐 与 `domain-set` 同款：相对路径按"当前配置文件所在目录"解析；
                    // 来源记录进 `ip_set_providers`（定时刷新按 `-interval` 判断周期），
                    // 内容在这里展开进 `ip_sets` —— 规则树构建时就要用到，不能等到运行时。
                    let p = p.with_resolved_file(|path| self.resolve_filepath(path));
                    self.ip_set_providers
                        .entry(p.name().to_string())
                        .or_default()
                        .push(p.clone());

                    match p.get_ip_set_cached(&self.proxy_servers, self.force_set_refresh) {
                        Ok(net) => {
                            let ips = self.ip_sets.entry(p.name().to_string()).or_default();
                            let len = ips.len();
                            ips.extend(net);
                            log::info!("IpSet load {} records into {}", ips.len() - len, p.name());
                        }
                        Err(err) => {
                            log::error!("IpSet load failed {} {}", p.name(), err);
                        }
                    }
                }
                MdnsLookup(enable) => self.mdns_lookup = Some(enable),
                IpAlias(alias) => self.ip_alias.push(alias),
                GroupBegin(v) => {
                    self.rule_group_stack
                        .push((v.clone(), RuleGroup::default()));
                }
                GroupEnd => {
                    if let Some((name, rule_group)) = self.rule_group_stack.pop() {
                        let group = self.rule_groups.entry(name).or_default();
                        group.merge(rule_group);
                    }
                }
                ClientRule(mut client_rule) => {
                    if client_rule.group.is_empty() {
                        client_rule.group = self
                            .rule_group_stack
                            .last()
                            .map(|(name, _)| name.clone())
                            .unwrap_or_else(|| DEFAULT_GROUP.to_string());
                    }
                    self.client_rules.push(client_rule)
                }
                GroupMatch(group_match) => {
                    // 目标组：显式 -g/--group 优先，否则使用「当前所在的规则组」
                    // （与 C 版 smartdns 的 _config_group_match 行为一致）
                    let group = match group_match.group {
                        Some(group) => group,
                        None => self
                            .rule_group_stack
                            .last()
                            .map(|(name, _)| name.clone())
                            .unwrap_or_else(|| DEFAULT_GROUP.to_string()),
                    };

                    // -c/--client-ip <ip|cidr|mac> 与 `client-rules <值> -g <组>` 完全等价，
                    // 直接复用已有的客户端规则匹配逻辑（含 app.rs 里的 MAC 查询）。
                    // 注意：这里必须写完整路径，因为本作用域内有 `use ConfigItem::*`，
                    // 裸写 ClientRule 会被解析成枚举变体 ConfigItem::ClientRule。
                    for client in group_match.clients {
                        self.client_rules.push(crate::config::ClientRule {
                            client,
                            group: group.clone(),
                        });
                    }

                    // -d/--domain 在 C 版里是「域名 → 规则组」的映射，本项目还没有这套机制。
                    // 明确报错而不是静默忽略，避免用户以为配置已经生效。
                    for domain in &group_match.domains {
                        log::error!(
                            "group-match -domain {domain:?} is not supported yet: \
                             domain-based rule group selection is not implemented, \
                             this entry is ignored"
                        );
                    }
                }
            },
            Ok((_, None)) => (),
            Err(err) => {
                warn!("unknown conf: {}, {:?}", line, err);
            }
        }
    }

    /// 🔐 P2：把 bind-tls / bind-https / bind-h3 的 `-ssl-certificate` / `-ssl-certificate-key`
    /// 相对路径锚定到「配置文件所在目录」（与 `bind-cert-file` 走的是同一套 `resolve_filepath`）。
    ///
    /// 原实现把这串路径原样存下来，运行时按**进程当前工作目录**解析：以服务方式启动时
    /// 那通常是 `/`（Windows 服务工作目录则是 System32），于是证书永远找不到，
    /// 而且报错要等到监听器初始化才出现，离配置解析已经很远，用户很难把两件事联系起来。
    fn anchor_tls_cert_paths(&mut self, mut bind: BindAddrConfig) -> BindAddrConfig {
        let ssl = match &mut bind {
            BindAddrConfig::Tls(cfg) => &mut cfg.ssl_config,
            BindAddrConfig::Https(cfg) => &mut cfg.ssl_config,
            BindAddrConfig::H3(cfg) => &mut cfg.ssl_config,
            _ => return bind,
        };

        // 绝对路径原样保留；相对路径按配置文件所在目录解析（找不到时 resolve_filepath 会回退原值）
        for path in [ssl.certificate.as_mut(), ssl.certificate_key.as_mut()]
            .into_iter()
            .flatten()
        {
            if path.is_relative() {
                *path = self.resolve_filepath(&*path);
            }
        }

        bind
    }

    #[inline]
    /// 把 `conf-file` 的路径展开成实际要加载的文件列表（支持通配符，见 [`expand_conf_pattern`]）。
    fn expand_conf_files(&self, path: &Path) -> Vec<PathBuf> {
        expand_conf_pattern(path, self.conf_file.as_ref())
    }

    #[inline]
    fn resolve_filepath<P: AsRef<Path>>(&self, filepath: P) -> PathBuf {
        let path = resolve_filepath(filepath, self.conf_file.as_ref());

        if path.exists() {
            return path;
        }
        let Some(name) = path.file_name() else {
            return path;
        };

        for dir in self.dirs.iter() {
            let p = dir.join(name);
            if p.is_file() {
                return p;
            }
        }
        path
    }
}

/// 🔐 `conf-file` 的取文件方式：普通路径只返回它自己；带通配符（`*` `?` `[`）时展开成
/// 实际命中的**文件**列表（目录不算）。
///
/// 排序是刻意的：同一份配置在不同机器上必须按同样顺序加载，否则"后写的覆盖先写的"
/// 这类顺序敏感的配置会出现"在我这儿好用、在你那儿不生效"。
/// 相对通配符同样相对"当前配置文件所在目录"（与 [`resolve_filepath`] 的规则一致）。
fn expand_conf_pattern(pattern: &Path, base_file: Option<&PathBuf>) -> Vec<PathBuf> {
    if !pattern.to_string_lossy().contains(['*', '?', '[']) {
        return vec![pattern.to_path_buf()];
    }

    let pattern = if pattern.is_absolute() {
        pattern.to_path_buf()
    } else {
        match base_file.and_then(|file| file.parent()) {
            Some(dir) => dir.join(pattern),
            None => pattern.to_path_buf(),
        }
    };

    let mut files: Vec<PathBuf> = glob::glob(&pattern.to_string_lossy())
        .map(|paths| paths.filter_map(|path| path.ok()).collect())
        .unwrap_or_default();
    files.retain(|path| path.is_file());
    files.sort();

    files
}

fn resolve_filepath<P: AsRef<Path>>(filepath: P, base_file: Option<&PathBuf>) -> PathBuf {
    let filepath = filepath.as_ref();
    if filepath.is_file() {
        return filepath.to_path_buf();
    }

    if !filepath.is_absolute()
        && let Some(base_conf_file) = base_file
            && let Some(dir) = base_conf_file.parent() {
                let new_path = dir.join(filepath);

                if new_path.is_file() {
                    return new_path;
                }

                if matches!(base_conf_file.file_name(), Some(file_name) if file_name == OsStr::new("smartdns.conf"))
                {
                    // eg: /etc/smartdns.d/custom.conf
                    let new_path = dir.join("smartdns.d").join(filepath);

                    if new_path.is_file() {
                        return new_path;
                    }
                }

                if let Ok(new_path) = std::env::current_dir().map(|dir| dir.join(filepath))
                    && new_path.is_file() {
                        return new_path;
                    }

                if let Some(new_path) = std::env::current_exe()
                    .ok()
                    .and_then(|exe| exe.parent().map(|dir| dir.join(filepath)))
                    && new_path.is_file() {
                        return new_path;
                    }
            }

    // try to resolve absolute path by extracting its file_name
    match filepath.file_name().map(Path::new) {
        Some(new_path) if new_path != filepath => {
            let new_path = resolve_filepath(new_path, base_file);
            if new_path.is_file() {
                log::warn!(
                    "File {} not found, but {} found",
                    filepath.display(),
                    new_path.display()
                );
                return new_path;
            }
        }
        _ => (),
    }

    filepath.to_path_buf()
}

#[cfg(test)]
mod tests {
    use crate::{dns::DomainRuleGetter, libdns::Protocol};
    use byte_unit::Byte;

    use crate::config::{BindAddr, HttpsBindAddrConfig, ServerOpts, SslConfig};

    use super::*;

    /// 🔐 P2（用户定策）：组不存在 → 走默认组 + 点名告警。
    /// 判定"组到底存不存在"要能区分"确实定义过"和"名字根本没见过"。
    #[test]
    fn test_group_existence_detection() {
        let cfg = RuntimeConfig::builder()
            .with("server 223.5.5.5:53 -group office")
            .with("group-begin lan")
            .with("client-rules 192.168.1.0/24")
            .with("nameserver /nas.lan/office")
            .with("group-end")
            .build()
            .unwrap();

        // 服务器组：`server ... -group office` 声明过的算存在；默认组/空名恒存在
        assert!(cfg.has_server_group("office"), "office 是 server 行上声明过的组");
        assert!(cfg.has_server_group("default"));
        assert!(cfg.has_server_group(""));
        assert!(cfg.has_server_group("DEFAULT"), "default 的大小写不敏感");
        // 拼错的组名必须判为"不存在"（新行为：回退默认组 + 告警）
        assert!(!cfg.has_server_group("ofice"), "拼错的组名不能算存在");

        // 规则组：group-begin 定义的组存在，没见过的不存在
        assert!(cfg.has_rule_group("lan"), "group-begin lan 定义的组应存在");
        assert!(cfg.has_rule_group("default"));
        assert!(!cfg.has_rule_group("nosuchgroup"));
    }

    /// 🔐 P2：`num-workers 0` 不能真的变成 0 个工作线程（那等于服务完全不解析、还不报错）。
    #[test]
    fn test_num_workers_zero_is_ignored() {
        let cfg = RuntimeConfig::builder()
            .with("num-workers 0")
            .build()
            .unwrap();
        assert!(
            cfg.num_workers() >= 1,
            "num-workers 0 必须被忽略并回落到自动值，实际 {}",
            cfg.num_workers()
        );
    }

    /// 🔐 P2：配置文件里出现非 UTF-8 字节时，**该行之后**的配置必须照常加载。
    /// （原实现用 `lines().map_while(Result::ok)`：一个坏字节会把后面全部配置静默丢掉。）
    #[test]
    fn test_non_utf8_line_does_not_stop_loading() {
        let dir = std::env::temp_dir().join(format!("smartdns-nonutf8-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bad.conf");
        std::fs::write(&path, b"# \xff\xfe garbled bytes\nlocal-ttl 123\n").unwrap();

        let cfg = RuntimeConfig::load(Some(dir.clone()), Some(&path));

        assert_eq!(cfg.local_ttl(), 123, "坏字节那一行之后的配置必须仍然生效");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 P2：bind-https 的证书相对路径必须按「配置文件所在目录」解析。
    /// （原实现按进程工作目录：服务方式启动时那是 `/` 或 System32，证书永远找不到。）
    #[test]
    fn test_tls_cert_relative_path_anchored_to_conf_dir() {
        let dir = std::env::temp_dir().join(format!("smartdns-cert-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let conf = dir.join("smartdns.conf");
        std::fs::write(
            &conf,
            "bind-https 0.0.0.0:8443 -ssl-certificate cert.pem -ssl-certificate-key key.pem\n",
        )
        .unwrap();
        std::fs::write(dir.join("cert.pem"), "x").unwrap();
        std::fs::write(dir.join("key.pem"), "x").unwrap();

        let cfg = RuntimeConfig::load(Some(dir.clone()), Some(&conf));
        let ssl = cfg
            .binds()
            .iter()
            .find_map(|b| match b {
                BindAddrConfig::Https(c) => Some(&c.ssl_config),
                _ => None,
            })
            .expect("应该有 bind-https 配置");

        assert_eq!(
            ssl.certificate.as_deref(),
            Some(dir.join("cert.pem").as_path()),
            "相对证书路径应解析成 <配置文件目录>/cert.pem"
        );
        assert_eq!(
            ssl.certificate_key.as_deref(),
            Some(dir.join("key.pem").as_path())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_binds_dedup() {
        let cfg = RuntimeConfig::builder()
            .with("bind-tcp 0.0.0.0:4453@eth1")
            .with("bind-tls 0.0.0.0:4452@eth1")
            .with("bind-https 0.0.0.0:4453@eth1")
            .build()
            .unwrap();

        assert_eq!(
            cfg.binds()
                .iter()
                .filter(|x| matches!(x, BindAddrConfig::Tcp(_)))
                .count(),
            0
        );
        assert_eq!(
            cfg.binds()
                .iter()
                .filter(|x| matches!(x, BindAddrConfig::Tls(_)))
                .count(),
            1
        );
        assert_eq!(
            cfg.binds()
                .iter()
                .filter(|x| matches!(x, BindAddrConfig::Https(_)))
                .count(),
            1
        );
    }

    #[test]
    fn test_config_bind_with_device() {
        let cfg = RuntimeConfig::builder()
            .with("bind 0.0.0.0:4453@eth100")
            .with("bind 0.0.0.0:4453@eth100")
            .build()
            .unwrap();

        assert_eq!(cfg.binds().len(), 1);

        let bind = cfg.binds().first().unwrap();

        assert_eq!(bind.addr(), BindAddr::V4("0.0.0.0".parse().unwrap()));
        assert_eq!(bind.port(), 4453);

        assert_eq!(bind.device(), Some("eth100"));
    }

    #[test]
    fn test_config_bind_with_device_flags() {
        let cfg = RuntimeConfig::builder()
            .with("bind-https 0.0.0.0:443@eth2 -no-rule-addr")
            .build()
            .unwrap();

        let listener = cfg.binds().first().unwrap();

        assert_eq!(
            listener,
            &BindAddrConfig::Https(HttpsBindAddrConfig {
                addr: BindAddr::V4("0.0.0.0".parse().unwrap()),
                port: 443,
                device: Some("eth2".to_string()),
                opts: ServerOpts {
                    no_rule_addr: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            })
        );
    }

    #[test]
    fn test_config_bind_https() {
        let mut cfg = RuntimeConfig::builder();

        cfg.config(
                "bind-https 0.0.0.0:4453 -server-name dns.example.com -ssl-certificate /etc/nginx/dns.example.com.crt -ssl-certificate-key /etc/nginx/dns.example.com.key",
            );

        let cfg = cfg.build().unwrap();

        assert!(!cfg.binds().is_empty());

        let listener = cfg.binds().first().unwrap();

        assert_eq!(
            listener,
            &BindAddrConfig::Https(HttpsBindAddrConfig {
                addr: BindAddr::V4("0.0.0.0".parse().unwrap()),
                port: 4453,
                ssl_config: SslConfig {
                    server_name: Some("dns.example.com".to_string()),
                    certificate: Some(Path::new("/etc/nginx/dns.example.com.crt").to_path_buf()),
                    certificate_key: Some(
                        Path::new("/etc/nginx/dns.example.com.key").to_path_buf()
                    ),
                    certificate_key_pass: None
                },
                ..Default::default()
            })
        );
    }

    #[test]
    fn test_config_server_0() {
        let cfg = RuntimeConfig::builder()
            .with(
                "server-https https://223.5.5.5/dns-query -group bootstrap -exclude-default-group",
            )
            .build()
            .unwrap();

        assert_eq!(cfg.get_server_group("bootstrap").len(), 1);

        let server_group = cfg.get_server_group("bootstrap");
        let server = server_group.first().cloned().unwrap();

        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");

        assert!(server.group.iter().any(|g| g == "bootstrap"));
        assert!(server.exclude_default_group);
    }

    #[test]
    fn test_config_server_1() {
        let cfg = RuntimeConfig::builder()
            .with("server-https https://223.5.5.5/dns-query")
            .build()
            .unwrap();

        assert_eq!(cfg.nameservers.len(), 1);

        let server_group = cfg.get_server_group(DEFAULT_GROUP);

        let server = server_group.first().cloned().unwrap();

        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");
        assert!(server.group.is_empty());
        assert!(!server.exclude_default_group);
    }

    #[test]
    fn test_config_server_2() {
        let cfg = RuntimeConfig::builder()
            .with("server-https https://223.5.5.5/dns-query  -bootstrap-dns -exclude-default-group")
            .build()
            .unwrap();

        let server = cfg.nameservers.iter().find(|s| s.bootstrap_dns).unwrap();

        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");
        assert!(server.exclude_default_group);
        assert!(server.bootstrap_dns);
    }

    #[test]
    fn test_config_bind_http_no_api() {
        // 写了 -no-api：该监听只提供 DoH，不挂管理后台
        let cfg = RuntimeConfig::builder()
            .with("bind-http 127.0.0.1:18000 -no-api")
            .build()
            .unwrap();
        let b = cfg
            .binds()
            .iter()
            .find_map(|b| match b {
                crate::config::BindAddrConfig::Http(h) => Some(h),
                _ => None,
            })
            .unwrap();
        assert!(b.opts.no_api());

        // 没写：后台照旧挂载（保持向后兼容）
        let cfg2 = RuntimeConfig::builder()
            .with("bind-http 127.0.0.1:18001")
            .build()
            .unwrap();
        let b2 = cfg2
            .binds()
            .iter()
            .find_map(|b| match b {
                crate::config::BindAddrConfig::Http(h) => Some(h),
                _ => None,
            })
            .unwrap();
        assert!(!b2.opts.no_api());
    }

    #[test]
    fn test_config_connection_limits() {
        let cfg = RuntimeConfig::builder()
            .with("max-connections 2000")
            .with("max-connections-per-ip 500")
            .build()
            .unwrap();
        assert_eq!(cfg.max_connections(), Some(2000));
        assert_eq!(cfg.max_connections_per_ip(), Some(500));

        // 未配置必须是 None（交给按内存自动推算，绝不写死默认值）
        let cfg2 = RuntimeConfig::builder().build().unwrap();
        assert_eq!(cfg2.max_connections(), None);
        assert_eq!(cfg2.max_connections_per_ip(), None);
    }

    #[test]
    fn test_config_first_packet_timeout() {
        // 默认 5 秒
        let cfg = RuntimeConfig::builder().build().unwrap();
        assert_eq!(
            cfg.first_packet_timeout(),
            Some(std::time::Duration::from_secs(5))
        );

        // 0 = 显式关闭
        let cfg2 = RuntimeConfig::builder()
            .with("first-packet-timeout 0")
            .build()
            .unwrap();
        assert_eq!(cfg2.first_packet_timeout(), None);
    }

    #[test]
    fn test_config_api_token() {
        // 配置里写了 api-token，就该读到它
        let cfg = RuntimeConfig::builder()
            .with("api-token my-strong-token-123")
            .build()
            .unwrap();
        assert_eq!(cfg.api_token(), Some("my-strong-token-123"));

        // 没写就必须是 None —— 代码里绝不允许留任何写死的默认口令
        let cfg = RuntimeConfig::builder().build().unwrap();
        assert_eq!(cfg.api_token(), None);
    }

    #[test]
    fn test_api_token_not_hardcoded() {
        // 只要用户没配置，判断就不能是"已配置"（这条锁住 P0-1：不许再有写死的默认口令）
        assert!(crate::api::has_configured_token(Some("set-by-user")));
        assert!(!crate::api::has_configured_token(Some("   ")));
    }

    #[test]
    fn test_config_server_with_client_subnet() {
        let cfg = RuntimeConfig::builder().with(
                "server-https https://223.5.5.5/dns-query  -bootstrap-dns -exclude-default-group -subnet 192.168.0.0/16",
            ).build().unwrap();

        let server = cfg.nameservers.iter().find(|s| s.bootstrap_dns).unwrap();

        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");
        assert_eq!(server.subnet, Some("192.168.0.0/16".parse().unwrap()));
        assert!(server.exclude_default_group);
        assert!(server.bootstrap_dns);
    }

    #[test]
    fn test_config_server_with_mark_1() {
        let cfg = RuntimeConfig::builder()
            .with("server-https https://223.5.5.5/dns-query -set-mark 255")
            .build()
            .unwrap();
        let server = cfg.nameservers.first().unwrap();
        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");
        assert_eq!(server.so_mark, Some(255));
    }

    #[test]
    fn test_config_server_with_mark_2() {
        let cfg = RuntimeConfig::builder()
            .with("server-https https://223.5.5.5/dns-query -set-mark 0xff")
            .build()
            .unwrap();

        let server = cfg.nameservers.first().unwrap();

        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");
        assert_eq!(server.so_mark, Some(255));
    }

    #[test]
    fn test_config_tls_server() {
        let cfg = RuntimeConfig::builder()
            .with(
                "server-tls 45.90.28.0 -host-name: dns.nextdns.io -tls-host-verify: dns.nextdns.io",
            )
            .build()
            .unwrap();

        let server = cfg.nameservers.first().unwrap();

        assert!(!server.exclude_default_group);
        assert_eq!(server.server.proto(), &Protocol::Tls);
        assert_eq!(
            server.server.to_string(),
            "tls://dns.nextdns.io?ip=45.90.28.0"
        );
        assert_eq!(server.server.ip(), "45.90.28.0".parse::<IpAddr>().ok());
        assert_eq!(server.server.name().as_ref(), "dns.nextdns.io");
    }

    #[test]
    fn test_config_address_soa() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/#");

        let cfg = builder.build().unwrap();

        let domain_addr_rule = cfg
            .rule_groups
            .get(DEFAULT_GROUP)
            .unwrap()
            .address_rules
            .last()
            .unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::SOA);
    }

    #[test]
    fn test_config_domain_rules_without_args() {
        let mut builder = RuntimeConfig::builder();
        builder
            .config("domain-set -name domain-forwarding-list -file tests/test_data/block-list.txt");
        builder.config("domain-rules /domain-set:domain-forwarding-list/");
        let cfg = builder.build().unwrap();
        assert!(
            cfg.rule_groups
                .get(DEFAULT_GROUP)
                .unwrap()
                .address_rules
                .last()
                .is_none()
        );
    }

    #[test]
    fn test_config_address_soa_v4() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/#4");

        let cfg = builder.build().unwrap();

        let domain_addr_rule = cfg.rule_group(DEFAULT_GROUP).address_rules.last().unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::SOAv4);
    }

    #[test]
    fn test_config_address_soa_v6() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/#6");

        let cfg = builder.build().unwrap();

        let domain_addr_rule = cfg.rule_group(DEFAULT_GROUP).address_rules.last().unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::SOAv6);
    }

    #[test]
    fn test_config_address_ignore() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/-");

        let cfg = builder.build().unwrap();
        let domain_addr_rule = cfg.rule_group(DEFAULT_GROUP).address_rules.last().unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::IGN);
    }

    #[test]
    fn test_config_address_ignore_v4() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/-4");

        let cfg = builder.build().unwrap();
        let domain_addr_rule = cfg.rule_group(DEFAULT_GROUP).address_rules.last().unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::IGNv4);
    }

    #[test]
    fn test_config_address_ignore_v6() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/-6");

        let cfg = builder.build().unwrap();
        let domain_addr_rule = cfg.rule_group(DEFAULT_GROUP).address_rules.first().unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::IGNv6);
    }

    #[test]
    fn test_config_address_whitelist_mode() {
        let cfg = RuntimeConfig::builder()
            .with("address /google.com/-")
            .with("address /./#")
            .build()
            .unwrap();

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"cloudflare.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"google.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::IGN)
        );
    }

    #[test]
    fn test_config_address_wildcard_1() {
        let cfg = RuntimeConfig::builder()
            .with("address /-.example.com/#")
            .build()
            .unwrap();
        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"example.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"aa.example.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            None
        );
    }

    #[test]
    fn test_config_address_wildcard_2() {
        let cfg = RuntimeConfig::builder()
            .with("address /*/#")
            .build()
            .unwrap();
        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"localhost".parse().unwrap())
                .cloned()
                .get_ref(|n| n.address.as_ref()),
            Some(&AddressRuleValue::SOA)
        );

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"aa.example.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            None
        );
    }

    #[test]
    fn test_config_address_wildcard_3() {
        let cfg = RuntimeConfig::builder()
            .with("address /+/#")
            .build()
            .unwrap();
        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"localhost".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"aa.example.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );
    }

    #[test]
    fn test_config_address_wildcard_4() {
        let cfg = RuntimeConfig::builder()
            .with("address /./#")
            .build()
            .unwrap();
        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"localhost".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"aa.example.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );
    }

    #[test]
    fn test_config_nameserver() {
        let mut builder = RuntimeConfig::builder();

        builder.config("nameserver /doh.pub/bootstrap");

        let cfg = builder.build().unwrap();
        let nameserver_rule = cfg
            .rule_groups
            .get(DEFAULT_GROUP)
            .unwrap()
            .forward_rules
            .first()
            .unwrap();

        assert_eq!(
            nameserver_rule.domain,
            Domain::Name("doh.pub".parse().unwrap())
        );

        assert_eq!(nameserver_rule.nameserver, "bootstrap");
    }

    #[test]
    fn test_config_domain_rule() {
        let mut builder = RuntimeConfig::builder();

        builder.config("domain-rule /doh.pub/ -c ping -a 127.0.0.1 -n test -d yes");

        let cfg = builder.build().unwrap();
        let domain_rule = cfg.rule_group(DEFAULT_GROUP).domain_rules.first().unwrap();

        assert_eq!(domain_rule.domain, Domain::Name("doh.pub".parse().unwrap()));
        assert_eq!(
            domain_rule.address,
            Some(AddressRuleValue::Addr {
                v4: Some(["127.0.0.1".parse().unwrap()].into()),
                v6: None
            })
        );
        assert_eq!(
            domain_rule.speed_check_mode,
            Some(vec![SpeedCheckMode::Ping].into())
        );
        assert_eq!(domain_rule.nameserver, Some("test".to_string()));
        assert_eq!(domain_rule.dualstack_ip_selection, Some(true));
    }

    #[test]
    fn test_config_domain_rule_2() {
        let mut builder = RuntimeConfig::builder();

        builder.config("domain-rules /doh.pub/ -c ping -a 127.0.0.1 -n test -d yes");

        let cfg = builder.build().unwrap();
        let domain_rule = cfg.rule_group(DEFAULT_GROUP).domain_rules.first().unwrap();

        assert_eq!(domain_rule.domain, Domain::Name("doh.pub".parse().unwrap()));
        assert_eq!(
            domain_rule.address,
            Some(AddressRuleValue::Addr {
                v4: Some(["127.0.0.1".parse().unwrap()].into()),
                v6: None
            })
        );
        assert_eq!(
            domain_rule.speed_check_mode,
            Some(vec![SpeedCheckMode::Ping].into())
        );
        assert_eq!(domain_rule.nameserver, Some("test".to_string()));
        assert_eq!(domain_rule.dualstack_ip_selection, Some(true));
    }

    #[test]
    fn test_config_domain_rule_3() {
        let cfg = RuntimeConfig::builder()
            .with("domain-rules /doh.pub/ -c ping -a # -n test -d yes")
            .build()
            .unwrap();

        let domain_rule = cfg
            .domain_rule_group("default")
            .find(&"doh.pub".parse().unwrap())
            .cloned()
            .unwrap();

        assert_eq!(domain_rule.name(), &"doh.pub".parse().unwrap());
        assert_eq!(domain_rule.address, Some(AddressRuleValue::SOA));
        assert_eq!(
            domain_rule.speed_check_mode,
            Some(vec![SpeedCheckMode::Ping].into())
        );
        assert_eq!(domain_rule.nameserver, Some("test".to_string()));
        assert_eq!(domain_rule.dualstack_ip_selection, Some(true));
    }

    #[test]
    fn test_parse_config_log_file_mode() {
        let mut cfg = RuntimeConfig::builder();

        cfg.config("log-file-mode 644");
        assert_eq!(cfg.log.file_mode, Some(0o644u32.into()));
        cfg.config("log-file-mode 0o755");
        assert_eq!(cfg.log.file_mode, Some(0o755u32.into()));
    }

    #[test]
    fn test_parse_config_speed_check_mode() {
        let mut cfg = RuntimeConfig::builder();
        cfg.config("speed-check-mode ping,tcp:123");

        assert_eq!(cfg.speed_check_mode.as_ref().unwrap().len(), 2);

        assert_eq!(
            cfg.speed_check_mode.as_ref().unwrap().first().unwrap(),
            &SpeedCheckMode::Ping
        );
        assert_eq!(
            cfg.speed_check_mode.as_ref().unwrap().get(1).unwrap(),
            &SpeedCheckMode::Tcp(123)
        );
    }

    #[test]
    fn test_parse_config_speed_check_mode_https_omit_port() {
        let mut cfg = RuntimeConfig::builder();
        // 修复：原写法是 "tcp,https" 并期望 tcp 省略端口时默认为 80。
        // 但按设计 tcp 必须显式带端口（见 src/config/parser/speed_mode.rs 的单元测试
        // 明确断言 `SpeedCheckMode::parse("tcp").is_err()`），只有 https 允许省略（默认 443）。
        // 因此给 tcp 补上端口；测试名关注的 "https 省略端口" 语义保持不变。
        cfg.config("speed-check-mode tcp:80,https");

        assert_eq!(cfg.speed_check_mode.as_ref().unwrap().len(), 2);

        assert_eq!(
            cfg.speed_check_mode.as_ref().unwrap().first().unwrap(),
            &SpeedCheckMode::Tcp(80)
        );
        assert_eq!(
            cfg.speed_check_mode.as_ref().unwrap().get(1).unwrap(),
            &SpeedCheckMode::Https(443)
        );
    }

    #[test]
    fn test_default_audit_size_1() {
        use byte_unit::Unit;
        let cfg = RuntimeConfig::builder().build().unwrap();
        assert_eq!(
            cfg.audit_size(),
            Byte::from_i64_with_unit(128, Unit::KB).unwrap().as_u64()
        );
    }

    #[test]
    fn test_parse_config_audit_size_1() {
        use byte_unit::Unit;
        let mut cfg = RuntimeConfig::builder();
        cfg.config("audit-size 80mb");
        assert_eq!(cfg.audit.size, Byte::from_i64_with_unit(80, Unit::MB));
    }

    #[test]
    fn test_parse_config_audit_size_2() {
        use byte_unit::Unit;
        let mut cfg = RuntimeConfig::builder();
        cfg.config("audit-size 30 gb");
        assert_eq!(cfg.audit.size, Byte::from_i64_with_unit(30, Unit::GB));
    }

    #[test]
    fn test_parse_load_config_file_b() {
        let cfg = RuntimeConfig::builder()
            .with_conf_file("tests/test_data/b_main.conf")
            .build()
            .unwrap();

        assert_eq!(cfg.server_name, "SmartDNS123".parse().ok());
        assert_eq!(
            cfg.rule_group(DEFAULT_GROUP)
                .forward_rules
                .first()
                .unwrap()
                .domain,
            Domain::Name("doh.pub".parse().unwrap())
        );
        assert_eq!(
            cfg.rule_group(DEFAULT_GROUP)
                .forward_rules
                .first()
                .unwrap()
                .nameserver,
            "bootstrap"
        );
    }

    #[test]
    fn test_parse_config_proxy_server() {
        let mut cfg = RuntimeConfig::builder();
        cfg.config("proxy-server socks5://127.0.0.1:1080 -n abc");

        assert_eq!(
            cfg.proxy_servers.get("abc").map(|s| s.to_string()),
            Some("socks5://127.0.0.1:1080".to_string())
        );
    }

    #[test]
    fn test_domain_set() {
        use crate::collections::DomainSet;

        let cfg = RuntimeConfig::builder()
            .with_conf_file("tests/test_data/b_main.conf")
            .build()
            .unwrap();

        assert!(!cfg.domain_set_providers.is_empty());

        let domain_set_providers = cfg
            .domain_set_providers
            .get("block")
            .map(|s| s.as_slice())
            .unwrap_or_default();

        let domain_set = domain_set_providers
            .iter()
            // 修复编译错误：get_domain_set() 后来新增了"代理池"参数（用于支持 domain-set
            // 通过代理下载），此测试不涉及代理，传一个空表即可。
            .flat_map(|p| p.get_domain_set(&Default::default()).unwrap_or_default())
            .collect::<DomainSet>();

        assert!(!domain_set.is_empty());

        assert!(domain_set.contains(&"ads1.com".parse().unwrap()));
        assert!(!domain_set.contains(&"ads2c.cn".parse().unwrap()));
        // assert!(domain_set.is_match(&Name::from_str("ads3.net").unwrap().into()));
        // assert!(domain_set.is_match(&Name::from_str("q.ads3.net").unwrap().into()));
    }

    #[test]
    fn test_parse_https_record() {
        let cfg = RuntimeConfig::builder()
            .with("https-record #")
            .build()
            .unwrap();
        assert_eq!(cfg.rule_group(DEFAULT_GROUP).https_records.len(), 1);
        assert_eq!(
            cfg.rule_group(DEFAULT_GROUP).https_records[0].config,
            HttpsRecordRule::SOA
        );
    }

    #[test]
    fn test_ip_set() {
        let cfg = RuntimeConfig::builder()
            .with_conf_file("tests/test_data/b_main.conf")
            .build()
            .unwrap();

        let v4: Vec<_> = include_str!("../tests/test_data/cf-ipv4.txt")
            .lines()
            .map(|line| line.parse().unwrap())
            .collect();
        let v6: Vec<_> = include_str!("../tests/test_data/cf-ipv6.txt")
            .lines()
            .map(|line| line.parse().unwrap())
            .collect();
        let all: [&[_]; 3] = [&["1.1.1.1/32".parse().unwrap()], &v4, &v6];
        let all = IpSet::new(all.into_iter().flatten().copied());

        assert_eq!(cfg.ip_sets["cf-ipv4"], v4);
        assert_eq!(cfg.ip_sets["cf-ipv6"], v6);
        assert_eq!(*cfg.whitelist_ip, all);
    }

    #[test]
    fn test_ip_alias() {
        let cfg = RuntimeConfig::builder()
            .with_conf_file("tests/test_data/b_main.conf")
            .build()
            .unwrap();
        let addr = |s: &str| s.parse::<IpAddr>().unwrap();
        let get_alias = |s: &str| &**cfg.ip_alias.get(&addr(s)).unwrap();

        assert_eq!(get_alias("104.16.0.0"), [addr("1.2.3.4"), addr("::5678")]);
        assert_eq!(get_alias("2400:cb00::"), [addr("::1234"), addr("5.6.7.8")]);
        assert_eq!(get_alias("172.64.0.0"), [addr("90AB::CDEF")]);
    }

    #[test]
    fn test_rule_group() {
        let cfg = RuntimeConfig::builder()
            .with("address /example.com/1.2.3.4")
            .with("group-begin a")
            .with("address /example.com/1.2.3.5")
            .with("group-end")
            .with("group-begin b")
            .with("address /example.com/1.2.3.6")
            .build()
            .unwrap();

        let g0 = cfg.rule_group("default");
        let g1 = cfg.rule_group("a");
        let g2 = cfg.rule_group("b");

        assert_eq!(
            g0.address_rules.first().unwrap().address,
            AddressRuleValue::Addr {
                v4: Some(vec!["1.2.3.4".parse().unwrap()].into()),
                v6: None
            }
        );
        assert_eq!(
            g1.address_rules.first().unwrap().address,
            AddressRuleValue::Addr {
                v4: Some(vec!["1.2.3.5".parse().unwrap()].into()),
                v6: None
            }
        );
        assert_eq!(
            g2.address_rules.first().unwrap().address,
            AddressRuleValue::Addr {
                v4: Some(vec!["1.2.3.6".parse().unwrap()].into()),
                v6: None
            }
        );
    }

    #[test]
    fn test_client_rule_without_group_uses_current_rule_group() {
        let cfg = RuntimeConfig::builder()
            .with("client-rules 192.168.1.0/24")
            .with("group-begin group-a")
            .with("client-rules 192.168.100.0/24")
            .with("group-end")
            .build()
            .unwrap();

        assert_eq!(cfg.client_rules().len(), 2);
        assert_eq!(cfg.client_rules()[0].group, DEFAULT_GROUP);
        assert_eq!(cfg.client_rules()[1].group, "group-a");
        assert_eq!(
            cfg.client_rules()[1].client,
            Client::IpAddr("192.168.100.0/24".parse().unwrap())
        );
    }

    #[test]
    fn test_client_rule_explicit_group_overrides_current_rule_group() {
        let cfg = RuntimeConfig::builder()
            .with("group-begin group-a")
            .with("client-rules 192.168.100.0/24 -group office")
            .with("group-end")
            .build()
            .unwrap();

        assert_eq!(cfg.client_rules().len(), 1);
        assert_eq!(cfg.client_rules()[0].group, "office");
    }

    #[test]
    fn test_group_match_client_ip_uses_current_group_and_explicit_group() {
        let cfg = RuntimeConfig::builder()
            .with("group-begin group-a")
            // 不带 -g：使用当前所在的规则组 group-a
            .with("group-match -client-ip 192.168.100.0/24")
            // 带 -g：使用指定的 group-b（顺便验证 C 版文档里的裸 IP 写法）
            .with("group-match -g group-b -client-ip 10.0.0.1")
            // MAC 地址同样支持
            .with("group-match -client-ip 01:02:03:04:05:06")
            .with("group-end")
            .build()
            .unwrap();

        let rules = cfg.client_rules();
        assert_eq!(rules.len(), 3);

        assert_eq!(rules[0].group, "group-a");
        assert_eq!(
            rules[0].client,
            Client::IpAddr("192.168.100.0/24".parse().unwrap())
        );

        assert_eq!(rules[1].group, "group-b");
        assert_eq!(rules[1].client, Client::IpAddr("10.0.0.1/32".parse().unwrap()));

        assert_eq!(rules[2].group, "group-a");
        assert_eq!(rules[2].client, Client::Mac("01:02:03:04:05:06".to_string()));
    }

    #[test]
    fn test_group_match_without_group_uses_default_group() {
        // 不在任何 group-begin 里 → 落到默认组
        let cfg = RuntimeConfig::builder()
            .with("group-match -client-ip 192.168.1.1")
            .build()
            .unwrap();

        assert_eq!(cfg.client_rules().len(), 1);
        assert_eq!(cfg.client_rules()[0].group, DEFAULT_GROUP);
        assert_eq!(
            cfg.client_rules()[0].client,
            Client::IpAddr("192.168.1.1/32".parse().unwrap())
        );
    }

    #[test]
    fn test_group_match_domain_is_not_supported_yet() {
        // -domain 在 C 版里是「域名 → 规则组」映射，本项目尚未实现该机制。
        // 这里锁定行为：它不产生任何客户端规则（加载时会打一条 error 日志提醒用户），
        // 而不是被静默当成"条件已生效"。
        let cfg = RuntimeConfig::builder()
            .with("group-begin office")
            .with("group-match -domain a.com")
            .with("group-end")
            .build()
            .unwrap();

        assert!(cfg.client_rules().is_empty());
    }

    /// `conf-file` 的通配符展开：只收**文件**、按名字排序、无通配符时原样返回一个路径。
    #[test]
    fn test_expand_conf_pattern() {
        let dir = std::env::temp_dir().join(format!("conf-pattern-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("conf.d")).unwrap();
        // 干扰项：名字像配置文件的**目录**，必须被跳过
        std::fs::create_dir_all(dir.join("conf.d").join("zz.conf")).unwrap();
        for name in ["20-b.conf", "10-a.conf", "05-先.conf", "note.txt"] {
            std::fs::write(dir.join("conf.d").join(name), "#\n").unwrap();
        }

        let names = |files: Vec<std::path::PathBuf>| -> Vec<String> {
            files
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect()
        };

        // 绝对路径通配符
        let pattern = dir.join("conf.d").join("*.conf");
        assert_eq!(
            names(expand_conf_pattern(&pattern, None)),
            ["05-先.conf", "10-a.conf", "20-b.conf"],
            "只取*.conf 文件、目录跳过，并且按名字排序（加载顺序要稳定）"
        );

        // 相对通配符 → 相对"当前配置文件所在目录"
        let base = dir.join("smartdns.conf");
        assert_eq!(
            names(expand_conf_pattern(std::path::Path::new("conf.d/*.conf"), Some(&base))),
            ["05-先.conf", "10-a.conf", "20-b.conf"]
        );

        // 没有通配符：原样返回（存在性判断交给 load_file）
        let plain = dir.join("conf.d").join("10-a.conf");
        assert_eq!(expand_conf_pattern(&plain, None), vec![plain.clone()]);

        // 通配符一个都没命中：返回空列表（调用方据此告警）
        let none = dir.join("conf.d").join("*.nomatch");
        assert!(expand_conf_pattern(&none, None).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// 哪些配置关键字的值属于敏感信息（口令/密码）—— 这类行**绝不能**原样进日志。
const SENSITIVE_CONFIG_KEYS: &[&str] = &["proxy-server", "api-token", "bind-cert-key-pass"];

/// 把一行"没认出来"的配置**脱敏**后再用于日志。
///
/// 为什么需要它：这条告警的目的是帮用户找到拼写错误，但整行原文里可能带口令 ——
/// `proxy-server socks5://user:pass@1.2.3.4:1080`（代理密码）、`api-token <口令>`、
/// `bind-cert-key-pass <私钥口令>`；而"行尾多写一个字""关键字拼错"恰好是最容易触发它的情形。
///
/// 规则：
/// 1. 首关键字属于敏感项 → 只报关键字，值整段隐藏；
/// 2. 其余行 → 原样返回，但把 URL 里的 `user:pass@` 打码（防"配置项认出来了、行尾粘了个带口令的代理 URL"）。
pub(crate) fn redact_config_line(line: &str) -> String {
    if let Some(kw) = line.trim_start().split_whitespace().next() {
        let kw_lower = kw.to_ascii_lowercase();
        if SENSITIVE_CONFIG_KEYS.contains(&kw_lower.as_str()) {
            return format!("{kw} <已隐藏：该行含口令/密码>");
        }
    }
    redact_url_userinfo(line)
}

/// 把 `scheme://user:pass@host` 打码成 `scheme://***@host`。
/// 不含 `://` 或 `@` 的行原样返回（保持日志里能看清拼写错误）。
fn redact_url_userinfo(line: &str) -> String {
    if !line.contains("://") || !line.contains('@') {
        return line.to_string();
    }
    line.split_whitespace()
        .map(|token| match (token.find("://"), token.rfind('@')) {
            (Some(scheme_end), Some(at)) if at > scheme_end + 3 => {
                let mut masked = String::with_capacity(token.len());
                masked.push_str(&token[..scheme_end + 3]);
                masked.push_str("***");
                masked.push_str(&token[at..]);
                masked
            }
            _ => token.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod config_line_redact_tests {
    use super::redact_config_line;

    /// 🔐 A1：含口令的配置行**不许**原样进日志。
    #[test]
    fn sensitive_config_lines_never_leak_secrets() {
        // 代理密码：整行被隐藏
        let masked = redact_config_line("proxy-server socks5://alice:s3cr3t@1.2.3.4:1080 多写的字");
        assert!(!masked.contains("s3cr3t"), "代理密码不得出现在日志里：{masked}");
        assert!(masked.contains("proxy-server"), "仍要报出是哪个关键字：{masked}");

        // 管理口令与私钥口令
        let masked = redact_config_line("api-token MyS3cretToken 多写的字");
        assert!(!masked.contains("MyS3cretToken"), "管理口令不得出现在日志里：{masked}");
        let masked = redact_config_line("bind-cert-key-pass MyKeyPass 多写的字");
        assert!(!masked.contains("MyKeyPass"), "私钥口令不得出现在日志里：{masked}");

        // 关键字本身写错（整行谁都不认）也要脱敏
        let masked = redact_config_line("  PROXY-SERVER socks5://u:p@h:1080 拼错了");
        assert!(!masked.contains(":p@"), "大小写不同的关键字也要挡住：{masked}");

        // 非敏感行：保留原文，用户才看得出拼写错在哪
        let plain = "addres /typo.test/1.2.3.4";
        assert_eq!(redact_config_line(plain), plain);

        // 行尾粘了带口令的 URL：只打码 user:pass，其余照旧
        let masked = redact_config_line("address /x.test/1.2.3.4 socks5://bob:hunter2@h:1080");
        assert!(!masked.contains("hunter2"), "URL 里的口令必须打码：{masked}");
        assert!(masked.contains("address /x.test/1.2.3.4"), "无关部分照旧显示：{masked}");
        assert!(masked.contains("socks5://***@h:1080"), "打码形态要能看出是个代理 URL：{masked}");
    }
}

#[cfg(test)]
mod ttl_clamp_tests {
    use crate::config::TTL_MAX;
    use crate::dns_conf::RuntimeConfig;

    /// 🔐 A7：TTL 类配置一律夹到 DNS 规范上限。`local-ttl` 与 `serve-expired-*` 以前漏了这一步，
    /// 写 `4294967297` 会被下游 `as u32` **静默**截成 1 秒（本地记录/过期答复的有效期瞬间崩掉）。
    #[test]
    fn ttl_configs_are_clamped_to_spec_max() {
        let cfg = RuntimeConfig::builder()
            .with("local-ttl 4294967297")
            .with("serve-expired-ttl 4294967297")
            .with("serve-expired-reply-ttl 4294967297")
            .with("serve-expired-prefetch-time 4294967297")
            .build()
            .unwrap();

        assert_eq!(cfg.local_ttl(), TTL_MAX, "local-ttl 必须夹到上限");
        assert_eq!(cfg.serve_expired_ttl(), TTL_MAX, "serve-expired-ttl 必须夹到上限");
        assert_eq!(
            cfg.serve_expired_reply_ttl(),
            TTL_MAX,
            "serve-expired-reply-ttl 必须夹到上限"
        );
        assert_eq!(
            cfg.serve_expired_prefetch_time(),
            TTL_MAX,
            "serve-expired-prefetch-time 必须夹到上限"
        );

        // 护栏：正常值不许被动过
        let cfg = RuntimeConfig::builder()
            .with("local-ttl 600")
            .with("serve-expired-reply-ttl 7")
            .build()
            .unwrap();
        assert_eq!(cfg.local_ttl(), 600);
        assert_eq!(cfg.serve_expired_reply_ttl(), 7);
    }
}


