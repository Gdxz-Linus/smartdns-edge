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

/// 🔐 Q3/Q5：`ipset-no-speed` / `nftset-no-speed` 的说明（每次加载只提示一次）。
///
/// 为什么不用开：本实现把解析出的地址**全部**写入集合（与既有的 `nftset` 行为一致）。
/// C 版的默认是「先测速、只把最快的那一个写进去」—— 那样按域名做分流时会漏掉其它 IP，
/// 所以我们不照抄那个默认，也不假装支持这两个开关：认下来 + 说明白。
fn notice_no_speed() {
    if log::warn_once("set-no-speed-is-default") {
        crate::log::warn!(
            "`ipset-no-speed` / `nftset-no-speed` need not be set: this implementation always writes all resolved addresses into the set, which is already equivalent to these switches. The configuration is accepted and behaviour is unchanged."
        );
    }
}

/// 📌 **按设计不支持**写进规则组的参数。
///
/// ## 这里曾经有过另一类拒绝：「尚未支持」
///
/// 上游 `dns_conf_group` 的 AUTO COPY 区段里，有 20 个参数既能写顶层、也能写进
/// `group-begin` 块。本仓库原先只实现了顶层那一半，而**写在组里的那些会被静默写进全局**
/// —— 那是"生效在了错的地方且无人告知"，对从上游迁移过来的用户尤其危险
/// （他们按老习惯在组里写是必然的）。
///
/// 当时的处置是"明确报错并忽略该行"，逐批补齐后，到 丙-2c（2026-09-26）为止
/// **那 20 个已全部支持**，相关的判定函数随之删除。保留这段沿革是为了说明：
/// 现在下面这个函数拒绝的理由**与那些完全不同**。
///
/// ## 现在这一类：**不是"以后会做"，而是设计取舍**
///
/// 理由：它们本质上属于**进程级策略**——
///
/// * `serve-expired-ttl` —— 过期数据在缓存里**保留多久才被清理**，由后台 GC
///   （每 900 秒逐分片扫全表）与预取扫描使用；
/// * `serve-expired-prefetch-time` —— 过期多久之后**才允许预取**，同样由后台任务使用。
///
/// 两者都**不体现在任何应答里**，也**不在逐查询路径上**。若按组区分，同一份缓存里
/// 会并存多种保留策略：用户看不到效果，排查却显著变难（"这条为什么被清了/没被清"
/// 要多问一层"它属于哪个组"）。收益不足以抵消这个代价。
///
/// > 注：上游 C 版把它们放在 `_dns_conf_group` 里，但 C 版**没有独立的全局层**
/// > （顶层配置本身就落在 `default` 组），因此不能据此推断"应该支持按组"。
///
/// 错误措辞与当年那类**刻意不同**：用户应当知道这不是遗留待办，而是设计取舍。
fn not_supported_in_rule_group_by_design(
    item: &crate::config::parser::ConfigItem,
) -> Option<&'static str> {
    use crate::config::parser::ConfigItem::*;

    Some(match item {
        ServeExpiredTtl(_) => "serve-expired-ttl",
        ServeExpiredPrefetchTime(_) => "serve-expired-prefetch-time",
        _ => return None,
    })
}

/// 📌 **哪些配置项写在 `group-begin` 块里是合法的**（白名单）。
///
/// ## 为什么需要它
///
/// 规则组这个机制是**逐项铺开**的：先有 2 个（`force-no-CNAME` / `force-AAAA-SOA`），
/// 甲/乙/丙 各批再补 18 个。在这期间，**没铺开的那些写进组里会被静默写进全局** ——
/// 也就是"用户以为只对 office 组生效，实际改了所有人"。
///
/// 那 20 个参数补齐后，**这类污染并没有消失**：`cache-size`、`max-connections`、
/// `bogus-nxdomain`…… 这些**按设计就没有组级概念**的项，写进组里照样一路写进全局。
/// 2026-09-26 实测确认（把 `cache-size` 写进组里，全局变成了组里那个值）。
///
/// ## 为什么用**白名单**而不是黑名单
///
/// 黑名单要求"每发现一个会污染的项就补一条"，**漏一个就是一个静默的坑**；
/// 而白名单下，将来新增配置项若忘了声明组级支持，会**明确报错**、当场被发现。
/// 这个取舍与本项目一贯的"绝不静默改写作用域"一致。
///
/// ## 白名单包含三类
///
/// * **A. 规则类** —— 本来就该写在组里（`address` / `cname` / `nameserver` 等）；
/// * **B. 组级参数** —— 与 [`crate::config::GroupParams`] 的字段**一一对应**，
///   加字段时必须同步这里（漏了会导致该参数写进组里被误拒，测试会当场抓住）；
/// * **C. 组结构 / 无分组语义的项** —— `group-begin`/`group-end`/`group-match`、
///   `conf-file`（可带 `-g` 挂到组）、`client-rules`（按组名引用）、
///   以及 `server` / `proxy-server` / 集合定义（它们落在全局容器里，
///   但写在组内**不会按组生效**，属既有语义，见下方说明）。
///
/// ## ⚠️ 已知的既有语义（本次未改，已单独记档）
///
/// `server` 写在组里**不会**"只对该组生效"，而是成为全局上游 ——
/// 按组指定上游要用 `server ... -group <组名>`。它留在白名单里是因为
/// "拒绝它"属于**功能改动**（要么实现组内归属、要么明确报错引导用户改写法），
/// 不该与本次"堵住静默污染"混在一起做。
fn allowed_in_rule_group(item: &crate::config::parser::ConfigItem) -> bool {
    use crate::config::parser::ConfigItem::*;

    matches!(
        item,
        // ── A. 规则类：本就写在组里 ──
        Address(_)
            | CNAME(_)
            | SrvRecord(_)
            | HttpsRecord(_)
            | DomainRule(_)
            | ForwardRule(_)
            // ── B. 组级参数：与 GroupParams 字段一一对应 ──
            | ForceNoCNAME(_)
            | ForceAAAASOA(_)
            | IpSetTimeout(_)
            | NftSetTimeout(_)
            | RrTtl(_)
            | RrTtlMin(_)
            | RrTtlMax(_)
            | RrTtlReplyMax(_)
            | LocalTtl(_)
            | MaxReplyIpNum(_)
            | SpeedMode(_)
            | ResponseMode(_)
            | DualstackIpSelection(_)
            | DualstackIpAllowForceAAAA(_)
            | DualstackIpSelectionThreshold(_)
            | Dns64(_)
            | ServeExpired(_)
            | ServeExpiredReplyTtl(_)
            | PrefetchDomain(_)
            | EdnsClientSubnet(_)
            // ── C. 组结构 / 无分组语义的项 ──
            | GroupBegin(_)
            | GroupEnd
            | GroupMatch(_)
            | ClientRule(_)
            | ConfFile(_)
            | DomainSetProvider(_)
            | IpSetProvider(_)
            | Server(_)
            | ProxyConfig(_)
    )
}

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

/// 🔐 问题 24：配置摘要里 `dualstack ip selection` 这一行该显示什么。
///
/// 抽成**只依赖两个 bool 的纯函数**，是为了让这条状态行**可被单测钉住** ——
/// 它要说的正是"两个开关互相依赖"这件事，措辞与触发条件都不能漂移。
///
/// 三种状态：
/// * 优选没开 → `OFF`（此时测速开不开都与它无关，不必多嘴）；
/// * 优选开了、但测速是 `none` → **`ON, but INACTIVE`** + 原因。
///   这是唯一值得特别提示的组合：用户以为自己开了优选，实际它做不了任何事
///   （族对决的唯一判据是测速结果，没有测速就不压制任何一族）；
/// * 优选开了、测速也有 → `ON`。
fn dualstack_ip_selection_status(enabled: bool, speed_check_off: bool) -> String {
    if !enabled {
        return "OFF".to_string();
    }

    if speed_check_off {
        return "ON, but INACTIVE (`speed-check-mode none` disables speed measurement, \
                so the A/AAAA race is skipped and neither family is suppressed)"
            .to_string();
    }

    "ON".to_string()
}

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
            let base_dir = self
                .conf_file
                .as_ref()
                .and_then(|f| f.parent())
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
                    if let Some(std::path::Component::Normal(_)) =
                        normalized.components().next_back()
                    {
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
            // 🔐 B-①：`conf_dir` 的推导**放宽**为"配置文件所在目录"（不再要求目录名叫 `smartdns`）。
            //
            // ⚠️ 推导逻辑**不在这里写**，而是统一放在 `with_conf_file()` 里 ——
            // 这样 `load()`（真实启动）与 `builder().with_conf_file(..).build()`
            // （测试与其它内部调用）走的是**同一份推导**，不会出现
            // "真实启动能用、测试路径算出 None"的两套口径。
            // 详细的影响分析与两条边界见 `with_conf_file()`。
            //
            // 这里只负责把路径交下去；`with_conf_file` 会在 `conf_dir` 仍为空时推导。
            builder = builder.with_conf_file(&path);
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
                eprintln!(
                    "💡 Hint: Please specify the config file using '-c' (e.g., smartdns run -c ./smartdns.conf)."
                );
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
                eprintln!(
                    "Hint: check the file for syntax errors, invalid parameters or unreadable referenced paths."
                );
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
            fatal_errors: Vec::new(),
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

        // 🔐 Q1：`ipset` 只在 Linux 上有意义 —— 别的平台**启动时就说清楚**，
        // 而不是等有人查了那个域名、或者干脆一直静默（这正是"配了不起作用"的老毛病）。
        // 🔐 Q7/Q8：系统日志只在 Linux 上存在，其它平台配了要明确说"不会生效"
        #[cfg(not(target_os = "linux"))]
        if self.log_syslog() || self.audit_syslog() {
            log::warn!(
                "`log-syslog` / `audit-syslog` are Linux-only (other platforms have no syslog); ignored here."
            );
        }

        // 🔐 Q8：开了 `audit-syslog` 但审计本身没开 —— 什么都不会送
        if self.audit_syslog() && !self.audit_enable() {
            log::warn!(
                "`audit-syslog` is configured but auditing is off (missing `audit-enable yes`), so no audit output will be produced."
            );
        }

        // 🔐 Q8：审计改送系统日志后**不再写审计文件**，这点要说清楚（否则用户会去找文件）
        if self.audit_syslog() {
            log::info!(
                "audit output now goes to syslog (`audit-syslog yes`): no audit file is written and lines carry no timestamp (syslog provides one)."
            );
        }

        // 🔐 Q11：配了 `local-domain` 却把 `mdns-lookup` 关着 —— 这些域名不会走 mDNS，
        // 用户会以为"配了没用"。启动时说清楚（只提示一次，且只在真配了的情况下提示）。
        if !self.local_domains.is_empty() && !self.mdns_lookup() {
            log::warn!(
                "{} `local-domain` entries are configured but `mdns-lookup` is off, so those names will not be resolved over mDNS. Add `mdns-lookup yes` to enable it.",
                self.local_domains.len()
            );
        }

        #[cfg(not(target_os = "linux"))]
        if !self.ipsets.is_empty() {
            log::warn!(
                "{} `ipset` rules are configured but this platform has no ipset (a Linux kernel feature), so they will not take effect.",
                self.ipsets.len()
            );
        }

        info!(
            "DNS Engine activated {} concurrent worker threads.",
            self.num_workers()
        );

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

            // 📌 丙-1：`prefetch-domain` / `serve-expired` 现在也能写进规则组，
            // 而摘要里的 `domain prefetch` 那一行反映的是**全局**值。
            // 若不说明，用户会以为"ON"就是所有组的实际行为。
            // 只在确实有组写了的时候提一句，避免正常情况刷无关信息。
            //
            // ⚠️ 这里必须**逐项**统计：`prefetch-domain` 与 `serve-expired` 是同一类
            // （全局值 + 可按组覆盖），只统计其中一个会让另一个悄无声息 ——
            // 用户在组里写了 `serve-expired no`，却从摘要里看不出它真的按组生效了。
            //
            // ⚠️ 摘要里**没有** `serve-expired` 这一行（它不参与启动期的开关判断，
            // 只在逐查询路径上生效），所以提示里不能引用"上面那一行"，
            // 只能说明"全局值不描述这些组"。
            let groups_with_prefetch = self
                .rule_groups()
                .values()
                .filter(|g| g.params.prefetch_domain.is_some())
                .count();
            if groups_with_prefetch > 0 {
                log::info!(
                    "{groups_with_prefetch} rule group(s) set `prefetch-domain` themselves; \
                     the line above shows the GLOBAL value only. Whether a reply is scheduled \
                     for prefetch follows each query's own rule group."
                );
            }

            let groups_with_serve_expired = self
                .rule_groups()
                .values()
                .filter(|g| g.params.serve_expired.is_some())
                .count();
            if groups_with_serve_expired > 0 {
                log::info!(
                    "{groups_with_serve_expired} rule group(s) set `serve-expired` themselves; \
                     whether a query may be served expired data follows its own rule group."
                );
            }
        }

        // 🔐 问题 24 连带：`none` 现在解析成 `Some([None])`（而不是折叠成 `None`），
        // 于是这里的 `Some(mode) => format!("{mode:?}")` 会打出 `None` ——
        // 与"**没配置**"那一支的 `OFF` 字样不一致，看日志的人会以为是两回事。
        // 两者在"要不要测速"上语义相同，统一按 `OFF` 呈现。
        let speed_check_off = self
            .speed_check_mode()
            .is_some_and(|mode| mode.iter().any(|m| m.is_none()));
        info!(
            "speed check mode: {}",
            match self.speed_check_mode() {
                Some(mode) if mode.iter().any(|m| m.is_none()) => "OFF".to_string(),
                Some(mode) => format!("{mode:?}"),
                None => "OFF".to_string(),
            }
        );

        // 🔐 问题 24（可观测性，用户定调）：**双栈优选与测速的联动**，就在这条状态行里说清楚。
        // 为什么值得单独一条状态行：`dualstack-ip-selection` 与 `speed-check-mode` 是
        // **互相依赖**的两个开关 —— 族对决的唯一判据就是测速结果，没有测速就没有判据，
        // 于是不压制任何一族。用户按"这是个独立开关"的直觉去配，很容易配出
        // "我开了优选怎么没效果"的组合，而原来的日志里**看不出这两者的关系**。
        //
        // **只在这里说一次**（配置摘要，启动与热重载各一遍），**不在查询路径上打** ——
        // 那是热路径，按域名刷 info 会把日志淹掉。这与本项目其它"配置层问题说一次"
        // 的做法一致（如 `managed_dir` 提示、`-device` 兼容别名告警）。
        let dualstack = self.dualstack_ip_selection();
        info!(
            "dualstack ip selection: {}",
            dualstack_ip_selection_status(dualstack, speed_check_off)
        );

        // 再单独给一条可操作的提示（只在真的存在这个矛盾组合时）。
        // 与上面那条状态行的分工：状态行说明"现在是什么状态"，这条说明"想让它生效该怎么做"。
        if dualstack && speed_check_off {
            info!(
                "dual-stack IP selection has no effect while speed measurement is off; set a speed check mode (e.g. `speed-check-mode ping,tcp:443`) to let it take effect"
            );
        }

        // 🔐 13-⑥：可信代理清单 —— 配了就要说清楚**它能做什么、不能做什么**。
        //
        // 这条尤其需要说明，因为它的适用面比名字听起来窄得多：
        // **只有 HTTP 类协议（DoH / bind-http / 管理后台）能解析 `X-Forwarded-For`**，
        // 普通 DNS 查询（UDP 53）里**根本没有"头"这个东西**，代理只能 SNAT，
        // 真实来源无从得知。不写清楚的话，用户会以为"配了就能让 UDP 也按真实客户端归组"。
        //
        // 同时提示"只用于归组"这一安全约束 —— 免得有人以为它能替代 ACL。
        let trusted = self.trusted_proxies();
        if !trusted.is_empty() {
            let list = trusted
                .nets()
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            info!(
                "trusted proxy: {} entr{} ({list}); X-Forwarded-For is only honoured for requests \
                 arriving from these addresses, and only for **grouping** (rate limiting / rule \
                 group selection) — never for allow/deny decisions",
                trusted.len(),
                if trusted.len() == 1 { "y" } else { "ies" }
            );
            info!(
                "note: trusted-proxy only applies to HTTP-based listeners (DoH / bind-http / the \
                 management console). Plain DNS over UDP has no HTTP headers, so a client behind a \
                 proxy is still grouped by the proxy address on that path"
            );
        }
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
        let f = self
            .cache
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
    ///
    /// 🔐 默认值 **5**（用户定调：**以代码为准**，2026-09-26）。
    ///
    /// 背景：文档站与上游 C 版都写 **3**，与本实现不符。取证时发现这个 5
    /// 来自上游 vendored 的旧代码（提交 `328b87b`），**不是本项目的独立决策**，
    /// 但既然当前默认部署的行为就是 5（且已存在多个版本），
    /// 用户决定**以代码为准**、改文档去对齐，而不是反过来改动运行时行为
    /// （改默认值会让现网过期缓存的回包 TTL 变化）。
    ///
    /// 顺带给它补一条**默认值测试**：此前这个数字**没有任何测试覆盖**，
    /// 这正是"文档与代码各说各话却长期没人发现"的原因。
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

    /// 强制不向客户端返回 CNAME（`force-no-CNAME yes`）
    #[inline]
    pub fn force_no_cname(&self) -> bool {
        self.force_no_cname.unwrap_or_default()
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
    ///
    /// 🔐 **保持既有语义：`rr-ttl-min` 没写时回落 `rr-ttl`**（用户定调，2026-09-26）。
    ///
    /// 取证时对照过上游 C 版：那边的三者**完全独立**
    /// （`dns_server/rules.c` 的 `_dns_server_get_conf_ttl`：`rr_ttl > 0` 直接 return，
    /// min/max 只做**互相夹逼**、不回落），与本实现不同。
    ///
    /// 用户决定**保持本仓库既有行为**、不改。原因是这是一处**用户可见的行为变更**：
    /// 现在"只写 `rr-ttl 600`、不写 min"会把最小 TTL 也抬到 600，
    /// 改成不回落会让现网一部分部署的缓存寿命变短 —— 收益（与 C 版对齐）
    /// 不值这个代价，且本仓库语义本身也是自洽的（"统一 TTL"更直观）。
    ///
    /// ⚠️ 记这一笔是为了**避免日后有人"照 C 版顺手改掉"** ——
    /// 那会是一次无人预期的默认行为变更。同样地，文档站应当写明本仓库的这条口径。
    #[inline]
    pub fn rr_ttl_min(&self) -> Option<u64> {
        self.rr_ttl_min.or_else(|| self.rr_ttl())
    }
    /// maximum ttl for resource record
    ///
    /// 与 `rr_ttl_min` 同理：**保持回落 `rr-ttl` 的既有语义**（用户定调），
    /// 与上游 C 版的"三者独立"有意不同。理由见上。
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

    /// 🔐 13-⑥：可信反向代理清单（由 `trusted-proxy <IP|CIDR>` 累加而来）。
    ///
    /// **空清单 = 不信任任何代理头**，行为与本项目原本完全一致。
    /// 只有来自清单内的请求才会解析 `X-Forwarded-For`，而且**只用于归组**。
    #[inline]
    pub fn trusted_proxies(&self) -> crate::trusted_proxy::TrustedProxies {
        crate::trusted_proxy::TrustedProxies::new(self.trusted_proxies.iter().copied())
    }

    /// 🔐 Q2：写进 ipset 的条目要不要带过期时间。默认关（永不过期，与改动前一致）。
    #[inline]
    pub fn ipset_timeout(&self) -> bool {
        self.ipset_timeout.unwrap_or(false)
    }

    /// 🔐 Q4：同上，nftables 那一半。
    #[inline]
    pub fn nftset_timeout(&self) -> bool {
        self.nftset_timeout.unwrap_or(false)
    }

    /// 🔐 Q6：往防火墙集合写地址时要不要打详细日志。
    #[inline]
    pub fn nftset_debug(&self) -> bool {
        self.nftset_debug.unwrap_or(false)
    }

    /// 🔐 Q10：整机同时处理的查询数上限。默认 65535（与 C 版一致），0 = 不限。
    #[inline]
    pub fn max_query_limit(&self) -> usize {
        self.max_query_limit.unwrap_or(65535)
    }

    /// 🔐 Q7：运行日志要不要同时送系统日志（只在 Linux 上真正生效）
    #[inline]
    pub fn log_syslog(&self) -> bool {
        self.log_syslog.unwrap_or(false)
    }

    /// 🔐 Q8：审计行要不要送系统日志（开着就不写审计文件了，与 C 版一致）
    #[inline]
    pub fn audit_syslog(&self) -> bool {
        self.audit.syslog.unwrap_or(false)
    }

    /// 🔐 Q11：这个域名是不是"用户点名要走 mDNS"的（`local-domain`）。
    ///
    /// 匹配规则：**域名本身或它的子域名**（与 C 版域名规则一致）：
    /// 配了 `lan`，那么 `nas.lan`、`a.b.lan` 都算。
    pub fn is_local_domain(&self, name: &crate::libdns::proto::rr::Name) -> bool {
        if self.local_domains.is_empty() {
            return false;
        }

        let name = name.to_ascii().to_ascii_lowercase();
        let name = name.trim_end_matches('.');

        self.local_domains
            .iter()
            .any(|d| name == d || name.ends_with(&format!(".{d}")))
    }

    pub fn audit_enable(&self) -> bool {
        self.audit.enable.unwrap_or_default()
    }

    /// 🔐 Q9：审计行要不要同时打到控制台（stdout）
    #[inline]
    pub fn audit_console(&self) -> bool {
        self.audit.console.unwrap_or(false)
    }

    #[inline]
    pub fn audit_file(&self) -> Option<PathBuf> {
        self.audit
            .file
            .as_ref()
            .map(|f| self.anchor_path(f.clone())) // 🌟 套上盾牌！
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

    /// 🔐 组级参数取值前的**组名归一化**：空组名与 `default` 是**同一个组**。
    ///
    /// 为什么必须有这一步：配置解析层把 `group-begin default` 与顶层都归到
    /// `DEFAULT_GROUP`（`"default"`），而查询侧在"客户端没有匹配到任何 client-rule"
    /// 时拿到的是**空字符串**（见 `DnsContext::effective_rule_group`）。
    /// 于是同一个组在**存**与**取**两头是两个键 —— 写在 `group-begin default` 块里的
    /// 组级参数，普通客户端**一个都读不到**。
    ///
    /// 这与上游语义不符：上游是"先造 default 组、顶层配置就落在它身上"，
    /// 所以"顶层写"与"`group-begin default` 里写"在上游**是同一处**。
    ///
    /// `domain_rule_group` 早已做过这层归一化（那里是历史的正确写法），
    /// 这里补上的是**组级参数**那条路径 —— 两处自本次起共用同一个判据，不再各写各的。
    #[inline]
    fn normalize_rule_group_name(group: &str) -> &str {
        if group.is_empty() {
            DEFAULT_GROUP
        } else {
            group
        }
    }

    /// 取某个规则组的组级参数（组名自动归一化）。
    #[inline]
    pub fn group_params(&self, group: &str) -> &GroupParams {
        &self
            .rule_group(Self::normalize_rule_group_name(group))
            .params
    }

    pub fn rule_groups(&self) -> &HashMap<String, RuleGroup> {
        &self.rule_groups
    }

    pub fn rule_group(&self, name: &str) -> &RuleGroup {
        self.rule_groups.get(name).unwrap_or(RuleGroup::empty())
    }

    /// 🔐 组级参数：按 **组级 > 全局** 取 `force-no-CNAME` 的生效值。
    ///
    /// 调用方应当已经把 bind 级算进来（bind 级优先级最高，见 `DnsContext` 的取值入口）。
    /// 组名不存在 / 组里没写 → 回退全局默认值，因此**不配组级时行为与以前完全一致**。
    pub fn force_no_cname_in_group(&self, group: &str) -> bool {
        self.group_params(group)
            .force_no_cname
            .unwrap_or_else(|| self.force_no_cname())
    }

    /// 🔐 组级参数：按 **组级 > 全局** 取 `force-AAAA-SOA` 的生效值。
    pub fn force_aaaa_soa_in_group(&self, group: &str) -> bool {
        self.group_params(group)
            .force_aaaa_soa
            .unwrap_or_else(|| self.force_aaaa_soa())
    }

    // ── 📌 甲类（2026-09-26 铺开）：只有两层（组级 > 全局），没有 bind 级对应项。
    //
    // 每个都是「组里没写 → 回落全局访问器」。**必须用全局访问器而不是裸字段**：
    // 访问器里带着该参数自己的默认值与级联规则（例如 `rr_ttl_min()` 会回落 `rr-ttl`），
    // 直接用裸字段会把那些语义丢掉。

    /// 组级 `ipset-timeout`（组里没写 → 全局）
    pub fn ipset_timeout_in_group(&self, group: &str) -> bool {
        self.group_params(group)
            .ipset_timeout
            .unwrap_or_else(|| self.ipset_timeout())
    }

    /// 组级 `nftset-timeout`（组里没写 → 全局）
    pub fn nftset_timeout_in_group(&self, group: &str) -> bool {
        self.group_params(group)
            .nftset_timeout
            .unwrap_or_else(|| self.nftset_timeout())
    }

    /// 组级 `rr-ttl-min`（组级 > 全局）
    ///
    /// 🔐 **级联口径：组内自洽**（用户 2026-09-26 定调）。
    ///
    /// 取值顺序是：**组级 `rr-ttl` → 组级 `rr-ttl-min` → 全局那一整条链**。
    ///
    /// ## 为什么不能整条交给全局
    ///
    /// `rr-ttl-min` 的语义是"给 `rr-ttl` 兜底"。若组里只写了 `rr-ttl 111`、
    /// 而 min 直接去全局取（全局 min 或全局 `rr-ttl` 可能是 500），
    /// 那么在 **min 被无条件使用**的地方（如双栈 TTL 对齐）111 会被抬回 500 ——
    /// **用户写了 111，行为却是 500**，正是本项目一直在消灭的"配置与行为对不上"。
    ///
    /// ## 组内自洽的形状
    ///
    /// 组里写了 `rr-ttl` ⇒ 本组 min 就用它（与全局侧"min 回落 rr-ttl"同构）；
    /// 组里连 `rr-ttl` 都没写 ⇒ 整条交给全局，不跨层拼接。
    pub fn rr_ttl_min_in_group(&self, group: &str) -> Option<u64> {
        let params = self.group_params(group);
        // ① 组内自洽：组级 rr-ttl 优先（同层兜底）
        if let Some(v) = params.rr_ttl {
            return Some(v);
        }
        // ② 否则组级 min 自己
        params.rr_ttl_min.or_else(|| self.rr_ttl_min())
    }

    /// 组级 `rr-ttl-max`（组级 > 全局）
    ///
    /// 级联口径与 [`Self::rr_ttl_min_in_group`] **完全一致**（同一族参数必须同规矩）。
    pub fn rr_ttl_max_in_group(&self, group: &str) -> Option<u64> {
        let params = self.group_params(group);
        if let Some(v) = params.rr_ttl {
            return Some(v);
        }
        params.rr_ttl_max.or_else(|| self.rr_ttl_max())
    }

    /// 组级 `rr-ttl` 本身（组级 > 全局）
    pub fn rr_ttl_in_group(&self, group: &str) -> Option<u64> {
        self.group_params(group).rr_ttl.or_else(|| self.rr_ttl())
    }

    /// 组级 `response-mode`（组级 > 全局）
    pub fn response_mode_in_group(&self, group: &str) -> ResponseMode {
        self.group_params(group)
            .response_mode
            .unwrap_or_else(|| self.response_mode())
    }

    /// 组级 `speed-check-mode`（组级 > 全局）
    ///
    /// 返回 `Option`：**外层 `None` 表示"这一层也没写"**，交给调用方继续往外找；
    /// `Some([None])` 表示**显式写了 `none`**（问题 24 的可区分性）。
    pub fn speed_check_mode_in_group(&self, group: &str) -> Option<SpeedCheckModeList> {
        self.group_params(group)
            .speed_check_mode
            .clone()
            .or_else(|| self.speed_check_mode().cloned())
    }

    // ── 📌 丙-1（2026-09-26 补齐组级支持）：只作用于**逐查询**那一侧。
    //
    // ⚠️ 这三个都有一份"同名但性质不同"的用途 —— **后台任务开关**，
    // 它**不跟组级走**。两个函数各自在文档里说清了边界，调用方必须照着用：
    //   · `serve_expired_in_group()`  → 只用于"这次查询要不要喂过期数据"；
    //   · `prefetch_domain_in_group()` → 只用于"这条应答要不要安排后台预取"；
    //   后台任务启停仍读全局访问器（`serve_expired()` / `prefetch_domain()`）。

    /// 组级 `serve-expired`（组级 > 全局）—— **只用于逐查询的"要不要喂过期数据"**。
    ///
    /// ## 为什么后台清理不用这个值
    ///
    /// `DnsCache::purge_dead_records` 与 `get_expired` 是**进程级后台任务**：
    /// 前者每 900 秒逐分片扫全表，后者遍历所有条目挑预取对象。
    /// 它们**不是"某个组在做事"**，而是"整个进程在维护缓存"。
    /// 若改成按组取值，就会出现"某个组写了 `serve-expired no`、把全进程的
    /// 过期数据保留策略一起改掉"这种**跨组误伤**。
    ///
    /// 因此分工是：**逐查询的处置按组，后台策略仍看全局。**
    pub fn serve_expired_in_group(&self, group: &str) -> bool {
        self.group_params(group)
            .serve_expired
            .unwrap_or_else(|| self.serve_expired())
    }

    /// 组级 `serve-expired-reply-ttl`（组级 > 全局）—— 逐查询
    ///
    /// 它决定"喂过期数据时回给客户端的 TTL"，是**本次应答的处置方式**，
    /// 所以按组取值是合理的（与 `serve-expired-ttl` 那种后台保留策略不同）。
    pub fn serve_expired_reply_ttl_in_group(&self, group: &str) -> u64 {
        self.group_params(group)
            .serve_expired_reply_ttl
            .unwrap_or_else(|| self.serve_expired_reply_ttl())
    }

    /// 组级 `prefetch-domain`（组级 > 全局）—— **只用于"这条应答要不要安排后台预取"**。
    ///
    /// ⚠️ 后台预取任务的**启停**仍用全局的 [`Self::prefetch_domain`]：
    /// 那个任务是一个进程一份、遍历所有缓存条目，不是"某个组在预取"。
    /// 若按组取值，某个组写 `no` 会把**整个进程**的后台预取停掉 —— 跨组误伤。
    pub fn prefetch_domain_in_group(&self, group: &str) -> bool {
        self.group_params(group)
            .prefetch_domain
            .unwrap_or_else(|| self.prefetch_domain())
    }

    // ── 📌 丙-2a / 丙-2b（2026-09-26 补齐组级支持）

    /// 组级 `dns64` 前缀（组级 > 全局）
    ///
    /// 返回 `Option`：`None` 表示"这一层也没配" ⇒ 该组**不做 DNS64**。
    pub fn dns64_prefix_in_group(&self, group: &str) -> Option<ipnet::Ipv6Net> {
        self.group_params(group).dns64_prefix.or(self.dns64_prefix)
    }

    /// 组级 `edns-client-subnet`（组级 > 全局）
    ///
    /// ⚠️ 这里返回的**不是最终值**：全局那一档其实存在 `NameServer` 里
    /// （启动期定型的默认值），由 `dns_client` 在真正发查询时做兜底。
    /// 本函数只负责"组级有没有写"——写了就返回，让调用方插在
    /// "域名规则级"与"NameServer 默认值"之间。
    pub fn edns_client_subnet_in_group(&self, group: &str) -> Option<IpNet> {
        self.group_params(group).edns_client_subnet
    }

    /// 组级 `dualstack-ip-selection`（组级 > 全局）
    ///
    /// 只覆盖**两层**（组级 > 全局）；域名规则级由调用方先取，
    /// bind 级那个单向总闸也不在这里（见 `config::resolve_dualstack_selection`）。
    pub fn dualstack_ip_selection_in_group(&self, group: &str) -> bool {
        self.group_params(group)
            .dualstack_ip_selection
            .unwrap_or_else(|| self.dualstack_ip_selection())
    }

    /// 组级 `rr-ttl-reply-max`（组里没写 → 全局）
    pub fn rr_ttl_reply_max_in_group(&self, group: &str) -> Option<u64> {
        self.group_params(group)
            .rr_ttl_reply_max
            .or_else(|| self.rr_ttl_reply_max())
    }

    /// 组级 `local-ttl`（组里没写 → 全局；全局侧会回落 `rr-ttl-min` 再兜底 60）
    pub fn local_ttl_in_group(&self, group: &str) -> u64 {
        self.group_params(group)
            .local_ttl
            .unwrap_or_else(|| self.local_ttl())
    }

    /// 组级 `dualstack-ip-allow-force-AAAA`（组里没写 → 全局）
    pub fn dualstack_ip_allow_force_aaaa_in_group(&self, group: &str) -> bool {
        self.group_params(group)
            .dualstack_ip_allow_force_aaaa
            .unwrap_or_else(|| self.dualstack_ip_allow_force_aaaa())
    }

    /// 组级 `dualstack-ip-selection-threshold`（组里没写 → 全局）
    pub fn dualstack_ip_selection_threshold_in_group(&self, group: &str) -> u64 {
        self.group_params(group)
            .dualstack_ip_selection_threshold
            .unwrap_or_else(|| self.dualstack_ip_selection_threshold())
    }

    /// 组级 `max-reply-ip-num`（组里没写 → 全局）
    pub fn max_reply_ip_num_in_group(&self, group: &str) -> Option<u8> {
        self.group_params(group)
            .max_reply_ip_num
            .or_else(|| self.max_reply_ip_num())
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
    /// 🔐 问题 38（真机测试补漏）：加载期间发现的**致命配置错误**。
    ///
    /// 与普通告警的区别：这些错误会让 `build()` **直接失败**（`smartdns test` 会以
    /// 非 0 退出码报出来），而不是"打一条日志、忽略该行、继续启动"。
    ///
    /// 为什么需要这个机制：`config_at` / `config_unchecked` 的返回类型是 `()`，
    /// 沿途没有错误上报通道，而某些配置错误（如"口令写了但没有用户名"）属于
    /// **用户以为配好了、实际完全没生效** —— 正是本次整改要消灭的静默失效，
    /// 不能降级成一条容易被忽略的告警。
    fatal_errors: Vec<String>,
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

        // 🔐 让「管理后台写下的配置」真正生效。
        //
        // 背景：管理接口（`/api/addresses`）把地址规则写进 `<配置目录>/managed/address.conf`，
        // 但**配置加载链里没有人读它** —— 于是接口返回 201、文件也写了，
        // 规则却从不进入运行时解析，表现为「配了不生效」。这属于最伤信任的静默无效。
        //
        // 这里把 `managed/` 下的所有 `.conf` 纳入加载（与主配置同一套解析流程，
        // 所以其中的语法错误、未知项都会照常告警）。顺序放在主配置**之后**，
        // 这样后台写入的规则位于规则链的后面；同理，用户在主配置里的同名规则不受影响。
        //
        // 目录不存在就什么也不做（首次启动、还没用过管理接口时是常态）。
        if let Some(managed_dir) = self.resolved_managed_dir()
            && managed_dir.is_dir()
        {
            let mut managed_files: Vec<PathBuf> = std::fs::read_dir(&managed_dir)
                .map(|dir| {
                    dir.filter_map(|e| e.ok())
                        .map(|e| e.path())
                        .filter(|p| {
                            p.is_file()
                                && p.extension()
                                    .is_some_and(|ext| ext.eq_ignore_ascii_case("conf"))
                        })
                        .collect()
                })
                .unwrap_or_default();
            // 排序保证加载顺序稳定（否则不同文件系统上的顺序可能不同，排障时对不上）
            managed_files.sort();

            for file in managed_files {
                // 与 `conf-file` 走同一条路径：同样支持去重、同样按字节读行并容错非 UTF-8。
                if let Err(err) = self.load_file(&file) {
                    warn!(
                        "failed to load managed configuration {}: {err}",
                        file.display()
                    );
                }
            }
        }

        let conf_file = self.conf_file;
        let conf_dir = self.conf_dir;
        let mut cfg = self.config;

        // 🔐 问题 38（真机测试补漏）：加载期间发现的**致命配置错误**在这里统一上报。
        //
        // 放在这（而不是 load_file 里）是刻意的：这一步已经把所有配置（含 `conf-file`
        // 引入的、`managed/` 下的）都读完了，因此能**一次报出全部**错误，
        // 用户改一轮就能改完，而不是"改一个、重启一次、再发现下一个"。
        if !self.fatal_errors.is_empty() {
            let mut msg = String::from(
                "the configuration has errors that would be silently ignored at runtime:",
            );
            for err in &self.fatal_errors {
                msg.push_str("\n  - ");
                msg.push_str(err);
            }
            anyhow::bail!(msg);
        }

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
                        log::info!("DomainSet {}: {} rules in effect", s.len(), p.name());
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
                &cfg.ipsets,
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

        // 🔐 B-①：`managed_dir` 的创建失败**必须看得见**。
        //
        // 原先写的是 `let _ = std::fs::create_dir_all(&dir);` —— 失败被静默吞掉。
        // 在"只有目录名叫 smartdns 才推出 conf_dir"的年代，这还能勉强说得过去
        // （能推出 conf_dir 说明目录结构本来就在）；但**放宽推导之后**，
        // 配置放在只读目录（如 `/etc/dns/`、容器里的只读挂载）也会推出 `conf_dir`，
        // 于是这里会**每次启动静默失败一次**。
        //
        // 表现会很隐蔽也不隐蔽：管理接口仍然返回 404（因为目录真没建成），
        // 但日志里一个字都没有 —— 用户无从知道是权限问题。
        // 所以改成告警，并且**明确说出该怎么办**（这正是 §22.7 里说的"本次要一并修"）。
        let managed_dir = conf_dir.as_deref().map(|dir| {
            let dir = dir.join("managed");
            if !dir.exists()
                && let Err(err) = std::fs::create_dir_all(&dir)
            {
                warn!(
                    "could not create the managed rules directory {}: {err}. \
                     The management API (/api/addresses) will return 404 until it exists; \
                     check that the configuration directory is writable, or start with `-d <writable-dir>`",
                    dir.display()
                );
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

/// 🔐 B-①：从配置文件路径推出「配置目录」。
///
/// 规则极简：**配置文件的父目录就是配置目录**（不再要求目录名等于 `smartdns`）。
///
/// ## 为什么要抽成独立函数
///
/// 一是**可单测**：边界（空父目录、根目录、相对路径）能直接被钉住，
/// 而不必构造一个真实的配置文件去跑 `build()`（那测到的是"文件存不存在"）。
///
/// 二是**两条路径共用**：`load()`（真实启动）与
/// `builder().with_conf_file(..).build()`（测试与内部调用）都走这一份推导，
/// 避免出现"真实启动能用、测试路径算出 `None`"的两套口径
/// —— 那正是问题 24 那类"同一件事两条路径两个答案"的老毛病。
///
/// ## 空父目录必须跳过
///
/// `Path::new("smartdns.conf").parent()` 返回**空路径** `""`。
/// 若采用它，`conf_dir` 是空路径、`managed_dir` 随之成为相对路径 `managed/`，
/// 会**落在进程当前工作目录**下 —— 服务方式启动时工作目录可能是 `/`（Windows 是 `System32`），
/// 那正是问题 52 花力气堵掉的"随工作目录漂移"一类隐患。故返回 `None`，
/// 由管理接口给出那条可操作提示（引导用户显式传 `-d`）。
fn derive_conf_dir_from_conf_file(conf_file: &Path) -> Option<PathBuf> {
    let dir = conf_file.parent()?;

    // 空父目录（`smartdns.conf` 这种没有目录成分的路径）不采用 —— 见上面的说明。
    if dir.as_os_str().is_empty() {
        return None;
    }

    Some(dir.to_path_buf())
}

impl RuntimeConfigBuilder {
    pub fn with(mut self, config: &str) -> Self {
        self.config(config.trim());
        self
    }

    pub fn with_conf_file<P: AsRef<Path>>(mut self, path: P) -> Self {
        let path = path.as_ref().to_path_buf();

        // 🔐 B-①：设配置文件的同时，**顺带推导 `conf_dir`**（若调用方还没设过）。
        //
        // ## 为什么放在这里，而不是只在 `load()` 里
        //
        // `load()` 是"真实启动"的入口，但 `builder().with_conf_file(..).build()`
        // 是**测试与其它内部调用**的入口，而且它同样会算出 `managed_dir`。
        // 只在 `load()` 里放宽，会造成**两条路径口径不一致** ——
        // 真实启动能用管理接口、测试/内部调用却算出 `None`，
        // 那正是问题 24 那类"同一件事两条路径两个答案"的老毛病。
        // 放在这里，两条路径共用同一个推导。
        //
        // ## 推导规则（放宽后）
        //
        // 配置文件的**父目录**就是配置目录 —— **不再要求目录名等于 `smartdns`**。
        // 原条件（目录名必须叫 smartdns）会让配置放在 `myconf/`、`/etc/dns/`
        // 这类目录下、又没传 `-d` 时 `managed_dir = None`，
        // 于是管理接口（`/api/addresses`）三个端点全部 404、地址规则功能不可用。
        //
        // ## 影响面（详见《实施记录》§22.7）
        //
        // `conf_dir` 的**实际消费者只有 `managed_dir`**；日志/缓存/审计/证书/
        // `conf-file` 的相对路径都**优先**用 `conf_file.parent()`，
        // 所以放宽这里**不会改变**那些锚点。
        //
        // ## 两条边界
        //
        //   · **显式 `-d` 优先**：调用方已经设过 `conf_dir` 时不动它；
        //   · **空父目录不采用**：`-c smartdns.conf`（无目录成分）时父目录是空路径，
        //     若采用它，`managed_dir` 会变成相对路径 `managed/`、**随进程工作目录漂移**
        //     —— 那是问题 52 花力气堵掉的一类隐患，这里必须跳过。
        if self.conf_dir.is_none()
            && let Some(dir) = derive_conf_dir_from_conf_file(&path)
        {
            self.conf_dir = Some(dir);
        }

        self.conf_file = Some(path);
        self
    }

    pub fn with_conf_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.conf_dir = Some(path.as_ref().to_path_buf());
        self
    }

    /// 推断「管理目录」的位置：`<配置目录>/managed`。
    ///
    /// ⚠️ 这里必须与 `build()` 结尾处计算 `managed_dir` 的算法**完全一致** ——
    /// 那是管理接口（`/api/addresses`）写入的目标目录。两处一旦不一致，
    /// 「这里加载的」与「接口写入的」就是两个不同目录，规则依旧不生效。
    fn resolved_managed_dir(&self) -> Option<PathBuf> {
        self.conf_dir.as_ref().map(|dir| dir.join("managed"))
    }

    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let path = self.resolve_filepath(path);
        self.load_resolved_file(path)
    }

    /// 🔐 问题 52：`conf-file` 专用的加载入口 —— 相对路径**不走**「进程当前工作目录」与
    /// 「程序可执行文件所在目录」这两级回退（见 [`RelativePathFallback`]）。
    ///
    /// 为什么不直接改 `resolve_filepath`：它被 12 处共用（日志/审计/证书/缓存/名单…），
    /// 那几处依赖后两级回退是既有部署的现实行为，一并删掉会破坏它们。而 `conf-file` 引入的是
    /// **配置劫持面**：以服务方式启动时工作目录通常是 `/`（Windows 服务则是 `System32`），
    /// 但便携部署、解压到用户目录、部分容器挂载下这两个位置可写 —— 放一个同名文件就能注入
    /// 任意配置（改上游、改地址规则、把日志写到任意位置）。所以只收紧 `conf-file` 这一条链。
    fn load_conf_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let path = self.resolve_conf_filepath(path);
        self.load_resolved_file(path)
    }

    /// 真正的加载主体。传入的路径**必须已经解析完毕** —— 这里不再做任何目录回退，
    /// 否则会绕开上面那条「按调用来源选择回退级别」的设计。
    fn load_resolved_file(&mut self, path: PathBuf) -> anyhow::Result<()> {
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
                        "configuration file {:?} line {} contains non-UTF-8 bytes; parsed with replacement characters (loading continues after this line)",
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
        // 🔐 问题 38（真机测试补漏）：凭据写了一半的代理配置必须**报配置错误**，不能只当"未识别行"。
        //
        // 背景：`proxy-server socks5://:口令@host -name x` 这种写法，`ProxyConfig::from_str`
        // 会返回 `PasswordWithoutUsername` 错误；但 `NamedProxyConfig::parse` 用 `map_res`
        // 包着它，解析失败后整个 `alt` 分支落空，最终被 `config_at` 归到
        // 「unrecognised configuration line (ignored as-is)」—— **配置自检照样报通过、退出码 0**。
        //
        // 也就是说：上一批在 `from_str` 里加了判据，但**错误到不了用户面前**，
        // 实际效果退化成"整条代理配置被静默忽略"，用户以为配好了代理、其实那条
        // `proxy-server` 完全没生效（比原始缺陷更隐蔽）。
        //
        // 这里在解析**之前**先单独识别这种写法，并记为致命配置错误。
        if let Some(detail) = detect_broken_proxy_credential(line) {
            self.fatal_errors.push(match lineno {
                Some(no) => format!("configuration file line {no}: {detail}"),
                None => detail,
            });
        }

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
                    format!(
                        "unrecognised configuration line (ignored as-is): {shown_line:?}; check the keyword spelling"
                    )
                } else {
                    format!(
                        "unrecognised content at the end of a configuration line (ignored): {shown_rest:?} -- full line: {shown_line:?}"
                    )
                };
                match lineno {
                    Some(no) => warn!("configuration file line {no}: {detail}"),
                    None => warn!("{detail}"),
                }
            }
        }
        self.config_unchecked(line, lineno);
    }

    /// 🔐 Q18：`group-begin <组名> [-inherit <另一组|none|parent|default>]`。
    ///
    /// 语义对齐 C 版 `src/dns_conf/dns_conf_group.c:228-302`：
    /// * 继承在**推入该组时**解析 → 被继承的组必须**已经定义过**（不支持前向引用），
    ///   写错会明确告警（与 C 版的 "inherit group %s not exist" 同义）；
    /// * `none` = 不继承；`parent` = 继承外层组；`default` = 继承 `default` 组；别的字符串 = 组名；
    /// * **不写这个选项时，嵌套组默认继承外层组**（C 版如此）。这条会打一行提示：
    ///   它改变的是"嵌套组以前是空白组"这个既有行为，不能悄悄改。
    fn group_begin(&mut self, group: &crate::config::GroupBegin) {
        let inherit = match group.inherit.as_deref() {
            Some(v) => Some(v.to_string()),
            None => {
                // 没写：嵌套就继承外层（顶层组不继承）
                if self.rule_group_stack.len() > 1 {
                    Some("parent".to_string())
                } else {
                    None
                }
            }
        };

        let inherited = match inherit.as_deref() {
            None | Some("none") => None,
            Some("parent") => self.rule_group_stack.last().map(|(_, g)| g.clone()),
            Some("default") => self.rule_groups.get(DEFAULT_GROUP).cloned(),
            Some(name) => match self.rule_groups.get(name) {
                Some(g) => Some(g.clone()),
                None => {
                    log::warn!(
                        "`group-begin {} -inherit {}`: that group is not defined yet (inheritance only accepts already defined groups, no forward references), so nothing is inherited this time",
                        group.name,
                        name
                    );
                    None
                }
            },
        };

        let mut rules = RuleGroup::default();

        if let Some(inherited) = inherited {
            rules.merge(inherited);

            // 嵌套默认继承要明确说出来（它改变了"嵌套组是空白组"的既有行为）
            if group.inherit.is_none() {
                log::info!(
                    "nested group `{}` inherits the outer group's rules by default (same as the C implementation); write `group-begin {} -inherit none` to opt out",
                    group.name,
                    group.name
                );
            }
        }

        self.rule_group_stack.push((group.name.clone(), rules));
    }

    /// 当前是否处于**显式写的** `group-begin ... group-end` 块内。
    ///
    /// 判据是栈深 > 1，而不是"栈非空"。原因：`config_unchecked` 开头会**懒加载**一个
    /// `default` 组压到栈底（见该函数第一段），所以顶层配置时栈深也恒为 1。
    /// 只有真正进了 `group-begin`（或 `conf-file ... -group`）才会变成 2 及以上。
    ///
    /// 这与 `group_begin` 里判断"嵌套继承"用的是同一个不变量（那里也写 `len() > 1`），
    /// 两处必须保持一致。
    fn in_rule_group(stack: &[(String, RuleGroup)]) -> bool {
        stack.len() > 1
    }

    fn config_unchecked(&mut self, line: &str, lineno: Option<usize>) {
        use crate::config::parser::ConfigItem::*;

        // 必须在取 `rule_group` 的可变借用**之前**算出这个标志：栈为空时它是 false，
        // 下面懒加载 default 组后栈深变 1，仍然应当是 false（顶层配置）。
        //
        // ⚠️ 顺序要紧：下面 `route!` 宏体里用到 `in_group`，而 `macro_rules!` 的卫生性
        // 是在**宏定义处**解析标识符的 —— 所以这两行必须在宏定义**之前**。
        let in_group = Self::in_rule_group(&self.rule_group_stack);

        // 先解析出这一行是什么（下面还要再 match 一次，这里只为"组内不该出现的项"提早判断）。
        let parsed = parser::parse_config(line);

        /// 📌 **组级 / 全局的"按层落位"** —— 把它抽成宏，是为了让每个参数**只声明一次
        /// "组里的格子叫什么、全局的字段叫什么"**，而不是在 `match` 的两支里各写一遍。
        ///
        /// 为什么非抽不可：这两个落点一旦分叉（组里写了 A、全局写了 B），
        /// 表现就是"配了不生效"或"生效在错的作用域"，而且**单看任一支都是对的**，
        /// 极难发现。抽成宏之后，两个落点在**同一行**里，改错了一眼看得出。
        ///
        /// 用法：`route!(v; rule_group.params.X, self.Y)` —— 在组里写组、否则写全局。
        macro_rules! route {
            ($value:expr; $group_slot:expr, $global_slot:expr) => {
                if in_group {
                    $group_slot = Some($value);
                } else {
                    $global_slot = Some($value);
                }
            };
        }

        /// 与 [`route!`] 同义，但**值本身已经是一个 `Option`**（例如 `speed-check-mode`：
        /// 解析结果就是 `Option<SpeedCheckModeList>`）。
        ///
        /// ⚠️ 不能拿它套用 `route!`：那会得到 `Some(Some([None]))` 之类的双层 `Option`，
        /// 而"写了 `none`"与"没写"的可区分性正是建立在这一层的形状上（问题 24）。
        macro_rules! route_opt {
            ($value:expr; $group_slot:expr, $global_slot:expr) => {
                if in_group {
                    $group_slot = $value;
                } else {
                    $global_slot = $value;
                }
            };
        }

        // 📌 **按设计不支持**写进规则组的参数：明确报错并忽略该行，绝不静默改写作用域。
        // 判据与理由见 `not_supported_in_rule_group_by_design`。
        //
        // （这里原先还有一类"**尚未支持**"的拒绝 —— 那是组级参数逐批补齐期间的过渡措施。
        //   到 丙-2c 为止那 20 个参数已全部支持，那一类判定随之删除。）
        if in_group && let Ok((_, Some(item))) = &parsed {
            // 带上行号：这个错误要求用户**回去改哪一行**，指不出位置等于让他自己找。
            // （`config_at` 已经有行号，之前只是没往下传。）
            let at = match lineno {
                Some(no) => format!("configuration file line {no}: "),
                None => String::new(),
            };

            if let Some(name) = not_supported_in_rule_group_by_design(item) {
                crate::log::error!(
                    "{at}`{name}` is a process-wide cache policy and is NOT supported inside a \
                     `group-begin` block by design (unlike the options that merely are not \
                     implemented yet). It decides how long expired cache entries are kept and \
                     when prefetch may start, neither of which shows up in any reply. Splitting it \
                     per group would put several retention policies into one cache without any \
                     visible benefit. This line is ignored; write it at the top level."
                );
                return;
            }

            // 🔐 2026-09-26：**白名单之外**的项写进组里，同样明确报错并忽略。
            //
            // 修的是什么：这类项（`cache-size`、`max-connections`、`bogus-nxdomain` …）
            // 按设计**没有组级概念**，而解析时它们会一路写进**全局** ——
            // 用户写 `group-begin office` + `cache-size 1024`，以为只影响 office，
            // 实际改了所有人的缓存容量，且**没有任何提示**。实测确认过。
            //
            // ⚠️ 这里**不是**"以后会支持"：绝大多数项在语义上就不该按组区分
            // （进程级资源上限、全局名单、监听配置……）。措辞要让用户明白
            // "这行没有组级写法"，而不是"等下一个版本"。
            //
            // ⚠️ 用 `from_str` 取回用户写的**源码文本**：错误信息里点名"是哪一项"
            // （如 `cache-size`）比只报行号有用得多 —— 与 `ConfigItem` 的 `Display`
            // 不同（后者对多数项只能打印 `[Unformatted Config Item]`）。
            // 取字段名需按空格切分：`ConfigItem` 没有提供机器可读的名字。
            if !allowed_in_rule_group(item) {
                let name = line
                    .split_whitespace()
                    .next()
                    .unwrap_or("(unknown option)")
                    .to_string();

                crate::log::error!(
                    "{at}`{name}` has no per-rule-group form: it is applied globally and cannot \
                     be set inside a `group-begin` block. This line is ignored — the global \
                     setting is left unchanged. Move it to the top level. \
                     (Options that DO accept a rule-group form are listed in the configuration \
                     reference.)"
                );
                return;
            }
        }

        let rule_group = match self.rule_group_stack.last_mut() {
            Some((_, rule_group)) => rule_group,
            None => {
                self.rule_group_stack
                    .push((DEFAULT_GROUP.to_string(), RuleGroup::default()));
                &mut self.rule_group_stack.last_mut().unwrap().1
            }
        };

        match parsed {
            Ok((_, Some(config_item))) => match config_item {
                AuditEnable(v) => self.audit.enable = Some(v),
                AclEnable(v) => self.acl.enable = Some(v),
                // 🔐 13-⑥：可重复项，多条**累加**成一个可信清单（与 `blacklist-ip` 等同样处理）
                TrustedProxy(v) => self.trusted_proxies.push(v),
                AuditFile(v) => self.audit.file = Some(self.resolve_filepath(v)),
                AuditFileMode(v) => self.audit.file_mode = Some(v),
                AuditConsole(v) => self.audit.console = Some(v),
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
                Dns64(v) => route!(v; rule_group.params.dns64_prefix, self.dns64_prefix),
                ExpandPtrFromAddress(v) => self.expand_ptr_from_address = Some(v),
                NftSet(v) => self.nftsets.push(v),
                IpSet(v) => self.ipsets.push(v),
                IpSetTimeout(v) => route!(v; rule_group.params.ipset_timeout, self.ipset_timeout),
                NftSetTimeout(v) => {
                    route!(v; rule_group.params.nftset_timeout, self.nftset_timeout)
                }
                NftSetDebug(v) => self.nftset_debug = Some(v),
                MaxQueryLimit(v) => self.max_query_limit = Some(v),
                LogSyslog(v) => self.log_syslog = Some(v),
                AuditSyslog(v) => self.audit.syslog = Some(v),
                LocalDomain(v) => {
                    let domain = v.trim().trim_end_matches('.').to_ascii_lowercase();
                    if domain.is_empty() || domain == "-" {
                        // 与 C 版一致：写 `-` 表示清空（我们把已配的全部清掉；C 版只记得住一条）
                        self.local_domains.clear();
                    } else {
                        self.local_domains.push(domain);
                    }
                }
                // 🔐 Q3/Q5：这两行我们**认**（不再报"未识别配置行"），但要说明白它们为什么不用开 ——
                // 免得用户以为「配了却没生效」。本实现一律写入全部解析出的地址。
                IpSetNoSpeed(v) => {
                    self.ipset_no_speed = Some(v);
                    notice_no_speed();
                }
                NftSetNoSpeed(v) => {
                    self.nftset_no_speed = Some(v);
                    notice_no_speed();
                }
                HttpsRecord(v) => rule_group.https_records.push(v),
                Server(server) => self.nameservers.push(server),
                ResponseMode(mode) => {
                    route!(mode; rule_group.params.response_mode, self.response_mode)
                }
                ResolvHostname(v) => self.resolv_hostname = Some(v),
                // 📌 丙-1：这两个的全局落点仍在 `self.cache.*`（缓存配置结构里），
                // 但**组级落点在 `GroupParams`** —— 所以不能用 `route!`（它要求两侧同形）。
                // 这里的形状是"组里进组、顶层进 cache 配置"，与组级参数同义。
                ServeExpired(v) => {
                    if in_group {
                        rule_group.params.serve_expired = Some(v);
                    } else {
                        self.cache.serve_expired = Some(v);
                    }
                }
                PrefetchDomain(v) => {
                    if in_group {
                        rule_group.params.prefetch_domain = Some(v);
                    } else {
                        self.cache.prefetch_domain = Some(v);
                    }
                }
                // 🔐 `force-AAAA-SOA` / `force-no-CNAME` 是**可以写进规则组的**参数
                // （C 版为 `_dns_conf_group_yesno`）。判断依据：当前是否处于
                // `group-begin ... group-end` 块内 —— 在组内就写进组、否则写全局默认值。
                // 生效时按 bind 级 > 组级 > 全局 取第一个有值者（见 `DnsContext`）。
                ForceAAAASOA(v) => {
                    if in_group {
                        rule_group.params.force_aaaa_soa = Some(v);
                    } else {
                        self.force_aaaa_soa = Some(v);
                    }
                }
                ForceHTTPSSOA(v) => self.force_https_soa = Some(v),
                ForceNoCNAME(v) => {
                    if in_group {
                        rule_group.params.force_no_cname = Some(v);
                    } else {
                        self.force_no_cname = Some(v);
                    }
                }
                DualstackIpAllowForceAAAA(v) => {
                    route!(v; rule_group.params.dualstack_ip_allow_force_aaaa, self.dualstack_ip_allow_force_aaaa)
                }
                DualstackIpSelection(v) => {
                    route!(v; rule_group.params.dualstack_ip_selection, self.dualstack_ip_selection)
                }
                ServerName(v) => self.server_name = Some(v),
                // 🔐 P2：`num-workers 0` 会让 tokio 一个工作线程都没有 —— 进程活着、端口也开着，
                // 但一个查询都不会被解析，而且没有任何报错（用户只会以为"DNS 彻底坏了"）。
                // 0 显然是笔误，这里忽略它、改用自动值，并把这件事明确说出来。
                NumWorkers(0) => {
                    crate::log::warn!(
                        "num-workers 0 is meaningless (it would stop all resolution); the value was ignored and the automatically computed worker count is used"
                    );
                    self.num_workers = None;
                }
                NumWorkers(v) => self.num_workers = Some(v),
                Domain(v) => self.domain = Some(v),
                SpeedMode(v) => {
                    route_opt!(v; rule_group.params.speed_check_mode, self.speed_check_mode)
                }
                ServeExpiredTtl(v) => self.cache.serve_expired_ttl = Some(v),
                ServeExpiredReplyTtl(v) => {
                    if in_group {
                        rule_group.params.serve_expired_reply_ttl = Some(v);
                    } else {
                        self.cache.serve_expired_reply_ttl = Some(v);
                    }
                }
                // 【新增这一行】：将解析器翻译出来的值装入容器
                ServeExpiredPrefetchTime(v) => self.cache.serve_expired_prefetch_time = Some(v),
                CacheSize(v) => self.cache.size = Some(v),
                ForceQtypeSoa(v) => {
                    self.force_qtype_soa.insert(v);
                }
                DualstackIpSelectionThreshold(v) => {
                    route!(v; rule_group.params.dualstack_ip_selection_threshold, self.dualstack_ip_selection_threshold)
                }
                RrTtl(v) => route!(v; rule_group.params.rr_ttl, self.rr_ttl),
                RrTtlMin(v) => route!(v; rule_group.params.rr_ttl_min, self.rr_ttl_min),
                RrTtlMax(v) => route!(v; rule_group.params.rr_ttl_max, self.rr_ttl_max),
                RrTtlReplyMax(v) => {
                    route!(v; rule_group.params.rr_ttl_reply_max, self.rr_ttl_reply_max)
                }
                Listener(listener) => {
                    // 🔐 P2：证书相对路径先锚定到配置文件所在目录，再入列表
                    let listener = self.anchor_tls_cert_paths(listener);
                    self.binds.push(listener);
                }
                LocalTtl(v) => route!(v; rule_group.params.local_ttl, self.local_ttl),
                LogConsole(v) => self.log.console = Some(v),
                LogNum(v) => self.log.num = Some(v),
                LogLevel(v) => self.log.level = Some(v),
                LogFile(v) => self.log.file = Some(self.resolve_filepath(v)),
                LogFileMode(v) => self.log.file_mode = Some(v),
                LogFilter(v) => self.log.filter = Some(v),
                LogSize(v) => self.log.size = Some(v),
                MaxReplyIpNum(v) => {
                    route!(v; rule_group.params.max_reply_ip_num, self.max_reply_ip_num)
                }
                BlacklistIp(v) => self.blacklist_ip.push(v),
                // 🔐 Q12：一段 IP + 一串开关，落到与顶层指令**同一批表**里
                IpRules(rules) => {
                    if rules.blacklist {
                        self.blacklist_ip.push(rules.key.clone());
                    }
                    if rules.whitelist {
                        self.whitelist_ip.push(rules.key.clone());
                    }
                    if rules.bogus {
                        self.bogus_nxdomain.push(rules.key.clone());
                    }
                    if rules.ignore {
                        self.ignore_ip.push(rules.key.clone());
                    }
                    if let Some(to) = rules.alias {
                        self.ip_alias.push(crate::config::IpAlias {
                            ip: rules.key.clone(),
                            to,
                        });
                    }
                }
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
                            "conf-file {:?} matched no files (the pattern hit nothing, or the path does not exist)",
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

                        if let Err(err) = self.load_conf_file(file.clone()) {
                            log::error!(
                                "failed to load extra configuration file {:?}: {err}; this file is skipped",
                                file
                            );
                        }

                        if v.group.is_some()
                            && let Some((name, rule_group)) = self.rule_group_stack.pop()
                        {
                            self.rule_groups.entry(name).or_default().merge(rule_group);
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
                EdnsClientSubnet(v) => {
                    route!(v; rule_group.params.edns_client_subnet, self.edns_client_subnet)
                }
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
                GroupBegin(v) => self.group_begin(&v),
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
        let path = resolve_filepath(
            filepath,
            self.conf_file.as_ref(),
            RelativePathFallback::Full,
        );

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

    /// 🔐 问题 52：`conf-file` 专用的路径解析。
    ///
    /// 与 [`Self::resolve_filepath`] 的区别只有一处 —— **不做**「进程当前工作目录」与
    /// 「程序可执行文件所在目录」两级回退。保留的回退级别是：
    /// 原路径 → 配置文件所在目录 → `<配置目录>/smartdns.d/` → 已加载配置所在目录。
    ///
    /// 最后一档（`self.dirs`）是历史行为，属于"在已知的配置目录里再找找"，
    /// 不构成劫持面，所以**保留**；被收回的只有那两个由进程环境决定、可能可写的位置。
    ///
    /// 找不到时**明确告警**（原先会静默地到那两个位置去碰运气，用户看不到任何提示）。
    fn resolve_conf_filepath<P: AsRef<Path>>(&self, filepath: P) -> PathBuf {
        let filepath = filepath.as_ref();
        let path = resolve_filepath(
            filepath,
            self.conf_file.as_ref(),
            RelativePathFallback::ConfigDirOnly,
        );

        // 🔐 问题 52（真机测试补漏）：这里**不能**直接用 `path.is_file()`。
        //
        // `resolve_filepath` 在收紧档下会把**找不到的相对路径原样返回**（例如 `e2e-trap.conf`），
        // 而相对路径的 `is_file()` 是相对**进程工作目录**求值的 —— 于是工作目录里只要
        // 有同名文件，这里就会命中并把它当作配置加载，前面所有的收紧全部白做。
        // 真机测试正是这样抓到它的（单元测试的工作目录是 target/debug/deps，没有陷阱文件）。
        //
        // 判据：只接受**绝对路径**，或确实由配置目录拼出来的路径。
        if path.is_absolute() && path.is_file() {
            return path;
        }

        // 与 `resolve_filepath`（方法）一致的"按文件名在已知配置目录里找一次"
        if let Some(name) = path.file_name() {
            for dir in self.dirs.iter() {
                let p = dir.join(name);
                if p.is_file() {
                    return p;
                }
            }
        }

        // 相对路径才有"应该在哪找"可言；绝对路径写错就是写错，提示保持简短。
        warn!(
            "conf-file {} not found (searched: the config file's directory, <config dir>/smartdns.d/, \
             and the directories of already loaded config files; for safety it is NOT looked up in \
             the current working directory or the program directory)",
            filepath.display()
        );

        path
    }
}

/// 🔐 问题 52：相对路径的回退级别。
///
/// 之所以做成参数而不是直接删掉后两级，是因为 `resolve_filepath` 被 12 处共用：
///   日志 / 审计 / 证书（bind-cert-file、bind-cert-key-file、bind-cert-key-pass）/
///   缓存文件 / dnsmasq-lease-file / resolv-file / 名单文件 …
/// 这些是**文件位置**类配置，[`Full`](RelativePathFallback::Full) 的既有行为要保留；
/// 而 `conf-file` 是**配置引入**类，多出来的两级是配置劫持面，所以用
/// [`ConfigDirOnly`](RelativePathFallback::ConfigDirOnly) 收紧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelativePathFallback {
    /// 原路径 → 配置文件所在目录 → `<配置目录>/smartdns.d/` → 当前工作目录 → 程序所在目录。
    /// 这是历史行为，文件位置类配置沿用。
    Full,
    /// 原路径 → 配置文件所在目录 → `<配置目录>/smartdns.d/`。**仅此三级**。
    /// `conf-file` 用这一档（问题 52）。
    ConfigDirOnly,
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

/// 🔐 问题 52：相对路径解析。
///
/// `fallback` 决定要不要走后两级（当前工作目录、程序所在目录）——
/// 只有 `conf-file` 走 [`RelativePathFallback::ConfigDirOnly`]，
/// 其余 12 个共用此函数的调用点走 [`RelativePathFallback::Full`]（行为与从前一致）。
///
/// 递归分支（按文件名再找一次）同样受 `fallback` 约束：否则收回的两级会被它绕回来 ——
/// 它会把「按文件名重新解析」再走一遍，而那一遍原先仍带着后两级。
/// 🔐 问题 52（真机测试补漏）：相对路径的 `is_file()` 是**相对进程工作目录**求值的。
///
/// 原来第一行是无条件的 `if filepath.is_file() { return ... }`，于是 `conf-file` 写相对路径时，
/// 只要**当前工作目录**里恰好有同名文件，就会在这一行直接被命中并返回 ——
/// 后面那个 `ConfigDirOnly` 档位根本没机会生效，收紧等于白做。
///
/// 这正是"单元测试全绿、真机一跑就露"的典型：单元测试里进程工作目录是 `target/debug/deps`，
/// 那里没有陷阱文件，所以检测不到。
///
/// 现在：**相对路径 + `ConfigDirOnly` 档**时跳过这第一级，直接交给下面按配置目录解析；
/// 绝对路径（以及 `Full` 档的相对路径）保持原行为不变。
fn resolve_filepath<P: AsRef<Path>>(
    filepath: P,
    base_file: Option<&PathBuf>,
    fallback: RelativePathFallback,
) -> PathBuf {
    let filepath = filepath.as_ref();

    // 只有"相对路径 + 仅配置目录"这一种组合才跳过按工作目录的存在性判断。
    let skip_cwd_probe = fallback == RelativePathFallback::ConfigDirOnly && !filepath.is_absolute();

    if !skip_cwd_probe && filepath.is_file() {
        return filepath.to_path_buf();
    }

    if !filepath.is_absolute()
        && let Some(base_conf_file) = base_file
        && let Some(dir) = base_conf_file.parent()
    {
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

        // 🔐 问题 52：后两级只在 `Full` 档下生效。
        if fallback == RelativePathFallback::Full {
            if let Ok(new_path) = std::env::current_dir().map(|dir| dir.join(filepath))
                && new_path.is_file()
            {
                return new_path;
            }

            if let Some(new_path) = std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|dir| dir.join(filepath)))
                && new_path.is_file()
            {
                return new_path;
            }
        }
    }

    // try to resolve absolute path by extracting its file_name
    match filepath.file_name().map(Path::new) {
        Some(new_path) if new_path != filepath => {
            let new_path = resolve_filepath(new_path, base_file, fallback);
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

    // 🔐 问题 52（真机测试补漏，这是最后一处漏洞）：
    // `ConfigDirOnly` 档**绝不能把没找到的相对路径原样返回**。
    //
    // 原因：调用链后半段还会再用一次这个路径 —— `load_conf_file` → `load_resolved_file`
    // 里做 `path.exists()` 与 `File::open(&path)`，而**相对路径的 `exists()`/`open()`
    // 是相对进程工作目录求值的**。于是工作目录里的同名文件照样会被打开、被当成配置解析，
    // 前面所有收紧全部失效，只在日志里多一条 "not found" 告警（极具迷惑性）。
    //
    // 修法：找不到时返回一个**由配置目录拼出的绝对路径**（它必然不存在），
    // 让后半段的 `exists()` 稳定为假；同时路径本身仍然可读，便于日志定位。
    //
    // 为什么单元测试发现不了：单元测试的进程工作目录是 `target/debug/deps`，
    // 那里没有与 conf-file 同名的文件，`exists()` 恰好为假，缺陷被完全掩盖 ——
    // 这条只有**真机端到端**（工作目录里放一个同名诱饵文件）才能暴露。
    if fallback == RelativePathFallback::ConfigDirOnly && !filepath.is_absolute() {
        if let Some(dir) = base_file.and_then(|f| f.parent()) {
            return dir.join(filepath);
        }
    }

    filepath.to_path_buf()
}

/// 🔐 问题 38（真机测试补漏）：识别「代理凭据只写了一半」的配置行并给出可读原因。
///
/// 只处理 `proxy-server` 这一条指令；命中时返回错误说明（**不含口令**），否则返回 `None`。
///
/// 为什么单独做这一步、而不是靠解析器报错：
/// `NamedProxyConfig::parse` 用 `map_res(..., ProxyConfig::from_str)` 包住凭据解析，
/// 凭据非法时该 `alt` 分支落空 → 整行被归为「unrecognised configuration line (ignored as-is)」，
/// **配置自检仍然通过**。也就是说错误到不了用户面前，实际退化成"整条代理配置被静默忽略" ——
/// 用户以为代理配好了，其实那条 `proxy-server` 完全没生效。
fn detect_broken_proxy_credential(line: &str) -> Option<String> {
    use std::str::FromStr;

    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("proxy-server")
        .or_else(|| trimmed.strip_prefix("proxy_server"))?;

    // 关键字后面必须跟空白，避免把 `proxy-server-xyz` 之类也当成命中
    if !rest.starts_with([' ', '\t']) {
        return None;
    }

    // 取第一个"长得像 URL"的字段（与解析器一样以空白分隔）
    let url = rest.split_whitespace().next()?;
    if !url.contains("://") {
        return None;
    }

    match crate::proxy::ProxyConfig::from_str(url) {
        // 只把「凭据写了一半」升级为致命错误；其它解析问题仍走原有的"未识别行"路径，
        // 避免把不属于本项的行为一并改掉。
        //
        // 🔐 错误信息里**必须对 URL 脱敏**：`socks5://:口令@host` 的口令就在 URL 里，
        // 直接回显会把口令写进 stderr / 日志 / CI 输出 —— 这与项目
        // `redact_config_line` 的纪律（"日志里不需要看到口令"）直接冲突。
        // 这条是**测试先抓出来的**：我最初的实现原样回显了 `socks5://:onlypassword@…`，
        // 被 `proxy_password_without_username_fails_the_whole_config` 的"不得包含口令"断言拦下。
        Err(crate::proxy::ProxyParseError::PasswordWithoutUsername) => Some(format!(
            "`proxy-server {masked}` has a password but no username. \
             Authentication is only performed when a username is present, so this password would be \
             silently ignored -- write `schema://username:password@host` instead",
            masked = redact_config_line(url)
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{dns::DomainRuleGetter, libdns::Protocol};
    use byte_unit::Byte;

    use crate::config::{BindAddr, HttpsBindAddrConfig, ServerOpts, SslConfig};

    use super::*;

    /// 🔐 问题 24：配置摘要里 `dualstack ip selection` 那一行的三种状态。
    ///
    /// 它要说的是"**双栈优选依赖测速**"这件容易被忽略的联动关系：
    /// 用户按"这是个独立开关"的直觉配出 `dualstack-ip-selection yes` +
    /// `speed-check-mode none`，实际优选做不了任何事（族对决没有判据）。
    /// 这条测试把那三种措辞钉住，防止后来者改坏提示、或把"不生效"显示成"ON"。
    #[test]
    fn dualstack_status_shows_the_race_is_inactive_without_speed_check() {
        // ① 优选没开：只说 OFF，不牵扯测速
        assert_eq!(
            dualstack_ip_selection_status(false, false),
            "OFF",
            "没开优选时显示 OFF"
        );
        assert_eq!(
            dualstack_ip_selection_status(false, true),
            "OFF",
            "没开优选时，测速开不开都与它无关，仍然只说 OFF（不必多嘴）"
        );

        // ② 优选开了、测速也有：正常 ON
        assert_eq!(
            dualstack_ip_selection_status(true, false),
            "ON",
            "优选开着且测速可用时显示 ON"
        );

        // ③ ⚠️ 关键组合：优选开着、但测速被 none 关掉 → 必须明说"不生效"
        let inactive = dualstack_ip_selection_status(true, true);
        assert!(
            inactive.contains("INACTIVE"),
            "优选开着但测速 none 时，必须显示为不生效（实际: {inactive}）—— \
             否则用户会以为优选在工作"
        );
        assert!(
            inactive.contains("speed-check-mode none"),
            "提示要点名是哪个配置造成的（实际: {inactive}）"
        );
    }

    /// 🔐 候选 A（用户定调「以代码为准」）：`serve-expired-reply-ttl` 的默认值。
    ///
    /// 文档站与上游 C 版都写 **3**，而本实现是 **5**。取证时查到这个 5 来自
    /// 上游 vendored 的旧代码（`328b87b`），不是本项目的独立决策。
    /// 用户决定**以代码为准**（改文档去对齐），因为改默认值会让现网
    /// 过期缓存的回包 TTL 发生变化。
    ///
    /// 这条测试的**首要价值是"钉住数字"**：此前它有**零测试覆盖**，
    /// 这正是"文档与代码长期各说各话、没人发现"的根本原因。
    /// 将来若有人要改这个默认值，会先被这条测试拦下来、必须显式说明理由。
    #[test]
    fn serve_expired_reply_ttl_default_is_pinned() {
        let cfg = RuntimeConfig::builder().build().unwrap();

        assert_eq!(
            cfg.serve_expired_reply_ttl(),
            5,
            "默认值必须是 5（用户定调：以代码为准；文档已据此更正）。\
             若确要改动，请同时更新文档站并说明为何要改变现网行为"
        );

        // 显式配置仍然能覆盖（别让"钉住默认值"变成"钉死配置"）
        let cfg = RuntimeConfig::builder()
            .with("serve-expired-reply-ttl 30")
            .build()
            .unwrap();
        assert_eq!(
            cfg.serve_expired_reply_ttl(),
            30,
            "显式配置必须能覆盖默认值"
        );
    }

    /// 🔐 候选 D（用户定调「保持既有」）：`rr-ttl-min/max` **回落** `rr-ttl`。
    ///
    /// 上游 C 版三者**完全独立**，本仓库则是"没写 min/max 就用 rr-ttl"。
    /// 用户决定**保持本仓库既有行为**（改它会让现网部分部署的缓存寿命变短）。
    ///
    /// 这条测试的作用与上一条同源：**把口径钉住**。
    /// 若日后有人"照 C 版顺手改成不回落"，会在这里失败，
    /// 从而必须显式确认那是一次有意的行为变更 —— 而不是无声的漂移。
    #[test]
    fn rr_ttl_min_max_fall_back_to_rr_ttl_by_design() {
        // 只写 rr-ttl：min/max 都应当回落到它
        let cfg = RuntimeConfig::builder().with("rr-ttl 600").build().unwrap();
        assert_eq!(
            cfg.rr_ttl_min(),
            Some(600),
            "本仓库口径：没写 rr-ttl-min 时回落 rr-ttl（与上游 C 版有意不同）"
        );
        assert_eq!(
            cfg.rr_ttl_max(),
            Some(600),
            "本仓库口径：没写 rr-ttl-max 时回落 rr-ttl"
        );

        // 显式写了 min/max：以显式的为准（回落只在"没写"时发生）
        let cfg = RuntimeConfig::builder()
            .with("rr-ttl 600")
            .with("rr-ttl-min 30")
            .with("rr-ttl-max 300")
            .build()
            .unwrap();
        assert_eq!(cfg.rr_ttl_min(), Some(30), "显式 rr-ttl-min 必须压过回落");
        assert_eq!(cfg.rr_ttl_max(), Some(300), "显式 rr-ttl-max 必须压过回落");

        // 三者都没写：min/max 应当是 None（不要凭空造出数字）
        let cfg = RuntimeConfig::builder().build().unwrap();
        assert_eq!(cfg.rr_ttl_min(), None, "都没写时不该有默认下限");
        assert_eq!(cfg.rr_ttl_max(), None, "都没写时不该有默认上限");
    }

    /// 🔐 13-⑥：`trusted-proxy` 的解析与累加。
    ///
    /// 三条要点：
    ///   ① **默认是空清单** —— 空 = 不信任任何代理头 = 与改动前行为一致；
    ///   ② **可重复**，多条要**累加**（不能后一条覆盖前一条 —— 那是本项目
    ///      "配了多条只留最后一条"的老毛病，`ipset`/`nftset` 都踩过）；
    ///   ③ 支持单个 IP **与网段**两种写法。
    #[test]
    fn trusted_proxy_parses_and_accumulates() {
        // ① 默认：空清单（安全默认 —— 不信任任何代理头）
        let cfg = RuntimeConfig::builder().build().unwrap();
        assert!(
            cfg.trusted_proxies().is_empty(),
            "🔐 没配 `trusted-proxy` 时必须是空清单 —— 空 = 不信任任何代理头，\
             这让本功能对未配置的部署做到行为零变化"
        );

        // ② 可重复 + 累加 + 支持网段
        let cfg = RuntimeConfig::builder()
            .with("trusted-proxy 192.168.1.1")
            .with("trusted-proxy 10.0.0.0/8")
            .with("trusted-proxy 2001:db8::/32")
            .build()
            .unwrap();

        let trusted = cfg.trusted_proxies();
        assert_eq!(
            trusted.len(),
            3,
            "🔐 三条 `trusted-proxy` 必须**累加**成三条 —— \
             若只留最后一条，那正是本项目反复治理的『配了多条只生效一条』"
        );

        // ③ 单个 IP 与网段都要能匹配
        assert!(
            trusted.contains("192.168.1.1".parse().unwrap()),
            "单个 IP 写法应当命中"
        );
        assert!(
            trusted.contains("10.1.2.3".parse().unwrap()),
            "网段内的地址应当命中"
        );
        assert!(
            trusted.contains("2001:db8::1".parse().unwrap()),
            "IPv6 网段也要支持"
        );
        assert!(
            !trusted.contains("11.0.0.1".parse().unwrap()),
            "网段外的不该命中"
        );
    }

    /// 🔐 P2（用户定策）：组不存在 → 走默认组 + 点名告警。
    /// 🔐 Q2/Q3/Q4/Q5/Q6：集合相关的那几个开关都要能解析进来，默认都不改行为
    #[test]
    fn test_kernel_set_switches_parse() {
        let cfg = RuntimeConfig::builder()
            .with("ipset-timeout yes")
            .with("nftset-timeout yes")
            .with("ipset-no-speed yes")
            .with("nftset-no-speed yes")
            .with("nftset-debug yes")
            .build()
            .unwrap();

        assert!(cfg.ipset_timeout(), "Q2：ipset 条目要带过期时间");
        assert!(cfg.nftset_timeout(), "Q4：nftset 条目要带过期时间");
        assert!(cfg.nftset_debug(), "Q6：打开 nftset 详细日志");
        // Q3/Q5 这两个开关只是"认下来 + 启动时说明"，不改变任何行为：
        // 本实现一律写全部地址，所以这两个值不该影响后面的判断（这里只验它们不 panic、不影响其它开关）
        assert!(!cfg.log_syslog(), "别的开关不该被它们带开");

        // 默认：全关
        let cfg = RuntimeConfig::builder().build().unwrap();
        assert!(!cfg.ipset_timeout() && !cfg.nftset_timeout() && !cfg.nftset_debug());
    }

    /// 🔐 Q18 `-inherit`：显式继承另一个组的规则
    #[test]
    fn test_group_inherit_named_group() {
        let cfg = RuntimeConfig::builder()
            .with("group-begin base")
            .with("address /a.test/1.2.3.4")
            .with("group-end")
            .with("group-begin child -inherit base")
            .with("group-end")
            .build()
            .unwrap();

        let name = Name::from_utf8("a.test").unwrap();
        assert!(
            cfg.find_domain_rule(&name, "base")
                .get(|n| n.address.clone())
                .is_some(),
            "base 组自己要有这条地址规则"
        );
        assert!(
            cfg.find_domain_rule(&name, "child")
                .get(|n| n.address.clone())
                .is_some(),
            "child 继承了 base 之后也该有"
        );
    }

    /// `-inherit none` = 不继承；写错组名 = 不继承（并且会告警，这里只验行为）
    #[test]
    fn test_group_inherit_none_and_missing() {
        let cfg = RuntimeConfig::builder()
            .with("group-begin base")
            .with("address /a.test/1.2.3.4")
            .with("group-end")
            .with("group-begin plain -inherit none")
            .with("group-end")
            .with("group-begin typo -inherit nosuchgroup")
            .with("group-end")
            .build()
            .unwrap();

        let name = Name::from_utf8("a.test").unwrap();
        assert!(
            cfg.find_domain_rule(&name, "plain")
                .get(|n| n.address.clone())
                .is_none(),
            "-inherit none 就是不继承"
        );
        assert!(
            cfg.find_domain_rule(&name, "typo")
                .get(|n| n.address.clone())
                .is_none(),
            "继承一个没定义过的组 → 不继承（C 版也是告警后不继承）"
        );
    }

    /// 嵌套组：默认继承外层（与 C 版一致）；`-inherit parent` 是显式写法
    #[test]
    fn test_group_inherit_nested_defaults_to_parent() {
        let cfg = RuntimeConfig::builder()
            .with("group-begin outer")
            .with("address /a.test/1.2.3.4")
            .with("group-begin inner")
            .with("group-end")
            .with("group-begin explicit -inherit parent")
            .with("group-end")
            .with("group-end")
            .build()
            .unwrap();

        let name = Name::from_utf8("a.test").unwrap();
        for group in ["inner", "explicit"] {
            assert!(
                cfg.find_domain_rule(&name, group)
                    .get(|n| n.address.clone())
                    .is_some(),
                "{group} 应该继承到外层组的地址规则"
            );
        }
    }

    /// 🔐 Q7/Q8：两条 syslog 开关要能解析进来（默认都是关）
    #[test]
    fn test_syslog_switches_parse() {
        let cfg = RuntimeConfig::builder()
            .with("log-syslog yes")
            .with("audit-enable yes")
            .with("audit-syslog yes")
            .build()
            .unwrap();

        assert!(cfg.log_syslog());
        assert!(cfg.audit_syslog());

        let cfg = RuntimeConfig::builder()
            .with("log-syslog no")
            .build()
            .unwrap();
        assert!(!cfg.log_syslog(), "写 no 就是关");
        assert!(!cfg.audit_syslog(), "没写默认关");
    }

    /// 🔐 Q19/Q20/Q21：三种写法都要能配上集合（监听级两个选项、`domain-rules` 里的两个选项）
    #[test]
    fn test_kernel_sets_from_listener_and_domain_rules() {
        let cfg = RuntimeConfig::builder()
            // 监听级：这个监听收到的查询都要写这几个集合
            .with("bind 127.0.0.1:0 -nftset #4:inet#filter#set4 -ipset #4:dns4")
            // 域名规则级：这条规则的域名单独写
            .with("domain-rules /rule.test/ -nftset #4:inet#filter#ruleset -ipset #6:dns6")
            // 独立指令（早已支持）：`nftset /域/...`
            .with("nftset /directive.test/#4:inet#filter#direct")
            .build()
            .unwrap();

        // ① 监听级
        let listener = cfg.binds().first().expect("应有一个监听");
        let crate::config::BindAddrConfig::Udp(udp) = listener else {
            panic!("示例里的监听是 UDP");
        };
        let listener_nft = udp.opts.nftset.clone().unwrap_or_default();
        let listener_ip = udp.opts.ipset.clone().unwrap_or_default();
        assert_eq!(listener_nft.len(), 1, "监听上配了 1 个 nftset");
        assert_eq!(listener_ip.len(), 1, "监听上配了 1 个 ipset");

        // ② domain-rules 级
        let rule = cfg
            .find_domain_rule(&Name::from_utf8("rule.test").unwrap(), "")
            .expect("应有 rule.test 的规则");
        assert_eq!(
            rule.get(|n| n.nftset.as_ref().map(|v| v.len()))
                .unwrap_or_default(),
            1,
            "domain-rules 里的 -nftset 要落到规则上"
        );
        assert_eq!(
            rule.get(|n| n.ipset.as_ref().map(|v| v.len()))
                .unwrap_or_default(),
            1,
            "domain-rules 里的 -ipset 要落到规则上"
        );

        // ③ 独立指令那条路没被搞坏
        let direct = cfg
            .find_domain_rule(&Name::from_utf8("directive.test").unwrap(), "")
            .expect("应有 directive.test 的规则");
        assert_eq!(
            direct
                .get(|n| n.nftset.as_ref().map(|v| v.len()))
                .unwrap_or_default(),
            1
        );
    }

    /// 监听上写错了集合语法 → 忽略并告警，但监听本身照常可用（不能因为一个选项就起不来）
    #[test]
    fn test_listener_bad_ipset_value_is_ignored() {
        let cfg = RuntimeConfig::builder()
            .with("bind 127.0.0.1:0 -ipset 这是错的")
            .build()
            .unwrap();

        let listener = cfg.binds().first().expect("监听仍应存在");
        let crate::config::BindAddrConfig::Udp(udp) = listener else {
            panic!("示例里的监听是 UDP");
        };
        assert!(
            udp.opts.ipset.as_deref().unwrap_or_default().is_empty(),
            "值不合法应该被丢掉"
        );
    }

    /// 🔐 Q11 `local-domain`：域名本身与**子域名**都算；大小写、末尾的点都不影响。
    #[test]
    fn test_local_domain_matching() {
        let cfg = RuntimeConfig::builder()
            .with("local-domain lan")
            .with("local-domain HOME.test")
            .build()
            .unwrap();

        let local = |s: &str| cfg.is_local_domain(&Name::from_utf8(s).unwrap());

        assert!(local("lan"), "域名本身算");
        assert!(local("LAN."), "大小写与末尾的点都不该影响");
        assert!(local("nas.lan"), "子域名算");
        assert!(local("a.b.lan"), "多级子域名也算");
        assert!(local("home.test"), "第二条也生效（C 版只记得住一条）");
        assert!(
            !local("lanx"),
            "lanx 不是 lan 的子域名（别按字符串前缀乱匹配）"
        );
        assert!(!local("example.com"));
    }

    /// `local-domain -` 清空已配的（与 C 版 `-` 的语义一致）
    #[test]
    fn test_local_domain_dash_clears() {
        let cfg = RuntimeConfig::builder()
            .with("local-domain lan")
            .with("local-domain -")
            .build()
            .unwrap();

        assert!(
            !cfg.is_local_domain(&Name::from_utf8("nas.lan").unwrap()),
            "写了 `-` 之后不该还有 local-domain"
        );
    }

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
        assert!(
            cfg.has_server_group("office"),
            "office 是 server 行上声明过的组"
        );
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
        // 网卡名故意用一张任何机器都不会有的：装载配置时，若该网卡真实存在，
        // dns_conf 会把监听地址换成它的 IP（见本文件 1090 行附近），那样这条用例的结果
        // 就取决于“跑测试的机器上有没有 eth2”，与它要验证的“选项解析”无关。
        let cfg = RuntimeConfig::builder()
            .with("bind-https 0.0.0.0:443@sde-testdev -no-rule-addr")
            .build()
            .unwrap();

        let listener = cfg.binds().first().unwrap();

        assert_eq!(
            listener,
            &BindAddrConfig::Https(HttpsBindAddrConfig {
                addr: BindAddr::V4("0.0.0.0".parse().unwrap()),
                port: 443,
                device: Some("sde-testdev".to_string()),
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
        assert_eq!(
            rules[1].client,
            Client::IpAddr("10.0.0.1/32".parse().unwrap())
        );

        assert_eq!(rules[2].group, "group-a");
        assert_eq!(
            rules[2].client,
            Client::Mac("01:02:03:04:05:06".to_string())
        );
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
            names(expand_conf_pattern(
                std::path::Path::new("conf.d/*.conf"),
                Some(&base)
            )),
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

    // ================= 🔐 问题 52：conf-file 不再到「工作目录 / 程序目录」找配置 =================

    /// 造一个「只存在于程序所在目录」的文件名（用 pid + 计数器避免与其他用例撞名）。
    ///
    /// 选程序所在目录（`target/<profile>/deps`）而不是当前工作目录，是为了**不动全局状态**：
    /// 用例是并发跑的，改 `current_dir` 会影响别的用例；而往 `deps` 目录写一个唯一名字的
    /// 临时文件不影响任何东西，用完即删。
    fn unique_name(tag: &str) -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        format!(
            "smartdns-conf52-{tag}-{}-{}.conf",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// 程序所在目录（测试二进制就在 `target/<profile>/deps/*.exe`）。
    fn exe_dir() -> std::path::PathBuf {
        std::env::current_exe()
            .expect("应当能取到当前可执行文件路径")
            .parent()
            .expect("可执行文件应当有父目录")
            .to_path_buf()
    }

    /// 🔐 问题 52 的核心回归：`conf-file` 写相对路径时，**只有**「配置文件所在目录」与
    /// `smartdns.d` 这两级回退，**不得**再去程序所在目录（以及当前工作目录）碰运气。
    ///
    /// ⚠️ 这里必须调用 `conf-file` **真正走的那个方法**（`resolve_conf_filepath`），
    /// 而不是直接调自由函数再手写档位 —— 后者测的只是"两档语义各自成立"，
    /// 无论 `load_conf_file` 实际挑了哪一档都会通过，属于**测不到接线**的假有效测试
    /// 🔐 问题 52（**真机端到端测试补漏**）：`conf-file` 找不到时，**绝不能把相对路径原样返回**。
    ///
    /// 这是单元测试漏掉、只有真机才暴露的一个真实缺陷。完整的失败链条是：
    ///   1. `resolve_filepath` 在 `ConfigDirOnly` 档找不到文件 → 原样返回相对路径 `trap.conf`；
    ///   2. `load_conf_file` → `load_resolved_file` 里再做 `path.exists()` 与 `File::open(&path)`；
    ///   3. **相对路径的 `exists()`/`open()` 是相对进程工作目录求值的** →
    ///      工作目录里那个同名文件照样被打开、被当作配置解析；
    ///   4. 结果：前面所有收紧全部失效，日志里却只多一条 "not found" 告警（极具迷惑性）。
    ///
    /// **为什么单元测试发现不了**：单元测试的进程工作目录是 `target/debug/deps`，
    /// 那里没有与 conf-file 同名的文件，`exists()` 恰好为假 —— 缺陷被完全掩盖。
    /// 真机把工作目录设为放有诱饵文件的目录后，立刻复现（诱饵规则 `address /trap.test/9.9.9.9` 生效）。
    ///
    /// 所以这条测试**必须显式模拟"工作目录里有同名文件"**才行。
    #[test]
    fn conf_file_never_returns_a_relative_path_when_not_found() {
        let dir = std::env::temp_dir().join(format!("conf52-rel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // 配置目录：**没有** trap.conf
        let conf_dir = dir.join("conf");
        std::fs::create_dir_all(&conf_dir).unwrap();
        let base = conf_dir.join("smartdns.conf");
        std::fs::write(&base, "# main\n").unwrap();

        // 另造一个"看起来像工作目录"的地方，并放上诱饵（模拟真机场景）
        let cwd_like = dir.join("cwd");
        std::fs::create_dir_all(&cwd_like).unwrap();
        std::fs::write(cwd_like.join("trap.conf"), "address /trap.test/9.9.9.9\n").unwrap();

        let builder = RuntimeConfig::builder().with_conf_file(&base);
        let resolved = builder.resolve_conf_filepath(std::path::Path::new("trap.conf"));

        // ① 必须是绝对路径 —— 这是本缺陷的**根因所在**：
        //    只要返回相对路径，后续 `exists()`/`open()` 就会按工作目录命中诱饵。
        assert!(
            resolved.is_absolute(),
            "🔐 问题 52：conf-file 找不到时必须返回绝对路径，否则会被进程工作目录劫持。\
             实际返回: {}",
            resolved.display()
        );

        // ② 解析结果必须**不是**那个诱饵文件
        assert_ne!(
            std::fs::canonicalize(&resolved).ok(),
            std::fs::canonicalize(cwd_like.join("trap.conf")).ok(),
            "🔐 问题 52：解析结果绝不能指向工作目录里的诱饵文件"
        );

        // ③ 它必须确实不存在（后续 `load_resolved_file` 的 `exists()` 会稳定为假）
        assert!(
            !resolved.exists(),
            "找不到时返回的路径必须不存在，否则会去加载一个错误的文件: {}",
            resolved.display()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// （反向验证时会照样通过）。端到端的接线由下一条用例覆盖。
    ///
    /// 这条同时钉住两件事，缺一不可：
    /// 1. `conf-file` 这一档确实收回了后两级 —— 否则文件会被找到；
    /// 2. `Full` 档仍保留后两级 —— 否则其余 12 个共用该函数的调用点（日志/证书/缓存…）行为被改坏。
    #[test]
    fn conf_file_must_not_fall_back_to_the_program_directory() {
        let dir = std::env::temp_dir().join(format!("conf52-resolve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let name = unique_name("resolve");
        let in_exe_dir = exe_dir().join(&name);
        std::fs::write(&in_exe_dir, "# 只存在于程序所在目录\n").unwrap();

        let base = dir.join("smartdns.conf");
        std::fs::write(&base, "# main\n").unwrap();

        let relative = std::path::Path::new(&name);

        // ① 走 `conf-file` 真正使用的方法：后两级被收回 → 找不到，原样返回相对路径
        let builder = RuntimeConfig::builder().with_conf_file(&base);
        let strict = builder.resolve_conf_filepath(relative);
        assert!(
            !strict.is_file(),
            "🔐 问题 52：conf-file 不得回退到程序所在目录，但它找到了: {}",
            strict.display()
        );

        // ② 其余调用点那一档：后两级仍在 → 能按程序所在目录找到（行为未被改坏）
        let full = resolve_filepath(relative, Some(&base), RelativePathFallback::Full);
        assert!(
            full.is_file(),
            "非 conf-file 的调用点必须保留「程序所在目录」回退（既有部署依赖它），实际得到: {}",
            full.display()
        );
        assert_eq!(
            std::fs::canonicalize(&full).unwrap(),
            std::fs::canonicalize(&in_exe_dir).unwrap(),
            "Full 档应当解析到程序所在目录里的那个文件"
        );

        let _ = std::fs::remove_file(&in_exe_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 问题 52 的端到端回归：走完整的配置装配流程。
    ///
    /// 断言「程序目录里那个同名文件**没有被当成配置加载**」——这是危害的实际后果
    /// （注入 `address` 规则可劫持解析）。同时验证正常的 `conf-file` 仍然生效，
    /// 确保这次收紧没有把正常用法一起收掉。
    #[test]
    fn conf_file_in_program_directory_is_not_loaded() {
        let dir = std::env::temp_dir().join(format!("conf52-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 程序所在目录里的"陷阱配置"：一旦被加载就会多出一条地址规则
        let name = unique_name("e2e");
        let planted = exe_dir().join(&name);
        std::fs::write(&planted, "address /planted-in-exe-dir.test/7.7.7.7\n").unwrap();

        // 正常的 conf-file（与主配置同目录）必须照常生效
        std::fs::write(dir.join("normal.conf"), "address /normal-ok.test/1.1.1.1\n").unwrap();

        let main_conf = dir.join("smartdns.conf");
        std::fs::write(
            &main_conf,
            format!("conf-file {name}\nconf-file normal.conf\n"),
        )
        .unwrap();

        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&main_conf)
            .build()
            .expect("配置应当能正常构建");

        let rules = &cfg.rule_group(DEFAULT_GROUP).address_rules;
        let domains: Vec<String> = rules.iter().map(|r| r.domain.to_string()).collect();

        assert!(
            !domains
                .iter()
                .any(|d| d.contains("planted-in-exe-dir.test")),
            "🔐 问题 52：程序所在目录里的同名文件被当成配置加载了（配置劫持面），实际加载到: {domains:?}"
        );
        assert!(
            domains.iter().any(|d| d.contains("normal-ok.test")),
            "正常的 conf-file（与主配置同目录）必须照常生效，实际加载到: {domains:?}"
        );

        let _ = std::fs::remove_file(&planted);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 问题 52：保留的那两级回退不能被误伤 —— 「配置文件所在目录」与 `smartdns.d` 仍要能用。
    /// 这条防止"为了修 52 而把正常路径一起收掉"。
    #[test]
    fn conf_file_still_uses_config_dir_and_smartdns_d() {
        let dir = std::env::temp_dir().join(format!("conf52-keep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("smartdns.d")).unwrap();

        // ① 与主配置同目录
        std::fs::write(
            dir.join("same-dir.conf"),
            "address /same-dir.test/1.1.1.1\n",
        )
        .unwrap();
        // ② `smartdns.d/` 子目录
        std::fs::write(
            dir.join("smartdns.d").join("in-d.conf"),
            "address /in-smartdns-d.test/2.2.2.2\n",
        )
        .unwrap();

        let main_conf = dir.join("smartdns.conf");
        std::fs::write(&main_conf, "conf-file same-dir.conf\nconf-file in-d.conf\n").unwrap();

        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&main_conf)
            .build()
            .expect("配置应当能正常构建");

        let rules = &cfg.rule_group(DEFAULT_GROUP).address_rules;
        let domains: Vec<String> = rules.iter().map(|r| r.domain.to_string()).collect();

        assert!(
            domains.iter().any(|d| d.contains("same-dir.test")),
            "「配置文件所在目录」这级回退必须保留，实际加载到: {domains:?}"
        );
        assert!(
            domains.iter().any(|d| d.contains("in-smartdns-d.test")),
            "`smartdns.d/` 这级回退必须保留，实际加载到: {domains:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ================= 🔐 问题 38（真机测试补漏）：凭据写一半必须是配置错误 =================

    /// 🔐 问题 38（**真机端到端测试补漏**）：`proxy-server socks5://:口令@host` 必须让
    /// `build()` **失败**，而不是只打一条"未识别行"告警然后照常启动。
    ///
    /// 为什么单元测试发现不了这个：上一批我在 `ProxyConfig::from_str` 里加了
    /// `PasswordWithoutUsername` 判据，也写了直接调 `from_str` 的测试 —— 那条测试**通过**，
    /// 但它只证明"函数会报错"，没证明"这个错误能走到用户面前"。
    ///
    /// 真实链路是：`NamedProxyConfig::parse` 用 `map_res(..., from_str)` 包住凭据解析 →
    /// 凭据非法时整个 `alt` 分支落空 → 整行被归为「unrecognised configuration line (ignored as-is)」
    /// → **配置自检仍报通过、退出码 0**。实际效果是"整条代理配置被静默忽略"，
    /// 比原始缺陷更隐蔽：用户以为代理配好了，其实那条 `proxy-server` 完全没生效。
    ///
    /// 这条测试走**完整装配路径**（`build()`），因此能钉住"错误真的会冒出来"。
    #[test]
    fn proxy_password_without_username_fails_the_whole_config() {
        let dir = std::env::temp_dir().join(format!("conf38-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let main_conf = dir.join("smartdns.conf");
        std::fs::write(
            &main_conf,
            "bind 127.0.0.1:15360\n\
             proxy-server socks5://:onlypassword@127.0.0.1:1080 -name bad\n\
             server 223.5.5.5 -proxy bad\n",
        )
        .unwrap();

        let err = match RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&main_conf)
            .build()
        {
            Ok(_) => panic!("🔐 问题 38：凭据写一半必须让配置构建失败，而不是静默忽略该行"),
            Err(err) => err,
        };

        let shown = format!("{err:#}");
        assert!(
            shown.contains("password but no username"),
            "错误信息应说明缺的是用户名，实际: {shown}"
        );
        assert!(
            shown.contains("line 2"),
            "错误信息应指出是第几行，实际: {shown}"
        );
        // 🔐 绝不能把口令本身回显到错误信息里
        assert!(
            !shown.contains("onlypassword"),
            "错误信息绝不能包含口令，实际: {shown}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 问题 38 的**反向保护**：三种合法写法都必须照常通过 —— 不能收紧过头。
    ///
    /// 尤其「只有用户名、没有口令」：它的认证是**照常发起**的（口令为空串），
    /// 不存在静默丢弃，因此必须继续被接受（既有测试 `test_parse_socks5_with_user` 也依赖它）。
    #[test]
    fn legitimate_proxy_forms_still_build_successfully() {
        for (label, proxy_line) in [
            ("纯匿名", "proxy-server socks5://127.0.0.1:1080 -name p"),
            (
                "只有用户名",
                "proxy-server socks5://user@127.0.0.1:1080 -name p",
            ),
            (
                "用户名+口令",
                "proxy-server socks5://user:pass@127.0.0.1:1080 -name p",
            ),
            ("http 匿名", "proxy-server http://127.0.0.1:8080 -name p"),
        ] {
            let dir =
                std::env::temp_dir().join(format!("conf38ok-{}-{}", std::process::id(), label));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();

            let main_conf = dir.join("smartdns.conf");
            std::fs::write(
                &main_conf,
                format!("bind 127.0.0.1:15360\n{proxy_line}\nserver 223.5.5.5 -proxy p\n"),
            )
            .unwrap();

            let result = RuntimeConfig::builder()
                .with_conf_dir(&dir)
                .with_conf_file(&main_conf)
                .build();

            if let Err(err) = result {
                panic!("🔐 问题 38：合法写法「{label}」不该被拒绝，但失败了: {err:#}");
            }

            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
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
        assert!(
            !masked.contains("s3cr3t"),
            "代理密码不得出现在日志里：{masked}"
        );
        assert!(
            masked.contains("proxy-server"),
            "仍要报出是哪个关键字：{masked}"
        );

        // 管理口令与私钥口令
        let masked = redact_config_line("api-token MyS3cretToken 多写的字");
        assert!(
            !masked.contains("MyS3cretToken"),
            "管理口令不得出现在日志里：{masked}"
        );
        let masked = redact_config_line("bind-cert-key-pass MyKeyPass 多写的字");
        assert!(
            !masked.contains("MyKeyPass"),
            "私钥口令不得出现在日志里：{masked}"
        );

        // 关键字本身写错（整行谁都不认）也要脱敏
        let masked = redact_config_line("  PROXY-SERVER socks5://u:p@h:1080 拼错了");
        assert!(
            !masked.contains(":p@"),
            "大小写不同的关键字也要挡住：{masked}"
        );

        // 非敏感行：保留原文，用户才看得出拼写错在哪
        let plain = "addres /typo.test/1.2.3.4";
        assert_eq!(redact_config_line(plain), plain);

        // 行尾粘了带口令的 URL：只打码 user:pass，其余照旧
        let masked = redact_config_line("address /x.test/1.2.3.4 socks5://bob:hunter2@h:1080");
        assert!(
            !masked.contains("hunter2"),
            "URL 里的口令必须打码：{masked}"
        );
        assert!(
            masked.contains("address /x.test/1.2.3.4"),
            "无关部分照旧显示：{masked}"
        );
        assert!(
            masked.contains("socks5://***@h:1080"),
            "打码形态要能看出是个代理 URL：{masked}"
        );
    }
}

#[cfg(test)]
mod ttl_clamp_tests {
    use crate::config::TTL_MAX;
    use crate::dns_conf::RuntimeConfig;
    // 管理目录那几条测试要用到默认组名
    use crate::dns_conf::DEFAULT_GROUP;
    // 🔐 B-①：推导函数的边界测试要直接调它（见 `empty_parent_directory_is_not_used_as_conf_dir`）
    use super::derive_conf_dir_from_conf_file;
    use std::path::{Path, PathBuf};

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
        assert_eq!(
            cfg.serve_expired_ttl(),
            TTL_MAX,
            "serve-expired-ttl 必须夹到上限"
        );
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

    /// 🔐 管理目录（`<配置目录>/managed`）下的 `.conf` 必须被真正加载。
    ///
    /// 背景：管理接口 `/api/addresses` 把地址规则写进 `managed/address.conf`，
    /// 但配置加载链里原先**没有任何地方读它** —— 接口返回 201、文件也写进去了，
    /// 规则却从不进入运行时解析，表现为「配了不生效」这种最伤信任的静默无效。
    #[test]
    fn managed_dir_configs_are_loaded() {
        let dir = std::env::temp_dir().join(format!("managed-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let managed = dir.join("managed");
        std::fs::create_dir_all(&managed).unwrap();

        // 主配置
        let main_conf = dir.join("smartdns.conf");
        std::fs::write(&main_conf, "# main\n").unwrap();

        // 管理目录下两份配置：都应加载（按名字排序，顺序稳定）
        std::fs::write(managed.join("address.conf"), "address /a.test/1.2.3.4\n").unwrap();
        std::fs::write(managed.join("extra.conf"), "address /b.test/5.6.7.8\n").unwrap();
        // 非 .conf 文件必须被忽略
        std::fs::write(managed.join("notes.txt"), "address /ignored.test/9.9.9.9\n").unwrap();
        // 子目录也必须被忽略
        std::fs::create_dir_all(managed.join("sub.conf")).unwrap();

        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&main_conf)
            .build()
            .unwrap();

        let rules = &cfg.rule_group(DEFAULT_GROUP).address_rules;
        let domains: Vec<String> = rules.iter().map(|r| r.domain.to_string()).collect();

        assert!(
            domains.iter().any(|d| d.contains("a.test")),
            "managed/address.conf 里的规则必须生效，实际加载到: {domains:?}"
        );
        assert!(
            domains.iter().any(|d| d.contains("b.test")),
            "managed 下所有 .conf 都该加载，实际加载到: {domains:?}"
        );
        assert!(
            !domains.iter().any(|d| d.contains("ignored.test")),
            "非 .conf 文件不该被当成配置，实际加载到: {domains:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 管理目录不存在时（首次启动、还没用过管理接口）不能报错、不能 panic。
    #[test]
    fn missing_managed_dir_is_fine() {
        let dir = std::env::temp_dir().join(format!("managed-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let main_conf = dir.join("smartdns.conf");
        std::fs::write(&main_conf, "# main\n").unwrap();

        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&main_conf)
            .build();
        assert!(cfg.is_ok(), "管理目录不存在时应当照常启动");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ───────────── 🔐 B-①：`managed_dir` 的推导放宽 ─────────────

    /// 🔐 **核心**：配置目录名**不是** `smartdns` 时，也必须能推出 `managed_dir`。
    ///
    /// ## 原缺陷
    ///
    /// `load()` 里推导 `conf_dir` 的条件之一是"**父目录名恰好等于 `smartdns`**"，
    /// 于是配置放在 `myconf/`、`/etc/dns/` 这类目录下、又没传 `-d` 时：
    /// `conf_dir = None` ⇒ `managed_dir = None` ⇒ `/api/addresses` **三个端点全 404**
    /// ⇒ 整个地址规则功能不可用（照文档配了却用不了）。
    ///
    /// ## 判别力
    ///
    /// 把 `load()` 里的推导改回"要求目录名等于 `smartdns`"，本测试**必然失败**。
    #[test]
    fn managed_dir_is_derived_for_any_config_directory_name() {
        // 关键：目录名故意**不叫** smartdns（这正是原缺陷的触发条件）
        for dir_name in ["myconf", "dns", "app-conf"] {
            let dir = std::env::temp_dir()
                .join(format!("managed-wide-{}-{dir_name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();

            let main_conf = dir.join("smartdns.conf");
            std::fs::write(&main_conf, "# main\n").unwrap();

            // 注意：**不传** `with_conf_dir`，模拟"用户没写 -d"这一真实路径
            let cfg = RuntimeConfig::builder()
                .with_conf_file(&main_conf)
                .build()
                .unwrap();

            let managed = cfg.managed_dir();
            assert!(
                managed.is_some(),
                "🔐 配置文件在 `{dir_name}/` 下（目录名不是 smartdns）时，\
                 managed_dir 必须仍能推导出来 —— 否则管理接口三个端点全 404（B-①）。\
                 实际: {managed:?}"
            );

            // 推导出来的位置必须是"配置文件所在目录/managed"
            let expected = dir.join("managed");
            assert_eq!(
                managed.unwrap(),
                expected,
                "managed_dir 应当锚定在**配置文件所在目录**下"
            );

            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// 显式传了 `-d` 时，**以 `-d` 为准**（放宽推导不能反过来覆盖用户的显式选择）。
    #[test]
    fn explicit_dash_d_still_wins() {
        let base = std::env::temp_dir().join(format!("managed-explicit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let conf_dir = base.join("conf");
        let other_dir = base.join("other");
        std::fs::create_dir_all(&conf_dir).unwrap();
        std::fs::create_dir_all(&other_dir).unwrap();

        // 配置放在 conf/，但用 -d 指定 other/
        let main_conf = conf_dir.join("smartdns.conf");
        std::fs::write(&main_conf, "# main\n").unwrap();

        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&other_dir)
            .with_conf_file(&main_conf)
            .build()
            .unwrap();

        assert_eq!(
            cfg.managed_dir(),
            Some(other_dir.join("managed").as_path()),
            "🔐 用户显式传了 -d 时必须以它为准 —— 放宽推导只该在'没传 -d'时兜底"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// 🔐 B-① 的**边界**：空父目录**不得**被当成 `conf_dir`。
    ///
    /// 触发场景：`-c smartdns.conf` 这种**没有目录成分**的相对路径，
    /// `Path::parent()` 返回的是**空路径** `""`。若直接采用它：
    ///   · `conf_dir` 会变成空路径；
    ///   · `managed_dir` 随之成为相对路径 `managed/`，
    ///     于是**落在进程当前工作目录**下 —— 那正是问题 52 花力气堵掉的
    ///     "随工作目录漂移"一类隐患（服务方式启动时工作目录可能是 `/` 或 `System32`）。
    ///
    /// ⚠️ 这里**直接测推导函数本身**，不经过 `load()`/`build()` ——
    /// 因为后者会去真实读文件（一个不存在的相对路径会让 `build()` 报错），
    /// 那样测到的就不是"推导规则"而是"文件存不存在"了。
    /// 这也正是把推导逻辑抽出来的价值：它能被单独钉住。
    #[test]
    fn empty_parent_directory_is_not_used_as_conf_dir() {
        // ① 没有目录成分的相对路径 → 父目录是空 → **不采用**
        assert_eq!(
            derive_conf_dir_from_conf_file(Path::new("smartdns.conf")),
            None,
            "`-c smartdns.conf`（无目录成分）时不该把空路径当成 conf_dir —— \
             否则 managed_dir 会变成相对路径、随工作目录漂移"
        );

        // ② 带目录的相对路径 → 采用该目录（B-① 放宽的正是这一类）
        assert_eq!(
            derive_conf_dir_from_conf_file(Path::new("myconf/smartdns.conf")),
            Some(PathBuf::from("myconf")),
            "带目录的相对路径应当推出 conf_dir（不再要求目录名叫 smartdns）"
        );

        // ③ 绝对路径 → 采用其父目录
        assert_eq!(
            derive_conf_dir_from_conf_file(Path::new("/etc/dns/smartdns.conf")),
            Some(PathBuf::from("/etc/dns")),
            "绝对路径应当推出父目录（这正是原缺陷会失败的场景：目录名不是 smartdns）"
        );

        // ④ 只有文件名的绝对路径（根目录下）→ 父目录是 `/`，**非空**，应当采用
        #[cfg(unix)]
        assert_eq!(
            derive_conf_dir_from_conf_file(Path::new("/smartdns.conf")),
            Some(PathBuf::from("/")),
            "根目录下的配置，其父目录 `/` 是非空的，应当采用"
        );
    }

    /// 管理目录里语法有问题的文件不能把整个配置加载搞崩，其余部分照常生效。
    #[test]
    fn broken_managed_file_does_not_break_the_rest() {
        let dir = std::env::temp_dir().join(format!("managed-broken-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let managed = dir.join("managed");
        std::fs::create_dir_all(&managed).unwrap();

        let main_conf = dir.join("smartdns.conf");
        std::fs::write(&main_conf, "address /main.test/1.1.1.1\n").unwrap();

        // 一个正常、一个含乱码字节
        std::fs::write(managed.join("a-ok.conf"), "address /ok.test/2.2.2.2\n").unwrap();
        std::fs::write(managed.join("b-bad.conf"), b"# \xff\xfe garbled\n").unwrap();

        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&main_conf)
            .build()
            .expect("坏文件不该让整个加载失败");

        let domains: Vec<String> = cfg
            .rule_group(DEFAULT_GROUP)
            .address_rules
            .iter()
            .map(|r| r.domain.to_string())
            .collect();

        assert!(
            domains.iter().any(|d| d.contains("main.test")),
            "主配置要照常"
        );
        assert!(
            domains.iter().any(|d| d.contains("ok.test")),
            "同目录的正常文件要照常"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 `force-no-CNAME` 的端到端连通性（问题 12）。
    ///
    /// 解析器认得这个关键字、展平函数本身正确 —— 这两件事分别有测试覆盖，
    /// 但**两者是否接通**（配置真的能影响运行时开关）没有被验证过。
    /// 这条测试就是补上这一环：写真实配置文件 → 加载 → 读开关。
    #[test]
    fn force_no_cname_is_wired_end_to_end() {
        let dir = std::env::temp_dir().join(format!("force-no-cname-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let conf = dir.join("smartdns.conf");

        // 1) 不写这一项：必须默认关闭，不能悄悄改变既有行为
        std::fs::write(&conf, "# 什么都不配\n").unwrap();
        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&conf)
            .build()
            .unwrap();
        assert!(!cfg.force_no_cname(), "默认必须关闭");

        // 2) 显式开启
        std::fs::write(&conf, "force-no-CNAME yes\n").unwrap();
        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&conf)
            .build()
            .unwrap();
        assert!(cfg.force_no_cname(), "写了 yes 就必须生效");

        // 3) 显式关闭
        std::fs::write(&conf, "force-no-CNAME no\n").unwrap();
        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&conf)
            .build()
            .unwrap();
        assert!(!cfg.force_no_cname(), "显式写 no 应当关闭");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 组级参数机制：写在 `group-begin` 里的开关**不能**污染全局。
    ///
    /// 这是整套机制最容易错的地方 —— `config_unchecked` 里规则组栈在顶层也会有一个
    /// 懒加载的 `default` 项，如果判据写成"栈非空"，顶层配置就会被误判成"在组里"，
    /// 于是 `force-no-CNAME yes` 会被写进 default 组、全局反而读不到。
    #[test]
    fn group_level_switch_does_not_leak_into_global() {
        let dir = std::env::temp_dir().join(format!("group-switch-global-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("smartdns.conf");

        // 顶层写 → 进全局；组里写 → 只进那个组
        //
        // ⚠️ 顶层这一行必须用 `yes`，而且**前面要先有一行别的配置**。两个理由：
        //   1. 顶层写 `no` 时，"全局=Some(false)" 与 "全局=None（默认也是 false）"
        //      结果一样，测试无法区分正确与错误实现 —— 必须用 `yes` 才能分辨；
        //   2. 若顶层这行是文件第一行，组规则栈此刻还空着，即便判据写成"栈非空"
        //      也会得到 false 而侥幸通过。前面先放一行，栈里就会有懒加载的 default 组，
        //      错误的判据才会暴露出来。
        std::fs::write(
            &conf,
            "server 8.8.8.8\n\
             force-no-CNAME yes\n\
             group-begin office\n\
             force-no-CNAME no\n\
             group-end\n",
        )
        .unwrap();

        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&conf)
            .build()
            .unwrap();

        assert!(
            cfg.force_no_cname(),
            "顶层写的是 yes，全局必须是 yes（组里的 no 不能漏上来）"
        );
        assert!(
            !cfg.force_no_cname_in_group("office"),
            "office 组里写了 no，该组必须是 no"
        );
        assert!(
            cfg.force_no_cname_in_group("default"),
            "没写过这个参数的组应当回退全局值"
        );
        assert!(
            cfg.force_no_cname_in_group("nosuchgroup"),
            "组不存在也必须安全回退全局值，不能 panic"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 组级参数：组级**压过全局**，且缺失时回退全局。
    #[test]
    fn group_level_switch_overrides_global() {
        let dir = std::env::temp_dir().join(format!("group-switch-prio-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("smartdns.conf");

        // 全局开、office 组显式关 → office 组应当是"关"
        // （同样先放一行别的配置，避免顶层那行撞上"栈还是空的"这个偶然情况）
        std::fs::write(
            &conf,
            "server 8.8.8.8\n\
             force-no-CNAME yes\n\
             group-begin office\n\
             force-no-CNAME no\n\
             group-end\n\
             group-begin guest\n\
             address /guest.test/1.2.3.4\n\
             group-end\n",
        )
        .unwrap();

        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&conf)
            .build()
            .unwrap();

        assert!(cfg.force_no_cname(), "全局写 yes");
        assert!(
            !cfg.force_no_cname_in_group("office"),
            "office 组显式写 no，必须压过全局的 yes"
        );
        assert!(
            cfg.force_no_cname_in_group("guest"),
            "guest 组没写这一项，应当回退全局的 yes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 `force-AAAA-SOA` 同样支持组级。
    #[test]
    fn group_level_force_aaaa_soa_is_supported() {
        let dir = std::env::temp_dir().join(format!("group-aaaa-soa-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("smartdns.conf");

        std::fs::write(
            &conf,
            "group-begin ipv6-shy\n\
             force-AAAA-SOA yes\n\
             group-end\n",
        )
        .unwrap();

        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&conf)
            .build()
            .unwrap();

        assert!(!cfg.force_aaaa_soa(), "没写全局，全局必须是关");
        assert!(
            cfg.force_aaaa_soa_in_group("ipv6-shy"),
            "组里写了 yes，该组必须生效"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 嵌套组的标量继承：本组没写的格子由外层填，本组写了的不被覆盖。
    ///
    /// 标量继承与规则继承是**两套语义**（规则是累加、标量是填空），
    /// 这条测试专门守住"标量不累加、只填空"这一点。
    #[test]
    fn nested_group_inherits_scalar_only_when_unset() {
        let dir = std::env::temp_dir().join(format!("group-nested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("smartdns.conf");

        std::fs::write(
            &conf,
            "group-begin outer\n\
             force-no-CNAME yes\n\
             force-AAAA-SOA yes\n\
             group-begin inner\n\
             force-no-CNAME no\n\
             group-end\n\
             group-end\n",
        )
        .unwrap();

        let cfg = RuntimeConfig::builder()
            .with_conf_dir(&dir)
            .with_conf_file(&conf)
            .build()
            .unwrap();

        assert!(cfg.force_no_cname_in_group("outer"), "outer 自己写了 yes");
        // inner 自己写了 no → 保留 no，不被 outer 的 yes 覆盖
        assert!(
            !cfg.force_no_cname_in_group("inner"),
            "inner 显式写了 no，不能被外层的 yes 覆盖"
        );
        // inner 没写 force-AAAA-SOA → 从 outer 继承 yes
        assert!(
            cfg.force_aaaa_soa_in_group("inner"),
            "inner 没写 force-AAAA-SOA，应当继承外层的 yes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 `GroupParams::inherit_from` 的纯逻辑：只填 `None`，不覆盖 `Some`。
    #[test]
    fn group_params_inherit_fills_only_empty_slots() {
        use crate::config::GroupParams;

        // ⚠️ 用 `..Default::default()` 而不是逐字段列出：这个结构会随组级参数铺开不断加字段，
        // 逐字段写会让**每加一个参数就编译失败一次**（而且失败信息在测试里，不在产品代码里）。
        let mut child = GroupParams {
            force_no_cname: Some(false),
            ..Default::default()
        };
        let parent = GroupParams {
            force_no_cname: Some(true),
            force_aaaa_soa: Some(true),
            ..Default::default()
        };
        child.inherit_from(&parent);

        assert_eq!(
            child.force_no_cname,
            Some(false),
            "本组写了 false，不能被父组 true 覆盖（标量是填空不是累加）"
        );
        assert_eq!(
            child.force_aaaa_soa,
            Some(true),
            "本组没写，应当接受父组的值"
        );
    }
}

/// 📌 组级作用域的两条铁律（本次修复新增）。
///
/// 这两组测试守的都是**作用域**问题 —— 不是"值算错了"，而是"值作用到了哪里"。
/// 它们与 §22 那批"配了不生效"是**反向的同一类病**：不是漏生效，是生效在错的地方。
#[cfg(test)]
mod rule_group_scope_tests {
    use super::*;

    /// 🔒 **在组里写"不支持写进组"的参数，必须被拒绝且不影响全局。**
    ///
    /// 修复前的实际行为（真机探针实测）：那些行**静默写进全局**，而组里一个都没进 ——
    /// 也就是"用户以为只对 office 组生效，实际改了所有人"。对从上游迁移过来的用户
    /// 尤其危险：上游里这些参数本来就都能写进组，按老习惯写是必然的。
    ///
    /// 判据必须**成对**：既要"组里没进去"，也要"全局没被改"。
    /// 只看一半会漏掉"两条路径都写"或"写到别处"这类错误实现。
    ///
    /// 📌 到 丙-2c 为止，原先那 20 个"尚未支持"的参数已**全部补齐**，
    /// 现在能触发这条拒绝的只剩**按设计不支持**的进程级策略
    /// （`serve-expired-ttl` / `serve-expired-prefetch-time`）。
    /// 这个**判据本身仍然有效、也必须继续守着** —— 它的理由是"绝不静默改写作用域"，
    /// 与"支持清单有几个"无关。
    #[test]
    fn writing_supported_list_rejects_do_not_leak_to_global() {
        let cfg = RuntimeConfig::builder()
            .with("group-begin office")
            .with("serve-expired-ttl 3600")
            .with("group-end")
            .build()
            .unwrap();

        // ① 全局**必须保持默认**（没被改写）
        assert_eq!(
            cfg.serve_expired_ttl(),
            86400,
            "写在组里被拒绝的行，绝不能改到全局（全局默认 86400）"
        );

        // ② 组里也**没有**悄悄存下来（是"明确拒绝"，不是"先收下"）
        let params = cfg.group_params("office");
        assert!(
            params.is_empty(),
            "被拒绝的行不应留下任何痕迹，实际: {params:?}"
        );
    }

    /// 🔒 丙-2c 补齐组级后的保证：`dualstack-ip-selection` 写在组里必须**真的进组**，
    /// 且**不得**污染全局。
    #[test]
    fn bing2c_dualstack_selection_is_accepted_inside_a_group() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("dualstack-ip-selection yes")
            .with("group-begin office")
            .with("dualstack-ip-selection no")
            .with("group-end")
            .build()
            .unwrap();

        // ① 组级真的存下来
        assert_eq!(
            cfg.group_params("office").dualstack_ip_selection,
            Some(false),
            "dualstack-ip-selection 要进组"
        );
        // ② 全局不能被改写
        assert!(
            cfg.dualstack_ip_selection(),
            "全局 dualstack-ip-selection 必须仍是顶层写的 yes"
        );
        // ③ 组级取值入口 + 未写组回落全局
        assert!(
            !cfg.dualstack_ip_selection_in_group("office"),
            "office 组写了 no"
        );
        assert!(
            cfg.dualstack_ip_selection_in_group("guest"),
            "没写过的组回落全局的 yes"
        );
    }

    /// 🔐 丙-2c 的**核心不变量**：**bind 级总闸压过一切，包括组级**。
    ///
    /// `bind ... -no-dualstack-selection` 不是取值链上的一层，而是**单向总闸**
    /// （只能关、不能开）。所以"这个监听不许做双栈优选"必须能压住
    /// "某个组写了 `dualstack-ip-selection yes`"。
    ///
    /// 这条测试直接按调用点（`dns_mw_dualstack.rs`）的算法复算一遍，
    /// 钉住"总闸在外、链在内"这个形状 —— 若有人把 bind 级塞进取值链里当成一档，
    /// 就会变成"能被强制打开"，与它的语义不符。
    #[test]
    fn bind_level_master_switch_overrides_group_level() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("dualstack-ip-selection no")
            .with("group-begin office")
            .with("dualstack-ip-selection yes") // 组里想开
            .with("group-end")
            .build()
            .unwrap();

        // 组里确实写了 yes
        assert!(
            cfg.dualstack_ip_selection_in_group("office"),
            "office 组写了 yes，链上应当为开"
        );

        // 调用点的算法：总闸 && 链
        let no_dualstack_on_listener = true; // 模拟 `bind ... -no-dualstack-selection`
        let enabled = !no_dualstack_on_listener
            && crate::config::resolve_dualstack_selection(None, Some(true), Some(false));

        assert!(
            !enabled,
            "监听写了 `-no-dualstack-selection` 时必须压过组级的 yes（总闸优先）"
        );

        // 对照：总闸没写时，组级的 yes 才生效
        let enabled_no_master =
            false || crate::config::resolve_dualstack_selection(None, Some(true), Some(false));
        let enabled = !false && enabled_no_master;
        assert!(enabled, "总闸没写时，组级的 yes 应当生效");
    }

    /// 🔐 丙-2d：`serve-expired-ttl` / `serve-expired-prefetch-time` 的拒绝是
    /// **设计取舍**，不是"尚未支持"。
    ///
    /// 这条测试钉住两点：
    ///   ① 它们仍然被拒绝（不写进组、也不改全局）；
    ///   ② 判定函数**只认这两个**，不会误伤已经支持组级的参数。
    ///
    /// 📌 到 丙-2c 为止，原先那一类"**尚未支持**"已全部补齐、判定函数已删除，
    /// 因此这里不再做"两类互斥"的断言（那种断言已无对象）。
    #[test]
    fn process_wide_cache_policy_is_rejected_by_design() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("group-begin office")
            .with("serve-expired-ttl 3600")
            .with("serve-expired-prefetch-time 60")
            .with("group-end")
            .build()
            .unwrap();

        // ① 全局保持默认
        assert_eq!(
            cfg.serve_expired_ttl(),
            86400,
            "全局 serve-expired-ttl 不能被改写"
        );
        assert_eq!(
            cfg.serve_expired_prefetch_time(),
            21600,
            "全局 serve-expired-prefetch-time 不能被改写"
        );
        // ② 组里没有存下来
        assert!(
            cfg.group_params("office").is_empty(),
            "被拒绝的行不应留下痕迹"
        );

        // ③ 判定函数只认这两个进程级策略，不误伤已支持的参数
        use crate::config::parser::ConfigItem;
        assert_eq!(
            not_supported_in_rule_group_by_design(&ConfigItem::ServeExpiredTtl(3600)),
            Some("serve-expired-ttl")
        );
        assert_eq!(
            not_supported_in_rule_group_by_design(&ConfigItem::ServeExpiredPrefetchTime(60)),
            Some("serve-expired-prefetch-time")
        );
        assert!(
            not_supported_in_rule_group_by_design(&ConfigItem::Dns64(
                "64:ff9b::/96".parse().unwrap()
            ))
            .is_none(),
            "已支持组级的参数不该走『按设计不支持』"
        );
        assert!(
            not_supported_in_rule_group_by_design(&ConfigItem::ServeExpired(false)).is_none(),
            "`serve-expired` 本身已支持组级（丙-1），不能被误伤"
        );
    }

    // ───────────── 🔐 2026-09-26：规则组写入的**白名单** ─────────────

    /// 🔒 **没有组级写法的参数写进 `group-begin`，必须被拒绝且不污染全局。**
    ///
    /// ## 这条测试守的是什么（修复前的真实行为）
    ///
    /// 规则组机制是**逐项铺开**的。那 20 个参数补齐后，人们容易以为"这类问题已经清零"，
    /// 但**按设计就没有组级概念**的项（进程级资源上限、全局名单、监听配置……）
    /// 写进组里照样一路写进**全局**：
    ///
    /// ```ini
    /// group-begin office
    /// cache-size 1024      # 用户以为只影响 office
    /// group-end
    /// ```
    ///
    /// 修复前实测：`全局 cache_size = 1024`，而 office 组**什么都没进** ——
    /// 正是本项目反复强调的"**生效在了错的地方且无人告知**"。
    ///
    /// ## 判据必须成对
    ///
    /// ① 全局**保持默认**（没被组里那行改掉）；
    /// ② 组里**也没存下**（是"拒绝"，不是"收下不用"）；
    /// ③ 对照组：白名单内的项（`rr-ttl`）**必须照旧进组** ——
    ///    否则一个"把所有项都拒掉"的错误实现也能让前两条通过。
    #[test]
    fn params_without_a_group_form_are_rejected_and_do_not_leak_to_global() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("cache-size 512")
            .with("group-begin office")
            .with("cache-size 1024") // ❌ 无组级写法
            .with("max-connections 12345") // ❌ 同上
            .with("rr-ttl 111") // ✅ 有组级写法（对照组）
            .with("group-end")
            .build()
            .unwrap();

        // ① 全局**没有被改写**（这正是修复前会失败的地方）
        assert_eq!(
            cfg.cache_size(),
            512,
            "`cache-size` 写在组里，绝不能改到全局（修复前会变成 1024）"
        );
        assert_ne!(
            cfg.max_connections(),
            Some(12345),
            "`max-connections` 写在组里，绝不能改到全局"
        );

        // ② 被拒的行**不留痕迹**
        let p = cfg.group_params("office");
        assert!(
            p.rr_ttl.is_some(),
            "对照组：白名单内的 `rr-ttl` 必须照旧进组"
        );

        // ③ 对照组确认：白名单确实"放行合法的"，不是一刀切全拒
        assert_eq!(
            p.rr_ttl,
            Some(111),
            "白名单内的项必须真进组（否则一个'全拒'的实现也能骗过上面两条）"
        );
    }

    /// 🔒 顶层写法**不受任何影响**（白名单只作用于"组内"）。
    ///
    /// 这条与上一条成对：上一条证明"组内被拒"，这一条证明"顶层照旧"。
    /// 缺了它，一个"把 `cache-size` 整个禁掉"的错误实现也能让上一条通过。
    #[test]
    fn top_level_writes_are_unaffected_by_the_group_whitelist() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("cache-size 2048")
            .with("max-connections 999")
            .build()
            .unwrap();

        assert_eq!(cfg.cache_size(), 2048, "顶层写 cache-size 必须照旧生效");
        assert_eq!(
            cfg.max_connections(),
            Some(999),
            "顶层写 max-connections 必须照旧生效"
        );
    }

    /// 🔒 白名单必须**覆盖全部 20 个组级参数**，一个都不能漏。
    ///
    /// 为什么单独钉这条：白名单是手写的 `matches!` 列表，与
    /// [`crate::config::GroupParams`] 的字段是**两处维护**。将来给 `GroupParams`
    /// 加字段却忘了同步白名单，表现就是"该参数写进组里**被误拒**"——
    /// 用户看到的是"这个参数明明文档说支持，配了却被忽略"。
    ///
    /// ⚠️ 用**真实配置行**逐个喂进去（而不是直接构造 `ConfigItem`）：这样测的是
    /// "解析 + 判定"整条链路，而且不依赖 `ConfigItem` 那些私有字段类型。
    #[test]
    fn the_whitelist_covers_every_group_level_parameter() {
        // (配置行, 读回来的校验——确认它**真的进了组**)
        let cases: Vec<&str> = vec![
            "force-no-CNAME yes",
            "force-AAAA-SOA yes",
            "ipset-timeout yes",
            "nftset-timeout yes",
            "rr-ttl 600",
            "rr-ttl-min 60",
            "rr-ttl-max 600",
            "rr-ttl-reply-max 60",
            "local-ttl 60",
            "max-reply-ip-num 3",
            "speed-check-mode none",
            "response-mode first-ping",
            "dualstack-ip-selection yes",
            "dualstack-ip-allow-force-AAAA yes",
            "dualstack-ip-selection-threshold 10",
            "dns64 64:ff9b::/96",
            "serve-expired yes",
            "serve-expired-reply-ttl 5",
            "prefetch-domain yes",
            "edns-client-subnet 1.1.1.0/24",
        ];

        assert_eq!(cases.len(), 20, "组级参数就是 20 个，别漏数");

        for line in &cases {
            let cfg = RuntimeConfig::builder()
                .with("server 8.8.8.8")
                .with("group-begin office")
                .with(line)
                .with("group-end")
                .build()
                .unwrap();

            assert!(
                !cfg.group_params("office").is_empty(),
                "`{line}` 是组级参数，写进规则组必须**真的进组**（被误拒了）"
            );
        }
    }

    /// 🔒 没有组级写法的项**必须不在**白名单内（否则会静默写进全局）。
    ///
    /// 逐条用真实配置行验证：写进组里后，**全局不能被改动**。
    #[test]
    fn items_without_a_group_form_never_reach_global() {
        // (组里写的行, 该行若被误接受会改到的全局值——用断言函数检查)
        struct Case {
            line: &'static str,
            check: fn(&RuntimeConfig) -> bool,
            what: &'static str,
        }

        let cases = vec![
            Case {
                line: "cache-size 1024",
                check: |c| c.cache_size() == 512,
                what: "cache-size 未被改写",
            },
            Case {
                line: "max-connections 12345",
                check: |c| c.max_connections() != Some(12345),
                what: "max-connections 未被改写",
            },
            Case {
                line: "num-workers 7",
                check: |c| c.num_workers() != 7,
                what: "num-workers 未被改写",
            },
            Case {
                line: "tcp-idle-time 999",
                check: |c| c.tcp_idle_time() != 999,
                what: "tcp-idle-time 未被改写",
            },
            Case {
                line: "max-query-limit 111",
                check: |c| c.max_query_limit() != 111,
                what: "max-query-limit 未被改写",
            },
            Case {
                line: "bogus-nxdomain 1.2.3.4",
                check: |c| c.bogus_nxdomain().is_empty(),
                what: "bogus-nxdomain 未被写进全局名单",
            },
            Case {
                line: "blacklist-ip 1.2.3.4",
                check: |c| c.blacklist_ip().is_empty(),
                what: "blacklist-ip 未被写进全局名单",
            },
        ];

        for case in &cases {
            let cfg = RuntimeConfig::builder()
                .with("server 8.8.8.8")
                .with("cache-size 512") // 顶层基线，供 cache-size 那条比对
                .with("group-begin office")
                .with(case.line)
                .with("group-end")
                .build()
                .unwrap();

            assert!(
                (case.check)(&cfg),
                "`{}` 写在组里被接受了，导致{} —— 说明它没被白名单拦住",
                case.line,
                case.what
            );
        }
    }

    /// 🔒 白名单放行**规则类**与**组结构类**指令（不能一刀切全拒）。
    ///
    /// 规则组的第一用途就是装规则 —— 若白名单漏了 `address` / `cname` / `nameserver`，
    /// 用户写在组里的规则会被整批拒掉，那比原来的静默污染更糟糕。
    #[test]
    fn the_whitelist_allows_rules_and_group_structure_items() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("group-begin office")
            .with("address /a.test/1.2.3.4")
            .with("cname /b.test/c.test")
            .with("nameserver /d.test/office")
            .with("domain-rules /e.test/ -c none")
            .with("group-end")
            .build()
            .unwrap();

        // 规则必须真的进了 office 组（被放行，不是被拒）
        let g = cfg.rule_group("office");
        assert!(
            !g.address_rules.is_empty(),
            "`address` 本就写在规则组里，不能被白名单拒掉"
        );
        assert!(!g.cnames.is_empty(), "`cname` 同理");
        assert!(!g.forward_rules.is_empty(), "`nameserver` 同理");
        assert!(!g.domain_rules.is_empty(), "`domain-rules` 同理");
    }

    /// 🔒 丙-2a / 丙-2b 补齐组级后的保证：`dns64` / `edns-client-subnet`
    /// 写在组里必须**真的进组**，且**不得**污染全局。
    #[test]
    fn bing2_params_are_accepted_inside_a_group_without_touching_global() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("dns64 64:ff9b::/96")
            .with("edns-client-subnet 1.1.1.0/24")
            .with("group-begin office")
            .with("dns64 2001:db8::/96")
            .with("edns-client-subnet 2.2.2.0/24")
            .with("group-end")
            .build()
            .unwrap();

        // ① 组级必须真的存下来
        let p = cfg.group_params("office");
        assert_eq!(
            p.dns64_prefix,
            Some("2001:db8::/96".parse().unwrap()),
            "dns64 要进组"
        );
        assert_eq!(
            p.edns_client_subnet,
            Some("2.2.2.0/24".parse().unwrap()),
            "edns-client-subnet 要进组"
        );

        // ② 全局不能被改写
        assert_eq!(
            cfg.dns64_prefix,
            Some("64:ff9b::/96".parse().unwrap()),
            "全局 dns64 必须仍是顶层写的那个"
        );
        assert_eq!(
            cfg.edns_client_subnet(),
            Some("1.1.1.0/24".parse().unwrap()),
            "全局 edns-client-subnet 必须仍是顶层写的那个"
        );

        // ③ 组级取值入口；未写过的组回落全局
        assert_eq!(
            cfg.dns64_prefix_in_group("office"),
            Some("2001:db8::/96".parse().unwrap())
        );
        assert_eq!(
            cfg.dns64_prefix_in_group("guest"),
            Some("64:ff9b::/96".parse().unwrap()),
            "没写过 dns64 的组回落全局"
        );
        assert_eq!(
            cfg.edns_client_subnet_in_group("office"),
            Some("2.2.2.0/24".parse().unwrap())
        );
    }

    /// 🔐 丙-2a 的**关键边界**：只有**某个组**配了 `dns64` 时，该组必须能生效、
    /// 而其它组必须**不做** DNS64。
    ///
    /// 这条守的是 web 修改最核心的那一点：旧实现是"全局没配就整个中间件不挂"，
    /// 于是"只有某组配了"会彻底失效。现在中间件无条件挂，取值按组。
    #[test]
    fn only_one_group_configured_still_works_for_that_group() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            // 全局**故意不配** dns64
            .with("group-begin v6only")
            .with("dns64 64:ff9b::/96")
            .with("group-end")
            .build()
            .unwrap();

        assert_eq!(
            cfg.dns64_prefix_in_group("v6only"),
            Some("64:ff9b::/96".parse().unwrap()),
            "只有该组配了，该组必须能取到（这正是旧实现失效的场景）"
        );
        assert_eq!(
            cfg.dns64_prefix_in_group("other"),
            None,
            "其它组没配，必须**不做** DNS64"
        );
        assert_eq!(cfg.dns64_prefix, None, "全局仍应保持未配置");
    }

    /// 🔒 丙-1 补齐组级后的保证：`serve-expired` / `serve-expired-reply-ttl` /
    /// `prefetch-domain` 写在组里必须**真的进组**，且**不得**污染全局。
    #[test]
    fn bing1_class_params_are_accepted_inside_a_group_without_touching_global() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("serve-expired yes")
            .with("serve-expired-reply-ttl 5")
            .with("prefetch-domain yes")
            .with("group-begin office")
            .with("serve-expired no")
            .with("serve-expired-reply-ttl 42")
            .with("prefetch-domain no")
            .with("group-end")
            .build()
            .unwrap();

        // ① 组级必须真的存下来
        let p = cfg.group_params("office");
        assert_eq!(p.serve_expired, Some(false), "serve-expired 要进组");
        assert_eq!(
            p.serve_expired_reply_ttl,
            Some(42),
            "serve-expired-reply-ttl 要进组"
        );
        assert_eq!(p.prefetch_domain, Some(false), "prefetch-domain 要进组");

        // ② 全局不能被改写
        assert!(cfg.serve_expired(), "全局 serve-expired 必须仍是 yes");
        assert_eq!(
            cfg.serve_expired_reply_ttl(),
            5,
            "全局 serve-expired-reply-ttl 必须仍是 5"
        );
        assert!(cfg.prefetch_domain(), "全局 prefetch-domain 必须仍是 yes");

        // ③ 组级取值入口
        assert!(!cfg.serve_expired_in_group("office"));
        assert_eq!(cfg.serve_expired_reply_ttl_in_group("office"), 42);
        assert!(!cfg.prefetch_domain_in_group("office"));
        // 未写过的组回落全局
        assert!(cfg.serve_expired_in_group("guest"));
        assert_eq!(cfg.serve_expired_reply_ttl_in_group("guest"), 5);
        assert!(cfg.prefetch_domain_in_group("guest"));
    }

    /// 🔐 丙-1 最要紧的**边界**：组级 `prefetch-domain` **不得**影响后台任务开关。
    ///
    /// ## 为什么单独钉这一条
    ///
    /// `prefetch-domain` 有两份用途，性质完全不同：
    ///   · **逐查询**："这条应答要不要安排后台预取" → 按组；
    ///   · **进程级**："要不要启动后台预取任务"     → 只认全局。
    ///
    /// 后台任务是一个进程一份、遍历所有缓存条目，不是"某个组在预取"。
    /// 若实现时图省事让任务开关也读组级值，就会出现
    /// **"某个组写了 `prefetch-domain no`、把整个进程的后台预取停掉"** ——
    /// 其它组明明没写这个参数，预取却一起没了（跨组误伤）。
    ///
    /// 判据成对：组级入口随组变，**全局访问器不随任何组变**。
    #[test]
    fn group_level_prefetch_never_disables_the_process_wide_task() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("prefetch-domain yes") // 全局：进程级任务要开
            .with("group-begin quiet")
            .with("prefetch-domain no") // 某个组自己不想预取
            .with("group-end")
            .build()
            .unwrap();

        // ① 逐查询那一侧：该组确实是"不预取"
        assert!(
            !cfg.prefetch_domain_in_group("quiet"),
            "quiet 组自己写了 no，它这条路径上的预取通知应当不发"
        );
        // ② 进程级那一侧：**仍然是开**，不能被那个组带偏
        assert!(
            cfg.prefetch_domain(),
            "某个组写了 no 绝不能关掉进程级后台预取任务（跨组误伤）"
        );

        // ③ 没写过这个参数的组照旧继承全局
        assert!(
            cfg.prefetch_domain_in_group("other"),
            "other 组没写，应当继承全局的 yes"
        );
    }

    /// 🔐 丙-1 第二要紧的边界：组级 `serve-expired` **不得**影响后台清理策略。
    ///
    /// `serve-expired-ttl`（过期数据保留多久才清理）与 `serve-expired-prefetch-time`
    /// 是**进程级后台策略**，本次**没有**给它们加组级支持（仍在拒绝名单里）。
    /// 这条测试钉住的是：即使某个组写了 `serve-expired no`，
    /// 后台清理用到的全局值也不能被改动。
    #[test]
    fn group_level_serve_expired_never_changes_background_policy() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("serve-expired yes")
            .with("serve-expired-ttl 7200")
            .with("group-begin office")
            .with("serve-expired no")
            .with("group-end")
            .build()
            .unwrap();

        // 组内不喂过期数据
        assert!(!cfg.serve_expired_in_group("office"));
        // 但进程级策略值原样不动（它们只认全局）
        assert_eq!(
            cfg.serve_expired_ttl(),
            7200,
            "后台清理策略只认全局，不能被组级 serve-expired 带偏"
        );
        assert!(cfg.serve_expired(), "全局 serve-expired 仍应为 yes");
    }

    /// 🔒 乙类补齐组级后的保证：`rr-ttl` / `response-mode` / `speed-check-mode`
    /// 写在组里必须**真的进组**，且**不得**污染全局。
    #[test]
    fn yi_class_params_are_accepted_inside_a_group_without_touching_global() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("rr-ttl 60")
            .with("response-mode fastest-response")
            .with("speed-check-mode ping")
            .with("group-begin office")
            .with("rr-ttl 777")
            .with("response-mode first-ping")
            .with("speed-check-mode none")
            .with("group-end")
            .build()
            .unwrap();

        // ① 组级必须真的存下来
        let p = cfg.group_params("office");
        assert_eq!(p.rr_ttl, Some(777), "rr-ttl 要进组");
        assert_eq!(
            p.response_mode,
            Some(crate::config::ResponseMode::FirstPing),
            "response-mode 要进组"
        );
        assert_eq!(
            p.speed_check_mode
                .as_ref()
                .map(|m| m.iter().any(|x| x.is_none())),
            Some(true),
            "speed-check-mode none 要进组（且是 Some([None]) 形状）"
        );

        // ② 全局不能被改写
        assert_eq!(cfg.rr_ttl(), Some(60), "全局 rr-ttl 必须仍是 60");
        assert_eq!(
            cfg.response_mode(),
            crate::config::ResponseMode::FastestResponse,
            "全局 response-mode 必须还是顶层写的那个"
        );
        assert_eq!(
            cfg.speed_check_mode().map(|m| format!("{m:?}")),
            Some("ICMP".to_string()),
            "全局 speed-check-mode 必须还是顶层写的 ping"
        );

        // ③ 组级取值入口
        assert_eq!(cfg.rr_ttl_in_group("office"), Some(777));
        assert_eq!(
            cfg.response_mode_in_group("office"),
            crate::config::ResponseMode::FirstPing
        );
        // 未写过的组回落全局
        assert_eq!(cfg.rr_ttl_in_group("guest"), Some(60));
        assert_eq!(
            cfg.response_mode_in_group("guest"),
            crate::config::ResponseMode::FastestResponse
        );
    }

    /// 🔐 **`rr-ttl` 家族必须"组内自洽"**（用户 2026-09-26 定调）。
    ///
    /// 场景：组里只写了 `rr-ttl 111`（没写 min/max），全局的 min/max 是别的值。
    /// 本组的 min/max 应当取**本组的 111**，而不是跨层去拿全局值 ——
    /// 否则在"min 被无条件使用"的地方（双栈 TTL 对齐），111 会被抬回全局的值，
    /// 表现为**用户写了 111、行为却是别的数**。
    ///
    /// 判据成对：组内自洽（得 111） **且** 未写 rr-ttl 的组仍走全局链。
    #[test]
    fn rr_ttl_family_is_self_consistent_within_a_group() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8")
            .with("rr-ttl-min 500")
            .with("rr-ttl-max 900")
            .with("group-begin office")
            .with("rr-ttl 111")
            .with("group-end")
            .build()
            .unwrap();

        // ① 组里写了 rr-ttl ⇒ 本组 min/max 都跟它走（组内自洽）
        assert_eq!(
            cfg.rr_ttl_min_in_group("office"),
            Some(111),
            "office 组写了 rr-ttl 111，本组 min 必须自洽取 111，不能跨层拿全局的 500"
        );
        assert_eq!(
            cfg.rr_ttl_max_in_group("office"),
            Some(111),
            "office 组写了 rr-ttl 111，本组 max 必须自洽取 111，不能跨层拿全局的 900"
        );

        // ② 对照：没写过 rr-ttl 的组必须照旧走全局链
        assert_eq!(
            cfg.rr_ttl_min_in_group("guest"),
            Some(500),
            "guest 组没写 rr-ttl，min 应当是全局的 500"
        );
        assert_eq!(
            cfg.rr_ttl_max_in_group("guest"),
            Some(900),
            "guest 组没写 rr-ttl，max 应当是全局的 900"
        );
    }

    /// 🔐 乙类最要紧的**不变量**：`speed-check-mode` 的
    /// **"没写"与"写了 `none`"必须仍然可区分**（问题 24 的核心成果）。
    ///
    /// 铺开组级时极易把它折掉 —— 一旦折掉，用户写 `none` 会被下游当成"没配置"，
    /// 转而**拿默认模式去测速**，与意图正好相反。
    #[test]
    fn speed_check_none_stays_distinguishable_at_group_level() {
        let cfg = RuntimeConfig::builder()
            .with("group-begin explicit-none")
            .with("speed-check-mode none")
            .with("group-end")
            .with("group-begin empty")
            .with("group-end")
            .build()
            .unwrap();

        // 写了 none ⇒ 组内的值是 Some([None]) 形状
        let explicit = cfg.group_params("explicit-none").speed_check_mode.clone();
        assert!(
            explicit
                .as_ref()
                .is_some_and(|m| m.iter().any(|x| x.is_none())),
            "写在组里的 `none` 必须是 Some([None])，不能折叠成 None"
        );

        // 没写 ⇒ 组内格子里是 None（外层），与"写了 none"可区分
        assert!(
            cfg.group_params("empty").speed_check_mode.is_none(),
            "没写过 speed-check-mode 的组，格子里必须是 None"
        );
        assert_ne!(
            explicit,
            cfg.group_params("empty").speed_check_mode,
            "『写了 none』与『没写』必须不同 —— 相同则下游无法区分二者（问题 24 的病根）"
        );
    }

    /// 🔒 甲类铺开后的**反向**保证：这 9 个写在组里必须**真的进组**（不再被拒绝），
    /// 而且**不得**污染全局。
    ///
    /// 与上一条恰好相反 —— 上一条守"未支持的别乱来"，这一条守"已支持的别漏进组、
    /// 也别漏到全局"。两者合起来才说明"支持名单"是准确的。
    #[test]
    fn jia_class_params_are_accepted_inside_a_group_without_touching_global() {
        let cfg = RuntimeConfig::builder()
            .with("server 8.8.8.8") // 先放一行别的配置（见 §9.4 的教训）
            .with("group-begin office")
            .with("ipset-timeout yes")
            .with("nftset-timeout yes")
            .with("rr-ttl-min 111")
            .with("rr-ttl-max 222")
            .with("rr-ttl-reply-max 333")
            .with("local-ttl 444")
            .with("dualstack-ip-allow-force-AAAA yes")
            .with("dualstack-ip-selection-threshold 55")
            .with("max-reply-ip-num 7")
            .with("group-end")
            .build()
            .unwrap();

        // ① 组级必须真的存下来了
        let p = cfg.group_params("office");
        assert_eq!(p.ipset_timeout, Some(true), "ipset-timeout 要进组");
        assert_eq!(p.nftset_timeout, Some(true), "nftset-timeout 要进组");
        assert_eq!(p.rr_ttl_min, Some(111), "rr-ttl-min 要进组");
        assert_eq!(p.rr_ttl_max, Some(222), "rr-ttl-max 要进组");
        assert_eq!(p.rr_ttl_reply_max, Some(333), "rr-ttl-reply-max 要进组");
        assert_eq!(p.local_ttl, Some(444), "local-ttl 要进组");
        assert_eq!(
            p.dualstack_ip_allow_force_aaaa,
            Some(true),
            "dualstack-ip-allow-force-AAAA 要进组"
        );
        assert_eq!(
            p.dualstack_ip_selection_threshold,
            Some(55),
            "dualstack-ip-selection-threshold 要进组"
        );
        assert_eq!(p.max_reply_ip_num, Some(7), "max-reply-ip-num 要进组");

        // ② 全局**一个都不能被改写**（这是"分流"是否正确的关键半边）
        assert!(!cfg.ipset_timeout(), "全局 ipset-timeout 必须保持默认关");
        assert!(!cfg.nftset_timeout(), "全局 nftset-timeout 必须保持默认关");
        assert_eq!(cfg.rr_ttl_min(), None, "全局 rr-ttl-min 必须仍为空");
        assert_eq!(cfg.rr_ttl_max(), None, "全局 rr-ttl-max 必须仍为空");
        assert_eq!(
            cfg.rr_ttl_reply_max(),
            None,
            "全局 rr-ttl-reply-max 必须仍为空"
        );
        assert_eq!(cfg.local_ttl(), 60, "全局 local-ttl 必须保持默认 60");
        assert!(
            !cfg.dualstack_ip_allow_force_aaaa(),
            "全局 dualstack-ip-allow-force-AAAA 必须保持默认关"
        );
        assert_eq!(
            cfg.dualstack_ip_selection_threshold(),
            10,
            "全局阈值必须保持默认 10"
        );
        assert_eq!(
            cfg.max_reply_ip_num(),
            None,
            "全局 max-reply-ip-num 必须仍为空"
        );

        // ③ 组级取值入口要取到组里的值；其它组要回落全局
        assert!(cfg.ipset_timeout_in_group("office"));
        assert_eq!(cfg.rr_ttl_min_in_group("office"), Some(111));
        assert_eq!(cfg.local_ttl_in_group("office"), 444);
        assert!(
            !cfg.ipset_timeout_in_group("guest"),
            "没写过这个参数的组必须回落全局（默认关）"
        );
        assert_eq!(
            cfg.local_ttl_in_group("guest"),
            60,
            "没写过的组回落全局默认值"
        );
    }

    /// 对照组：**顶层**写同样的三行，必须照常生效。
    ///
    /// 没有这一条，"拒绝组级写入"就可能被实现成"把这一行整个丢掉"，
    /// 而那会误伤所有正常写在顶层的配置 —— 是本修复最需要防的副作用。
    #[test]
    fn the_same_options_at_top_level_still_take_effect() {
        let cfg = RuntimeConfig::builder()
            .with("serve-expired no")
            .with("rr-ttl 111")
            .with("speed-check-mode none")
            .build()
            .unwrap();

        assert!(!cfg.serve_expired(), "顶层 serve-expired 必须生效");
        assert_eq!(cfg.rr_ttl(), Some(111), "顶层 rr-ttl 必须生效");
        assert_eq!(
            cfg.speed_check_mode()
                .map(|m| m.iter().any(|x| x.is_none())),
            Some(true),
            "顶层 speed-check-mode none 必须生效，且保持『写了 none』的可辨识性"
        );
    }

    /// 已支持组级的两项**不受本次拦截影响**（防止拦得过宽）。
    #[test]
    fn already_supported_group_options_are_not_rejected() {
        let cfg = RuntimeConfig::builder()
            .with("group-begin office")
            .with("force-no-CNAME yes")
            .with("force-AAAA-SOA yes")
            .with("group-end")
            .build()
            .unwrap();

        assert!(
            cfg.force_no_cname_in_group("office"),
            "force-no-CNAME 是已支持的组级参数，必须照常写进组"
        );
        assert!(
            cfg.force_aaaa_soa_in_group("office"),
            "force-AAAA-SOA 是已支持的组级参数，必须照常写进组"
        );
        // 且都**没有**污染全局（它们本来就该只进组）
        assert!(!cfg.force_no_cname(), "组级值不得改写全局");
        assert!(!cfg.force_aaaa_soa(), "组级值不得改写全局");
    }

    /// 🔒 铁律二：**`group-begin default` 与顶层是同一处**，空组名查询必须能读到。
    ///
    /// 修复前的实际行为（真机探针实测）：`*_in_group("default")` 为 true，
    /// 而 `*_in_group("")` 为 false —— 而**绝大多数查询用的正是空组名**
    /// （客户端没有匹配到任何 client-rule 时，`DnsContext::effective_rule_group`
    /// 返回的就是空串）。于是写在 `group-begin default` 里的组级参数，
    /// 普通客户端一个都读不到，等于白写。
    ///
    /// 上游语义：先造 default 组、顶层配置就落在它身上 ⇒ 两者本就是同一处。
    #[test]
    fn default_group_written_in_a_block_is_visible_to_unmatched_clients() {
        let cfg = RuntimeConfig::builder()
            .with("group-begin default")
            .with("force-no-CNAME yes")
            .with("group-end")
            .build()
            .unwrap();

        // "default" 这个字面量与空串（未匹配任何 client-rule 的客户端）必须等价
        assert!(
            cfg.force_no_cname_in_group("default"),
            "按字面量取当然要能取到"
        );
        assert!(
            cfg.force_no_cname_in_group(""),
            "**空组名必须同样取得到** —— 这才是绝大多数查询走的那条路"
        );
        assert_eq!(
            cfg.force_no_cname_in_group(""),
            cfg.force_no_cname_in_group(DEFAULT_GROUP),
            "空组名与 default 必须是同一个答案（这是本测试的核心不变量）"
        );
    }

    /// 与上一条配套：**别的组名不能被错误地归一化到 default**。
    ///
    /// 归一化只该对"空串 → default"生效。若写成"取不到就回退 default"，
    /// 那么任何拼错的组名都会静默拿到 default 的组级参数 —— 又一个"生效在错的地方"。
    #[test]
    fn normalization_does_not_leak_default_params_to_other_group_names() {
        let cfg = RuntimeConfig::builder()
            .with("group-begin default")
            .with("force-no-CNAME yes")
            .with("group-end")
            .with("group-begin office")
            .with("group-end")
            .build()
            .unwrap();

        assert!(
            !cfg.force_no_cname_in_group("office"),
            "office 组自己没写，不该拿到 default 的组级值"
        );
        assert!(
            !cfg.force_no_cname_in_group("no-such-group-typo"),
            "拼错的组名不该静默拿到 default 的组级值"
        );
    }
}
