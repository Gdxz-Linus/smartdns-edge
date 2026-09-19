use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::LazyLock;
use std::{borrow::Borrow, net::IpAddr, time::Duration};
use tokio::sync::Semaphore;

// 🌟 全局测速限流关卡：最多并发 1500 个测速任务！
// 剩余的 548 个系统线程被死死锁住，专门留给日志和缓存落盘使用，防止 I/O 饿死。
static PING_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(1500));

use crate::dns_client::{LookupOptions, NameServer};
use crate::infra::ipset::{IpMap, IpSet};
use crate::{
    config::{ResponseMode, SpeedCheckMode, SpeedCheckModeList},
    dns::*,
    dns_client::{DnsClient, GenericResolver, NameServerGroup},
    dns_error::LookupError,
    log::{debug, error},
    middleware::*,
};

use crate::libdns::proto::rr::domain::usage::LOCAL;
use crate::libdns::proto::{op::ResponseCode, rr::rdata::opt::EdnsCode};
use futures::FutureExt;
use rr::rdata::opt::EdnsOption;
use std::sync::Mutex;
use tokio::sync::broadcast; // 🌟 引入广播频道
use tokio::time::sleep; // 🌟 引入互斥锁

pub struct NameServerMiddleware {
    client: DnsClient,
    // 🌟 新增：底层收费站复印机 (合并相同的 4 倍冗余请求)
    inflight: Arc<Mutex<HashMap<String, broadcast::Sender<Option<DnsResponse>>>>>,
}

impl NameServerMiddleware {
    pub fn new(client: DnsClient) -> Self {
        Self {
            client,
            inflight: Arc::new(Mutex::new(HashMap::new())), // 🌟 初始化
        }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for NameServerMiddleware {
    #[inline]
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        _next: crate::middleware::Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let name: &Name = req.query().name().borrow();
        let rtype = req.query().query_type();

        let client = &self.client;

        if rtype.is_ip_addr()
            && let Some(lookup) = client.lookup_nameserver(name.clone(), rtype).await
        {
            debug!(
                "lookup nameserver {} {} ip {:?}",
                name,
                rtype,
                lookup
                    .answers()
                    .iter()
                    .filter_map(|record| record.data().ip_addr())
                    .collect::<Vec<_>>()
            );
            ctx.no_cache = true;
            return Ok(lookup);
        }

        let lookup_options = LookupOptions {
            // 无论客户端带不带 DO 标志，向外网查询时一律填 false，拒绝向上游索要加密签名！
            is_dnssec: false,
            record_type: rtype,
            client_subnet: req
                .extensions()
                .as_ref()
                .and_then(|edns| {
                    edns.option(EdnsCode::Subnet).and_then(|opt| match opt {
                        EdnsOption::Subnet(subnet) => Some(*subnet),
                        _ => None,
                    })
                })
                .or_else(|| ctx.domain_rule.get_ref(|r| r.subnet.as_ref()).cloned()),
        };

        // skip nameserver rule
        if ctx.server_opts.no_rule_nameserver() {
            return client.lookup(name.clone(), lookup_options).await;
        }

        let group_name = ctx.server_group_name().to_string();

        let name_server = {
            // 🔐 Q11：两种域名都交给 mDNS 那一组 ——
            //   ① 系统标准里的"本地域"（`.local` 之类，原本就支持）；
            //   ② 用户在 `local-domain` 里点名要本地解析的域名（含子域名）。
            let want_mdns =
                ctx.cfg().mdns_lookup() && (LOCAL.zone_of(name) || ctx.cfg().is_local_domain(name));

            let name_server = if want_mdns {
                client.get_server_group("mdns").await
            } else {
                None
            };

            let name_server = match name_server {
                Some(ns) => Some(ns),
                None => client.get_server_group(group_name.as_ref()).await,
            };

            match name_server {
                Some(ns) => ns,
                None => {
                    // 🔐 P2（用户定策）：服务器组不存在 → **不直接失败**，退回默认组并点名告警。
                    // 组名是硬引用（拼错、改名后忘了同步都很常见），而 DNS 是家里的基础设施：
                    // "能解析"优先于"严格报错"。但绝不能静默 —— 走默认组意味着可能换了一条出口，
                    // 所以日志点名组名 + 触发它的域名，且只报一次。
                    if ctx.cfg().has_server_group(group_name.as_str()) {
                        error!("no available nameserver found for {}", name);
                        return Err(ProtoErrorKind::NoConnections.into());
                    }

                    if crate::log::warn_once(&format!("server-group:{group_name}")) {
                        crate::log::warn!(
                            "no upstream server group named `{}` in the configuration (query {} matched it); falling back to the default group. Check the group names in server/nameserver `-group`, in bind `-group` and in the nameserver /domain/group rules",
                            group_name,
                            name
                        );
                    }

                    match client.get_server_group("default").await {
                        Some(ns) => ns,
                        None => {
                            error!("no available nameserver found for {}", name);
                            return Err(ProtoErrorKind::NoConnections.into());
                        }
                    }
                }
            }
        };

        debug!(
            "query name: {} type: {}{} via[Group: {}]",
            name,
            rtype,
            match lookup_options.client_subnet.as_ref() {
                Some(subnet) => format!("\tsubnet: {}/{}", subnet.addr(), subnet.scope_prefix()),
                None => String::with_capacity(0),
            },
            group_name
        );

        // IP 类查询要用的选项：**提前在这里算好**。原先它在下面的异步块里构造，那时折叠键
        // 早已算完，导致等待者只能拿到"领跑者"的处理结果；现在折叠键会覆盖这几项（见下）。
        let ip_opts = rtype.is_ip_addr().then(|| {
            let cfg = ctx.cfg();

            let mut opts = match ctx.domain_rule.as_ref() {
                Some(rule) => LookupIpOptions {
                    response_strategy: rule
                        .get(|n| n.response_mode)
                        .unwrap_or_else(|| cfg.response_mode()),
                    speed_check_mode: match rule.speed_check_mode.as_ref() {
                        Some(mode) => Some(mode.clone()),
                        None => cfg.speed_check_mode().cloned(),
                    },
                    no_speed_check: ctx.server_opts.no_speed_check(),
                    ignore_ip: cfg.ignore_ip().clone(),
                    blacklist_ip: cfg.blacklist_ip().clone(),
                    whitelist_ip: cfg.whitelist_ip().clone(),
                    ip_alias: cfg.ip_alias().clone(),
                    lookup_options: lookup_options.clone(),
                },
                None => LookupIpOptions {
                    response_strategy: cfg.response_mode(),
                    speed_check_mode: cfg.speed_check_mode().cloned(),
                    no_speed_check: ctx.server_opts.no_speed_check(),
                    ignore_ip: cfg.ignore_ip().clone(),
                    blacklist_ip: cfg.blacklist_ip().clone(),
                    whitelist_ip: cfg.whitelist_ip().clone(),
                    ip_alias: cfg.ip_alias().clone(),
                    lookup_options: lookup_options.clone(),
                },
            };

            if ctx.server_opts.is_background {
                opts.response_strategy = ResponseMode::FastestIp;
            }

            opts
        });

        ctx.source = LookupFrom::Server(group_name.to_string());

        // 🌟 【底层收费站合并器】：彻底终结 Dualstack 和 Cache 带来的 4 倍风暴！
        //
        // 折叠键必须覆盖**所有会影响这次上游查询结果的请求级差异**，否则等待者会拿到
        // "为别人算出来"的答案（P1-4）。进键的四类差异：
        //   1. name/type —— 查询本身；
        //   2. group —— 客户端规则能带来的差异只有"选哪个分组"，已经在这里；
        //   3. ecs —— 客户端自带的 EDNS0 Client Subnet（读不到时用域规则的 -subnet）。
        //      不区分它，不同网段的客户端会共用一次上游查询、拿到别人地区的 IP，而且这个错答案
        //      还会被缓存层按自己的 ECS 键存下来，在整个 TTL 内持续污染；
        //   4. 处理选项（响应模式 / 测速模式 / 绑定级 -no-speed-check）—— 它们会被"固化"进
        //      共享答案（测速排序、按模式挑选 IP），所以不同绑定的客户端也不能互相借用。
        let fold_ecs = lookup_options
            .client_subnet
            .map(|subnet| format!("{}/{}", subnet.addr(), subnet.source_prefix()))
            .unwrap_or_default();
        let fold_proc = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            if let Some(opts) = ip_opts.as_ref() {
                opts.response_strategy.hash(&mut hasher);
                opts.speed_check_mode.hash(&mut hasher);
                opts.no_speed_check.hash(&mut hasher);
            }
            hasher.finish()
        };
        let cache_key = format!(
            "{}:{}:{}:{}:{:x}",
            name, rtype, group_name, fold_ecs, fold_proc
        );

        let rx = {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.get(&cache_key) {
                Some(tx.subscribe()) // 已经有相同的请求出门了，领个号码牌坐着等
            } else {
                let (tx, _) = broadcast::channel(1);
                map.insert(cache_key.clone(), tx);
                None // 我是第一个到的，我负责去外网查
            }
        };

        if let Some(mut receiver) = rx {
            // 作为被合并的冗余请求，坐板凳等待复印件，绝不去外网！
            return match receiver.recv().await {
                Ok(Some(res)) => Ok(res),
                _ => Err(ProtoErrorKind::NoConnections.into()),
            };
        }

        // 🌟 发放智能对讲机工牌，防意外阵亡！
        let mut inflight_guard = InflightNsGuard {
            inflight: self.inflight.clone(),
            cache_key: cache_key.clone(),
            done: false, // 初始状态为没干完活
        };

        // 我是真正冲向外网的独苗请求！开始干活：
        // 🌟 修复第一步：用一个 async 块（闭包）把底层的外网查询逻辑打包起来，作为挂炸弹的目标
        let lookup_future = async {
            if rtype.is_ip_addr() {
                let Some(opts) = ip_opts.as_ref() else {
                    // 逻辑上到不了：ip_opts 与 rtype.is_ip_addr() 是同一个条件构造的
                    return Err(ProtoErrorKind::NoConnections.into());
                };

                lookup_ip(name_server.deref(), name.clone(), opts).await
            } else {
                // 🌟 同理洗白非 IP 类的查询
                match name_server.lookup(name.clone(), lookup_options).await {
                    Ok(r) => Ok(r),
                    Err(e) => {
                        let q = crate::libdns::proto::op::Query::query(name.clone(), rtype);
                        if let Some(soa_resp) = e.as_soa(&q) {
                            Ok(soa_resp)
                        } else {
                            Err(e)
                        }
                    }
                }
            }
            .map(|res| res.with_name_server_group(group_name.to_string()))
        };

        // 🌟 核心保护（定时炸弹）：强制 5 秒超时！哪怕底层网络黑洞、UDP丢包或死锁，
        // 只要 5 秒一到，立刻砍断执行权！触发大哥的异常，从而拯救所有在等候室无限挂起的小弟！
        let mut actual_result =
            match tokio::time::timeout(Duration::from_secs(5), lookup_future).await {
                Ok(result) => result, // 5秒内回来了，正常交差
                Err(_) => {
                    // 超时触发！操作系统强杀！
                    crate::log::debug!(
                        "Global timeout (5s) triggered for query: {} {}",
                        name,
                        rtype
                    );
                    Err(DnsError::Io(Arc::new(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "upstream request timeout (5s)",
                    ))))
                }
            };

        // 🌟 【终极修复：初始 TTL 限制器】：在刚拿到上游包裹时，立刻用配置的界限去约束它！
        // 这样 Dualstack 和 Cache 拿到的就是天然合规的包裹，倒计时完美生效！
        if let Ok(ref mut res) = actual_result {
            // 🌟 提取 rr-ttl (如果配置了，它拥有最高统治权)
            let rr_ttl = ctx
                .domain_rule
                .as_ref()
                .and_then(|r| r.rr_ttl)
                .map(|i| i as u32)
                .or_else(|| ctx.cfg().rr_ttl().map(|i| i as u32));

            let rr_ttl_min = ctx
                .domain_rule
                .as_ref()
                .and_then(|r| r.rr_ttl_min)
                .map(|i| i as u32)
                .unwrap_or_else(|| ctx.cfg().rr_ttl_min().unwrap_or(0) as u32);
            let rr_ttl_max = ctx
                .domain_rule
                .as_ref()
                .and_then(|r| r.rr_ttl_max)
                .map(|i| i as u32)
                .unwrap_or_else(|| ctx.cfg().rr_ttl_max().unwrap_or(86400) as u32);

            // 裁剪逻辑抽成独立函数 clamp_record_ttl（见本文件末尾），便于单元测试直接覆盖。
            let clamp_ttl =
                |record: &mut Record| clamp_record_ttl(record, rr_ttl, rr_ttl_min, rr_ttl_max);

            res.answers_mut().iter_mut().for_each(&clamp_ttl);
            res.authorities_mut().iter_mut().for_each(&clamp_ttl);
            res.additionals_mut().iter_mut().for_each(&clamp_ttl);
        }

        // 🌟 活干完了，拿到结果后，复印分发给所有坐在板凳上等待的兄弟！
        {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.remove(&cache_key) {
                let broadcast_res = actual_result.as_ref().ok().cloned();
                let _ = tx.send(broadcast_res);
            }
        }
        inflight_guard.done = true; // 🌟 安全下车，解除阵亡警报
        actual_result
    }
}

struct LookupIpOptions {
    response_strategy: ResponseMode,
    speed_check_mode: Option<SpeedCheckModeList>,
    no_speed_check: bool,
    ignore_ip: Arc<IpSet>,
    whitelist_ip: Arc<IpSet>,
    blacklist_ip: Arc<IpSet>,
    ip_alias: Arc<IpMap<Arc<[IpAddr]>>>,
    lookup_options: LookupOptions,
}

impl Deref for LookupIpOptions {
    type Target = LookupOptions;

    fn deref(&self) -> &Self::Target {
        &self.lookup_options
    }
}

impl From<LookupIpOptions> for LookupOptions {
    fn from(value: LookupIpOptions) -> Self {
        value.lookup_options
    }
}

impl From<&LookupIpOptions> for LookupOptions {
    fn from(value: &LookupIpOptions) -> Self {
        value.lookup_options.clone()
    }
}

/// 🔐 第三部分第 3 条（上游 `-fallback`）：按组查 IP 时也分两轮 ——
/// **第一轮只问正常那批服务器**，只有它们给不出可用答案（超时/故障/只剩截断包）时，
/// 才把后备服务器拉进来再问一遍。与 C 版 `dns_client.c:405` 的语义一致，
/// 也与"整组竞速"那条路径（`dns_client.rs` 里的 `NameServerGroup::lookup`）保持同一套规矩。
async fn lookup_ip(
    server: &NameServerGroup,
    name: Name,
    options: &LookupIpOptions,
) -> Result<DnsResponse, LookupError> {
    let (primary, fallback): (Vec<_>, Vec<_>) =
        server.iter().cloned().partition(|ns| !ns.is_fallback());

    // 组里全是后备服务器：那就照旧一起用，别把查询搞成失败
    if primary.is_empty() {
        let all = fallback;
        return lookup_ip_with(&all, name, options).await;
    }

    let first = lookup_ip_with(&primary, name.clone(), options).await;

    if fallback.is_empty() || !crate::dns_client::needs_fallback(&first) {
        return first;
    }

    // 第二轮：后备服务器上场
    let second = lookup_ip_with(&fallback, name, options).await;

    if crate::dns_client::needs_fallback(&second) {
        first
    } else {
        second
    }
}

/// 把一批服务器同时问出去，按既定的响应策略挑结果（原来的 `lookup_ip` 主体）
async fn lookup_ip_with(
    servers: &[std::sync::Arc<NameServer>],
    name: Name,
    options: &LookupIpOptions,
) -> Result<DnsResponse, LookupError> {
    use ResponseMode::*;
    use futures_util::future::{Either, select, select_all};

    assert!(options.record_type.is_ip_addr());

    let mut query_tasks = servers
        .iter()
        .map(|ns| per_nameserver_lookup_ip(ns, name.clone(), options).boxed())
        .collect::<Vec<_>>();

    if query_tasks.is_empty() {
        return Err(ProtoErrorKind::NoConnections.into());
    }

    // ignore speed check
    let mut response_strategy = if options.no_speed_check || options.speed_check_mode.is_none() {
        FastestResponse
    } else {
        options.response_strategy
    };

    let mut speed_check_mode = options
        .speed_check_mode
        .as_ref()
        .map(|m| m.as_slice())
        .unwrap_or_default();

    if speed_check_mode.iter().any(|m| m.is_none()) {
        response_strategy = FastestResponse; // ignore speed check
        speed_check_mode = &[];
    }

    let mut ok_tasks = vec![];
    let mut err_tasks = vec![];

    let selected_ip = match response_strategy {
        FirstPing => {
            let mut ping_tasks = Vec::new();
            let mut fastest_ip = None;

            loop {
                if query_tasks.is_empty() && ping_tasks.is_empty() {
                    break;
                }

                #[allow(clippy::type_complexity)]
                let (ping_res, query_res): (
                    Option<Option<IpAddr>>,
                    Option<Result<DnsResponse, DnsError>>,
                ) = match (query_tasks.len(), ping_tasks.len()) {
                    (0, 0) => break,
                    (0, _) => {
                        let (res, _, rest) = select_all(ping_tasks).await;
                        ping_tasks = rest;
                        (Some(res), None)
                    }
                    (_, 0) => {
                        let (res, _, rest) = select_all(query_tasks).await;
                        query_tasks = rest;
                        (None, Some(res))
                    }
                    _ => {
                        let a = select_all(ping_tasks);
                        let b = select_all(query_tasks);
                        match select(a, b).await {
                            Either::Left(((res, _, rest), other)) => {
                                ping_tasks = rest;
                                query_tasks = other.into_inner();
                                (Some(res), None)
                            }
                            Either::Right(((res, _, rest), other)) => {
                                query_tasks = rest;
                                ping_tasks = other.into_inner();
                                (None, Some(res))
                            }
                        }
                    }
                };

                // 1. 处理测速结果：谁现实里第一个冲过终点线拿到真实 IP，谁就赢！
                if let Some(ping_result) = ping_res
                    && let Some(ip) = ping_result
                {
                    // 只要有任何一个模式（如 TCP 或降级的 ICMP）测通了，瞬间结束！
                    fastest_ip = Some(ip);
                    break;
                }
                // 如果这个 IP 的所有模式都失败了（ping_result 为 None）
                // 绝对不 break！什么都不做，继续等其他还在查询或测速的任务！

                // 2. 处理上游查询结果：滚动发车！
                if let Some(q_res) = query_res {
                    match q_res {
                        Ok(lookup) => {
                            let ip_addrs = lookup.ip_addrs();
                            ok_tasks.push(lookup);

                            // 【修复漏洞】：哪怕上游只返回了 1 个 IP，也必须乖乖去测速！绝不开后门！
                            if !ip_addrs.is_empty() {
                                ping_tasks.push(
                                    multi_mode_ping_fastest(
                                        name.clone(),
                                        ip_addrs,
                                        speed_check_mode.to_vec(),
                                    )
                                    .boxed(),
                                );
                            }
                        }
                        Err(err) => {
                            err_tasks.push(err);
                        }
                    }
                }
            }

            match fastest_ip {
                Some(ip) => Some(ip),
                None => {
                    // 【终极兜底】：如果非常倒霉，所有上游返回的所有 IP 全都测不通
                    // 挑选返回次数最多的那个 IP 给客户端
                    let ip_addr_stats = ok_tasks.iter().flat_map(|r| r.ip_addrs()).fold(
                        HashMap::<IpAddr, usize>::new(),
                        |mut map, ip| {
                            map.entry(ip).and_modify(|n| *n += 1).or_insert(1);
                            map
                        },
                    );
                    ip_addr_stats
                        .into_iter()
                        .max_by_key(|(_, n)| *n)
                        .map(|(ip, _)| ip)
                }
            }
        }
        FastestIp => {
            let mut ip_addr_stats = HashMap::new();
            let mut fastest_ip: Option<IpAddr> = None;

            // 【阶段一：Gather (等待上游返回)】
            // 设定全局最大等待时间 800ms (等待上游交卷的时间，保持不变)
            let mut gather_timeout = sleep(Duration::from_millis(800)).boxed();

            loop {
                // 如果所有上游都返回了，提前跳出，不再死等
                if query_tasks.is_empty() {
                    break;
                }

                match select(select_all(query_tasks), gather_timeout).await {
                    Either::Left(((res, _idx, rest), pending_timeout)) => {
                        query_tasks = rest; // 剩下的上游继续等
                        gather_timeout = pending_timeout; // 继承剩下的超时时间

                        match res {
                            Ok(lookup) => {
                                ok_tasks.push(lookup); // 成功收集
                            }
                            Err(err) => {
                                err_tasks.push(err); // 报错不影响其他上游
                            }
                        }
                    }
                    Either::Right(_) => {
                        // 500ms 到达！不再等剩下的上游，直接发车！
                        break;
                    }
                }
            }

            // 【阶段二：并发测速阶段 (大一统引擎)】
            for lookup in &ok_tasks {
                for ip in lookup.ip_addrs() {
                    *ip_addr_stats.entry(ip).or_insert(0usize) += 1;
                }
            }

            // 🌟 核心接入：将所有去重后的 IP 聚合成一个 Vec，
            // 霸气地一次性塞给通用测速大引擎，不再做拆分单兵作战！
            let all_ips: Vec<IpAddr> = ip_addr_stats.keys().copied().collect();
            if !all_ips.is_empty() {
                fastest_ip =
                    multi_mode_ping_fastest(name.clone(), all_ips, speed_check_mode.to_vec()).await;
            }

            match fastest_ip {
                Some(ip) => Some(ip), // 选出了最强王者
                None => ip_addr_stats // 全军覆没，按返回次数最多的兜底
                    .into_iter()
                    .max_by_key(|(_, n)| *n)
                    .map(|(ip, _)| ip),
            }
        }
        FastestResponse => {
            loop {
                if query_tasks.is_empty() {
                    break;
                }
                let (res, _idx, rest) = select_all(query_tasks).await;
                query_tasks = rest;

                match res {
                    Ok(response) => {
                        let code = response.response_code();
                        // 🌟 核心修复 1：绝不轻信 NXDOMAIN！
                        // 只有拿到真正的 NoError 且附带有效解答记录（如 IP 或 CNAME），才配得上“立刻抢答返回”！
                        if code == ResponseCode::NoError && !response.answers().is_empty() {
                            return Ok(response);
                        }
                        // 虚假的 NXDOMAIN、真实的 NoData 空包、或其他报错码，全部暂存冰柜，强行等候其他上游的交叉验证！
                        ok_tasks.push(response);
                    }
                    Err(err) => {
                        err_tasks.push(err);
                    }
                }
            }
            None // 未能提前抢答，selected_ip 置空，交给底部的全局统一优选逻辑兜底
        }
    };

    if let Some(selected_ip) = selected_ip {
        // 🔐 P0-2：这里原来是 `for mut res in ok_tasks { ... }` 加末尾的 unreachable!()。
        // 一旦"选中了 IP、却没有任何答案包含它"（缓存/过滤后可能出现这种不一致），
        // 就会直接 panic —— 远程可触发的 panic 等于一个拒绝服务入口。
        // 现在改为按索引定位：只在真正找到时才取出并返回；
        // 找不到则保持 ok_tasks 完好，继续走下面的通用优选兜底（与后面逻辑的假设一致）。
        let mut selected: Option<DnsResponse> = None;
        for idx in 0..ok_tasks.len() {
            // 先检查这个包裹里有没有赢家 IP
            let has_target = ok_tasks[idx]
                .answers()
                .iter()
                .any(|r| matches!(r.data().ip_addr(), Some(ip) if ip == selected_ip));

            if has_target {
                let mut res = ok_tasks.remove(idx);
                // 🌟 核心修复：忠实还原完整的 CNAME 链路！
                // 仅仅剔除落选的其他 IP 记录，而 CNAME 等非 IP 记录无条件保留。
                res.answers_mut().retain(|record| {
                    match record.data().ip_addr() {
                        Some(ip) => ip == selected_ip, // 是 IP 的话，只留冠军
                        None => true,                  // 不是 IP（如 CNAME），无条件保留！
                    }
                });
                selected = Some(res);
                break;
            }
        }

        if let Some(res) = selected {
            return Ok(res);
        }

        crate::log::warn!("selected ip not found in answers, fall through to generic selection");
    }

    // =================================================================================
    // 🌟 全局统一的“降级与防污染兜底”策略：
    // 当所有上游都没有测出最快 IP，或者处于 FastestResponse 模式且没有上游能给出完美答卷时，进行质量评优。
    // =================================================================================
    let best_fallback = ok_tasks.into_iter().min_by_key(|res| {
        let code = res.response_code();
        let has_answers = !res.answers().is_empty();

        // 🌟 提取包裹中是否携带了珍贵的 SOA 权威记录
        let has_soa = res
            .authorities()
            .iter()
            .any(|r| r.record_type() == RecordType::SOA)
            || res
                .answers()
                .iter()
                .any(|r| r.record_type() == RecordType::SOA)
            || res
                .additionals()
                .iter()
                .any(|r| r.record_type() == RecordType::SOA);

        // 🌟 优先级降维打击排序：
        match (code, has_answers, has_soa) {
            (ResponseCode::NoError, true, _) => 0, // 0级：有 Answer 的完美合法包
            (ResponseCode::NoError, false, true) => 1, // 🌟 1级：【极品空包】带有真实 SOA 的合法 NoData，无情碾压太监包！
            (ResponseCode::NoError, false, false) => 2, // 🌟 2级：【太监空包】没有 SOA 的残缺空包（如本地代理抢答的阉割包）。
            (ResponseCode::NXDomain, _, true) => 3,     // 3级：带有 SOA 的规范 NXDOMAIN
            (ResponseCode::NXDomain, _, false) => 4,    // 4级：光秃秃的虚假 NXDOMAIN
            _ => 5,
        }
    });

    match best_fallback {
        Some(lookup) => Ok(lookup),
        None => match err_tasks.into_iter().next() {
            Some(err) => Err(err),
            None => {
                // 🌟 核心修复：将“装死（崩溃）”改为“主动通知系统超时”！
                // 程序走到这里直接向上层抛出一个合法的 Timeout 错误。
                Err(ProtoErrorKind::Timeout.into())
            }
        },
    }
}

// =================================================================================
// 🌟 通用大一统引擎：协议降级与动态梯队竞速
// 完美同时服务于 First-Ping 和 Fastest-Ip 两种模式
// =================================================================================
async fn multi_mode_ping_fastest(
    name: Name,
    ip_addrs: Vec<IpAddr>,
    modes: Vec<SpeedCheckMode>,
) -> Option<IpAddr> {
    let domain_str = name.to_string(); // 🌟 转为字符串
    for mode in &modes {
        debug!(
            "Dynamic Tier Speed test {} {:?} ping {:?}",
            name, mode, ip_addrs
        );
        // 🌟 透传 domain
        if let Some((ip, _)) = dynamic_tier_ping(&domain_str, &ip_addrs, mode).await {
            return Some(ip);
        }
    }
    None
}

// 🌟 核心算法：3次并发、动态最高目标降级、600ms绝对死线
async fn dynamic_tier_ping(
    domain: &str, // 🌟 接收 domain
    ip_addrs: &[IpAddr],
    mode: &SpeedCheckMode,
) -> Option<(IpAddr, Duration)> {
    if ip_addrs.is_empty() {
        return None;
    }
    let dests = mode.to_ping_addrs(ip_addrs);
    if dests.is_empty() {
        return None;
    }

    use crate::infra::ping::{PingAddr, PingOptions, ping};
    use futures_util::stream::{FuturesUnordered, StreamExt};

    const PINGS_PER_IP: u8 = 3; // 同一 IP 并发探测次数
    // 🌟 核心修复：同理，将这里的内核并发发包超时严格对齐到底部的 timeout(600ms) 绝对死线！
    let ping_ops = PingOptions::default().with_timeout(Duration::from_millis(600));
    let mut futures = FuturesUnordered::new();

    // 1. 错峰齐发：将所有 IP 的并发测速包以 25ms 间隔投入网络，打破微突发关联丢包！
    for &dest in &dests {
        for i in 0..PINGS_PER_IP {
            // 🌟 核心改良：引入 25ms 的发包阶梯错峰 (Micro-Staggering)
            let stagger_delay = Duration::from_millis((i as u64) * 25);

            futures.push(async move {
                let _permit = match PING_SEMAPHORE.acquire().await {
                    Ok(p) => p,
                    Err(_) => return (dest, Err(())),
                };

                if stagger_delay > Duration::ZERO {
                    tokio::time::sleep(stagger_delay).await;
                }

                // 🌟 将 domain 喂给底层核心引擎！
                let res = ping(dest, Some(domain), ping_ops).await;

                (dest, res.map(|o| o.elapsed()).map_err(|_| ()))
            });
        }
    }

    struct IpState {
        dest: PingAddr,
        successes: u8,
        failures: u8,
        sum_latency: Duration, // 用于算平均值
        min_latency: Duration, // 🌟 新增：全场最佳纪录（最小延迟），代表物理极限！
    }

    impl IpState {
        // 🌟 核心算法：基础分[(平均延迟 + 最小延迟)/2] + 丢包罚时
        fn score(&self) -> Duration {
            if self.successes == 0 {
                return Duration::from_secs(60); // 0分直接出局
            }

            let avg = self.sum_latency / (self.successes as u32);
            // 🌟 最小延时补偿：将平均值和历史最佳成绩按 1:1 混合，平滑抖动
            let base_score = (avg + self.min_latency) / 2;

            // 丢 1 个包罚 50ms。容忍极速节点轻微丢包，同时拦截高丢包死节点。
            let penalty = Duration::from_millis(50) * (3 - self.successes as u32);

            base_score + penalty
        }
    }

    let mut states: Vec<IpState> = dests
        .iter()
        .map(|&d| IpState {
            dest: d,
            successes: 0,
            failures: 0,
            sum_latency: Duration::ZERO,
            min_latency: Duration::MAX, // 初始化为最大值，方便后续取小
        })
        .collect();

    let mut target_score = PINGS_PER_IP; // 初始最高期望值：满分 3 次全通

    let race_logic = async {
        // 2. 状态机推进：有包回来就结算，无需主观等待
        while let Some((dest, result)) = futures.next().await {
            let state = states.iter_mut().find(|s| s.dest == dest).unwrap();

            match result {
                Ok(latency) => {
                    state.successes += 1;
                    state.sum_latency += latency;
                    state.min_latency = state.min_latency.min(latency); // 🌟 刷新该 IP 的物理极限纪录

                    // 🏁 终点线触发：只要有任何 1 个 IP 拿到了最高目标分，立刻敲钟结算！
                    if state.successes == target_score {
                        // 比赛结束，不用等后面的烂包了！按照“加权公式”核算全场成绩
                        let winner = states
                            .iter()
                            .filter(|s| s.successes > 0)
                            .min_by_key(|s| s.score())
                            .unwrap();

                        // 返回时，告诉上层它真实的平均体感延迟（不带罚时，仅供外部日志打印或参考）
                        let winner_avg = winner.sum_latency / (winner.successes as u32);
                        return Some((winner.dest, winner_avg));
                    }
                }
                Err(_) => {
                    state.failures += 1;

                    // 3. 动态降级：如果有包丢了，评估全局理论最高期望值是否需要下调
                    let new_target = states
                        .iter()
                        .map(|s| PINGS_PER_IP - s.failures)
                        .max()
                        .unwrap_or(0);

                    // 期望值发生实质跌落（比如全场都没人能拿 3 分了，降级到 2 分）
                    if new_target < target_score {
                        target_score = new_target;

                        if target_score == 0 {
                            return None; // 全员得 0 分，本协议彻底死局，退出去降级 TCP
                        }

                        // 🏁 降级撞线触发：既然目标降低了，看看是不是已经有人达到新目标了？立刻敲钟！
                        if states.iter().any(|s| s.successes >= target_score) {
                            let winner = states
                                .iter()
                                .filter(|s| s.successes > 0)
                                .min_by_key(|s| s.score())
                                .unwrap();

                            let winner_avg = winner.sum_latency / (winner.successes as u32);
                            return Some((winner.dest, winner_avg));
                        }
                    }
                }
            }
        }
        None
    };

    // 5. 绝对死线：600ms 兜底 (包含高延时节点，并防止黑洞无限期挂起)
    match tokio::time::timeout(Duration::from_millis(600), race_logic).await {
        Ok(Some((dest, latency))) => Some((dest.ip_addr(), latency)), // 正常决出胜负
        Ok(None) => None,                                             // 确认全部失败
        Err(_) => {
            // 600ms 超时触发：强行按照统一的评分公式，结算当前场上的最好成绩！
            let winner = states
                .iter()
                .filter(|s| s.successes > 0) // 必须至少成功 1 次
                .min_by_key(|s| s.score());

            winner.map(|s| (s.dest.ip_addr(), s.sum_latency / (s.successes as u32)))
        }
    }
}

async fn per_nameserver_lookup_ip(
    server: &NameServer,
    name: Name,
    options: &LookupIpOptions,
) -> Result<DnsResponse, LookupError> {
    assert!(options.lookup_options.record_type.is_ip_addr());

    // 🌟 核心修复：洗白底层误伤的 SOA！
    let res = match server.lookup(name.clone(), options).await {
        Ok(r) => Ok(r),
        Err(e) => {
            let q = crate::libdns::proto::op::Query::query(
                name.clone(),
                options.lookup_options.record_type,
            );
            // 如果这个 Error 兜里揣着 SOA 证书，说明它是合法的空包/NXDOMAIN，立刻赦免为 Ok！
            if let Some(soa_resp) = e.as_soa(&q) {
                Ok(soa_resp)
            } else {
                Err(e) // 真正的网络超时或断网，维持 Err 扔进 err_tasks
            }
        }
    };

    let ns_opts = server.options();
    let whitelist_on = ns_opts.whitelist_ip;
    let blacklist_on = ns_opts.blacklist_ip;

    let LookupIpOptions {
        whitelist_ip,
        blacklist_ip,
        ip_alias,
        ignore_ip,
        ..
    } = options;

    if !whitelist_on && !blacklist_on && ignore_ip.is_empty() && ip_alias.is_empty() {
        return res;
    }

    let ip_filter = |ip: &IpAddr| {
        // whitelist
        if whitelist_on && whitelist_ip.contains(ip) {
            return true;
        }

        if blacklist_on && blacklist_ip.contains(ip) {
            return false;
        }

        !ignore_ip.contains(ip)
    };

    match res {
        Ok(mut lookup) => {
            let answers = lookup.take_answers();
            let answers = {
                let mut new_ans = Vec::new();
                let mut alias_set = Vec::new(); // dedup
                for record in answers {
                    // 🌟 【重大修复】：不能粗暴使用 filter 绞碎非 IP 记录！
                    let ip_opt = record.data().ip_addr();

                    // 如果这条记录根本不是 IP（比如是 CNAME 别名记录），必须原封不动地保留！
                    if ip_opt.is_none() {
                        new_ans.push(record);
                        continue;
                    }

                    // 走到这里说明是 IP，进行黑白名单过滤
                    let ip = ip_opt.unwrap();
                    if !ip_filter(&ip) {
                        continue; // 命中黑名单，抛弃这个 IP
                    }

                    // 剩下的合法 IP 进行 alias (别名) 映射处理
                    match ip_alias.get(&ip) {
                        None => new_ans.push(record),
                        Some(alias_ips) if !alias_set.contains(&alias_ips.as_ptr()) => {
                            alias_set.push(alias_ips.as_ptr());
                            new_ans.extend(alias_ips.iter().filter_map(|&alias_ip| {
                                let mut record = record.clone();
                                record.set_data(alias_ip.into());
                                match (options.record_type, alias_ip) {
                                    (RecordType::A, IpAddr::V4(_))
                                    | (RecordType::AAAA, IpAddr::V6(_)) => Some(record),
                                    _ => {
                                        lookup.add_additional(record);
                                        None
                                    }
                                }
                            }));
                        }
                        Some(_) => continue,
                    }
                }
                new_ans
            };

            *lookup.answers_mut() = answers;
            lookup.set_valid_until_max();

            Ok(lookup)
        }
        Err(err) => Err(err),
    }
}

/// 用 rr-ttl / rr-ttl-min / rr-ttl-max 约束单条记录的 TTL。
///
/// 语义：配置了 rr-ttl 时直接采用它（优先级最高），否则把 TTL 夹逼到
/// `[ttl_min, ttl_max]` 区间内。
///
/// 抽成独立函数是为了能被单元测试直接覆盖：这段裁剪逻辑原先只在 Address
/// 中间件里留有测试，而实现后来被搬到了本中间件，导致那三个测试长期失败
/// （见 dns_mw_addr.rs 测试模块里的说明）。
fn clamp_record_ttl(record: &mut Record, rr_ttl: Option<u32>, ttl_min: u32, ttl_max: u32) {
    let new_ttl = match rr_ttl {
        // rr-ttl 拥有最高统治权
        Some(exact_ttl) => exact_ttl,
        None => record.ttl().clamp(ttl_min, ttl_max),
    };
    record.set_ttl(new_ttl);
}

#[cfg(test)]
mod clamp_ttl_tests {
    use crate::libdns::proto::rr::{RData, Record};

    use super::clamp_record_ttl;

    fn rec(ttl: u32) -> Record {
        Record::from_rdata(
            "dns.google".parse().unwrap(),
            ttl,
            RData::A("8.8.8.8".parse().unwrap()),
        )
    }

    /// rr-ttl-min：过短的抬到下限，区间内的不动
    #[test]
    fn test_clamp_ttl_min() {
        let (mut lo, mut hi) = (rec(48), rec(96));
        clamp_record_ttl(&mut lo, None, 50, 86400);
        clamp_record_ttl(&mut hi, None, 50, 86400);
        assert_eq!(lo.ttl(), 50, "低于 rr-ttl-min 的应抬到下限");
        assert_eq!(hi.ttl(), 96, "区间内的不应改动");
    }

    /// rr-ttl-max：过长的压到上限，区间内的不动
    #[test]
    fn test_clamp_ttl_max() {
        let (mut lo, mut hi) = (rec(48), rec(96));
        clamp_record_ttl(&mut lo, None, 0, 50);
        clamp_record_ttl(&mut hi, None, 0, 50);
        assert_eq!(hi.ttl(), 50, "高于 rr-ttl-max 的应压到上限");
        assert_eq!(lo.ttl(), 48, "区间内的不应改动");
    }

    /// rr-ttl-min 与 rr-ttl-max 同时生效
    #[test]
    fn test_clamp_ttl_min_max() {
        let (mut lo, mut hi) = (rec(48), rec(96));
        clamp_record_ttl(&mut lo, None, 55, 66);
        clamp_record_ttl(&mut hi, None, 55, 66);
        assert_eq!(lo.ttl(), 55);
        assert_eq!(hi.ttl(), 66);
    }

    /// rr-ttl 优先级最高：直接覆盖，min/max 不再参与
    #[test]
    fn test_exact_rr_ttl_overrides_bounds() {
        let mut r = rec(96);
        clamp_record_ttl(&mut r, Some(20), 50, 60);
        assert_eq!(r.ttl(), 20, "配了 rr-ttl 时应直接采用它");
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::libdns::proto::rr::rdata::opt::ClientSubnet;

    use super::*;
    use crate::{dns_conf::RuntimeConfig, third_ext::FutureJoinAllExt};

    #[test]
    fn test_edns_client_subnet() {
        async fn inner_test(i: usize) -> bool {
            let servers = [
                "server https://120.53.53.53/dns-query",
                "server https://223.5.5.5/dns-query",
            ];

            let server = servers[i % servers.len()];

            let cfg = RuntimeConfig::builder().with(server).build().unwrap();

            let domain = "www.bing.com";

            let client = cfg.create_dns_client().await;

            let subnets = ["113.65.29.0/24", "103.225.87.0/24", "113.65.29.0/24"];

            let results = subnets
                .into_iter()
                .map(|subnet| {
                    client.lookup(
                        domain,
                        LookupOptions {
                            is_dnssec: false,
                            record_type: RecordType::A,
                            client_subnet: Some(ClientSubnet::from_str(subnet).unwrap()),
                        },
                    )
                })
                .join_all()
                .await
                .into_iter()
                .flatten()
                .map(|lookup| {
                    let mut ips = lookup.ip_addrs();
                    ips.sort();
                    ips
                })
                .collect::<Vec<_>>();

            let t1 = results[0].clone();
            let t2 = results[1].clone();
            let t3 = results[2].clone();
            let success = t1 == t3 && t1 != t2;
            if !success {
                println!("{t1:?}");
                println!("{t2:?}");
                println!("{t3:?}");
            }
            success
        }

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use futures_util::future::select_all;
                let mut success = false;
                let mut tasks = (0..10).map(|i| inner_test(i).boxed()).collect::<Vec<_>>();

                loop {
                    let (res, _idx, rest) = select_all(tasks).await;

                    if res {
                        success = res;
                        break;
                    }

                    if rest.is_empty() {
                        break;
                    }

                    tasks = rest;
                }
                assert!(success);
            });
    }
}

// ==========================================
// 🌟 制造对讲机工牌：防止 NS 底层带头大哥半路阵亡导致全网死等
// ==========================================
struct InflightNsGuard {
    inflight: Arc<Mutex<HashMap<String, tokio::sync::broadcast::Sender<Option<DnsResponse>>>>>,
    cache_key: String,
    done: bool,
}

impl Drop for InflightNsGuard {
    fn drop(&mut self) {
        if !self.done {
            // 🚨 发生意外崩溃或中断，强行清理仓库并发送 None 告诉小弟散了！
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.remove(&self.cache_key) {
                let _ = tx.send(None);
            }
        }
    }
}
