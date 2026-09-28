use serde::Deserialize;
use std::sync::Arc;
// 🌟 修复：引入读写锁，细化并发粒度
use std::sync::LazyLock;
use tokio::sync::RwLock;

use crate::{
    config::{
        AddressRule, Domain,
        parser::{ConfigFile, ConfigItem, ConfigLine},
    },
    third_ext::serde_str,
};

use super::openapi::{IntoRouter, ToSchema, routes};
use super::{ApiError, DataListPayload, ServeState, StatefulRouter};
use axum::{Json, extract::State, http::StatusCode};

// 🌟 修复：全局异步读写锁，GET 共享，POST/DELETE 排他，防止大粒度阻塞
static CONFIG_FILE_LOCK: LazyLock<RwLock<()>> = LazyLock::new(|| RwLock::new(()));

/// 🔐 `managed_dir` 未确定时的错误说明 —— **必须可操作**。
///
/// ## 背景（B-① 之后已收窄）
///
/// `managed_dir` 派生自 `conf_dir`（`<配置目录>/managed`）。
/// **B-① 之前**，`conf_dir` 只在"配置目录名恰好等于 `smartdns`"或用户传了 `-d` 时才推导，
/// 于是配置放在 `myconf/`、`/etc/dns/` 这类目录下时 `managed_dir` 是 `None`，
/// `/api/addresses` 三个端点全返回 404。
///
/// **B-① 之后**，推导已放宽为"**配置文件所在目录**"（见 `dns_conf.rs` 的 `load()`），
/// 所以 `conf_dir` 为 `None` 的情形**只可能**出现在"配置路径连父目录都取不到"的极端情况
/// （例如 `-c smartdns.conf` 这种没有目录成分的相对路径）。
///
/// ## 因此这条提示的定位变了
///
/// 它从"**常见**的用户配置问题"变成了"**理论上不该出现**的兜底"。
/// 但**仍然保留**，因为：
///   1. 真有用户用 `-c smartdns.conf`（不带目录）启动时，这里就是唯一的解释；
///   2. 提示里给出 `-d` 这条**可操作**的出路，比一句 `managed_dir not found` 有用得多。
///
/// ⚠️ 措辞已按 B-① 更新：不再推荐"把配置放进名叫 `smartdns` 的目录"
/// （那条自动推导条件**已被放宽取代**，再写会误导用户去做无用功）。
fn managed_dir_unavailable(cfg: &crate::dns_conf::RuntimeConfig) -> ApiError {
    ApiError::NotFound(managed_dir_unavailable_message(cfg.conf_dir()))
}

/// 生成"`managed_dir` 不可用"的提示文本。
///
/// 抽成**只依赖 `Option<&Path>`** 的纯函数，是为了让提示内容**可被单测直接钉住** ——
/// `RuntimeConfig` 构造很重（要真实配置解析），若把生成逻辑写在里面就没法单测，
/// 而这段提示的**全部价值**就在于"用户照着做能不能解决"，必须能验证。
fn managed_dir_unavailable_message(conf_dir: Option<&std::path::Path>) -> String {
    let hint = match conf_dir {
        // 理论上不该出现：`managed_dir` 就是由 `conf_dir` 派生的，
        // 有 `conf_dir` 却拿不到 `managed_dir` 说明推导出了问题，让用户报障。
        Some(dir) => format!(
            "the configuration directory is '{}' but no 'managed' sub-directory is in use; \
             this should not happen — please report it",
            dir.display()
        ),
        // B-① 之后这条只会在"配置路径连父目录都取不到"时出现（如 `-c smartdns.conf`）。
        None => "the configuration directory could not be determined, so the managed rules \
                 directory is unavailable. Start the server with an explicit `-d <config-dir>` \
                 (e.g. `smartdns run -c /path/to/smartdns.conf -d /path/to`), or give the \
                 configuration file a path that includes its directory \
                 (e.g. `-c /path/to/smartdns.conf` instead of a bare `-c smartdns.conf`)"
            .to_string(),
    };

    format!("managed_dir not found: {hint}")
}

pub fn routes() -> StatefulRouter {
    routes![list, create, update, delete].into_router()
}

#[utoipa::path(get, path = "/addresses", tag = "Addresses")]
async fn list(State(state): State<Arc<ServeState>>) -> Json<DataListPayload<AddressRule>> {
    // 🌟 抢占共享读锁：多个 GET 请求可完全并发，只有写操作时才会被短暂阻塞
    let _guard = CONFIG_FILE_LOCK.read().await;

    let groups = state
        .app
        .cfg()
        .await
        .rule_groups()
        .get("default")
        .map(|group| group.address_rules.clone())
        .unwrap_or_default();

    Json(groups.into())
}

#[utoipa::path(post, path = "/addresses", tag = "Addresses")]
async fn create(
    State(state): State<Arc<ServeState>>,
    Json(input): Json<CreateAddressRule>,
) -> Result<StatusCode, ApiError> {
    let rule = input.rule;
    let cfg = state.app.cfg().await;
    let Some(managed_dir) = cfg.managed_dir() else {
        return Err(managed_dir_unavailable(&cfg));
    };

    // 🌟 抢占排他写锁：写入期间，其他读写请求全部等待
    let _guard = CONFIG_FILE_LOCK.write().await;

    if !managed_dir.exists() {
        // 🌟 修复 1：全面替换为 tokio::fs 异步 I/O
        tokio::fs::create_dir_all(&managed_dir).await?;
    }
    let file = managed_dir.join("address.conf");

    if file.exists() {
        let text = tokio::fs::read_to_string(&file).await?;
        let (_, mut config) = ConfigFile::parse(&text).map_err(|err| err.to_owned())?;

        let rules = config
            .iter()
            .enumerate()
            .flat_map(|(i, c)| match c {
                ConfigLine::Config {
                    config: ConfigItem::Address(rule),
                    ..
                } => Some((i, rule.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();

        let idx = rules
            .iter()
            .find(|r| r.1.domain == rule.domain)
            .map(|(i, _)| *i);

        if idx.is_some() {
            // 🔐 P2：重复域名是「冲突」，回 409，不能再回 500 —— 后者会误触监控告警。
            return Err(ApiError::Conflict(format!(
                "domain {} already exists",
                rule.domain
            )));
        } else {
            config.push(ConfigLine::Config {
                config: ConfigItem::Address(rule),
                comment: None,
            });
        };

        safe_write_config(&file, format!("{config}")).await?;
    } else {
        let config = ConfigItem::Address(rule);
        safe_write_config(&file, format!("{config}")).await?;
    }

    Ok(StatusCode::CREATED)
}

/// 🔐 P2：原实现是**空函数体** —— 返回 200 却什么都不做，调用方以为改成功了（静默丢写）。
/// 现在按 domain 定位并整条替换该 address 规则；找不到就回 404。
/// 注意：域名是这条规则的「键」，要改域名本身请用 DELETE + POST。
#[utoipa::path(put, path = "/addresses", tag = "Addresses")]
async fn update(
    State(state): State<Arc<ServeState>>,
    Json(input): Json<UpdateAddressRule>,
) -> Result<StatusCode, ApiError> {
    let rule = input.rule;

    let cfg = state.app.cfg().await;
    let Some(managed_dir) = cfg.managed_dir() else {
        return Err(managed_dir_unavailable(&cfg));
    };

    // 🌟 抢占排他写锁：写入期间，其他读写请求全部等待
    let _guard = CONFIG_FILE_LOCK.write().await;

    let file = managed_dir.join("address.conf");
    if !file.exists() {
        return Err(ApiError::NotFound(format!(
            "Domain {} not found",
            rule.domain
        )));
    }

    let text = tokio::fs::read_to_string(&file).await?;
    let (_, mut config) = ConfigFile::parse(&text).map_err(|err| err.to_owned())?;

    let mut replaced = 0usize;
    for line in config.iter_mut() {
        if let ConfigLine::Config {
            config: ConfigItem::Address(existing),
            ..
        } = line
            && existing.domain == rule.domain
        {
            *existing = rule.clone();
            replaced += 1;
        }
    }

    if replaced == 0 {
        return Err(ApiError::NotFound(format!(
            "Domain {} not found",
            rule.domain
        )));
    }

    safe_write_config(&file, format!("{config}")).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/addresses", tag = "Addresses")]
async fn delete(
    State(state): State<Arc<ServeState>>,
    Json(input): Json<DeleteAddressRule>,
) -> Result<StatusCode, ApiError> {
    let domain = input.domain;

    let cfg = state.app.cfg().await;
    let Some(managed_dir) = cfg.managed_dir() else {
        return Err(managed_dir_unavailable(&cfg));
    };

    // 🌟 抢占排他写锁：写入期间，其他读写请求全部等待
    let _guard = CONFIG_FILE_LOCK.write().await;

    if !managed_dir.exists() {
        return Err(ApiError::NotFound(format!("Domain {domain} not found")));
    }
    let file = managed_dir.join("address.conf");
    if !file.exists() {
        return Err(ApiError::NotFound(format!("Domain {domain} not found")));
    }

    // 🌟 替换为异步 I/O
    let text = tokio::fs::read_to_string(&file).await?;
    let (_, mut config) = ConfigFile::parse(&text).map_err(|err| err.to_owned())?;

    let idx = config
        .iter()
        .enumerate()
        .flat_map(|(i, c)| match c {
            ConfigLine::Config {
                config: ConfigItem::Address(rule),
                ..
            } if rule.domain == domain => Some(i),
            _ => None,
        })
        .collect::<Vec<_>>();

    if idx.is_empty() {
        return Err(ApiError::NotFound(format!("Domain {domain} not found")));
    }

    for i in idx.iter().rev() {
        config.remove(*i);
    }

    safe_write_config(&file, format!("{config}")).await?;

    Ok(StatusCode::NO_CONTENT)
}

// 🌟 核心修复：原子化配置文件写入，杜绝断电/强杀导致的配置清零问题
//
// 🔐 问题 13-④：**必须真正落到磁盘**，否则"原子"只做了一半。
//
// 原来是 `tokio::fs::write(tmp)` + `rename` —— 两步都没错，但缺了关键一步：
// `fs::write` 只是把数据交给**操作系统页缓存**就返回了，**没有 fsync**。
// 于是"机器掉电"时可能出现：rename 已生效（目录项指向新文件），
// 而新文件的**内容还在页缓存里没落盘** ⇒ 开机后看到一个**空的或半截的配置**。
// 这正是原注释「杜绝断电导致配置清零」想说却没说全的事 —— 注释比实现更满。
//
// 正确顺序（每一步都必要）：
//   ① 写临时文件 → ② **fsync 临时文件**（内容真的落盘）→ ③ rename（原子替换）
//   → ④ **fsync 目录**（让"改名"这个动作本身也落盘）。
// 第 ④ 步常被忽略：只 fsync 文件的话，掉电后可能"新内容已落盘、但改名还没生效"，
// 于是磁盘上仍是旧配置 —— 不算数据损坏，但与"写入已成功返回"的承诺不符。
async fn safe_write_config(file: &std::path::Path, content: String) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    // ① + ②：写临时文件并 fsync
    let tmp_file = file.with_extension("tmp");
    {
        let mut f = tokio::fs::File::create(&tmp_file).await?;
        f.write_all(content.as_bytes()).await?;
        f.flush().await?;
        // `sync_all` = fsync：把文件内容与元数据都刷到磁盘
        f.sync_all().await?;
    }

    // ③ 操作系统级原子重命名，只有写入完全成功后才会瞬间覆盖原文件
    tokio::fs::rename(&tmp_file, file).await?;

    // ④ 把"改名"这个目录操作也刷盘。
    // ⚠️ 目录 fsync 在 **Windows 上不支持**（打开目录会失败），所以只在 Unix 上做；
    // 失败也**不影响正确性**（最坏是掉电后回退到旧配置），因此只记 debug 日志、不报错。
    #[cfg(unix)]
    if let Some(dir) = file.parent() {
        match tokio::fs::File::open(dir).await {
            Ok(d) => {
                if let Err(err) = d.sync_all().await {
                    crate::log::debug!(
                        "could not fsync the directory {} after writing {}: {err} \
                         (the file itself is already durable; only the rename may not be)",
                        dir.display(),
                        file.display()
                    );
                }
            }
            Err(err) => {
                crate::log::debug!(
                    "could not open the directory {} to fsync it: {err}",
                    dir.display()
                );
            }
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
struct CreateAddressRule {
    rule: AddressRule,
}

/// PUT 的请求体：`rule.domain` 用来定位要替换的那条规则。
#[derive(Debug, Deserialize, ToSchema)]
struct UpdateAddressRule {
    rule: AddressRule,
}

#[derive(Debug, Deserialize, ToSchema)]
struct DeleteAddressRule {
    #[serde(with = "serde_str")]
    #[schema(value_type = String)]
    domain: Domain,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// 🔐 问题 13-④：配置写入必须**真正落盘**（fsync），而不是只交给页缓存。
    ///
    /// 原实现是 `tokio::fs::write(tmp)` + `rename`：两步都没错，但缺了 fsync ——
    /// 掉电时可能出现"改名已生效、内容还在页缓存里"⇒ 开机后看到一个空的/半截的配置。
    /// 原注释写的是「杜绝断电导致配置清零」，比实现更满。
    ///
    /// 这条测试验证三件事（fsync 本身**无法在单测里直接观测**，所以按可观测的等价物断言）：
    ///   ① 内容完整落盘（读回来一字不差）；
    ///   ② 临时文件**不残留**（说明确实走了 rename）；
    ///   ③ 覆盖写时**旧内容不残留**（长度不同也不能有尾巴）；
    ///   ④ 写入路径确实调用了 sync_all —— 用"调用链里出现过"来间接确认
    ///      （见下方注释：这是静态保证，不是运行时观测）。
    #[tokio::test]
    async fn config_write_is_durable_and_leaves_no_temp_file() {
        let dir = std::env::temp_dir().join(format!("smartdns-addr-fsync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("managed.conf");

        // ① 首次写入
        safe_write_config(&file, "address /a.test/1.2.3.4\n".to_string())
            .await
            .expect("写入应当成功");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "address /a.test/1.2.3.4\n",
            "内容必须完整落盘"
        );

        // ② 临时文件不得残留（残留说明 rename 没走，原子性无从谈起）
        let tmp = file.with_extension("tmp");
        assert!(!tmp.exists(), "写完后不该留下临时文件：{}", tmp.display());

        // ③ 覆盖写：换成更短的内容，旧尾巴不能残留
        safe_write_config(&file, "x\n".to_string())
            .await
            .expect("覆盖写应当成功");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "x\n",
            "覆盖写必须截断旧内容，不能留尾巴"
        );

        // ④ 用的必须是"带 fsync 的写"而不是 `fs::write`
        //    （运行时观测不到 fsync，这里用源码断言把它钉住 ——
        //     若有人把实现改回 `tokio::fs::write`，这条会失败）
        //
        // ⚠️ 判据必须**只看 safe_write_config 的函数体**，而且要**区分两种 fsync**：
        //    这个函数里有两处 `sync_all()` —— 一处刷**文件**（关键）、一处刷**目录**。
        //    只搜 "sync_all()" 会被**目录那处**蒙混过关：
        //    实测把文件的 fsync 注释掉后，断言**仍然通过**（假通过）。
        //    所以这里必须精确到 `f.sync_all()`（变量名 `f` = 临时文件句柄）。
        let src = include_str!("address.rs");
        let body_start = src
            .find("async fn safe_write_config")
            .expect("应当找得到 safe_write_config");
        let body = &src[body_start..];
        let body_end = body.find("\n}").map(|i| i + 2).unwrap_or(body.len());
        let body = &body[..body_end];
        let code: String = body
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            code.contains("f.sync_all().await"),
            "safe_write_config 必须对**临时文件**调用 sync_all（`f.sync_all()`）才能真落盘；\
             只刷目录不够 —— 掉电时可能\"改名生效、内容还在页缓存\"。实际函数体：\n{code}"
        );
        assert!(
            !code.contains("fs::write("),
            "不得退回 `tokio::fs::write`（它不 fsync），实际函数体：\n{code}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 `managed_dir` 不可用时，提示**必须给出可操作的解法**。
    ///
    /// 这是方案②的**全部价值**所在：原提示只有 `managed_dir not found` 五个词，
    /// 用户既不知道原因、也不知道 `-d` 能解决 —— 于是
    /// "地址规则功能整个不可用"这件事会变成一个查不下去的故障。
    ///
    /// 这条测试把"提示必须包含什么"钉死，避免日后被简化回一句无信息量的话。
    #[test]
    fn managed_dir_hint_tells_the_user_how_to_fix_it() {
        let msg = managed_dir_unavailable_message(None);

        // ① 保留原始关键词，便于用户/搜索引擎对上号
        assert!(
            msg.contains("managed_dir not found"),
            "应当保留原有错误关键词（便于检索与日志匹配），实际: {msg}"
        );

        // ② 必须给出**具体**的解决办法 `-d`
        assert!(
            msg.contains("-d "),
            "🔐 提示必须给出 `-d` 这个解法 —— 否则用户只能看到「功能坏了」，无从下手。实际: {msg}"
        );

        // ③ B-① 之后：不再推荐"把配置放进名叫 smartdns 的目录" —— 那条自动推导条件
        //    已被"配置文件所在目录"取代，再写会误导用户做无用功。
        //    改为推荐"给出带目录的配置路径"（这才是 B-① 之后真正有用的第二条出路）。
        assert!(
            !msg.contains("directory named `smartdns`"),
            "🔐 B-① 之后不该再推荐「把配置放进名为 smartdns 的目录」——\
             该推导条件已被放宽取代，这条建议会让人白折腾。实际: {msg}"
        );
        assert!(
            msg.contains("includes its directory"),
            "应当给出 B-① 之后真正有用的第二条出路：让 `-c` 的路径带上目录。实际: {msg}"
        );

        // ④ 说得足够具体：至少给一个可照抄的 `-c` 路径示例
        assert!(
            msg.contains("-c /path/to/smartdns.conf"),
            "提示里应当有一个可照抄的启动示例。实际: {msg}"
        );
    }

    /// 🔐 "有 `conf_dir` 却拿不到 `managed_dir`"是**不该发生**的内部矛盾：
    /// 此时提示应当让用户报障，而不是给一个明显不对的解法（让他去传 `-d`，
    /// 而他其实已经传了 —— 会白折腾一轮）。
    #[test]
    fn managed_dir_hint_distinguishes_the_internal_inconsistency_case() {
        let msg = managed_dir_unavailable_message(Some(Path::new("/etc/smartdns")));

        assert!(
            msg.contains("/etc/smartdns"),
            "应当把已确定的配置目录报出来（便于用户核对）。实际: {msg}"
        );
        assert!(
            msg.contains("please report"),
            "这是内部矛盾，应当引导用户报障。实际: {msg}"
        );
        assert!(
            !msg.contains("-d <config-dir>"),
            "已经确定了配置目录时，不该再让用户去传 `-d`（那是无效建议）。实际: {msg}"
        );
    }
}
