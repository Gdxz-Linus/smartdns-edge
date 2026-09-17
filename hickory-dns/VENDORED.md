# 内嵌依赖（vendored）说明 —— hickory-dns

> 一句话：**这个目录是本项目自己的代码。** 本文件记录两件事：它是从哪来的、以及我们改过它什么。
> **第 4 节的改动清单是核心**，其余各节只解释背景与边界。

## 一、为什么内嵌，以及由此确定的原则

**这是本项目的既定原则，不是权宜之计。**

- 我们需要在 DNS 报文解析这一层做**必要的定制修改**（下面第 4 节列了已经做的），
  而 `crates.io` 上的正式发行版不提供这个能力：改不了上游的接线，就只能绕。
- 因此 **本仓库只使用这里的内嵌副本**，不以"改用公开发行版依赖"为出路。

**按此原则，下列事情本项目明确不做**（2026-09-15 确认）：

| 不做的事 | 理由 |
|---|---|
| 不追上游版本、不要求可追溯来源 | 它已经是我们的代码；"它当年对应上游哪个提交"不影响我们怎么维护它 |
| 不启用任何自动更新（dependabot / `cargo update` / RUSTSEC 自动告警） | 这些渠道对 `path` 依赖本来就无效，也不需要 |
| 不把"与上游同步"当作既定动作（没有季度/月度节奏、没有待办事项） | 只在针对性的安全通告出现时才临时处理，见第 5 节 |

**已知代价（记录事实，不作为待办）**：`0.26.0-alpha.1` 不在 RUSTSEC / crates.io 漏洞公告的覆盖范围内，
所以"这个库有没有已知漏洞"这件事，本项目**不通过自动渠道回答**。若外部出现明确指向 hickory-dns 的通告，
按第 5 节的应急流程处理即可 —— 那是应急手段，不是日程。

## 二、这份副本的来源

| 项目 | 内容 |
|---|---|
| 上游仓库 | `hickory-dns`（https://github.com/hickory-dns/hickory-dns ） |
| 上游版本号 | `0.26.0-alpha.1`（**已发布到 crates.io 的预发布版**；但我们这份副本的内容与该发布版不同，见下） |
| 拷入本仓库的时间 | 2026-06-28 |
| 拷入本仓库的提交 | `3b2c655fc49bf2a3d7e8a7c7eb20570c6d210f15`（"update"） |
| 拷入范围 | 仅 `crates/proto` 与 `crates/resolver` 两个 crate（共 **170** 个受 git 跟踪的文件） |
| **未**拷入的部分 | `crates/recursor`、上游的 `tests/` 集成测试目录 |
| 依赖方式 | 根 `Cargo.toml` 以 `path` 依赖引用（`hickory-proto`、`hickory-resolver`） |

### 内容来源的核实结论（2026-09-15 一次性调查，**终态**）

这里原本写着"待补"。已经花一次工查清了，结论是**不可追溯**；按第 1 节的原则，这件事到此为止，不再继续追：

- **内容确实源自上游 hickory-dns**：两个未改动文件的 blob 能在上游历史里精确命中 ——
  `crates/proto/src/lib.rs` → `70e40a1c66fae6ad0ee9afa5bb8d0e0bab5d318b`（2025-08-12）、
  `crates/proto/src/rr/lower_name.rs` → `1272852e285a274613ee3577783b67dbe15101a7`（2025-09-04）。
- **但它不是任何公开提交的干净快照**。已实测排除：
  ① 上游 hickory-dns 的**所有**分支/tag 尖端；
  ② `mokeyish/smartdns-rs`（本项目 README 点名的"基础项目"）—— 该仓库**根本没有 `hickory-dns` 目录**；
  ③ crates.io 发布的 `hickory-proto 0.26.0-alpha.1` —— 144 个文件同名同数，但 **28 个内容不同且是双向差异**
  （`dnssec/dnssec_dns_handle/mod.rs` +202/−168、`op/message.rs` +96/−90 …）。
- **决定性判据**：抽 **10 个我们从未改动过的文件**，在上游 main 的 2025-05-27 ～ 2025-08-29 六个候选提交上比对，
  **每个日期都有 6～10 个对不上**（10/10、9/10、6/10、8/10、8/10、8/10）；全量 170 文件的最小差异数是 49。
  差异数**逐日变化**、且部分文件能在某些提交上精确匹配 → 不可能是换行符/编码之类的假差异，
  而是**内容本身是混合状态**（像是从不同时间点/不同分支拼起来的，或某个 fork 带着自己的改动）。

⇒ **结论：不能靠"与上游 diff"来审计这个目录。** 第 4 节的清单是唯一可信的记录 —— 这就是为什么第 4 节必须维护。

（若哪天真的想复核上面这个判断，最小代价的办法：clone 上游，取任意 main 提交 `C`，抽 10 个未改动文件，
逐个比对 `git -C <本仓库> hash-object <文件>` 与 `git rev-parse "$C:<对应路径>"`。）

## 三、副本内容指纹（用于核对第 4 节有没有漏记）

以下两个文件**至今未被本地修改**，其 blob 指纹即等于拷入时的内容：

| 文件 | blob SHA-1 |
|---|---|
| `crates/proto/src/lib.rs` | `a9860b57b7a277ccad0d5c8c157f9814edf5fe2f` |
| `crates/resolver/src/lib.rs` | `bcd913c244723f97fa441b0105763d442a1ec6e3` |

## 四、我们对内嵌副本做过的修改（逐条）

> **这是本文件最重要的一节。** 因为不再与上游比对，这里是唯一能说明"我们改过什么"的记录。
> 规则：**每改一处，就在这里加一行**。带 `P0-x` / `P1-x` 编号的是 2026-09-14 审计报告的条目。

### 4.1 `Cargo.toml`（workspace 清单修复）

- **改动**：`members` 去掉 `crates/recursor`、补上 `crates/resolver`；
  删除 `hickory-recursor`（指向未拷入的目录）与 `test-support.path = "tests/test-support"`
  （既指向未拷入的目录，写法本身也不合法）。
- **原因**：原样拷贝的清单让**任何**读取它的工具都失败
  （`cargo metadata --no-deps --manifest-path hickory-dns/Cargo.toml` 退出码 101，
  `cargo fmt` 直接报错），该目录完全无法单独构建 / 测试。
- **验证**：修复后 `cargo metadata` 退出码 0。

### 4.2 `crates/proto/src/tcp/tcp_stream.rs`（P0-5）

- **改动**：新增 `const READ_CHUNK: usize = 4096`；`ReadTcpState::Bytes` 增加 `planned` 字段；
  读取时**按需分块增长**，不再按长度前缀声明的长度一次性 `vec![0; length]`。
- **原因**：DNS over TCP/DoT 的长度前缀只有 2 字节、最大可声明 65535 字节。
  攻击者只发 2 字节就能让服务端白占 64 KiB，可被远程用于耗尽内存。

### 4.3 `crates/proto/src/quic/quic_stream.rs`（P0-5）

- **改动**：与 `tcp_stream.rs` 同理，新增 `const READ_CHUNK: usize = 4096`，改为分块读取，
  `BytesMut::with_capacity(len.min(READ_CHUNK))`。
- **原因**：DoQ 同样不允许按客户端声明的长度预分配内存。

### 4.4 `crates/proto/src/udp/udp_stream.rs`（P1-9）

- **改动**：`connect_with_bind()` 中**恢复真正的 `socket.connect(addr)`**。
- **原因**：上游原版把这一行注释掉了（`// TODO: research connect more, it appears to break
  UDP receiving tests`），导致该函数的文档承诺（"will only receive packets from the associated
  address"）完全落空：套接字保持未连接状态，**任何能到达该临时端口、猜中 16 位事务 ID 的主机
  都能注入伪造应答**。本项目内嵌此库，正是为了能改这类"契约没兑现"的地方。
- **说明**：上游担心的是它自己的 UDP 接收测试（那些测试从另一个套接字发包），与生产语义无关；
  本项目未用到该代码路径的行为不变（未连接 = 与修复前一致）。

### 4.5 `crates/proto/src/xfer/dns_response.rs`（修一个编译期缺陷：no_std 构建直接失败）

- **改动**：把两个**被错误门控的导入**改为无门控 ——
  `#[cfg(feature = "std")] use alloc::boxed::Box;` → `use alloc::boxed::Box;`；
  `#[cfg(feature = "std")] use crate::{ProtoErrorKind, error::ProtoResult};` →
  `use crate::ProtoErrorKind;` + 单独的 `#[cfg(feature = "std")] use crate::error::ProtoResult;`
  （`ProtoResult` 只在 std 门控的 mpsc 代码里用到，保持门控）。
- **原因**：`DnsResponse::new_with_checked()` **不在任何 `#[cfg(feature = "std")]` 块里**，
  却无条件使用了 `Box::new(…)` 与 `ProtoErrorKind::FormError`；而这两个名字只在 std 门控的
  导入里出现。于是 `--no-default-features`（即 no_std）构建必然失败：

  ```
  error[E0433]: cannot find type `Box` in this scope
  error[E0433]: use of undeclared type `ProtoErrorKind`
  ```

  这是上游 alpha 阶段迁移 no_std 时留下的疏漏（本项目当初想单独构建内嵌 dhcproto 时才暴露出来）。
- **验证**：`cargo check -p hickory-proto --no-default-features` 通过
  （实测：修复前报上面两个错，修复后 `Finished`）。
  补充：no_std 下还会剩 **1 条 dead_code 警告**（`xfer/retry_dns_handle.rs:78` 的
  `struct RetrySendStream` 在该特性组合下从未被构造），无功能影响，也未改动。
- **另一个表现**：修好后 no_std 的**编译**通了，但**链接**宿主程序仍会失败
  （原因见下条），所以"用 no_std 跑测试"仍然不可行 —— 这不是本缺陷的残留。
- **已知边界**：no_std 下**链接**宿主测试程序仍会失败，原因是 hickory 在 no_std 里依赖
  `critical-section`，需要平台实现 `critical_section_1_0_acquire/release` 符号
  （嵌入式目标由对应的 impl crate 提供）。这是 no_std 的固有要求，不是本缺陷，**本项目不使用 no_std**。

### 4.6 拷进来时就带着的改动（**不是我们改的**，内容已无法追溯）

这份副本**不是干净的上游快照**（第 2 节已证明）。除了我们改的那几处之外，还有一批文件在**拷贝进来的时候就已经被人改过**了 —— 我们没有它们的原始版本可比对，也没法说清"改了哪些、为什么改"。所以这一节只做一件事：**把范围写清楚**，免得以后有人误以为"这个目录就等于上游原版"。

**这个清单是怎么来的（谁都能自己跑一遍）**：

```bash
cd D:/smartdns-edge

# ① 我们自己动手改过的文件：从拷贝提交 3b2c655 到现在的差异
git diff --stat 3b2c655 HEAD -- hickory-dns
#   结果只有这几个，全部在第 4 节有记录：
#     hickory-dns/Cargo.toml                        → 4.1
#     hickory-dns/VENDORED.md                       → 本文件
#     crates/proto/src/tcp/tcp_stream.rs            → 4.2
#     crates/proto/src/quic/quic_stream.rs          → 4.3
#     crates/proto/src/udp/udp_stream.rs            → 4.4
#     crates/proto/src/xfer/dns_response.rs         → 4.5

# ② 另一条线索：内嵌目录里出现中文注释的文件
#    （上游 hickory-dns 是英文项目，冒出中文只可能是本地人改过）
grep -rlP '[\x{4e00}-\x{9fff}]' hickory-dns/crates/
```

把 ② 里属于 ① 的挑出去，剩下的就是**拷入时就带着改动、我们从未动过**的文件 —— **8 个，全部在 resolver**：

| 文件 | 中文注释行数 | 抽样看到的内容 |
|---|---|---|
| `crates/resolver/src/cache.rs` | 3 | `use crate::lookup::Lookup; // 🌟 引入 Lookup` |
| `crates/resolver/src/caching_client.rs` | 3 | `// 🌟 核心优化：直接从缓存中获取 Lookup，0 拼装开销！` |
| `crates/resolver/src/hosts.rs` | 5 | `// 🌟 优化 1：一次性将整个文件内容读入单个大 String 中…` |
| `crates/resolver/src/lookup.rs` | 1 | `pub(crate) records: Arc<[Record]>, // 🌟 开放给同 crate 的缓存模块…` |
| `crates/resolver/src/lookup_ip.rs` | 4 | `// 🌟 优化：改用无堆分配的 Either 双路选择器` |
| `crates/resolver/src/resolver.rs` | 8 | `use futures_util::future::Either; // 🌟 新增导入` |
| `crates/resolver/src/name_server/name_server.rs` | 4 | `// 🌟 性能优化：接收外部统一传入的时间戳，消灭高频系统调用` |
| `crates/resolver/src/name_server/name_server_pool.rs` | 8 | `// 🌟 辅助枚举：用于控制处理后的流程走向，极简优雅` |

> 另外有两个文件（`crates/proto/src/dnssec/roots/20326.rsa`、`38696.rsa`）也会被上面那条 `grep` 命中，
> 它们是二进制内容被正则碰巧匹配上的**误报**，已核对排除，不计入这份清单。

**边界声明（这一段很重要）**：

- 这 8 个文件里的改动**不在第 4 节的账本内**，原始版本不可追溯（原因见第 2 节）。
- 所以：**不要把它们当成"上游原版"**，也不要拿它们跟任何上游提交做比对 —— 比出来的差异，既不能算在我们头上，也不能证明干净。
- 将来如果真要从上游挑补丁进来（第 5 节），**这 8 个文件必须一个一个人工核对，不能整目录覆盖粘贴**。

## 五、（应急用，默认不做）如果哪天要从上游取一个修复

默认**没有**同步日程、也没有待办。只有在"外部明确通告 hickory-dns 有安全问题、且影响我们用到的路径"时，
才临时做一次：

1. clone 上游，按提交信息找到那个修复（`git log --oneline -- crates/proto crates/resolver`）；
2. **只把那个补丁挑进来**，不要整目录覆盖粘贴 —— 那会把第 4 节的改动冲掉；
3. 回归：`cd hickory-dns && cargo test -p hickory-proto`（以及 `-p hickory-resolver`）。
   内嵌副本**自带上游单测**（`crates/proto/src/tests/`、`crates/resolver/src/tests.rs`，
   共 **400** 处 `#[test]` / `#[tokio::test]`），所以"改了内嵌库没法验证"并不成立；
   跑完再在主仓库跑一次单元测试。
4. 把这次改动**补记进第 4 节**（哪怕只是"把上游某提交的补丁挑进来了"）。

## 六、与 dhcproto 的关系（"两个 DNS 报文解析器"问题已解决）

- **已解决**：上游 `dhcproto` 原先从 crates.io 拉了一份 `hickory-proto 0.25.2`，
  与本内嵌副本并存 —— 等于两个 DNS 报文解析器同时处理外部输入。
  现在 **`dhcproto` 也已内嵌**（见 `dhcproto/VENDORED.md`），其 `hickory-proto` 依赖指向
  **本目录**，全图只剩这一个 hickory-proto。验证：
  `cargo tree -i hickory-proto` 只输出一项；`cargo tree -i hickory-proto@0.25.2` 报
  "did not match any packages"。
- **为适配 0.26 而对上游代码做的唯一一处修改**在 dhcproto 侧
  （`src/v4/options.rs` 的 FQDN 编码，见 `dhcproto/VENDORED.md` 第 3.2 节）。
- 试过用根 `Cargo.toml` 的 `[patch.crates-io]` 直接替换 0.25.2，**实测无效**：
  补丁版本必须满足依赖方的版本要求，`0.26.0-alpha.1` 不满足 `^0.25.2`，cargo 会忽略补丁。

## 七、注意事项（事实记录）

- **预发布版本不在漏洞公告的覆盖范围内**：`0.26.0-alpha.1` 不被 RUSTSEC / crates.io 覆盖；
  按第 1 节的原则，本项目**不通过自动渠道**跟踪它（这是原则的既定代价，不是待办）。
- **第 4 节的清单是唯一的"账本"**：这个目录不再有"上游"可对照，所以一旦第 4 节与代码不一致，
  就等于失去了唯一能说明"里面有什么"的记录 —— **这是本目录维护上唯一真正的红线**。
- **补充（2026-09-17）：第 4.6 节是"边界声明"**：那 8 个 `resolver` 文件的改动是**拷贝进来时就带着**的、
  内容不可追溯，它们**不在账本内**。别把它们当上游原版，也别拿它们去跟上游比对（理由与复核命令都在 4.6 节）。
