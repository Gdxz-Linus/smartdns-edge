# 内嵌副本：surge-ping

**来源**：crates.io 的 [`surge-ping`](https://crates.io/crates/surge-ping) **0.8.2**（异步 ICMP ping 库）
**上游仓库**：https://github.com/kolapapa/surge-ping
**许可证**：MIT
**内嵌方式**：源码放入本目录，`Cargo.toml` 里以 path 依赖引用（`surge-ping = { path = "./surge-ping" }`）。

> 为什么内嵌：**测速里的 ICMP 探测走的就是它**（`src/infra/ping.rs` 用 `surge_ping::{Client, Config, Pinger}`）。
> 与 hickory-dns / dhcproto / axum-h3 一样，内嵌的目的是"需要时可改"，不再跟踪上游、不接自动更新。

## 本目录的改动清单（逐条）

### 1. `LICENSE`（补上许可证正文）

- **改动**：新增 MIT 许可证正文（+21 行），此前本目录只有 `Cargo.toml` 里的 `license = "MIT"` 声明、
  没有任何许可证文本与版权声明。
- **依据**：2026-09-14 审计报告「许可证合规」条目 —— 声明 MIT 却未随附正文。相邻的内嵌副本
  （hickory-dns 的两个许可证）当时是保留完整的，因此这一处属遗漏。
- **核对方式**：`head -2 surge-ping/LICENSE` 应显示 `MIT License`。

### 2. `src/client.rs`（内嵌时即有的实质改动，2026-10-14 审计补记）

这些改动在审计基线 `41ebf9f` **之前**就存在（内嵌时对上游 0.8.2 做的），首次建账时
误写为"一字未动"，此处补记：

- **`set_ttl_v4` 支持**（`Client::new` 内，`config.ttl` 非空时调用）——上游 0.8.2
  没有 TTL 设置能力；主仓测速需要指定探测包 TTL。
- **`RecvTaskGuard` 守卫体系**（结构体 + Drop abort + `Client._recv` 字段）——上游
  原版把收包任务的 `JoinHandle` 直接丢弃，任务随 Client 克隆而失控（永不中止、
  泄漏）；守卫保证最后一个 Client 引用释放时收包任务被 abort。

### 3. `src/ping.rs`（内嵌时即有的实质改动，同上补记）

- **`last_sequence` 跟踪与清理**（`Pinger` 内）——记录最后一次发送的序号，收到应答
  或超时后清空，避免 Drop 时对已完成的请求再做多余的锁请求。

### 4. `Cargo.toml`（内嵌时即有的改动，同上补记）

- **新增依赖 `socket2`**（features = ["all"]）——`set_ttl_v4`/`bind_device` 等
  socket 细粒度控制经由它实现。
- **保留 `[[example]]` 段**：上游的 examples/ 源文件未随副本带入，段声明待清理
  （见修复台账 R-P3-14）。

### 5. 源文件数量更正

本目录 `src/` 下实际为 **8 个 `.rs` 源文件**（含 `icmp/` 子目录 3 个），首次建账时
写"9 个"有误。

## 与主仓的关系

| 问题 | 结论 |
|---|---|
| 用到多少 | 只在 `src/infra/ping.rs` 里用于 ICMP 测速；`app.rs` 里关于线程池的注释也提到它（那处注释已按实情更正） |
| 是否 workspace 成员 | **不是**，与其它三个内嵌副本一样，是独立的 path 依赖包 |
| 依赖更新提醒 | `dependabot.yml` 只覆盖仓库根（`directory: "/"`），不覆盖本目录 —— 这是**刻意**的：内嵌副本按项目定调不再跟踪上游 |

## 维护约定

改本目录任何一处，就在上面的「改动清单」里加一条 —— 与 `hickory-dns/VENDORED.md`、`dhcproto/VENDORED.md`、
`axum-h3/VENDORED.md` 同一规矩：内嵌副本不与上游比对，这份清单是唯一可信记录。
