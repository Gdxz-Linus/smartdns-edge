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

### 2. 未改动其它文件

除上面的 `LICENSE` 外，本目录的 9 个源文件与 `Cargo.toml` **一字未动**（审计基线 `41ebf9f` 以来的
`git diff --numstat 41ebf9f..HEAD -- surge-ping` 只有 `LICENSE` 一行，+21/−0）。

## 与主仓的关系

| 问题 | 结论 |
|---|---|
| 用到多少 | 只在 `src/infra/ping.rs` 里用于 ICMP 测速；`app.rs` 里关于线程池的注释也提到它（那处注释已按实情更正） |
| 是否 workspace 成员 | **不是**，与其它三个内嵌副本一样，是独立的 path 依赖包 |
| 依赖更新提醒 | `dependabot.yml` 只覆盖仓库根（`directory: "/"`），不覆盖本目录 —— 这是**刻意**的：内嵌副本按项目定调不再跟踪上游 |

## 维护约定

改本目录任何一处，就在上面的「改动清单」里加一条 —— 与 `hickory-dns/VENDORED.md`、`dhcproto/VENDORED.md`、
`axum-h3/VENDORED.md` 同一规矩：内嵌副本不与上游比对，这份清单是唯一可信记录。
