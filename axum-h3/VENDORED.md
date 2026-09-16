# 内嵌副本：axum-h3

**来源**：crates.io 的 [`axum-h3`](https://crates.io/crates/axum-h3) **0.0.6**（截至内嵌时是**最新版**；2026-07-20 发布）
**上游仓库**：https://github.com/youyuanwu/tonic-h3
**许可证**：MIT（发布包 `axum-h3-0.0.6.crate` 里**没有附 LICENSE 文件**，许可证正文见上游仓库根目录 —— 内嵌时保持原样、未改动其授权声明）
**内嵌方式**：解包 `.crate` 后放入本目录，`Cargo.toml` 里以 path 依赖引用（`axum-h3 = { path = "axum-h3" }`）。

> 为什么内嵌：**它的上游至今没把"客户端对端地址"传给下游**，导致 DoH3 路径上
> "基于客户端 IP 的规则"完全不生效、审计日志里的来源地址失真（审计报告 P2 的中间件/传输层条目）。
> 上游源码里那行本可以做这件事的代码从 0.0.1 到 0.0.6 一直是**注释状态**：
>
> ```rust
> let svc = tower::ServiceBuilder::new()
>     //.add_extension(Arc::new(ConnInfo { addr, certificates }))   // ← 上游注释掉了
>     .service(svc);
> ```

---

## 一、本地改动（与上游 0.0.6 的**全部**差异）

只有一处功能改动，都在 `src/lib.rs`：

1. **新增 `PeerAcceptor` trait**（替代上游 `h3_util::server::H3Acceptor` 这个边界）。
   差别是 `accept()` 会**一并返回对端地址** `Option<SocketAddr>`。
   为什么要换掉上游那个 trait：`h3_quinn::Connection` 把内部的 `quinn::Connection` 藏成了私有字段、
   没有任何公开访问器，所以**"接受连接"这一步是唯一能拿到客户端地址的时机**，
   必须在这个边界上把它顺手带出来。
2. **`serve_request()` 增加 `peer: Option<SocketAddr>` 参数**，并把它注入请求扩展：

   ```rust
   if let Some(addr) = peer {
       parts.extensions.insert(axum::extract::ConnectInfo(addr));
   }
   ```

   `axum::serve` 在 HTTP/1、HTTP/2 路径上注入的正是这个类型的扩展，
   所以下游 Handler 照常写 `ConnectInfo<SocketAddr>` 就能拿到**真实客户端地址**，两种协议行为一致。
3. 其余为文档注释（在文件头写清本改动）+ `Cargo.toml` 精简（去掉发布包自动生成的
   `autolib/autotests/...` 规范化开关，只保留构建需要的包信息与依赖）。

**除此之外与上游逐字节相同** —— 想核对时，拿同版本 `.crate` 解包后与本目录 diff 即可
（`curl -sSL https://static.crates.io/crates/axum-h3/axum-h3-0.0.6.crate | tar -xzO axum-h3-0.0.6/src/lib.rs`）。

## 二、调用方需要配合的地方（本项目内）

- `src/server/h3.rs` 里实现 `axum_h3::PeerAcceptor`（`QuinnPeerAcceptor`）：
  用 `quinn::Endpoint::accept()` 拿到 `Incoming`，握手成功后取 `conn.remote_address()`，
  再包成 `h3_quinn::Connection` 交给上层。**不要再往 router 上塞 0.0.0.0 的假 `ConnectInfo`**。
- 依赖版本必须配套：`h3-util` 要 >= 0.0.6（本副本的 `Cargo.toml` 要求 `^0.0.6`），
  否则会出现两个 `h3-util`、`h3_util::Error` 变成不同类型而编译不过。
  另外 `h3-util 0.0.3` 曾声明 `tokio features = ["full"]`（顺手替我们养着 `tokio::fs`），
  0.0.6 把它收窄了 —— 所以本项目自己的 `tokio` 依赖里**必须显式写清要用的 feature**（见根 `Cargo.toml`）。

## 三、验证方式

`D:\Hermes\Documents\smartdns-edge-e2e\run_p2h3.py`：真 QUIC/HTTP3 客户端（aioquic）打真实二进制，
用"只对 `127.0.0.0/8` 生效的客户端规则"判别来源地址是否真的传下去了
（拿到 → 走规则组返回 9.9.9.9；拿不到 → 落回默认组 10.0.0.1）。
判定以服务端日志为决定性证据：`src:https://127.0.0.1#<port>`（改造前是 `0.0.0.0:0`）。

## 四、更新方式（应急用，默认不做）

内嵌即自有代码：**不追上游、不自动同步**。若确实需要升级：
1. 下载新版本 `.crate` 解包，与本目录 diff，确认上述三处改动仍然必要（上游若自己补了 ConnInfo，就把我们的改动去掉、直接用上游版本）；
2. 覆盖 `src/`，按"一、本地改动"重放那三处；
3. 同步升 `h3-util` 到配套版本；
4. 跑 `run_p2h3.py` 确认客户端地址仍然正确传递。
