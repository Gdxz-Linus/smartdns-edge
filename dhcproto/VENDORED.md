# 内嵌依赖（vendored）说明 —— dhcproto

> 与 `hickory-dns/VENDORED.md` 同一套规则：**这个目录是本项目自己的代码。**
> 本文件记录两件事：它是从哪来的、以及我们改过它什么（**第 3 节的改动清单是核心**）。
> 按项目原则（见 `hickory-dns/VENDORED.md` 第 1 节）：**不追上游版本、不启用自动更新、不把同步当既定动作。**

## 一、为什么内嵌

两条理由，第二条才是主因：

1. **项目原则**：需要在必要的第三方代码上直接改（`hickory-dns` 同此原则）。
2. **只保留一份 DNS 报文解析器**：上游 `dhcproto 0.13.0` 把
   `hickory-proto = { version = "0.25.2", default-features = false }` 写成了**非可选依赖**，
   于是同一个二进制里同时存在两份 hickory-proto：
   - 本仓库内嵌的 `0.26.0-alpha.1`（path）
   - crates.io 拉来的 `0.25.2`（registry）

   等于**两个独立的 DNS 报文解析器同时处理不可信输入**，安全更新路径还各自割裂。
   把 dhcproto 也内嵌、让它指向本仓库那一份，全图就只剩一个 hickory-proto 了。

> 试过但**不行**的办法：在根 `Cargo.toml` 写
> `[patch.crates-io] hickory-proto = { path = "./hickory-dns/crates/proto" }`。
> 实测无效 —— 补丁版本必须满足依赖方的版本要求，而 `0.26.0-alpha.1` 不满足 `^0.25.2`，
> cargo 会直接忽略该补丁（`cargo tree -i hickory-proto@0.25.2` 依然命中）。

## 二、来源

| 项目 | 内容 |
|---|---|
| 上游仓库 | `dhcproto`（https://github.com/bluecatengineering/dhcproto ） |
| 上游版本 | **正式发布版 `0.13.0`**（不是预发布版） |
| 拷入本仓库的时间 | 2026-09-15 |
| 来源 | crates.io 的发布包（本机 registry 缓存 `dhcproto-0.13.0`） |
| 拷入范围 | `src/`（18 个 `.rs`，共 6666 行）+ `LICENSE` / `README.md` / `CHANGELOG.md` |
| **未**拷入 | `benches/`、`rust-toolchain`（避免在本目录内钉死工具链）、上游的 `Cargo.lock` 与 `Cargo.toml.orig` |
| 依赖方式 | 根 `Cargo.toml`：`dhcproto = { path = "./dhcproto" }`；实际使用点只有 `src/infra/dhcp.rs`（DHCPv4 解析/编码） |

**因为拷入的是正式发布版，所以"上游基线"就是 crates.io 上的 `0.13.0` 这个版本本身**，
不需要像 `hickory-dns` 那样去反查 commit SHA —— 随时可以下载 `0.13.0` 的发布包与本目录 diff。

## 三、本地改动清单（逐条）

> 规则同 `hickory-dns/VENDORED.md`：**每改一处就在这里加一行**。

### 3.1 `Cargo.toml`（唯一实质改动）

```toml
# 上游：
hickory-proto = { version = "0.25.2", default-features = false }
# 本地：
hickory-proto = { path = "../hickory-dns/crates/proto", features = ["std"] }
```

两处调整及其理由：

- **改成 path**：这就是"只保留一份 hickory-proto"的关键动作。
- **`default-features = false` 改为 `features = ["std"]`**（两处说明）：
  1. 上游写 `default-features = false` 是为了 no_std 兼容，**而本仓库内嵌的 hickory-proto 原先在
     no_std 下根本编译不过**（`xfer/dns_response.rs` 的 `Box` / `ProtoErrorKind` 导入被错误门控）。
     该缺陷已在 **`hickory-dns/VENDORED.md` 第 4.5 节**修好，现在 no_std 的 **编译**（`cargo check`）
     是通的；但 no_std 下**链接**宿主程序还需要 `critical-section` 的平台实现（嵌入式才有），
     所以 dhcproto 单独跑测试会链接失败。
  2. 因此这里仍显式要 `std`：本项目只用 std，且主构建里 `std` 本来就是开着的
     （`hickory-resolver` 的默认特性带来了它，可用 `cargo tree -e features -i hickory-proto` 确认）
     —— **对 smartdns 的构建结果没有任何影响**；好处是本目录能单独编译、单独跑它自带的 43 个单测。

顺带去掉上游的 `[dev-dependencies]`（criterion / serde_json）与两个 `[[bench]]` 段
—— 因为 `benches/` 未拷入，留着会因找不到 bench 目标而报错。

### 3.2 `src/v4/options.rs`（适配 0.26 的 API 变化）

内嵌的 hickory-proto 0.26 移除了 `Name::emit_as_canonical(&mut enc, canonical)`，
改由**编码器**决定大小写与压缩。FQDN 选项（option 81）的"规范格式"编码因此改为：

```rust
// 上游（hickory-proto 0.25）：
domain.emit_as_canonical(&mut name_encoder, true)?;
// 本地（hickory-proto 0.26）：
name_encoder.set_name_encoding(NameEncoding::UncompressedLowercase);
domain.emit(&mut name_encoder)?;
```

语义等价：`canonical = true` 就是"标签转小写 + 不压缩"，正是 `UncompressedLowercase`。
（对应地，文件头的 `use` 里多引了 `NameEncoding`。）

**这是全仓库唯一一处为了适配 0.26 而改的上游代码。** 如果将来上游 dhcproto 支持了
hickory-proto 0.26，这一处补丁就可以直接丢掉。

### 3.2.1 坏选项降级（2026-10-19）

`DhcpOption` 单项解析失败时降级为 `Unknown`，保留原始 code 与载荷；遇到下一个
不同选项或 `End` 后仍会继续解析后续选项，避免一个畸形 DHCP 选项提前终止整个
`DhcpOptions` 解析。

### 3.3 解码健壮性加固（2026-10-13，R-P1-3 + R-P2-12 附属）

背景：审计发现三类畸形输入问题，全部按"构造的畸形报文单测断言不崩溃"验证：

1. **`src/v4/mod.rs` Message::decode 补 magic cookie 校验**：上游留有
   `// TODO: check magic bytes against expected?`，本仓库补上——magic 不等于
   `MAGIC` 即返回 `DecodeError`。任意非 DHCP 的 UDP 垃圾包在入口即被拒绝。
   同时把 decode 重写为先取值再构造 `Message` 的形式（原先的 struct 字面量里
   没法插入校验逻辑）。
2. **`src/v4/options.rs` ClasslessStaticRoute（option 121）**：原先
   `Ipv4Net::new(...).unwrap()`——host 位非零（如 /23 前缀的 dest 第 3 字节最低位为 1）
   时直接 panic。改为先按前缀掩零主机位（宽容解析）再构造，构造失败返回
   `DecodeError`。调用方（smartdns 主程序 `src/infra/dhcp.rs`）本就主动请求该选项，
   局域网内一个畸形 OFFER 即可打崩解析任务，属必改。
3. **六处 `len - N` 下溢防护**（v4：BulkLeaseQueryStatusCode、ClientFQDN；
   v6：Authentication、StatusCode、VendorClass、VendorOpts）：畸形长度字段
   （如 option 151 len=0）原先在 release 下因回绕触发 read_slice 失败使整个
   options 解码静默截断、debug 下溢出 panic；现统一先判 `len < N` 返回
   `DecodeError::NotEnoughBytes`。

新增 5 个单测（option 121 host 位掩零 / /24 对齐回归 / option 151 len=0 /
option 81 len=2 / 坏 magic），`cargo test`＝48 过 / 0 败（+17 文档测试全过）。
对 smartdns 的使用无接口变化。


### 3.4 chaddr 越界与 DHCPv6 短选项解码加固（2026-10-28，批次二十 68/70）

- **`src/v4/mod.rs` `Message::chaddr()`**：`hlen` 来自报文且未经校验，原实现直接
  `&self.chaddr[..hlen]`，当 `hlen > 16` 时切片越界 panic。改为按 `chaddr` 字段长度
  截断，畸形 `hlen` 不再能打崩解析。
- **`src/v6/options.rs` StatusCode / VendorClass**：补齐 `len < 2` / `len < 4` 的
  前置校验，避免 `len - N` 在 debug 构建下溢出 panic、release 构建下回绕成巨大长度。
- 新增 3 个单测：`chaddr` 超大 `hlen`、短 StatusCode、短 VendorClass。

### 3.5 内嵌模块编码/解码加固（2026-10-28，批次二十一 71/72）

- **`src/v4/options.rs` BulkLeaseQueryStatusCode（option 151）编码**：消息超过
  254 字节时，原实现 `msg.len() as u8 + 1` 会静默截断长度字段，但实际仍写入完整
  消息，导致解码方按错误长度读取、后续选项全部错位。现在按 254 字节截断消息本体
  （UTF-8 字符边界安全），保证长度字段与实际写入字节数一致，并输出截断告警。
- **`src/decoder.rs` `read_domains`**：原实现 `while let Ok(...)` 把任何解码错误都
  当作正常结束，畸形域名之后的列表项被静默丢弃。现在区分"无剩余字节"与"解码失败"，
  后者如实返回错误。
- 新增 2 个单测：option 151 超长消息长度字段一致性、`read_domains` 损坏输入报错。

## 四、验证方式

统一到内嵌版本后，这几条必须成立（改完顺手跑一次）：

```bash
cargo tree -i hickory-proto          # 必须只有一个（0.26.0-alpha.1，路径在本仓库内）
cargo tree -i hickory-proto@0.25.2   # 必须报 "did not match any packages"
cargo test                           # 根包全绿

# 本目录自带的单测（43 处 #[test] + 17 个文档测试）也能单独跑：
cd dhcproto && CARGO_TARGET_DIR="$LOCALAPPDATA/Temp/dhcproto-verify" cargo test --offline
```

> 单独跑测试时请把 `CARGO_TARGET_DIR` 指到仓库外，否则会在本目录里生成一份
> `target/` 与 `Cargo.lock`（本目录不是 workspace 成员，见第 6 节）。

## 五、smartdns 实际用到它多少

只用了 7 种 DHCP 选项类型：`ClientIdentifier`、`DomainNameServer`、`End`、`Hostname`、
`MessageType`、`NameServer`、`ParameterRequestList`（见 `src/infra/dhcp.rs`），
即"发一个 DHCP DISCOVER 并解析回复"。

**第 3.2 节改动的 FQDN 选项（option 81）在本仓库里从未被构造过**（全仓检索
`ClientFqdn` / `ClientFQDN` / `FqdnFlags` 无任何构造点），所以那一处适配
只要求"能编译通过"，不在任何运行时路径上 —— 风险面为零。

## 六、它不是 workspace 成员（别惊讶）

根 `Cargo.toml` **没有 `[workspace]` 段**，所以根包自成一个 workspace，
作为 `path` 依赖的 dhcproto 不会成为成员。后果：

- 根目录 `cargo test` **不会**跑到本目录的 **43 个单测**（另有 17 个文档测试；要跑就按第 4 节那条命令单独跑）；
- 本目录的 `Cargo.lock` / `target/` 都是多余的，别提交。

## 七、（应急用，默认不做）如果哪天要从上游取一个修复

默认**没有**同步日程、也没有待办（见第 1 节的原则：内嵌即自有代码）。
只有在"外部明确通告 dhcproto 有安全问题、且影响我们用到的路径"时，才临时做一次。
比 hickory 那边省事，因为**基线是正式发布版 `0.13.0`**，随时可以拿来 diff：

1. 取一个新版 dhcproto 的发布包（从 registry 缓存或 GitHub tag）；
2. 与本目录 diff，重点看**安全 / 解码健壮性**相关的改动；
3. 把需要的改动并进来，然后**重新施加第 3 节那两处本地改动**（改动很少，重放成本极低）；
4. `cargo test` 全绿后，把新版本号更新到第 2 节表格，并在第 3 节记一笔"这次取了什么"。

> 提醒：它是 `path` 依赖，**dependabot / `cargo update` 都看不到它** ——
> 按第 1 节的原则这是**有意为之**，不是缺陷；需要时靠上面这条应急流程即可。
