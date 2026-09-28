# 端到端模拟测试脚本（真机：起进程 + 真发 DNS 查询）

**用途**：对已完成的批次做**真机端到端**验证 —— 单元测试抓不到的**接线层**问题在这里才暴露。

**它不是单元测试的替代品，而是补充。** 两类测试抓的东西不同：

| 层 | 抓什么 | 抓不到什么 |
|---|---|---|
| 单元测试（`cargo test --bin smartdns`） | 函数级逻辑、边界值 | 进程工作目录、配置装配、异步队列接线 |
| **本脚本** | 上述"真实运行才成立"的前提 | 需要特定平台环境的项（见文末"边界"） |

## 为什么必须有它（真实战绩）

写这个脚本的第一轮就抓到**两个单元测试全绿、实际却有缺陷**的问题：

1. **问题 52 的修复漏了一半**：`conf-file` 的收紧档位被 `resolve_filepath` 里
   第一行无条件的 `if filepath.is_file()` 绕过 —— **相对路径的 `is_file()` 是相对
   进程工作目录求值的**。单元测试的工作目录是 `target/debug/deps`（那里没有诱饵文件），
   所以永远测不到；真机把工作目录设成放有诱饵配置的目录后立刻复现。
2. **问题 38 的修复到不了用户面前**：`from_str` 里加的判据会被
   `map_res` 吞掉、整行降级成"未识别行"告警，**配置自检照样通过**。
   单元测试直接调 `from_str`，证明的是"函数会报错"，而不是"错误能冒出来"。

两次都是**同一类错误**：单元测试证明了"代码写了"，没证明"接线通了"。

## 用法

```powershell
# Windows
pwsh -File .\tests/e2e/run_e2e.ps1

# 只跑某一项（按名称过滤）
pwsh -File .\tests/e2e/run_e2e.ps1 -Filter 52
```

**要求**：先 `cargo build --offline --bin smartdns`（脚本会检查二进制是否比源码新）。
需要网络（用真实公网上游 `223.5.5.5`）。


```bash
# Linux 真机检查（9 项，必须 root —— 否则内核相关项会如实报 SKIP）
wsl -d Ubuntu -u root -- bash -lc "cd /mnt/d/smartdns-edge && python3 tests/e2e/wsl_linux_checks.py"
```

> ⚠️ 以 root 运行时程序会**自动降权到 `nobody`**，临时目录必须 `chmod 777`，
> 否则日志写不进去 —— 那是"环境没准备好"，不是产品缺陷（脚本已处理）。
## 辅助工具

| 文件 | 用途 |
|---|---|
| `fake_upstream.py` | 可控上游：对指定域名返回**不带 SOA 的 NXDOMAIN**（模拟被污染的上游），其余回真答案；支持 `delay_ms` 参数制造确定性时序。用于验证**问题 6** |
| `ttl_upstream.py` | 双栈 TTL 实验上游：对同一域名返回 A（TTL 60 + 3600 两条）与 AAAA（TTL 3600），用于验证**问题 5**（对齐后应统一到较短值 60） |
| `internal_upstream.py` | **"内网权威 DNS"模拟上游**：只解析指定内网域名，**对 `example.com` 一律 REFUSED**；会统计 `example.com` 被问了几次（修复后应为 0）。用于验证**问题 46** |

```bash
# 假上游（0ms 先回）/ 真上游（300ms 后回）
python3 tests/e2e/fake_upstream.py 26400 fake-nx 0
python3 tests/e2e/fake_upstream.py 26401 real 300

# 双栈 TTL 上游
python3 tests/e2e/ttl_upstream.py 26510

# 内网上游（问题 46）：只答 intranet.test，其它（含 example.com）REFUSED
python3 tests/e2e/internal_upstream.py 26921 --allow intranet.test --alias multi.test
```

## 第七批（系统服务与跨平台）的专项脚本

这些**不在 `run_e2e.ps1` 里**（有的需要 Windows、有的需要 Linux root），按需单独跑：

| 脚本 | 平台 | 验证问题 | 用法 |
|---|---|---|---|
| `_p44_lockpath.sh` | Linux（root） | **44** 锁路径不跟 `-p` 走 | `wsl -d Ubuntu -u root -- bash -lc "cd /mnt/d/smartdns-edge && bash tests/e2e/_p44_lockpath.sh"` |
| `_p44_probe.sh` | Linux（root） | **44** 原缺陷反向复现（两种启动方式各锁各的） | 同上，换文件名 |
| `_p49_local.sh` | Linux（root，需 `nft`） | **49** nftset 写入失败可见 | 同上 |
| `_p49_ok.sh` | Linux（root，需 `nft`） | **49** 成功场景不被误报 | 同上 |
| `_p46_warmup.ps1` | Windows | **46** 不再发 `example.com` 试探 | `pwsh -NoProfile -File .\tests\e2e\_p46_warmup.ps1` |
| `_p50_device.ps1` | Windows | **50** `-interface` 指错网卡时有告警 | `pwsh -NoProfile -File .\tests\e2e\_p50_device.ps1` |
| `_p48_ps_syntax.ps1` | Windows | **48** 服务命令的 PowerShell 语法 | 先 `cargo test --offline --bin smartdns export_generated_powershell_commands`，再 `pwsh -NoProfile -File .\tests\e2e\_p48_ps_syntax.ps1` |

> ⚠️ **第七批的两条纪律**（详见审查报告 §28）：
> ① 这一批涉及服务管理，而**本机装着用户的生产服务** ——
> **绝不执行 `smartdns service install/uninstall/stop/restart`**；
> 服务命令改为"导出 + 语法校验"（`_p48_ps_syntax.ps1`）来验证。
> ② 问题 46 的原缺陷**只在多地址竞速路径与命名组上触发**，
> 所以 `_p46_warmup.ps1` 必须用 `-group` + 域名形式的上游
> （单 IP 上游走快捷路径，测不出来）。

## 第八批（解析行为，组1+组3）的专项脚本

| 脚本 | 平台 | 验证问题 | 用法 |
|---|---|---|---|
| `_p26_fallback.ps1` | Windows | **26** `-address #6` 下 A 查询**会**向父域回落（报告说"不回落"，**实测相反**） | `pwsh -NoProfile -File .\tests\e2e\_p26_fallback.ps1` |
| `_p27_3_monotonic.py` | 任意（纯 Python） | **27-3** 两种预取排序键**结果恒等**（报告说"会错序"，**判定不成立**） | `python tests/e2e/_p27_3_monotonic.py` |

> ⚠️ **这两个脚本的用途是"推翻结论"，不是"证明修复"**：
> 它们各自给出**可复算的证据**（真机行为 / 穷举 4680 种组合），
> 用来钉住"报告描述的现象不存在"这一事实，避免日后重复排查。

## 最后一批·甲（问题 24、27-1）的专项脚本

| 脚本 | 平台 | 验证问题 | 用法 |
|---|---|---|---|
| `_p24_27_1_dualstack.ps1` | Windows | **24** `speed-check-mode none` 对双栈生效（摘要显示 `ON, but INACTIVE`）；**27-1** `force-AAAA-SOA` 只短路 AAAA、不短路 A | `pwsh -NoProfile -File .\tests\e2e\_p24_27_1_dualstack.ps1` |

**该脚本的三组用例**（共 9 项断言）：

1. **`none` + 优选** → 摘要必须打出 `speed check mode: OFF`、
   `dualstack ip selection: ON, but INACTIVE (...)`，以及可操作提示；
2. **对照组（测速可用）** → 必须显示为正常的 `ON`，且**不得**出现 `INACTIVE`
   （防判据过宽，与 §19.4 的同类教训一致）；
3. **`force-AAAA-SOA` 打开后** → A 查询仍发生族对决（日志 `Tie, keep both`）并返回真实地址；
   AAAA 照旧回 SOA。

> ⚠️ **第 3 组里"A 查询返回真实地址"那条判别力有限**：反向验证（撤掉 27-1 修复）时它**照样通过**，
> 因为 `force-AAAA-SOA` 本来就不改 A 查询的答案来源。它只是"防止把 A 查询整个改坏"的底线断言，
> **不能当作修复证据** —— 真正有判别力的是"族对决日志"那条。
> 这类"必须诚实标注判别力"的习惯见《实施记录》§14.2、§19.3、§23.4。
> 结论详见审查报告第三十节。

## 第九批（DoH 互操作）的专项脚本

| 脚本 | 平台 | 验证问题 | 用法 |
|---|---|---|---|
| `_p32_33_doh.ps1` | Windows | **32** JSON 里 `AD`/`CD` 的实际取值；**33** `Accept: ..., */*` 应回报文、RFC 8484 `?dns=` 可用、`?cd=1` 可解析、错误信息可操作 | `pwsh -NoProfile -File .\tests\e2e\_p32_33_doh.ps1` |
| `_p42_ipset_ack.sh` | Linux（root，需 `ipset`） | **42** 写不存在的集合要失败可见；写存在的集合要真写入且**不误报** | `wsl -d Ubuntu -u root -- bash -lc "cd /mnt/d/smartdns-edge && bash tests/e2e/_p42_ipset_ack.sh"` |

> ⚠️ **`_p32_33_doh.ps1` 是"必需品"而非补充**：问题 32/33 的两个真实缺陷
> （`CD` 取错了来源、`?cd=1` 无法解析）**单元测试全是绿的** ——
> 单测直接调函数，碰不到 axum 的参数提取器，也回答不了
> "这个位从请求取还是从响应取"。
> **凡是改动落在 HTTP 入口 / 参数解析 / 字段语义上，都必须写这样的脚本。**
>
> 它同时验证**两层反向**（撤掉修复后应精确复现）：
> 撤 `Accept` 的 `*/*` → 回 `application/json`；撤 `CD` 修复 → 不带 `cd` 时 `CD=True`。

> ⚠️ **`_p42_ipset_ack.sh` 的判别力边界（实测得出，务必如实理解）**：
> 把长度门槛**退回旧值后，它仍然全绿** —— 因为**内核实际发出的总是完整的 36 字节回执**，
> "偏短回执"在真机路径上**根本不会发生**。
> 因此它管的是**接线层**（回执真的被读了吗？失败真的报出来了吗？成功有没有被误报？），
> 而"偏短回执不被当成成功"这条核心修复由**单元测试** `classify_ack` 保证
> （人造报文可精确构造 16/19/20 字节与"自述长度撒谎"，反向验证在那里有效）。
> **两者互补而非替代** —— 不要因为"真机全绿"就认为这条修复被验证过了。

## 第十批（文档与发布说明）的专项脚本

| 脚本 | 平台 | 验证问题 | 用法 |
|---|---|---|---|
| `_p10_docs_consistency.py` | 任意（纯 Python） | **21** 发布说明数字要绑定版本且说明是总量；**43** 两项静态检查必须分开列明；**20** `SECURITY.md` 不得指向不存在的文档；中英文数字必须一致 | `python tests/e2e/_p10_docs_consistency.py` |

> ⚠️ **这一批 `cargo test` 没有判别力** —— 它不会读 `RELEASE_NOTES.md` 或 `SECURITY.md`。
> 所以本脚本改为**对文档内容做断言**（11 项），并做了 4 处反向验证：
> 退回混用表述 / 去掉版本绑定 / 退回悬空引用 / 英文项数改回 19 —— 都会 FAIL。
>
> 📌 **本项目由此有了第二类验证方式**：前九批是"单测 + 真机"，
> 纯文档/配置类改动需要的是**内容断言**。

## 第十批（官网与发布流程）的专项脚本

**这一批不碰主程序，`cargo test` 没有判别力** —— 它不会读文档、不开浏览器、也不看 workflow。
所以每组的验证手段都不同（这是本批最重要的方法论收获）：

| 脚本 | 组 | 验证什么 | 用法 |
|---|---|---|---|
| `_p10_docs_consistency.py` | D | 发布说明数字**绑定版本**且说明是总量；两项静态检查**分开列明**；`SECURITY.md` 不指向不存在的文档；中英数字一致 | `python tests/e2e/_p10_docs_consistency.py` |
| `_p10_docs_links.py` | C | 死链与**悬空引用**、菜单登记的文档路径、第三方资源**固定版本**、CSP 存在 | `python tests/e2e/_p10_docs_links.py` |
| `_p10_site_browser.js` | C | **浏览器真机**（CDP 驱动 Edge）：无控制台错误、无 CSP/SRI 违规、正文渲染、导航、页脚、语言/主题切换 | `node tests/e2e/_p10_site_browser.js` |
| `_p22_xss.js` | C | 错误信息按**文本**插入 + **判据有效性**对照 | `node tests/e2e/_p22_xss.js` |
| `_p22_xss_forced.js` | C | **强行让 `err.message` 带标签**，验证错误详情确实走文本插入 | `node tests/e2e/_p22_xss_forced.js` |
| `_p10_release_flow.py` | B | **流程结构断言**：测试是否在写远端之前、action 是否都固定 SHA、复核步骤是否在发布前 | `python tests/e2e/_p10_release_flow.py` |
| `_p17_verify_release.sh` | B | 把 `build.yml` 的**复核逻辑原样抽出来真跑**（含篡改/缺文件必须被拦） | `wsl -d Ubuntu -- bash -lc "cd /mnt/d/smartdns-edge && bash tests/e2e/_p17_verify_release.sh"` |
| `_p17_action_shas.js` | B | 从 GitHub API 取 action 的**真实 commit SHA**（SHA 写错会让 CI 直接挂，不能手抄） | `node tests/e2e/_p17_action_shas.js` |
| `_p4_download.js` | A | **直接 import Cloudflare Function 并调用 `onRequest`**（含 fetch mock）：未知 key 必须 404 且**不外发**、路径穿越、错误不回显、CORS 收紧 | `node tests/e2e/_p4_download.js` |

> ⚠️ **C 组的教训（务必记住）**：第一版 CSP 只改了内联事件、**漏了那块 460 行的内联 `<script>`**，
> 于是**整页脚本被拦、官网白屏**。而**所有静态检查都是绿的** ——
> 是 `_p10_site_browser.js`（真机浏览器）抓出来的。
> **改动落在"前端 / 浏览器行为"上时，静态检查不算验证。**
>
> ⚠️ **B 组的教训**：第一版复核逻辑用了 `sha256sum -c`，但 `just` 的 `sha256_file()`
> 返回的是**纯哈希、不含文件名**，`sha256sum -c` 解析不了 ⇒ **会让 CI 卡住**。
> 是 `_p17_verify_release.sh`（把逻辑抽出来真跑）发现的。**能真跑的逻辑就不要只看代码。**
>
> ⚠️ **A 组的做法值得复用**：Cloudflare Pages Function 是 ES module、`onRequest` 是普通函数，
> 所以**可以直接 `import` 并构造 `Request` 调用它**，再把 `fetch` 换成 mock
> （用来验证"有没有真的外发到 GitHub"）。这比读代码强得多 ——
> 它证明了"未知 key 确实没有拼成 GitHub URL"，而不只是"代码看起来会返回 404"。

## 第十一批（本地加固）的专项脚本

| 脚本 | 验证问题 | 用法 |
|---|---|---|
| `_p13_api.ps1` | **13-②/13-③**：管理接口的**真机 HTTP 行为** —— 分页正确性、`offset=10^9` 不崩不超时、逐页不重不漏、鉴权仍生效、错误响应体**不含**服务器路径/详情 | `pwsh -NoProfile -File .\tests\e2e\_p13_api.ps1` |

> ⚠️ **13-③ 有两半，验证手段不同（这是本批最重要的经验）**：
> - **返回值那半**（total 如实、不重不漏、超界返回空页）→ 由**这个真机脚本**覆盖；
> - **代价那半**（收满就停、超界不遍历）→ 它**不改变返回值**，
>   真机脚本**测不出来**（实测：退回旧实现，真机仍然全绿），
>   必须靠**单测里埋的确定性计数器**（`pagination_does_not_scan_entries_it_does_not_need`）。
>
> 📌 **另一条教训**：真机脚本第一版用 `smartdns resolve` CLI 灌缓存，
> 结果缓存始终为空 —— 查清是**脚本问题**（CLI 那条路径在本机 UDP 上游下报
> `os error 10054`，而直接发 UDP 查询完全正常）。
> 已改为**直接发 UDP 查询**，并**同时开 `bind` 与 `bind-http`**（只开 HTTP 发不进查询）。
> **测试脚本自身的错误会伪装成产品缺陷，必须先查清。**

## 覆盖的检查项

| # | 检查 | 对应问题 | 判定方式 |
|---|---|---|---|
| 1 | 真实公网上游解析 | 基础 | 查询 `www.baidu.com` 应返回真实 IP |
| 2 | 本地 `address` 规则 | 基础 | `local.test` 应返回配置的 IP |
| 3 | TCP 传输 | 基础 | `bind-tcp` 上查询应成功 |
| 4 | **不输出 NXDOMAIN** | 项目基点 §6 | 不存在的域名应回 NOERROR + SOA |
| 5 | `conf-file` 不被工作目录/程序目录劫持 | **52** | 诱饵配置里的规则**不得**生效 |
| 6 | 代理凭据写一半 → 配置错误 | **38** | 退出码应为 2，且错误信息**不含口令** |
| 7 | 明文 http 名单 → 拒绝 | **39** | 日志应出现 "plaintext http is not allowed" |
| 8 | `log-size 0` 不每行归档 | **41-③** | 日志目录文件数应为 1（修复前是几十个） |
| 9 | 外部轮转后日志自愈 | **40** | 改名搬走后应**重建**活动日志并继续写 |
| 10 | 审计档不被日志轮转误删 | 9（回归） | 日志与审计同目录、`log-num` 很小时审计档仍在 |
| 11 | 日志指标在管理接口可见 | 41-① | `/api/system/status` 应含三个 `log_*` 字段 |

## 边界（本脚本**不**覆盖，如实说明）

- **问题 45（OpenWrt 拒绝）**：`is_openwrt()` 硬编码读 `/etc/os-release`，
  无法从外部注入；该逻辑由 Linux 单元测试（`problem_45_tests`，WSL 真内核下跑）覆盖。
  本脚本只验证**反向保护**：非 OpenWrt 平台上服务安装路径未被误伤。
- **平台相关项**：ipset/nftset 真写入内核、syslog、单实例锁、ARP 分流等
  需要 root 与真实内核环境，由 WSL 单元测试或手工检查覆盖。
  （项目基点提到的 `wsl_linux_checks.py` 目前**不在磁盘上**，属验证资产缺失，待确认。）

## 设计要点（避免踩过的坑）

1. **工作目录必须可控**：问题 52 的验证全靠这一点。脚本用 `-WorkingDirectory` 显式指定。
2. **诱饵文件不能放在配置同目录**：那样会被"配置文件所在目录"这级**合法**回退找到，
   测不出问题 —— 第一版就写错了。
3. **测自愈必须有真实日志流量**：`log-level info` 下查询**不产生日志**，
   最初那次"改名后没有重建"其实是**没有新日志行**，不是产品缺陷。
   脚本用 `-v -v`（debug 级）制造持续写入。
4. **`log-size 0` 要写 `0K`**：不带单位的 `0` 会被配置解析器判为"未识别行"，
   根本到不了守卫逻辑。
5. **每个用例用完即停进程**，避免端口占用与"上一个实例的产物"干扰判定。
