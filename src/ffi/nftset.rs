//! 把解析出来的 IP 写进 nftables 的 set（nftset）—— 给"按域名分流到不同线路"用。
//!
//! 这里原本是 `include/nftset.c`（约 740 行 C）＋ `build.rs` 里的 `cc`/`bindgen`。
//! 本文件是它的**纯 Rust 翻译**，目的有三：
//!
//!   1. **去掉 C 工具链依赖**：不再需要 C 编译器与 libclang，发行版打包、
//!      容器镜像、交叉编译都跟着减负；
//!   2. **报文构造变成可单测的纯逻辑**：那份 C 文件在 Windows 上根本编不了
//!      （与 `ipset.rs` 开头说的是同一个理由），现在两平台都能跑单测；
//!   3. **消除三类结构性缺陷**（见下）。
//!
//! 走的内核接口与 C 版完全相同（nfnetlink / `NFNL_SUBSYS_NFTABLES`），
//! 报文布局逐字段对齐 —— **这是翻译，不是重写**，可观测行为必须与 C 版一致。
//!
//! # 🔐 必须保留的四项成果（问题 49 的真机整改）
//!
//! 翻译最容易犯的错就是"顺手化简"掉这几处，而那会**精确复现历史缺陷**：
//!
//! ① **`BATCH_END` 必须带 `NLM_F_ACK`**（见 [`encode_batch_end`]）。
//!    去掉它内核**一个字节都不回**，读回执的逻辑必然等到超时、把成功误报成失败。
//! ② **等回执要容忍慢**：收超时 1 秒（C 版原来是 100ms，真机抓出过假告警）。
//! ③ **套接字初始化必须原子**：用 `compare_exchange`，且**失败可重试**
//!    （C 版注释专门解释了为何不用 `pthread_once` —— 那会把一次瞬时失败永久固化）。
//! ④ **`add_batch` 返回实际条数**，不是状态码（C 侧成功时返回 0，日志会打
//!    `wrote 0 addresses`，用户以为没生效）。
//!
//! # 顺带消除的 C 侧缺陷（翻译时**不照抄**）
//!
//! * **栈缓冲按单条校验却装三条报文**：C 的 `nftset_add` 用 2048 字节栈缓冲装
//!   BEGIN+elem+END，而每条消息都以 `maxlen = 2048` 校验 ⇒ 理论上可写越界。
//!   这里用 `Vec`，问题**结构性消失**。
//! * **`close()` 覆盖 errno**：C 在建套接字失败分支里先 `close` 再记错误码，
//!   而 `close` 可能改写 errno，用户拿到的原因不准。这里先存 `io::Error` 再关。
//! * **请求序号用 `time(NULL)`**：同一秒内的两次请求序号相同，回执会串包，
//!   表现为随机误判成功/失败。这里改用递增的 `AtomicU32`。
//! * **fd 判空口径不一**（C 里一处 `> 0`、一处 `!= 0`）：这里统一用 `-1` 作初值。
//!
//! # ⚠️ 刻意**保留**的 C 版行为（不是缺陷，是"翻译要保持一致"）
//!
//! * **集合没有任何标志时，超时不会归零**：C 的 `add_batch` 用 `if (flags != 0)`
//!   决定要不要读集合标志，而"集合无标志"与"读标志失败"都得到 `flags == 0`，
//!   于是超时属性照发 ⇒ 内核回 `EINVAL`。真机复现过（集合不带 `timeout` 标志
//!   且开 `nftset-timeout yes` 时写入失败）。
//!   这是 C 版的既有行为，**B-② 的目标是行为一致，不在此处顺手改**
//!   （改了就无法判断差异是"翻译引入"还是"有意改进"）。已单独登记待定调。

#![allow(dead_code)]

// ⚠️ 这里**不**导入 `std::io`：它只在"非 Linux"的 `imp` 分支里用到，
// 而本文件在 Linux 上也会编译 —— 顶层导入会触发 unused_imports 告警。
// 各 `imp` 模块自己按需 `use std::io;`。
use std::net::IpAddr;

// ─────────────────────────── nfnetlink / nftables 常量 ───────────────────────────

/// nftables 的 nfnetlink 子系统号（`NFNL_SUBSYS_NFTABLES`）
const NFNL_SUBSYS_NFTABLES: u16 = 10;
/// 批量事务开始（`NFNL_MSG_BATCH_BEGIN`）
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
/// 批量事务结束（`NFNL_MSG_BATCH_END`）
const NFNL_MSG_BATCH_END: u16 = 0x11;

/// 新增集合元素（`NFT_MSG_NEWSETELEM`）
const NFT_MSG_NEWSETELEM: u16 = 12;
/// 删除集合元素（`NFT_MSG_DELSETELEM`）
const NFT_MSG_DELSETELEM: u16 = 14;
/// 查询集合（`NFT_MSG_GETSET`）
const NFT_MSG_GETSET: u16 = 10;

/// 集合支持超时（`NFT_SET_TIMEOUT`）
const NFT_SET_TIMEOUT: u32 = 0x10;
/// 集合是区间集合（`NFT_SET_INTERVAL`）
const NFT_SET_INTERVAL: u32 = 0x4;
/// 该元素是区间的**结束**标记（`NFT_SET_ELEM_INTERVAL_END`）
const NFT_SET_ELEM_INTERVAL_END: u32 = 0x1;

// 属性编号。注意 GETSET 与 SETELEM 的 table/set 属性**同号**（C 版正是借此复用）。
/// `NFTA_SET_ELEM_LIST_TABLE` / `NFTA_SET_TABLE`
const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
/// `NFTA_SET_ELEM_LIST_SET` / `NFTA_SET_NAME`
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
/// `NFTA_SET_ELEM_LIST_ELEMENTS`（嵌套）
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
/// `NFTA_LIST_ELEM`（嵌套）
const NFTA_LIST_ELEM: u16 = 1;
/// `NFTA_SET_ELEM_KEY`（嵌套）
const NFTA_SET_ELEM_KEY: u16 = 1;
/// `NFTA_SET_ELEM_FLAGS`
const NFTA_SET_ELEM_FLAGS: u16 = 3;
/// `NFTA_SET_ELEM_TIMEOUT`
const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
/// `NFTA_DATA_VALUE`
const NFTA_DATA_VALUE: u16 = 1;
/// `NFTA_SET_FLAGS`（回执里用它判断集合能力）
const NFTA_SET_FLAGS: u16 = 3;

/// 属性是嵌套的（`NLA_F_NESTED`）
const NLA_F_NESTED: u16 = 1 << 15;
/// 属性内容是网络字节序（`NLA_F_NET_BYTEORDER`）
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
/// nftables 用的是 `NLM_F_CREATE`（**不是** ipset 那边的 `NLM_F_REPLACE`）
const NLM_F_CREATE: u16 = 0x400;

/// `nlmsghdr` 固定长度
const NLMSG_HDR_LEN: usize = 16;
/// `nfgenmsg` 固定长度
const NFGENMSG_LEN: usize = 4;
/// `NLMSG_ERROR`
const NLMSG_ERROR: u16 = 2;
/// 读**错误码**所需的最小长度：`nlmsghdr`(16) + `nlmsgerr.error`(4)
const NLMSG_ERROR_MIN_LEN: usize = NLMSG_HDR_LEN + 4;
/// 一条 netlink 报文（不含属性）的长度
const NLMSG_BASE_LEN: usize = NLMSG_HDR_LEN + NFGENMSG_LEN;

const NLMSG_ALIGNTO: usize = 4;

// nfgenmsg.nfgen_family（`NFPROTO_*`）
const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_ARP: u8 = 3;
const NFPROTO_NETDEV: u8 = 5;
const NFPROTO_BRIDGE: u8 = 7;
const NFPROTO_IPV6: u8 = 10;
const NFPROTO_DECNET: u8 = 12;

/// netlink 的 4 字节对齐（`NLMSG_ALIGN`）
#[inline]
fn align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

#[inline]
fn pad_to_align(buf: &mut Vec<u8>) {
    let padded = align(buf.len());
    buf.resize(padded, 0);
}

/// 家族名 → `nfgen_family`。
///
/// 与 C 版 `_nftset_get_nffamily_from_str` 逐项对齐。C 用的是
/// `strncmp(family, X, sizeof(X))`，即**要求结尾的 NUL 也相等** ⇒ 实际是**精确匹配**
/// （"inetfoo" 不匹配 "inet"）。这里用精确匹配表达同一语义。
fn nffamily_from_str(family: &str) -> u8 {
    match family {
        "inet" => NFPROTO_INET,
        "ip" => NFPROTO_IPV4,
        "ip6" => NFPROTO_IPV6,
        "arp" => NFPROTO_ARP,
        "netdev" => NFPROTO_NETDEV,
        "bridge" => NFPROTO_BRIDGE,
        "decnet" => NFPROTO_DECNET,
        _ => NFPROTO_UNSPEC,
    }
}

/// 写一个"头 + 内容"的属性，并把缓冲区补齐到 4 字节（长度含头、记**精确值**）。
///
/// 与 C 版 `_nftset_addattr` 的约定一致：属性自身的 `len` 是 `4 + 内容长度`（不含补齐），
/// 而缓冲区照样补 0 —— 补齐字节必须**真的写进缓冲区**，否则第二个属性的起点就歪了。
fn push_attr(buf: &mut Vec<u8>, ty: u16, content: &[u8]) {
    let start = buf.len();
    buf.extend_from_slice(&0u16.to_ne_bytes()); // len 占位
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(content);
    let len = (buf.len() - start) as u16;
    buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    pad_to_align(buf);
}

/// 写一个以 NUL 结尾的字符串属性（`_nftset_addattr_string`）
fn push_attr_string(buf: &mut Vec<u8>, ty: u16, s: &str) {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    push_attr(buf, ty, &bytes);
}

/// 开一个嵌套属性，返回它的起点（交给 [`close_nested`] 收尾）
fn open_nested(buf: &mut Vec<u8>, ty: u16) -> usize {
    let start = buf.len();
    push_attr(buf, ty, &[]);
    start
}

/// 收尾一个嵌套属性：长度 = 对齐后的结束位置 − 起点（**含**补齐字节）。
///
/// 与 C 版 `_nftset_addattr_nest_end` 一致：嵌套属性只是"边界"，
/// 内核按 4 字节对齐逐个走子属性，末尾多几个补齐字节会被忽略。
fn close_nested(buf: &mut Vec<u8>, start: usize) {
    pad_to_align(buf);
    let len = (buf.len() - start) as u16;
    buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
}

/// 拼 `nlmsghdr + nfgenmsg` 头部。
///
/// ⚠️ `res_id` 用**原生字节序** —— 这是 C 版的写法（`req->m.res_id = NFNL_SUBSYS_NFTABLES;`），
/// 经真内核实测可用。内核头文件把它声明为 `__be16`，但在 nfnetlink 的这条路径上
/// 两种写法都被接受；**选择与 C 版逐字节一致**正是本次翻译的目标。
fn nlmsg_header(buf: &mut Vec<u8>, msg_type: u16, flags: u16, family: u8, res_id: u16, seq: u32) {
    buf.extend_from_slice(&(NLMSG_BASE_LEN as u32).to_ne_bytes()); // len 先占位
    buf.extend_from_slice(&msg_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // pid：内核不管，0 即可
    buf.push(family);
    buf.push(0); // version = NFNETLINK_V0
    buf.extend_from_slice(&res_id.to_ne_bytes());
}

/// 批量事务开始报文（`_nftset_start_batch`）。
///
/// 注意这里**只有** `NLM_F_REQUEST`、**没有** ACK —— ACK 是加在 BATCH_END 上的
/// （netlink 批量协议的规矩：内核处理完整个批之后针对 END 回一条）。
fn encode_batch_begin(seq: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(NLMSG_BASE_LEN);
    nlmsg_header(
        &mut buf,
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        0,
        NFNL_SUBSYS_NFTABLES,
        seq,
    );
    buf
}

/// 批量事务结束报文（`_nftset_end_batch`）。
///
/// 🔐 **成果①（问题 49）：这里必须带 `NLM_F_ACK`。**
///
/// 批量写入原先既没有 ACK、发送方也不读回执 —— 于是"集合不存在""权限不足"
/// 全被吞掉。补上读回执之后，这里必须**同时**补 ACK，否则读取循环会一直等到超时，
/// 把**成功**误报成失败（真机实测过：地址确实写进内核集合了，日志却报
/// `Resource temporarily unavailable`）。
///
/// 加在 BATCH_END 上正是协议的规矩；批内某条元素出错时，内核回的则是带错误码的
/// `NLMSG_ERROR`，两者都能被 [`classify_ack`] 识别。
fn encode_batch_end(seq: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(NLMSG_BASE_LEN);
    nlmsg_header(
        &mut buf,
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST | NLM_F_ACK,
        0,
        NFNL_SUBSYS_NFTABLES,
        seq,
    );
    buf
}

/// 追加一条"集合元素"报文（`_nftset_add_element` / `_nftset_del_element`）。
///
/// 报文结构（与 C 版逐字段对齐）：
/// ```text
/// nlmsghdr { type = SUBSYS<<8 | NFT_MSG_NEWSETELEM|DELSETELEM, flags = REQUEST|CREATE }
/// nfgenmsg { family, version = 0, res_id = 0 }      ← C 版元素报文的 res_id 恒为 0
/// attr TABLE
/// attr SET
/// attr ELEMENTS (nested) {
///     attr LIST_ELEM (nested) {
///         attr KEY (nested) { attr DATA_VALUE = 地址 }
///         attr TIMEOUT = u64(大端, 毫秒)          ← 只有 timeout > 0 才有
///     }
///     attr LIST_ELEM (nested) {                   ← 只有区间集合才有（第二个兄弟元素）
///         attr FLAGS = u32(大端, INTERVAL_END)
///         attr KEY (nested) { attr DATA_VALUE = 结束地址 }
///     }
/// }
/// ```
///
/// ⚠️ **超时的单位是毫秒**：`nftset` 是 `u64` 毫秒、**不带** `NLA_F_NET_BYTEORDER` 标志；
/// 而 `ipset` 是 `u32` 秒、**带**那个标志。两者"看起来很像"，照抄 `ipset.rs` 会写错。
#[allow(clippy::too_many_arguments)]
fn append_set_elem(
    buf: &mut Vec<u8>,
    msg_type: u16,
    family: u8,
    table: &str,
    set_name: &str,
    addr: &[u8],
    interval_end: Option<&[u8]>,
    timeout_secs: u64,
    seq: u32,
) {
    let msg_start = buf.len();
    nlmsg_header(
        buf,
        (NFNL_SUBSYS_NFTABLES << 8) | msg_type,
        NLM_F_REQUEST | NLM_F_CREATE,
        family,
        0, // C 版元素报文没有设置 res_id
        seq,
    );

    push_attr_string(buf, NFTA_SET_ELEM_LIST_TABLE, table);
    push_attr_string(buf, NFTA_SET_ELEM_LIST_SET, set_name);

    let list = open_nested(buf, NFTA_SET_ELEM_LIST_ELEMENTS);
    let elem = open_nested(buf, NFTA_LIST_ELEM);
    let key = open_nested(buf, NFTA_SET_ELEM_KEY);
    push_attr(buf, NFTA_DATA_VALUE, addr);
    close_nested(buf, key);
    if timeout_secs > 0 {
        // u64、毫秒、大端；**刻意不带** NLA_F_NET_BYTEORDER（与 C 版一致）
        let millis = timeout_secs.saturating_mul(1000);
        push_attr(buf, NFTA_SET_ELEM_TIMEOUT, &millis.to_be_bytes());
    }
    close_nested(buf, elem);

    if let Some(end) = interval_end {
        let interval_elem = open_nested(buf, NFTA_LIST_ELEM);
        push_attr(
            buf,
            NFTA_SET_ELEM_FLAGS,
            &NFT_SET_ELEM_INTERVAL_END.to_be_bytes(),
        );
        let end_key = open_nested(buf, NFTA_SET_ELEM_KEY);
        push_attr(buf, NFTA_DATA_VALUE, end);
        close_nested(buf, end_key);
        close_nested(buf, interval_elem);
    }

    close_nested(buf, list);

    // 回填本条消息的长度（C 版是累加 n->nlmsg_len）
    let total = (buf.len() - msg_start) as u32;
    buf[msg_start..msg_start + 4].copy_from_slice(&total.to_ne_bytes());
}

/// 拼一条 GETSET 查询（`_nftset_get_nftset`），用来读集合的能力标志。
fn encode_getset(family: u8, table: &str, set_name: &str, seq: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    nlmsg_header(
        &mut buf,
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSET,
        NLM_F_REQUEST | NLM_F_ACK,
        family,
        NFNL_SUBSYS_NFTABLES,
        seq,
    );
    push_attr_string(&mut buf, NFTA_SET_ELEM_LIST_TABLE, table);
    push_attr_string(&mut buf, NFTA_SET_ELEM_LIST_SET, set_name);
    buf
}

/// 从 GETSET 的回执里取出 `NFTA_SET_FLAGS`（`_nftset_get_flags` 的解析部分）。
///
/// ⚠️ 标志值是**大端**（C 版用 `ntohl`）—— 经真内核实测确认。
fn parse_set_flags(message: &[u8]) -> Option<u32> {
    if message.len() < NLMSG_BASE_LEN {
        return None;
    }
    let msg_len = u32::from_ne_bytes([message[0], message[1], message[2], message[3]]) as usize;
    let end = msg_len.min(message.len());

    let mut off = NLMSG_BASE_LEN;
    while off + 4 <= end {
        let len = u16::from_ne_bytes([message[off], message[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([message[off + 2], message[off + 3]]);
        if len < 4 || off + len > end {
            break;
        }
        if (ty & 0x3fff) == NFTA_SET_FLAGS && off + 8 <= end {
            return Some(u32::from_be_bytes([
                message[off + 4],
                message[off + 5],
                message[off + 6],
                message[off + 7],
            ]));
        }
        off += align(len);
    }
    None
}

/// `_nftset_process_setflags` 的结果。
#[derive(Debug, PartialEq, Eq)]
struct ProcessedFlags {
    /// 区间集合的"结束地址"（`地址 + 1`）；非区间集合为 `None`
    interval_end: Option<Vec<u8>>,
    /// 实际要用的超时秒数（集合不支持超时 → 归零）
    timeout: u64,
    /// C 版在 `地址 + 1` 溢出时返回 -1（调用方据此放弃区间标记）
    overflow: bool,
}

/// 按集合能力调整"超时"与"区间结束地址"（`_nftset_process_setflags`）。
///
/// 两个作用：
///   ① **集合不支持超时 ⇒ 把超时归零**。这一条是**必需**的：给不支持超时的集合
///      发超时属性，内核会回 `EINVAL`，整个写入失败（真内核实测确认）。
///   ② 区间集合 ⇒ 生成"结束地址"（末字节 +1），溢出则标记 `overflow`。
fn process_set_flags(flags: u32, addr: &[u8], timeout: u64) -> ProcessedFlags {
    let timeout = if (flags & NFT_SET_TIMEOUT) == 0 {
        0
    } else {
        timeout
    };

    if (flags & NFT_SET_INTERVAL) != 0 && !addr.is_empty() {
        let mut end = addr.to_vec();
        let last = end.len() - 1;
        end[last] = end[last].wrapping_add(1);
        if end[last] == 0 {
            return ProcessedFlags {
                interval_end: None,
                timeout,
                overflow: true,
            };
        }
        return ProcessedFlags {
            interval_end: Some(end),
            timeout,
            overflow: false,
        };
    }

    ProcessedFlags {
        interval_end: None,
        timeout,
        overflow: false,
    }
}

/// 一条 netlink 报文对本次写入的裁决结果（与 `ipset.rs` 同形）。
#[derive(Debug, PartialEq, Eq)]
pub enum AckOutcome {
    /// 不是我们要的那条回执（类型/序号不符，或长度不合法）→ 继续读下一条
    NotMine,
    /// 内核确认成功（错误码为 0）
    Success,
    /// 内核明确拒绝，携带 **errno（正数）**
    Failed(i32),
}

/// 判定一条已收到的 netlink 报文是不是我们要的回执、以及它说了什么。
///
/// 长度三重校验（照 `ipset.rs` 的做法）：`msg_len >= 20`、`msg_len <= n`、`n >= 20`。
/// 少任何一条，偏短回执里偏移 16..20 读到的就是**缓冲区残留的零值** ⇒ 被当成"成功"，
/// 退化成"配了不生效还没人知道"。
fn classify_ack(buf: &[u8], n: usize, seq: u32) -> AckOutcome {
    if n < NLMSG_ERROR_MIN_LEN || buf.len() < NLMSG_ERROR_MIN_LEN {
        return AckOutcome::NotMine;
    }

    let msg_len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    let msg_seq = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);

    if msg_len < NLMSG_ERROR_MIN_LEN || msg_len > n || n < NLMSG_ERROR_MIN_LEN {
        return AckOutcome::NotMine;
    }
    if msg_type != NLMSG_ERROR || msg_seq != seq {
        return AckOutcome::NotMine;
    }

    let code = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
    if code == 0 {
        AckOutcome::Success
    } else if code < 0 {
        // 内核给的是负 errno
        AckOutcome::Failed(-code)
    } else {
        // 协议上不该出现正数；真出现了也要**如实报失败**，不能当成功
        AckOutcome::Failed(code)
    }
}

// ─────────────────────────────── 公开接口（与 C 版同名同义）───────────────────────────────

/// 往集合里加一条地址（`nftset_add`）。返回 C 版同义的"状态码"（成功为 0）。
pub fn add(
    family_name: &str,
    table_name: &str,
    set_name: &str,
    addr: IpAddr,
    timeout: u64,
) -> anyhow::Result<i32> {
    let bytes = addr_to_bytes(addr);
    imp::add(family_name, table_name, set_name, &bytes, timeout)?;
    Ok(0)
}

/// 从集合里删一条地址（`nftset_del`）。
pub fn del(
    family_name: &str,
    table_name: &str,
    set_name: &str,
    addr: IpAddr,
) -> anyhow::Result<i32> {
    let bytes = addr_to_bytes(addr);
    imp::del(family_name, table_name, set_name, &bytes)?;
    Ok(0)
}

/// 批量写入（`nftset_add_batch`）。
///
/// 🔐 **成果④（问题 49）：返回"实际写入的条数"，而不是对端的状态码。**
///
/// C 侧成功时返回 `0`（那是状态码：0 = 成功），而本函数的返回值在上游被当作**条数**用 ——
/// 于是日志打出 `nftset: wrote 0 addresses ...`：地址**确实写进了内核集合**，
/// 却报告"写了 0 个"，用户看到 0 会以为没生效、白排查一轮。
pub fn add_batch(
    family_name: &str,
    table_name: &str,
    set_name: &str,
    addrs: &[IpAddr],
    timeout: u64,
) -> anyhow::Result<i32> {
    if addrs.is_empty() {
        return Ok(0);
    }

    // 地址族必须一致：C 版由调用方保证，这里显式拒绝（保持原有的显式检查）
    let first_is_v4 = addrs[0].is_ipv4();
    if addrs.iter().any(|a| a.is_ipv4() != first_is_v4) {
        anyhow::bail!("nftset: mixed IPv4/IPv6 addresses in one batch");
    }

    let raw: Vec<u8> = addrs
        .iter()
        .flat_map(|a| addr_to_bytes(*a).to_vec())
        .collect();

    imp::add_batch(family_name, table_name, set_name, &raw, timeout)?;

    Ok(addrs.len() as i32)
}

#[inline]
fn addr_to_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

// ─────────────────────────────────── 套接字层（Linux）───────────────────────────────────

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::mem::size_of;
    use std::os::fd::RawFd;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

    use super::{
        AckOutcome, NFT_MSG_DELSETELEM, NFT_MSG_NEWSETELEM, append_set_elem, classify_ack,
        encode_batch_begin, encode_batch_end, encode_getset, nffamily_from_str, parse_set_flags,
        process_set_flags,
    };

    /// 复用一个 netlink 套接字（C 版也是全局复用一个 fd）
    static NFT_FD: AtomicI32 = AtomicI32::new(-1);
    /// 报文序号，用来跟回执对上。
    ///
    /// 🔐 C 版用的是 `time(NULL)`：**同一秒内的两次请求序号相同**，回执会串包，
    /// 表现为随机误判成功/失败。这里改成递增计数器。
    static SEQ: AtomicU32 = AtomicU32::new(1);
    /// 收/发配对的锁：netlink 套接字不适合多线程同时 send/recv
    static SOCKET_LOCK: Mutex<()> = Mutex::new(());

    /// 🔐 **成果②（问题 49）：等回执的上限是 1 秒**（C 版原来只有 100ms）。
    ///
    /// 批量写入的 ACK 由内核在处理完整批之后才发，慢一点就超时 ——
    /// 于是出现"地址**确实写进了内核集合**、日志却报失败"的假告警（真机实测过）。
    /// 实测：成功 ACK 在 0.0ms 到达，集合不存在在 ~20ms 回 ENOENT，1 秒余量充裕。
    const ACK_TIMEOUT_MS: i64 = 1000;

    /// 建套接字。
    ///
    /// 🔐 **成果③（问题 49）：初始化的"检查 + 创建 + 赋值"必须原子。**
    ///
    /// 原实现是典型的 check-then-act：两个线程同时走到这里都会看到"未初始化"，
    /// 于是各建一个套接字，后赋值的把先前的覆盖掉 —— **被覆盖的 fd 再也没人关闭**，
    /// 高并发下持续泄漏。
    ///
    /// ⚠️ 这里**刻意不用 `OnceLock`**：套接字创建**可能失败**（权限、内核不支持），
    /// 而 `OnceLock` 失败后不会重试，会把一次瞬时失败永久固化。
    /// C 版注释专门解释了同一个取舍（所以它用互斥锁而不是 `pthread_once`）。
    /// `AtomicI32` 初值 `-1` 天然满足"失败可重试"。
    fn socket_or_init() -> io::Result<RawFd> {
        let fd = NFT_FD.load(Ordering::Relaxed);
        if fd >= 0 {
            return Ok(fd);
        }

        // AF_NETLINK / SOCK_RAW / NETLINK_NETFILTER(12)
        let new_fd =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 12) };
        if new_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // 收回执要有超时，否则内核不回时会把线程挂死。
        // ⚠️ 用**阻塞**套接字 + SO_RCVTIMEO：非阻塞套接字上这个选项无效，
        //    会退化成忙等 EAGAIN（C 版是 NONBLOCK + 自旋，这里不照抄）。
        let timeout = libc::timeval {
            tv_sec: (ACK_TIMEOUT_MS / 1000) as libc::time_t,
            tv_usec: ((ACK_TIMEOUT_MS % 1000) * 1000) as libc::suseconds_t,
        };
        let rc = unsafe {
            libc::setsockopt(
                new_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            // ⚠️ 先存错误再关：`close` 可能改写 errno（C 版正是在这里踩了坑）
            let err = io::Error::last_os_error();
            unsafe { libc::close(new_fd) };
            return Err(err);
        }

        // 已经有别的线程抢先建好了就用它的（把这条多余的关掉）
        match NFT_FD.compare_exchange(-1, new_fd, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => Ok(new_fd),
            Err(existing) => {
                unsafe { libc::close(new_fd) };
                Ok(existing)
            }
        }
    }

    fn next_seq() -> u32 {
        SEQ.fetch_add(1, Ordering::Relaxed)
    }

    fn send_all(fd: RawFd, packet: &[u8]) -> io::Result<()> {
        let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst.nl_family = libc::AF_NETLINK as u16;

        let mut sent = 0usize;
        while sent < packet.len() {
            let n = unsafe {
                libc::sendto(
                    fd,
                    packet[sent..].as_ptr() as *const libc::c_void,
                    packet.len() - sent,
                    0,
                    &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
                    size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "netlink sendto wrote 0 bytes",
                ));
            }
            sent += n as usize;
        }
        Ok(())
    }

    /// 发一条请求并读回执；把**第一条数据报文**（若有）带回来。
    ///
    /// 返回 `(data, ())`：`data` 是第一条非 `NLMSG_ERROR` 的报文（GETSET 用它取标志），
    /// SETELEM 场景下是空的。
    fn exchange(fd: RawFd, packet: &[u8], seq: u32) -> io::Result<Vec<u8>> {
        send_all(fd, packet)?;

        let mut buf = vec![0u8; 4096];
        let mut captured: Vec<u8> = Vec::new();

        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // 超时（WouldBlock/TimedOut）：本轮确实没拿到回执，如实报错，不无限等
                return Err(err);
            }
            let n = n as usize;

            match classify_ack(&buf, n, seq) {
                AckOutcome::Success => return Ok(captured),
                AckOutcome::Failed(errno) => {
                    return Err(io::Error::from_raw_os_error(errno));
                }
                AckOutcome::NotMine => {
                    // 不是回执 ⇒ 可能是 GETSET 的数据报文（也可能是别的线程的，已由锁排除）。
                    // 记下第一条，继续读回执 —— GETSET 是"数据 + ACK"两条。
                    if captured.is_empty()
                        && n >= 16
                        && u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]) == seq
                    {
                        let msg_len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                        let take = msg_len.min(n);
                        if take >= 16 {
                            captured = buf[..take].to_vec();
                        }
                    }
                }
            }
        }
    }

    /// 读集合的能力标志（`_nftset_get_flags`）。
    ///
    /// 读不到时返回 `Err` —— 调用方据此决定"放弃区间标记"，与 C 版一致。
    fn get_flags(family: u8, table: &str, set_name: &str) -> io::Result<u32> {
        let seq = next_seq();
        let packet = encode_getset(family, table, set_name, seq);

        let _guard = SOCKET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fd = socket_or_init()?;
        let data = exchange(fd, &packet, seq)?;

        if data.is_empty() {
            // 只回了 ACK、没有数据 ⇒ 什么都没读到。C 版此时会把 flags 当 0。
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "GETSET returned no set attributes",
            ));
        }

        parse_set_flags(&data).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "GETSET reply carried no NFTA_SET_FLAGS",
            )
        })
    }

    fn family_of(family_name: &str) -> u8 {
        nffamily_from_str(family_name)
    }

    pub fn add(
        family_name: &str,
        table: &str,
        set_name: &str,
        addr: &[u8],
        timeout: u64,
    ) -> io::Result<()> {
        let family = family_of(family_name);

        // 与 C 版 `nftset_add` 同序：先读集合标志，再决定超时是否归零 / 是否生成区间结束
        let mut effective_timeout = timeout;
        let interval_end: Option<Vec<u8>> = match get_flags(family, table, set_name) {
            Ok(flags) => {
                let p = process_set_flags(flags, addr, effective_timeout);
                if p.overflow {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "nftset: interval end address overflows",
                    ));
                }
                effective_timeout = p.timeout;
                p.interval_end
            }
            Err(_) => None,
        };

        let seq = next_seq();
        let mut packet = Vec::new();

        // timeout > 0 时先删一遍（C 版语义：避免残留的旧区间标记影响新值）
        if effective_timeout > 0 {
            packet.extend_from_slice(&encode_batch_begin(seq));
            append_set_elem(
                &mut packet,
                NFT_MSG_DELSETELEM,
                family,
                table,
                set_name,
                addr,
                interval_end.as_deref(),
                0,
                seq,
            );
            packet.extend_from_slice(&encode_batch_end(seq));
            let _guard = SOCKET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let fd = socket_or_init()?;
            exchange(fd, &packet, seq)?;
            packet.clear();
        }

        packet.extend_from_slice(&encode_batch_begin(seq));
        append_set_elem(
            &mut packet,
            NFT_MSG_NEWSETELEM,
            family,
            table,
            set_name,
            addr,
            interval_end.as_deref(),
            effective_timeout,
            seq,
        );
        packet.extend_from_slice(&encode_batch_end(seq));

        let _guard = SOCKET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fd = socket_or_init()?;
        exchange(fd, &packet, seq)?;
        Ok(())
    }

    pub fn del(family_name: &str, table: &str, set_name: &str, addr: &[u8]) -> io::Result<()> {
        let family = family_of(family_name);

        let interval_end = match get_flags(family, table, set_name) {
            Ok(flags) => {
                let p = process_set_flags(flags, addr, 0);
                if p.overflow {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "nftset: interval end address overflows",
                    ));
                }
                p.interval_end
            }
            Err(_) => None,
        };

        let seq = next_seq();
        let mut packet = Vec::new();
        packet.extend_from_slice(&encode_batch_begin(seq));
        append_set_elem(
            &mut packet,
            NFT_MSG_DELSETELEM,
            family,
            table,
            set_name,
            addr,
            interval_end.as_deref(),
            0,
            seq,
        );
        packet.extend_from_slice(&encode_batch_end(seq));

        let _guard = SOCKET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fd = socket_or_init()?;
        exchange(fd, &packet, seq)?;
        Ok(())
    }

    pub fn add_batch(
        family_name: &str,
        table: &str,
        set_name: &str,
        addrs: &[u8],
        timeout: u64,
    ) -> io::Result<()> {
        let family = family_of(family_name);
        let addr_len = if family == super::NFPROTO_IPV6 { 16 } else { 4 };
        let count = addrs.len() / addr_len.max(1);
        if count == 0 {
            return Ok(());
        }

        // ⚠️ 忠实复刻 C 版：读标志失败时 `flags = 0`，而下面的判据是 `if (flags != 0)`，
        //    于是"读失败"与"集合无标志"都**跳过** `process_set_flags` ——
        //    超时因此不会被归零（既有行为，见文件头说明）。
        let flags = get_flags(family, table, set_name).unwrap_or(0);
        let mut effective_timeout = timeout;

        let addr_at = |i: usize| &addrs[i * addr_len..(i + 1) * addr_len];

        // ── timeout > 0 时先批量删一遍 ──
        if timeout > 0 {
            let seq = next_seq();
            let mut packet = Vec::new();
            packet.extend_from_slice(&encode_batch_begin(seq));
            for i in 0..count {
                let addr = addr_at(i);
                let end = if flags != 0 {
                    process_set_flags(flags, addr, 0).interval_end
                } else {
                    None
                };
                append_set_elem(
                    &mut packet,
                    NFT_MSG_DELSETELEM,
                    family,
                    table,
                    set_name,
                    addr,
                    end.as_deref(),
                    0,
                    seq,
                );
            }
            packet.extend_from_slice(&encode_batch_end(seq));

            let _guard = SOCKET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let fd = socket_or_init()?;
            // C 版对这一次 send 的返回值**不判失败**（只写不读），这里同样忽略其结果，
            // 保持行为一致：真正的失败由下面那次写入的告警负责暴露。
            let _ = exchange(fd, &packet, seq);
        }

        // ── 批量新增 ──
        let seq = next_seq();
        let mut packet = Vec::new();
        packet.extend_from_slice(&encode_batch_begin(seq));
        for i in 0..count {
            let addr = addr_at(i);
            let end = if flags != 0 {
                // C 版把 `&timeout` 传进去，可能被归零；这里逐轮同步该值
                let p = process_set_flags(flags, addr, effective_timeout);
                effective_timeout = p.timeout;
                if p.overflow { None } else { p.interval_end }
            } else {
                None
            };
            append_set_elem(
                &mut packet,
                NFT_MSG_NEWSETELEM,
                family,
                table,
                set_name,
                addr,
                end.as_deref(),
                effective_timeout,
                seq,
            );
        }
        packet.extend_from_slice(&encode_batch_end(seq));

        let _guard = SOCKET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fd = socket_or_init()?;
        exchange(fd, &packet, seq)?;
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;

    /// nftables 是 Linux 内核的特性，其它平台明确报"不支持"（由调用方限流告警一次），
    /// **绝不假装成功** —— 那会变成"配了不生效还没人知道"。
    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "nftset is a Linux kernel feature and is not available on this platform (the configuration was ignored)",
        )
    }

    pub fn add(
        _family_name: &str,
        _table: &str,
        _set_name: &str,
        _addr: &[u8],
        _timeout: u64,
    ) -> io::Result<()> {
        Err(unsupported())
    }

    pub fn del(_family_name: &str, _table: &str, _set_name: &str, _addr: &[u8]) -> io::Result<()> {
        Err(unsupported())
    }

    pub fn add_batch(
        _family_name: &str,
        _table: &str,
        _set_name: &str,
        _addrs: &[u8],
        _timeout: u64,
    ) -> io::Result<()> {
        Err(unsupported())
    }
}

// ──────────────────────────────────────── 单元测试 ────────────────────────────────────────
//
// 这一整块是"纯 Rust 翻译"最大的红利：那份 C 文件在 Windows 上根本编不了，
// 而下面的报文构造、标志解析、回执判定**两平台都能跑**。

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// 按属性逐个走一遍（内核就是这样按 4 字节对齐往前走的）
    fn walk_attrs(buf: &[u8], mut off: usize) -> Vec<(u16, usize, usize)> {
        let mut out = Vec::new();
        while off + 4 <= buf.len() {
            let len = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
            let ty = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]);
            if len < 4 || off + len > buf.len() {
                break;
            }
            out.push((ty & 0x3fff, off, len));
            off += align(len);
        }
        out
    }

    // ───────────── 成果①：BATCH_END 必须带 ACK ─────────────

    /// 🔐 问题 49 成果①：`BATCH_END` **必须**带 `NLM_F_ACK`，而 `BATCH_BEGIN` **不该**带。
    ///
    /// 去掉 END 上的 ACK，内核**一个字节都不回**，读回执的逻辑必然等到超时，
    /// 于是把**成功**误报成失败 —— 真机实测过（地址确实进了集合，日志却报
    /// `Resource temporarily unavailable`）。这条测试就是防止后人"顺手化简"。
    #[test]
    fn batch_end_requests_ack_but_batch_begin_does_not() {
        let begin = encode_batch_begin(7);
        let end = encode_batch_end(7);

        let begin_flags = u16::from_ne_bytes([begin[6], begin[7]]);
        let end_flags = u16::from_ne_bytes([end[6], end[7]]);

        assert_eq!(
            end_flags & NLM_F_ACK,
            NLM_F_ACK,
            "BATCH_END 必须带 NLM_F_ACK，否则内核不回执、成功会被误报成失败"
        );
        assert_eq!(
            begin_flags & NLM_F_ACK,
            0,
            "BATCH_BEGIN 不该带 ACK（协议上 ACK 挂在 END）"
        );
        assert_eq!(begin_flags & NLM_F_REQUEST, NLM_F_REQUEST);
        assert_eq!(end_flags & NLM_F_REQUEST, NLM_F_REQUEST);

        // 类型：BEGIN/END 是裸的 NFNL_MSG_BATCH_*，子系统号放在 res_id 里
        assert_eq!(
            u16::from_ne_bytes([begin[4], begin[5]]),
            NFNL_MSG_BATCH_BEGIN
        );
        assert_eq!(u16::from_ne_bytes([end[4], end[5]]), NFNL_MSG_BATCH_END);
        // res_id = NFNL_SUBSYS_NFTABLES
        assert_eq!(
            u16::from_ne_bytes([begin[18], begin[19]]),
            NFNL_SUBSYS_NFTABLES
        );
        // 长度字段 == 实际长度
        assert_eq!(
            u32::from_ne_bytes([begin[0], begin[1], begin[2], begin[3]]) as usize,
            begin.len()
        );
    }

    // ───────────── 报文可走通 / 长度自洽 ─────────────

    /// 属性的声明长度必须与布局一致，且走完正好落在报文末尾。
    ///
    /// 只记长度、不补字节，就会从第二个属性开始错位（`ipset.rs` 的真机教训）。
    #[test]
    fn element_message_attributes_are_walkable_and_consistent() {
        let addr4 = [10u8, 20, 30, 40];
        let addr6 = [0x20u8, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        for (addr, end, timeout, family) in [
            (&addr4[..], None, 0u64, NFPROTO_INET),
            (&addr4[..], None, 900, NFPROTO_INET),
            (&addr4[..], Some(&[10u8, 20, 30, 41][..]), 60, NFPROTO_INET),
            (&addr6[..], None, 0, NFPROTO_IPV6),
            (
                &addr6[..],
                Some(&[0x20u8, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2][..]),
                3600,
                NFPROTO_IPV6,
            ),
        ] {
            let mut buf = Vec::new();
            append_set_elem(
                &mut buf,
                NFT_MSG_NEWSETELEM,
                family,
                "filter",
                "dns4",
                addr,
                end,
                timeout,
                1,
            );

            // 长度字段 == 实际长度，且 4 字节对齐
            let declared = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            assert_eq!(
                declared,
                buf.len(),
                "报文头声明 {declared}，实际 {}",
                buf.len()
            );
            assert_eq!(buf.len() % 4, 0, "报文总长要 4 字节对齐");

            // 属性走完必须正好到末尾
            let attrs = walk_attrs(&buf, NLMSG_BASE_LEN);
            let last_off = attrs.last().map(|(_, off, len)| off + align(*len));
            assert_eq!(last_off, Some(buf.len()), "属性走完必须正好到末尾");

            // 顶层属性序列：TABLE(1) + SET(2) + ELEMENTS(3)
            let tops: Vec<u16> = attrs.iter().map(|(ty, _, _)| *ty).collect();
            assert_eq!(tops, vec![1, 2, 3], "顶层属性序列不对: {tops:?}");

            // 报文类型里带着子系统号
            assert_eq!(
                u16::from_ne_bytes([buf[4], buf[5]]),
                (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM
            );
        }
    }

    /// 🔐 **超时的编码口径**：`u64`、大端、**不带** `NLA_F_NET_BYTEORDER` 标志。
    ///
    /// 这是 nftset 与 ipset 差异最大、最容易照抄写错的地方：
    /// ipset 是 `u32` 秒 + 带网络序标志，这里是 `u64` 毫秒 + 不带标志。
    #[test]
    fn timeout_is_u64_milliseconds_big_endian_without_net_byteorder_flag() {
        let mut buf = Vec::new();
        append_set_elem(
            &mut buf,
            NFT_MSG_NEWSETELEM,
            NFPROTO_INET,
            "filter",
            "s",
            &[10, 0, 0, 1],
            None,
            900, // 900 秒
            1,
        );

        // 递归找出 TIMEOUT 属性（它在 ELEMENTS → LIST_ELEM 里）
        let mut found = None;
        for (_, off, len) in walk_attrs(&buf, NLMSG_BASE_LEN) {
            // 进入嵌套块
            let mut inner = off + 4;
            let end = off + len;
            while inner + 4 <= end && inner + 4 <= buf.len() {
                let ty = u16::from_ne_bytes([buf[inner + 2], buf[inner + 3]]);
                let ln = u16::from_ne_bytes([buf[inner], buf[inner + 1]]) as usize;
                if ln < 4 {
                    break;
                }
                if (ty & 0x3fff) == NFTA_SET_ELEM_TIMEOUT {
                    found = Some((ty, inner));
                }
                // 再往里一层
                let mut deeper = inner + 4;
                while deeper + 4 <= inner + ln && deeper + 4 <= buf.len() {
                    let ty2 = u16::from_ne_bytes([buf[deeper + 2], buf[deeper + 3]]);
                    let ln2 = u16::from_ne_bytes([buf[deeper], buf[deeper + 1]]) as usize;
                    if ln2 < 4 {
                        break;
                    }
                    if (ty2 & 0x3fff) == NFTA_SET_ELEM_TIMEOUT {
                        found = Some((ty2, deeper));
                    }
                    deeper += align(ln2);
                }
                inner += align(ln);
            }
        }

        let (ty, off) = found.expect("900 秒应当产生一条 TIMEOUT 属性");
        assert_eq!(
            ty & NLA_F_NET_BYTEORDER,
            0,
            "nftset 的超时属性**不带** NLA_F_NET_BYTEORDER（这与 ipset 不同）"
        );
        let millis = u64::from_be_bytes([
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
            buf[off + 8],
            buf[off + 9],
            buf[off + 10],
            buf[off + 11],
        ]);
        assert_eq!(millis, 900_000, "超时必须是『秒 × 1000』的毫秒值");
    }

    /// timeout = 0 时**不该**出现 TIMEOUT 属性。
    ///
    /// 反例同样重要：给不支持超时的集合发这个属性，内核会回 EINVAL（真机实测）。
    #[test]
    fn zero_timeout_emits_no_timeout_attribute() {
        let mut buf = Vec::new();
        append_set_elem(
            &mut buf,
            NFT_MSG_NEWSETELEM,
            NFPROTO_INET,
            "filter",
            "s",
            &[10, 0, 0, 1],
            None,
            0,
            1,
        );

        let bytes = buf.windows(2).collect::<Vec<_>>();
        // 属性编号 4（TIMEOUT）在小端下是 [04, 00]，扫一遍确保没有
        let hit = bytes
            .iter()
            .enumerate()
            .any(|(i, w)| i >= NLMSG_BASE_LEN && w[0] == 4 && w[1] == 0 && i % 4 == 2);
        assert!(!hit, "timeout=0 时不该发出 TIMEOUT 属性");
    }

    /// 区间集合要生成"结束地址"（末字节 +1），并作为**第二个** `LIST_ELEM` 兄弟出现。
    #[test]
    fn interval_set_gets_a_second_list_elem_for_the_end_address() {
        let mut with_end = Vec::new();
        append_set_elem(
            &mut with_end,
            NFT_MSG_NEWSETELEM,
            NFPROTO_INET,
            "t",
            "s",
            &[10, 20, 30, 40],
            Some(&[10, 20, 30, 41]),
            0,
            1,
        );
        let mut without = Vec::new();
        append_set_elem(
            &mut without,
            NFT_MSG_NEWSETELEM,
            NFPROTO_INET,
            "t",
            "s",
            &[10, 20, 30, 40],
            None,
            0,
            1,
        );

        assert!(
            with_end.len() > without.len(),
            "带区间结束地址的报文必须更长（多了第二个 LIST_ELEM）"
        );
        // 结束地址的内容必须真的出现在报文里
        assert!(
            with_end.windows(4).any(|w| w == [10, 20, 30, 41]),
            "报文中应当含有结束地址 10.20.30.41"
        );
        assert!(
            !without.windows(4).any(|w| w == [10, 20, 30, 41]),
            "不带区间结束地址时，不该出现 .41"
        );
    }

    // ───────────── process_set_flags ─────────────

    /// 🔐 **集合不支持超时 ⇒ 超时必须归零**。
    ///
    /// 这一条是**必需**的：给不支持超时的集合发超时属性，内核回 `EINVAL`，
    /// 整个写入失败（真内核实测确认）。漏掉它会让"开 nftset-timeout"在
    /// 普通集合上全线失败。
    #[test]
    fn timeout_is_zeroed_when_the_set_does_not_support_it() {
        let p = process_set_flags(NFT_SET_INTERVAL, &[10, 0, 0, 1], 600);
        assert_eq!(p.timeout, 0, "集合无 NFT_SET_TIMEOUT ⇒ 超时必须归零");

        let p = process_set_flags(NFT_SET_TIMEOUT, &[10, 0, 0, 1], 600);
        assert_eq!(p.timeout, 600, "集合支持超时 ⇒ 原样保留");

        let p = process_set_flags(0, &[10, 0, 0, 1], 600);
        assert_eq!(p.timeout, 0, "集合没有任何标志 ⇒ 同样归零");
    }

    /// 区间集合生成 `地址 + 1`；非区间集合不生成。
    #[test]
    fn interval_flag_generates_the_end_address() {
        let p = process_set_flags(NFT_SET_INTERVAL, &[10, 20, 30, 40], 0);
        assert_eq!(p.interval_end.as_deref(), Some(&[10u8, 20, 30, 41][..]));
        assert!(!p.overflow);

        // IPv6：末字节 +1
        let v6 = [0x20u8, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        let p = process_set_flags(NFT_SET_INTERVAL, &v6, 0);
        assert_eq!(p.interval_end.as_ref().map(|v| v[15]), Some(6));

        // 非区间集合：不生成
        let p = process_set_flags(NFT_SET_TIMEOUT, &[10, 20, 30, 40], 0);
        assert!(p.interval_end.is_none(), "非区间集合不该生成结束地址");
    }

    /// 末字节 +1 溢出（255 → 0）时如实报 `overflow`，**不**静默回绕。
    ///
    /// C 版在这里返回 -1，调用方据此放弃区间标记。静默回绕会写进一个错误的区间，
    /// 把整个网段加进防火墙集合 —— 后果远大于放弃。
    #[test]
    fn overflowing_interval_end_is_reported_not_wrapped_silently() {
        let p = process_set_flags(NFT_SET_INTERVAL, &[10, 20, 30, 255], 0);
        assert!(p.overflow, "末字节 255+1 溢出必须被报出来");
        assert!(p.interval_end.is_none(), "溢出时不该给出回绕后的地址");
    }

    // ───────────── 家族名映射 ─────────────

    #[test]
    fn family_names_map_like_the_c_version() {
        assert_eq!(nffamily_from_str("inet"), NFPROTO_INET);
        assert_eq!(nffamily_from_str("ip"), NFPROTO_IPV4);
        assert_eq!(nffamily_from_str("ip6"), NFPROTO_IPV6);
        assert_eq!(nffamily_from_str("arp"), NFPROTO_ARP);
        assert_eq!(nffamily_from_str("netdev"), NFPROTO_NETDEV);
        assert_eq!(nffamily_from_str("bridge"), NFPROTO_BRIDGE);
        assert_eq!(nffamily_from_str("decnet"), NFPROTO_DECNET);
        // C 版用 strncmp(.., sizeof(..)) ⇒ 精确匹配："inetfoo" **不**匹配 "inet"
        assert_eq!(nffamily_from_str("inetfoo"), NFPROTO_UNSPEC);
        assert_eq!(nffamily_from_str("nonsense"), NFPROTO_UNSPEC);
    }

    // ───────────── 标志解析 ─────────────

    /// GETSET 回执里的 `NFTA_SET_FLAGS` 是**大端**（C 版用 `ntohl`）。
    #[test]
    fn set_flags_are_parsed_from_big_endian() {
        let mut msg = vec![0u8; NLMSG_BASE_LEN];
        msg[0..4].copy_from_slice(&0u32.to_ne_bytes()); // 长度最后回填
        msg[16] = NFPROTO_INET;

        // 无 FLAGS 属性 ⇒ None
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());
        assert_eq!(parse_set_flags(&msg), None);

        // 加一条 NFTA_SET_FLAGS，值 0x14（interval|timeout），大端
        push_attr(&mut msg, NFTA_SET_FLAGS, &0x14u32.to_be_bytes());
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());
        assert_eq!(
            parse_set_flags(&msg),
            Some(0x14),
            "标志必须按大端读（C 版用 ntohl）"
        );

        // 换个小端写法应当读出不同的值 —— 钉住"确实按大端读"
        let mut le = vec![0u8; NLMSG_BASE_LEN];
        push_attr(&mut le, NFTA_SET_FLAGS, &0x14u32.to_le_bytes());
        let total = le.len() as u32;
        le[0..4].copy_from_slice(&total.to_ne_bytes());
        assert_ne!(parse_set_flags(&le), Some(0x14));
    }

    // ───────────── 回执判定（照搬 ipset.rs 的结论，重新钉一遍）─────────────

    fn ack_packet(seq: u32, error: i32, declared_len: usize, actual_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; actual_len.max(20)];
        buf[0..4].copy_from_slice(&(declared_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[16..20].copy_from_slice(&error.to_ne_bytes());
        buf
    }

    /// 🔐 **偏短的回执绝不能被当成写入成功**（问题 42 的同类判据）。
    #[test]
    fn short_ack_is_not_treated_as_success() {
        let mut short = vec![0u8; 16];
        short[0..4].copy_from_slice(&16u32.to_ne_bytes());
        short[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        short[8..12].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(
            classify_ack(&short, 16, 7),
            AckOutcome::NotMine,
            "16 字节装不下错误码（需 20），必须判为不认识而不是成功"
        );

        let ok = ack_packet(7, 0, 20, 20);
        assert_eq!(classify_ack(&ok, 20, 7), AckOutcome::Success);
    }

    /// 自述长度超出实收字节数（被截断）⇒ 丢弃，不能采信。
    #[test]
    fn truncated_ack_is_rejected() {
        let lying = ack_packet(7, 0, 36, 20);
        assert_eq!(classify_ack(&lying, 20, 7), AckOutcome::NotMine);
        let honest = ack_packet(7, 0, 36, 36);
        assert_eq!(classify_ack(&honest, 36, 7), AckOutcome::Success);
    }

    /// 内核拒绝时把**真实 errno** 带回去 —— 这是"失败可见"的根据。
    /// `ENOENT(2)` = 集合/表不存在，`EPERM(1)` = 权限不足，两者必须可区分。
    #[test]
    fn failed_ack_reports_the_real_errno() {
        assert_eq!(
            classify_ack(&ack_packet(7, -2, 36, 36), 36, 7),
            AckOutcome::Failed(2)
        );
        assert_eq!(
            classify_ack(&ack_packet(7, -1, 36, 36), 36, 7),
            AckOutcome::Failed(1)
        );
        // 协议上不该出现的正数也要如实报失败
        assert_eq!(
            classify_ack(&ack_packet(7, 5, 36, 36), 36, 7),
            AckOutcome::Failed(5)
        );
    }

    /// 不是我们要的回执（别人的序号 / 别的类型）要跳过，不能误判成本次结果。
    #[test]
    fn foreign_ack_is_skipped() {
        assert_eq!(
            classify_ack(&ack_packet(99, -2, 36, 36), 36, 7),
            AckOutcome::NotMine
        );
        let mut other_type = ack_packet(7, 0, 36, 36);
        other_type[4..6].copy_from_slice(&3u16.to_ne_bytes());
        assert_eq!(classify_ack(&other_type, 36, 7), AckOutcome::NotMine);
    }

    // ───────────── 对外错误语义（替代原先依赖 C 侧状态码的两条测试）─────────────

    /// 🔐 原实现的两条测试测的是 `check_nftset_ret`（把 C 侧负返回码判为失败）。
    /// 纯 Rust 后不再有"负返回码"这个东西，**被测对象消失** ——
    /// 因此换成等价断言：errno 必须沿**返回值**显式传递、且可判别。
    ///
    /// 这比原来更结实：C 版靠 `errno` 全局变量传递，是个隐式且脆弱的契约
    /// （任何中间的 Rust 调用都可能覆盖它）。
    #[test]
    fn errno_is_carried_explicitly_and_distinguishable() {
        let not_found = io::Error::from_raw_os_error(2);
        let denied = io::Error::from_raw_os_error(1);

        assert_eq!(not_found.raw_os_error(), Some(2));
        assert_eq!(denied.raw_os_error(), Some(1));
        assert_ne!(
            not_found.raw_os_error(),
            denied.raw_os_error(),
            "『集合不存在』与『权限不足』必须能区分，否则告警无法指向正确的原因"
        );
    }

    /// 空批次不该产生任何报文，也不该被当成失败。
    #[test]
    fn empty_batch_is_a_no_op() {
        assert_eq!(add_batch("inet", "t", "s", &[], 0).unwrap(), 0);
    }

    /// 混用地址族必须**明确报错**，不能悄悄按第一个地址的长度去解析后面的。
    #[test]
    fn mixed_address_families_are_rejected() {
        let addrs = [
            IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ];
        let err = add_batch("inet", "t", "s", &addrs, 0).unwrap_err();
        assert!(
            err.to_string().contains("mixed"),
            "应当明确说明是地址族混用，实际: {err}"
        );
    }
}
