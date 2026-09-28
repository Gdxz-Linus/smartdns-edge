//! 🔐 Q1：把解析出来的 IP 写进 Linux 的 ipset（netfilter 集合）—— 给"域名分流"用。
//!
//! 为什么要这个功能：软路由/旁路由上常见的做法是"让某些域名的 IP 进 ipset，防火墙据此决定
//! 这些流量走哪条线"。C 版有 `ipset /www.example.com/#4:dns4` 这条指令，我们一直没有 ——
//! 照 C 版文档配的人不会报错，只是**那些 IP 从来没进过集合**（典型的"配了不起作用"）。
//!
//! 走的内核接口与 C 版 `src/utils/ipset.c` 是同一条（nfnetlink / `NFNL_SUBSYS_IPSET`），
//! 报文布局逐字段对齐，但这里是**纯 Rust**：
//!   · 报文构造是纯逻辑 → 能在非 Linux 上单测（那个 C 文件在 Windows 上根本编不了）；
//!   · 不新增 C 代码、不动 build.rs。
//!
//! 比 C 版多做的两件事（都是为了"配了不生效"能被看见）：
//!   ① 发请求时带 `NLM_F_ACK` 并读回执 —— 集合不存在、权限不足等会被内核明确拒绝，
//!      我们把**真实原因**带回去（C 版只 `sendto` 不读，内核拒绝了它也不知道）；
//!   ② 失败按"集合名 + 原因"在调用方限流告警一次，不刷屏。

use std::io;
use std::net::IpAddr;

/// 内核里 ipset 集合名的上限（含结尾的 0，`IPSET_MAXNAMELEN`）
pub const IPSET_MAXNAMELEN: usize = 32;

/// ipset 的 nfnetlink 子系统号（`NFNL_SUBSYS_IPSET`）
const NFNL_SUBSYS_IPSET: u16 = 6;
/// 加元素（`IPSET_CMD_ADD`）
const IPSET_CMD_ADD: u16 = 9;
/// ipset 协议版本（`IPSET_PROTOCOL`）
///
/// 🌟 2026-09-18（WSL 真内核上跑通才敢定）：**必须是 7**。写 6 时新内核直接回
/// "集合不存在"（`No such file or directory`），日志里只会看到一条"写入失败" ——
/// 表现是"配置了像没配"，而集合其实建得好好的。老内核（协议 6）会写不进去，
/// 那种情况下我们的失败告警会明确报出来（每次启动只提示一次），不会静默。
const IPSET_PROTOCOL: u8 = 7;

const IPSET_ATTR_PROTOCOL: u16 = 1;
const IPSET_ATTR_SETNAME: u16 = 2;
const IPSET_ATTR_TIMEOUT: u16 = 6;
const IPSET_ATTR_DATA: u16 = 7;
const IPSET_ATTR_IP: u16 = 1;
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

/// 属性是嵌套的（`NLA_F_NESTED`）
const NLA_F_NESTED: u16 = 1 << 15;
/// 属性内容是网络字节序（`NLA_F_NET_BYTEORDER`）
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_REPLACE: u16 = 0x100;

const NLMSG_ALIGNTO: usize = 4;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// netlink 的 4 字节对齐（`NETLINK_ALIGN`）
#[inline]
fn align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

/// `nlmsghdr` 的固定长度（len/type/flags/seq/pid 各 4 字节）
const NLMSG_HDR_LEN: usize = 16;
/// `NLMSG_ERROR`
const NLMSG_ERROR: u16 = 2;
/// 读**错误码**所需的最小长度：`nlmsghdr`(16) + `nlmsgerr.error`(4)。
///
/// 内核发出的完整回执通常是 **36** 字节（还要带上原请求的 16 字节头），
/// 但那 16 字节我们并不使用 —— 所以这里按"**真正要读的字段**"定门槛。
/// 详见 [`classify_ack`] 的说明。
const NLMSG_ERROR_MIN_LEN: usize = NLMSG_HDR_LEN + 4;

/// 一条netlink 报文对本次写入的裁决结果。
///
/// 抽成独立类型 + [`classify_ack`] 这个**纯函数**，是为了能在**任意平台**上单测
/// （与 `encode_add` 同样的理由：这份逻辑不该只有 Linux 才验证得了）。
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
/// 🔐 问题 42：长度必须**按报文自述的长度**校验，且必须覆盖到我们真正要读的字段。
///
/// 原实现只查 `n < 16`，而错误码位于偏移 **16..20** —— 一旦收到偏短的回执，
/// `buf[16..20]` 读到的就是缓冲区里的**残留零值**，于是 `code == 0` 被当成
/// "写入成功"。这恰好退化成"**配了不生效还没人知道**"，
/// 与本次整改强调的"失败要看得见"完全相悖。
///
/// 三个条件缺一不可：
///   ① `msg_len >= 20` —— 报文**自称**的长度要够装下错误码；
///   ② `msg_len <= n`  —— 自称长度不得超出**本次实收**字节数（截断的报文不可信）；
///   ③ `n >= 20`       —— 实收字节也要够（防御自述长度与实际不符的情况）。
///
/// 任一条不满足就当作"这条报文我们不认识"，丢弃并继续读下一条 ——
/// 套接字带 500ms 收超时，因此不可能是死循环（真收不到最后会返回超时错误）。
fn classify_ack(buf: &[u8], n: usize, seq: u32) -> AckOutcome {
    // 连头部都读不全：无法解释，丢弃
    if n < NLMSG_HDR_LEN || buf.len() < NLMSG_HDR_LEN {
        return AckOutcome::NotMine;
    }

    let msg_len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    let msg_seq = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);

    // ①②③：长度三重校验（见函数文档）
    if msg_len < NLMSG_ERROR_MIN_LEN || msg_len > n || n < NLMSG_ERROR_MIN_LEN {
        return AckOutcome::NotMine;
    }

    // 不是我们要的那条回执（比如别的线程的、或通知消息）：跳过继续读
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

/// 拼一条 `IPSET_CMD_ADD` 报文（返回值就是 `sendto` 要发的字节）。
///
/// 布局与 C 版 `_ipset_operate()` 逐字段对齐：
/// ```text
/// nlmsghdr { len, type = IPSET_CMD_ADD | (NFNL_SUBSYS_IPSET << 8),
///            flags = REQUEST | REPLACE (我们再加 ACK), seq, pid = 0 }
/// nfgenmsg { family = AF_INET/AF_INET6, version = 0, res_id = htons(NFNL_SUBSYS_IPSET) }
/// attr PROTOCOL  = u8 7
/// attr SETNAME   = 集合名 + '\0'
/// attr DATA (nested) {
///     attr IP (nested) { attr IPADDR_IPV4|NET_BYTEORDER(4B) 或 IPADDR_IPV6|NET_BYTEORDER(16B) }
///     attr TIMEOUT|NET_BYTEORDER = u32(网络序)   ← 只有 timeout > 0 才有
/// }
/// ```
/// 注意：嵌套属性的 `len` 按 C 版的做法取"对齐后的结束位置 − 起始位置"（含补齐字节）。
fn encode_add(setname: &str, addr: IpAddr, timeout: u64, seq: u32) -> io::Result<Vec<u8>> {
    if setname.as_bytes().len() + 1 > IPSET_MAXNAMELEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "ipset set name too long: '{}' is {} bytes; the kernel limit is {} bytes (including the terminator), at most {} characters",
                setname,
                setname.as_bytes().len() + 1,
                IPSET_MAXNAMELEN,
                IPSET_MAXNAMELEN - 1
            ),
        ));
    }

    let (af, addr_bytes): (u8, Vec<u8>) = match addr {
        IpAddr::V4(v4) => (AF_INET, v4.octets().to_vec()),
        IpAddr::V6(v6) => (AF_INET6, v6.octets().to_vec()),
    };
    let addr_attr_type = match addr {
        IpAddr::V4(_) => IPSET_ATTR_IPADDR_IPV4,
        IpAddr::V6(_) => IPSET_ATTR_IPADDR_IPV6,
    };

    let mut buf: Vec<u8> = Vec::with_capacity(128);

    // ── nlmsghdr（先把 len 占位，最后回填）──
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&(IPSET_CMD_ADD | (NFNL_SUBSYS_IPSET << 8)).to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_ACK).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // pid：内核不管，0 即可

    // ── nfgenmsg ──
    buf.push(af);
    buf.push(0); // version = NFNETLINK_V0
    buf.extend_from_slice(&NFNL_SUBSYS_IPSET.to_be_bytes()); // res_id 是网络序

    // ── attr PROTOCOL ──
    push_attr(&mut buf, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);

    // ── attr SETNAME（带结尾 0）──
    let mut setname_bytes = setname.as_bytes().to_vec();
    setname_bytes.push(0);
    push_attr(&mut buf, IPSET_ATTR_SETNAME, &setname_bytes);

    // ── attr DATA（嵌套）──
    let data_start = buf.len();
    push_attr_header(&mut buf, NLA_F_NESTED | IPSET_ATTR_DATA);

    //     └── attr IP（嵌套）──
    let ip_start = buf.len();
    push_attr_header(&mut buf, NLA_F_NESTED | IPSET_ATTR_IP);
    push_attr(&mut buf, addr_attr_type | NLA_F_NET_BYTEORDER, &addr_bytes);
    close_nested_attr(&mut buf, ip_start);

    if timeout > 0 {
        let expire = (timeout as u32).to_be_bytes();
        push_attr(&mut buf, IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER, &expire);
    }

    close_nested_attr(&mut buf, data_start);

    // 回填 nlmsghdr.len（对齐后的长度），并把缓冲区补到同样长度 ——
    // C 版发出去的就是 `nlmsg_len` 这么多字节（它那个 1024 字节的栈缓冲本来就是 0 填充的）
    let total = align(buf.len());
    buf.resize(total, 0);
    buf[0..4].copy_from_slice(&(total as u32).to_ne_bytes());

    Ok(buf)
}

/// 写一个属性头（4 字节：len + type），len 先占位，之后由 `push_attr` / `close_nested_attr` 回填
fn push_attr_header(buf: &mut Vec<u8>, attr_type: u16) {
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
}

/// 收尾一个嵌套属性：长度 = 对齐后的结束位置 − 属性起点。
///
/// 嵌套属性只是"边界"（内核按 4 字节对齐逐个走子属性，末尾多几个补齐字节会被忽略），
/// 所以这里带上补齐是安全的；要紧的是 SETNAME 那类**带长度上限**的属性用精确值（见 `push_attr`）。
fn close_nested_attr(buf: &mut Vec<u8>, start: usize) {
    pad_to_align(buf);
    let len = (buf.len() - start) as u16;
    buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
}

/// 写一个"头 + 内容"的属性，并把内容补齐到 4 字节（长度含头）。
///
/// ⚠️ 补齐字节必须**真的写进缓冲区**：属性长度按 4 字节对齐记账，而属性之间的起点也要落在
/// 对齐位置 —— 只记长度不补字节，第二个属性起位置就歪了，内核会认不出后面的属性。
/// （C 版靠的是它那个 `memset` 过的 1024 字节栈缓冲；我们这里显式补，行为一致。）
fn push_attr(buf: &mut Vec<u8>, attr_type: u16, content: &[u8]) {
    let start = buf.len();
    push_attr_header(buf, attr_type);
    buf.extend_from_slice(content);

    // 长度记"精确值"（头 + 内容，不含补齐字节）—— 与官方 `ipset` 工具一致。
    // 这点很重要：像 SETNAME 这种内核带长度上限的属性，把补齐字节算进去会白白多 3 个字节，
    // 名字长的集合会被内核以"太长"拒掉。补齐字节仍然要写进缓冲区，但**不算在长度里**。
    let len = (buf.len() - start) as u16;
    buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());

    pad_to_align(buf);
}

/// 把缓冲区补到 4 字节边界（补 0）
#[inline]
fn pad_to_align(buf: &mut Vec<u8>) {
    let padding = align(buf.len()) - buf.len();
    buf.resize(buf.len() + padding, 0);
}

/// 一批写入的结果：成功几条、失败几条、第一个失败的地址与原因
#[derive(Debug, Default)]
pub struct BatchResult {
    pub added: usize,
    pub failed: usize,
    pub first_error: Option<(IpAddr, io::Error)>,
}

impl BatchResult {
    /// 全成功？
    #[inline]
    pub fn is_ok(&self) -> bool {
        self.failed == 0
    }
}

/// 把若干地址写进同一个 ipset。
///
/// `timeout` 为 0 表示不设过期时间（与不写 `ipset-timeout` 时的行为一致）。
/// 集合不存在等错误不 panic：带回来交给调用方告警（限流一次）。
pub fn add_batch(setname: &str, addrs: &[IpAddr], timeout: u64) -> BatchResult {
    let mut result = BatchResult::default();

    for addr in addrs {
        match imp::add(setname, *addr, timeout) {
            Ok(()) => result.added += 1,
            Err(err) => {
                result.failed += 1;
                if result.first_error.is_none() {
                    result.first_error = Some((*addr, err));
                }
            }
        }
    }

    result
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::mem::size_of;
    use std::net::IpAddr;
    use std::os::fd::RawFd;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

    use super::{AckOutcome, NFNL_SUBSYS_IPSET, classify_ack, encode_add};

    /// 复用一个 netlink 套接字（C 版也是全局复用一个 fd）
    static IPSET_FD: AtomicI32 = AtomicI32::new(-1);
    /// 报文序号，用来跟回执对上
    static SEQ: AtomicU32 = AtomicU32::new(1);
    /// 收/发配对的锁：netlink 套接字不适合多线程同时 send/recv
    static SOCKET_LOCK: Mutex<()> = Mutex::new(());

    /// 等回执的上限：内核处理一条 ADD 是微秒级，超过这个时间就当没回执（不阻塞查询线程）
    const ACK_TIMEOUT_MS: i64 = 500;

    fn socket_or_init() -> io::Result<RawFd> {
        let fd = IPSET_FD.load(Ordering::Relaxed);
        if fd >= 0 {
            return Ok(fd);
        }

        // AF_NETLINK / SOCK_RAW / NETLINK_NETFILTER(12)
        let new_fd =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 12) };
        if new_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // 收回执要有超时，否则内核不回时会把线程挂死
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
            let err = io::Error::last_os_error();
            unsafe { libc::close(new_fd) };
            return Err(err);
        }

        // 已经有别的线程抢先建好了就用它的（把这条多余的关掉）
        match IPSET_FD.compare_exchange(-1, new_fd, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => Ok(new_fd),
            Err(existing) => {
                unsafe { libc::close(new_fd) };
                Ok(existing)
            }
        }
    }

    /// 读一条回执；成功返回 Ok(())，失败把内核给的 errno 变成 io::Error。
    ///
    /// 判定逻辑在 [`classify_ack`]（纯函数、两平台可单测）；这里只负责收包与循环。
    /// 🔐 问题 42：原实现只查 `n >= 16` 就取偏移 16..20 的错误码，
    /// 偏短回执会读到缓冲区残留的零值 ⇒ **被当成写入成功**。
    /// 现在长度不够的报文一律判为"不认识"，继续读；真读不到最终由收超时报错。
    fn read_ack(fd: RawFd, seq: u32) -> io::Result<()> {
        let mut buf = [0u8; 1024];
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                // 超时/被打断：拿不到回执就当"内核没理我们"，直接报错，不无限等
                return Err(err);
            }

            match classify_ack(&buf, n as usize, seq) {
                AckOutcome::NotMine => continue,
                AckOutcome::Success => return Ok(()),
                AckOutcome::Failed(errno) => {
                    return Err(io::Error::from_raw_os_error(errno));
                }
            }
        }
    }

    pub fn add(setname: &str, addr: IpAddr, timeout: u64) -> io::Result<()> {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let packet = encode_add(setname, addr, timeout, seq)?;

        let _guard = SOCKET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fd = socket_or_init()?;

        // 🌟 2026-09-18（WSL 真机首编暴露）：`sockaddr_nl` 的 `nl_pad` 是给编译器看的填充字节，
        // 新版 libc 把它收成了**私有字段**，直接写 `nl_pad: 0` 在 Linux 上编不过（E0451）。
        // 它本来就该是 0，改用"整块清零 + 只填 family"，既不依赖 libc 的字段可见性，
        // 行为也和原来逐字节一致。
        let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst.nl_family = libc::AF_NETLINK as u16;

        let sent = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        read_ack(fd, seq)
    }

    /// 目前没用上，但留着：把元素从集合里删掉（C 版有 `ipset_del`）
    #[allow(dead_code)]
    pub fn _subsys() -> u16 {
        NFNL_SUBSYS_IPSET
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;
    use std::net::IpAddr;

    /// ipset 是 Linux 内核的特性，其它平台明确报"不支持"（由调用方限流告警一次），
    /// 绝不假装成功 —— 那会变成"配了不生效还没人知道"。
    pub fn add(_setname: &str, _addr: IpAddr, _timeout: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ipset is a Linux kernel feature and is not available on this platform (the configuration was ignored)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// 按**官方 `ipset` 工具**的约定独立拼一遍（属性长度写精确值、起点 4 字节对齐），
    /// 与我们的编码逐字节对照 —— 两套独立实现对照，比"自己测自己"强。
    /// （这版参照是"真内核验证"之后修正过的：早先两套实现一起犯了"只记对齐长度、不补字节"的错，
    ///   单测互相点头、内核却拒收 —— 所以还必须有真机那一步。）
    fn reference_expected(setname: &str, addr: IpAddr, timeout: u64, seq: u32) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // nlmsghdr
        buf.extend_from_slice(&0u32.to_ne_bytes()); // len 占位
        buf.extend_from_slice(&(9u16 | (6u16 << 8)).to_ne_bytes()); // IPSET_ADD
        buf.extend_from_slice(&(0x01u16 | 0x100u16 | 0x04u16).to_ne_bytes()); // REQUEST|REPLACE|ACK
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());

        // nfgenmsg
        let (af, addr_bytes): (u8, Vec<u8>) = match addr {
            IpAddr::V4(v4) => (2, v4.octets().to_vec()),
            IpAddr::V6(v6) => (10, v6.octets().to_vec()),
        };
        buf.push(af);
        buf.push(0);
        buf.extend_from_slice(&6u16.to_be_bytes());

        // 属性：长度写精确值（头 + 内容，不含补齐），补齐字节照样写进缓冲区
        let attr = |buf: &mut Vec<u8>, ty: u16, content: &[u8]| {
            let start = buf.len();
            buf.extend_from_slice(&0u16.to_ne_bytes());
            buf.extend_from_slice(&ty.to_ne_bytes());
            buf.extend_from_slice(content);
            let len = (buf.len() - start) as u16;
            buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
            buf.resize(align(buf.len()), 0);
        };

        attr(&mut buf, 1, &[7u8]); // PROTOCOL
        let mut name = setname.as_bytes().to_vec();
        name.push(0);
        attr(&mut buf, 2, &name); // SETNAME

        let data_start = buf.len();
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&(NLA_F_NESTED | 7).to_ne_bytes());

        let ip_start = buf.len();
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&(NLA_F_NESTED | 1).to_ne_bytes());

        let addr_type = if af == 2 { 1u16 } else { 2u16 };
        attr(&mut buf, addr_type | NLA_F_NET_BYTEORDER, &addr_bytes);

        buf.resize(align(buf.len()), 0);
        let len = (buf.len() - ip_start) as u16;
        buf[ip_start..ip_start + 2].copy_from_slice(&len.to_ne_bytes());

        if timeout > 0 {
            let expire = (timeout as u32).to_be_bytes();
            attr(&mut buf, 6 | NLA_F_NET_BYTEORDER, &expire);
        }

        buf.resize(align(buf.len()), 0);
        let len = (buf.len() - data_start) as u16;
        buf[data_start..data_start + 2].copy_from_slice(&len.to_ne_bytes());

        let total = align(buf.len());
        buf.resize(total, 0);
        buf[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
        buf
    }

    #[test]
    fn encode_matches_c_version_ipv4() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let ours = encode_add("dns4", addr, 0, 7).unwrap();
        assert_eq!(ours, reference_expected("dns4", addr, 0, 7));
    }

    #[test]
    fn encode_matches_c_version_ipv6_with_timeout() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ours = encode_add("dns6", addr, 3600, 7).unwrap();
        assert_eq!(ours, reference_expected("dns6", addr, 3600, 7));
    }

    /// 报文关键字段必须肉眼可核（类型/子系统号/属性编号），
    /// 免得"两套实现一起写错"还互相点头
    #[test]
    fn encode_key_fields() {
        let addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let buf = encode_add("s", addr, 0, 42).unwrap();

        // nlmsg_type = IPSET_CMD_ADD(9) | (NFNL_SUBSYS_IPSET(6) << 8) = 0x0609
        assert_eq!(u16::from_ne_bytes([buf[4], buf[5]]), 0x0609);
        // flags 里有 REQUEST | REPLACE | ACK
        let flags = u16::from_ne_bytes([buf[6], buf[7]]);
        assert_eq!(flags & (NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_ACK), flags);
        // seq 原样带上
        assert_eq!(u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]), 42);
        // nfgenmsg.family = AF_INET
        assert_eq!(buf[16], AF_INET);
        // nfgenmsg.res_id = htons(6)
        assert_eq!(&buf[18..20], &[0x00, 0x06]);
        // 长度字段 == 实际长度（4 字节对齐）
        assert_eq!(
            u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize,
            buf.len()
        );
        assert_eq!(buf.len() % 4, 0);
    }

    /// 🩹 这一条是"真机验证"换来的教训：应答里所有属性的**声明长度必须和实际布局一致**，
    /// 且一步步走下来要正好落在报文末尾。只记长度、不补字节，就会从第二个属性开始错位
    /// （内核认不出后面的属性，回 IPSET_ERR_PROTOCOL，就是本机实测踩到的那个坑）。
    #[test]
    fn attributes_are_walkable_and_consistent() {
        for (setname, addr, timeout) in [
            ("dns4", IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 0u64),
            ("a", IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 60),
            ("dns6", IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            (
                "a-very-long-set-name-31chars-ab",
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                300,
            ),
        ] {
            let buf = encode_add(setname, addr, timeout, 1).unwrap();

            // 报头声明的长度必须等于实际字节数
            let declared = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            assert_eq!(
                declared,
                buf.len(),
                "报文头声明 {declared}，实际 {}",
                buf.len()
            );
            assert_eq!(buf.len() % 4, 0, "报文总长要 4 字节对齐");

            // 从第一个属性开始走：每个属性的长度都必须"含头、且落在 4 字节边界上"
            let mut off = 20; // nlmsghdr(16) + nfgenmsg(4)
            let mut seen = Vec::new();
            while off < buf.len() {
                assert!(off + 4 <= buf.len(), "属性头越界 @{off}");
                let len = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
                let ty = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]);
                assert!(len >= 4, "属性长度不合法 {len} @{off}");
                assert!(off + len <= buf.len(), "属性超出报文 @{off} len={len}");
                assert_eq!(off % 4, 0, "属性起点必须 4 字节对齐 @{off}");
                seen.push(ty & 0x3fff);
                off += align(len); // 内核就是这样按 4 字节对齐往前走的
            }
            assert_eq!(off, buf.len(), "属性走完必须正好到末尾");
            // 命令级属性：PROTOCOL(1) + SETNAME(2) + DATA(7)
            assert_eq!(seen, vec![1, 2, 7], "属性序列不对：{seen:?}");
        }
    }

    /// 嵌套块（DATA → IP → IPADDR）的长度也要自洽：把 IP 块单独走一遍
    #[test]
    fn nested_blocks_are_consistent() {
        let buf = encode_add("dns4", IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 90, 1).unwrap();

        // 找 DATA 属性（type & 0x3fff == 7）
        let mut off = 20;
        let data_off = loop {
            assert!(off + 4 <= buf.len(), "没找到 DATA 属性");
            let len = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
            let ty = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]);
            if ty & 0x3fff == 7 {
                assert_ne!(ty & NLA_F_NESTED, 0, "DATA 必须带 NLA_F_NESTED");
                break off;
            }
            assert!(len >= 4, "属性长度不合法 {len} @{off}");
            // 内核是按 4 字节对齐往前走的（nla_next → NLA_ALIGN）—— 这里必须照做，
            // 否则会走进属性中间的字节，读出 0 长度然后死循环（本测试踩过这个坑）
            off += align(len);
        };
        let data_len = u16::from_ne_bytes([buf[data_off], buf[data_off + 1]]) as usize;

        // DATA 里：IP 块 + TIMEOUT
        let p = data_off + 4;
        let ip_len = u16::from_ne_bytes([buf[p], buf[p + 1]]) as usize;
        let ip_ty = u16::from_ne_bytes([buf[p + 2], buf[p + 3]]);
        assert_eq!(ip_ty & 0x3fff, 1, "DATA 里第一个应该是 IP");
        assert_ne!(ip_ty & NLA_F_NESTED, 0, "IP 要带 NLA_F_NESTED");

        // IP 里：IPADDR
        let q = p + 4;
        let addr_len = u16::from_ne_bytes([buf[q], buf[q + 1]]) as usize;
        let addr_ty = u16::from_ne_bytes([buf[q + 2], buf[q + 3]]);
        assert_eq!(addr_ty & 0x3fff, 1, "IP 里应该是 IPADDR_IPV4");
        assert_ne!(addr_ty & NLA_F_NET_BYTEORDER, 0, "地址要网络字节序");
        assert_eq!(addr_len, 8, "IPv4 地址属性 4+4");
        assert_eq!(&buf[q + 4..q + 8], &[10, 1, 2, 3], "地址内容");

        let after_ip = p + ip_len;
        let to_len = u16::from_ne_bytes([buf[after_ip], buf[after_ip + 1]]) as usize;
        let to_ty = u16::from_ne_bytes([buf[after_ip + 2], buf[after_ip + 3]]);
        assert_eq!(to_ty & 0x3fff, 6, "IP 之后是 TIMEOUT");
        assert_ne!(to_ty & NLA_F_NET_BYTEORDER, 0, "超时要网络字节序");
        assert_eq!(to_len, 8);
        assert_eq!(
            u32::from_be_bytes([
                buf[after_ip + 4],
                buf[after_ip + 5],
                buf[after_ip + 6],
                buf[after_ip + 7]
            ]),
            90
        );

        assert_eq!(
            after_ip + to_len,
            data_off + data_len,
            "DATA 的长度要正好包住里面两个属性"
        );
    }

    /// 集合名长度按内核上限卡住，并且**说明白**为什么被拒（不是静默失败）
    #[test]
    fn setname_length_is_checked() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(
            encode_add(&"a".repeat(31), addr, 0, 1).is_ok(),
            "31 字符可以"
        );

        let err = encode_add(&"a".repeat(32), addr, 0, 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("too long"),
            "must state the reason: {err}"
        );
    }

    /// add_batch：能分开报"成了几条、第一条错是什么"
    #[test]
    fn batch_result_reports_first_error() {
        let addrs = [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let r = add_batch("some-set-that-does-not-exist", &addrs, 0);
        if cfg!(target_os = "linux") {
            assert_eq!(r.added + r.failed, 1);
        } else {
            // 非 Linux：明确失败，且带原因（调用方会限流告警）
            assert_eq!(r.added, 0);
            assert_eq!(r.failed, 1);
            let (_, err) = r.first_error.as_ref().expect("要有原因");
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }
    }

    // ==================== 🔐 问题 42：回执长度校验 ====================

    /// 拼一条 `NLMSG_ERROR` 回执（按内核的真实布局）。
    ///
    /// ```text
    /// nlmsghdr { len, type = NLMSG_ERROR(2), flags, seq, pid }
    /// nlmsgerr { error: i32, msg: <原请求头> }
    /// ```
    /// `total_len` 用于**故意**把自述长度写小/写大，构造畸形报文。
    fn ack_packet(seq: u32, error: i32, declared_len: usize, actual_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; actual_len.max(20)];
        // nlmsghdr
        buf[0..4].copy_from_slice(&(declared_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        // nlmsgerr.error
        buf[16..20].copy_from_slice(&error.to_ne_bytes());
        buf
    }

    /// 🔐 问题 42 的核心：**偏短的回执绝不能被当成写入成功**。
    ///
    /// 修复前只查 `n >= 16` 就取偏移 16..20 —— 偏短报文的这四个字节是**残留零值**，
    /// 于是 `code == 0` ⇒ "成功"。表现为"ipset 写入静默失败"，
    /// 正是本次整改最要消灭的那类问题。
    #[test]
    fn short_ack_is_not_treated_as_success() {
        // 恰好在旧门槛上：16 字节，够旧代码取"错误码"（其实是缓冲区残留的 0）
        let mut short = vec![0u8; 16];
        short[0..4].copy_from_slice(&16u32.to_ne_bytes()); // 自述长度也是 16
        short[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        short[8..12].copy_from_slice(&7u32.to_ne_bytes());

        assert_eq!(
            classify_ack(&short, 16, 7),
            AckOutcome::NotMine,
            "16 字节的回执装不下错误码（需 20 字节），必须判为不认识而不是成功"
        );

        // 19 字节：只差一个字节，同样不可信
        let nearly = ack_packet(7, 0, 19, 19);
        assert_eq!(
            classify_ack(&nearly, 19, 7),
            AckOutcome::NotMine,
            "19 字节仍不足以读完整错误码"
        );

        // 刚好 20 字节：可以读错误码了 ⇒ 这才是合法的"成功"回执
        let ok = ack_packet(7, 0, 20, 20);
        assert_eq!(classify_ack(&ok, 20, 7), AckOutcome::Success);
    }

    /// 自述长度 > 实收字节数（被截断的报文）不可信 —— 必须丢弃。
    #[test]
    fn truncated_ack_is_rejected() {
        // 自称 36 字节（内核完整回执的长度），实际只收到 20 字节
        let lying = ack_packet(7, 0, 36, 20);
        assert_eq!(
            classify_ack(&lying, 20, 7),
            AckOutcome::NotMine,
            "自述长度超出实收字节数 ⇒ 报文被截断，不能采信"
        );

        // 对照：实收 36（与自述一致）⇒ 正常采信
        let honest = ack_packet(7, 0, 36, 36);
        assert_eq!(classify_ack(&honest, 36, 7), AckOutcome::Success);
    }

    /// 内核拒绝时要把**真实 errno** 带回去（这是"失败可见"的根据）。
    #[test]
    fn failed_ack_reports_the_real_errno() {
        // 内核给的是负 errno：-ENOENT(2) = 集合不存在
        let denied = ack_packet(7, -2, 36, 36);
        assert_eq!(classify_ack(&denied, 36, 7), AckOutcome::Failed(2));

        // -EPERM(1) = 权限不足
        let perm = ack_packet(7, -1, 36, 36);
        assert_eq!(classify_ack(&perm, 36, 7), AckOutcome::Failed(1));

        // 协议上不该出现的正数：也要**如实报失败**，绝不能当成功
        let weird = ack_packet(7, 5, 36, 36);
        assert_eq!(classify_ack(&weird, 36, 7), AckOutcome::Failed(5));
    }

    /// 不是我们要的回执（别人的序号 / 别的类型）要跳过，不能误判成本次的结果。
    #[test]
    fn foreign_ack_is_skipped() {
        // 序号对不上 → 丢弃（否则会拿别的线程的结果回答自己）
        let other_seq = ack_packet(99, -2, 36, 36);
        assert_eq!(classify_ack(&other_seq, 36, 7), AckOutcome::NotMine);

        // 类型不是 NLMSG_ERROR → 丢弃
        let mut other_type = ack_packet(7, 0, 36, 36);
        other_type[4..6].copy_from_slice(&3u16.to_ne_bytes());
        assert_eq!(classify_ack(&other_type, 36, 7), AckOutcome::NotMine);
    }
}
