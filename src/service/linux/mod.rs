use super::{
    SERVICE_NAME,
    installer::{InstallStrategy::*, Installer, UninstallStrategy::*},
    service_manager::{ServiceCommand, ServiceCommands, ServiceDefinition},
};

pub const BIN_PATH: &str = "/usr/sbin/smartdns";
pub const CONF_DIR: &str = "/etc/smartdns";
pub const CONF_PATH: &str = "/etc/smartdns/smartdns.conf";

mod initd;
mod runit;
mod systemd;

/// 🔐 问题 45（**真机测试补漏**）：OpenWrt 不在支持范围，**任何服务管理器下都拒绝安装**。
///
/// 背景：先前的检查只写在 `initd`（sysvinit）分支里。而 OpenWrt 的较新版本、
/// 以及部分第三方固件是带 systemd 的 —— 那些环境下 `is_systemd()` 为真，
/// **根本走不到 initd 分支**，于是检查被完全绕过、服务被**静默安装**，
/// 恰好是问题 45 要消灭的"静默误装"。
///
/// 真机复现（本次）：把 `/etc/os-release` 伪装成 `ID=openwrt` 后执行 `service install` ——
/// 期望被拒绝，实际却装出了 `/usr/sbin/smartdns`、`/etc/smartdns/smartdns.conf` 与
/// `/usr/lib/systemd/system/smartdns-rs.service`，且退出码为 0。
/// 原因就是那台机器上 `is_systemd()` 为真、绕过了只挂在 initd 上的检查。
///
/// 所以把这道检查**提到分支选择之前**，让它对所有服务管理器一视同仁。
/// 这也与用户当初的决定一致：OpenWrt 不属于支持范围，应给出明确报错而不是继续安装。
pub fn refuse_on_openwrt() {
    if is_openwrt_platform() {
        // 只用 eprintln!：走到这里时日志系统不一定已就绪（`service` 子命令不初始化日志）。
        eprintln!(
            "\n❌ [ERROR] OpenWrt is not a supported platform for smartdns-edge.\n\
             \x20  This build targets enterprise/industrial edge gateways (Windows / Linux / macOS / Docker).\n\
             \x20  On OpenWrt, please use the C implementation (pymumu/smartdns) instead.\n\
             \x20  No service files were installed.\n"
        );
        crate::log::error!(
            "refusing to install the service on OpenWrt: it is not a supported platform (use the C implementation instead)"
        );

        // 以非 0 退出码结束，脚本与 CI 才能判断"没有装成功"
        std::process::exit(1);
    }
}

/// 当前平台是不是 OpenWrt（把判定单独抽出来，便于单元测试 —— `refuse_on_openwrt` 会 exit，
/// 在测试进程里没法直接调用）。
fn is_openwrt_platform() -> bool {
    crate::infra::os_release::get()
        .map(|os| os.is_openwrt())
        .unwrap_or_default()
}

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
    // 先拦截不受支持的平台，再决定用哪个服务管理器。
    refuse_on_openwrt();

    if detect::is_systemd() {
        systemd::create_service_definition()
    } else if detect::is_initd() {
        initd::create_service_definition()
    } else if detect::is_runit() {
        runit::create_service_definition()
    } else {
        // 🔐 P2：原来是 `unimplemented!()` —— 在没有 systemd/sysvinit/runit 的系统上执行
        // `service install` 会**直接 panic**（用户只看到 "not yet implemented"，没有原因、没有出路）。
        // 现在给出可读说明并退回 sysvinit 脚本定义：不崩，且至少给出一个能试的方向。
        crate::log::warn!(
            "no systemd / sysvinit / runit service manager detected; installing as a sysvinit script. If your system uses another service manager, configure autostart manually"
        );
        initd::create_service_definition()
    }
}

mod detect {
    pub use super::initd::is_initd;
    pub use super::systemd::is_systemd;
    pub use crate::infra::os_release;
    /// 🔐 P2：runit 的识别（此前这条链上根本没有它，所以 runit/Termux 环境会掉进上面的 panic 分支）。
    ///
    /// 判据取最保守的几个：Termux 用 `PREFIX` 标记且自带 runit；常见的 runit 系统会有
    /// `/etc/runit`（服务目录）或 `/etc/sv`。
    pub fn is_runit() -> bool {
        std::env::var_os("PREFIX").is_some()
            || std::path::Path::new("/etc/runit").is_dir()
            || std::path::Path::new("/etc/sv").is_dir()
    }
}

#[cfg(test)]
mod problem_45_systemd_gap_tests {
    use super::*;

    /// 🔐 问题 45（**真机测试补漏**）：OpenWrt 拦截必须发生在**服务管理器分支选择之前**。
    ///
    /// **这是真机测试抓出来的真实缺陷**：原先的检查只写在 `initd`（sysvinit）分支里，
    /// 而带 systemd 的 OpenWrt / 第三方固件根本走不到那个分支 ——
    /// `is_systemd()` 为真时直接走 systemd 分支，**检查被完全绕过、服务被静默安装**。
    ///
    /// 真机复现（伪装 `/etc/os-release` 为 `ID=openwrt`）：
    /// 修复前 —— 装出了 `/usr/sbin/smartdns`、`/etc/smartdns/smartdns.conf`、
    /// `/usr/lib/systemd/system/smartdns-rs.service`，**退出码 0**（静默误装，正是问题 45 要消灭的）；
    /// 修复后 —— 明确报错、退出码 1、不安装任何文件。
    ///
    /// 本测试**从源码结构上**钉住这个修复：断言 `create_service_definition()` 里
    /// `refuse_on_openwrt()` 的调用出现在 `is_systemd()` 判断**之前**。
    ///
    /// 为什么要用"读源码"这种形式：`refuse_on_openwrt()` 命中时会 `std::process::exit(1)`，
    /// 在测试进程内无法直接调用；而这条缺陷的本质是**调用位置错了**（挂在分支里而非分支前），
    /// 所以"位置"正是要断言的东西。
    #[test]
    fn openwrt_refusal_happens_before_service_manager_dispatch() {
        let src = include_str!("mod.rs");

        let refuse_at = src
            .find("refuse_on_openwrt();")
            .expect("create_service_definition 必须调用 refuse_on_openwrt()");
        let dispatch_at = src
            .find("if detect::is_systemd()")
            .expect("应当能找到服务管理器分支选择");

        assert!(
            refuse_at < dispatch_at,
            "🔐 问题 45：OpenWrt 拦截必须在服务管理器分支选择【之前】。\
             若放在 systemd/initd/runit 的某个分支里，其它服务管理器的环境会绕过检查、\
             静默安装服务（这正是真机测试抓到的缺陷）。\
             refuse 位置={refuse_at}, 分支选择位置={dispatch_at}"
        );
    }

    /// 🔐 反向保护：正常发行版不得被判定为 OpenWrt（否则会误拒正常安装）。
    ///
    /// 这条在**当前运行环境**上断言 —— 测试机是 Ubuntu，所以必须返回 false。
    #[test]
    fn current_platform_is_not_openwrt() {
        assert!(
            !is_openwrt_platform(),
            "当前测试环境不是 OpenWrt，判定必须为 false（不能误拒正常发行版）"
        );
    }
}
