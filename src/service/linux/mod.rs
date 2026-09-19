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

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
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
