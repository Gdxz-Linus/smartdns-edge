use super::super::{
    SERVICE_NAME,
    installer::{InstallStrategy::*, Installer, UninstallStrategy::*},
    service_manager::{ServiceCommand, ServiceCommands, ServiceDefinition},
};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_arch = "aarch64")] {
        // 🌟 核心修复 1：针对 Apple M1/M2/M3 芯片使用原生标准的 opt 路径
        pub const BIN_PATH: &str = "/opt/homebrew/sbin/smartdns";
        pub const CONF_DIR: &str = "/opt/homebrew/etc/smartdns";
        pub const CONF_PATH: &str = "/opt/homebrew/etc/smartdns/smartdns.conf";
    } else {
        // 针对老款 Intel Mac 保持 usr 路径
        pub const BIN_PATH: &str = "/usr/local/sbin/smartdns";
        pub const CONF_DIR: &str = "/usr/local/etc/smartdns";
        pub const CONF_PATH: &str = "/usr/local/etc/smartdns/smartdns.conf";
    }
}

const SERVICE_FILE_PATH: &str = "/Library/LaunchDaemons/smartdns-rs.plist";
const SERVICE_FILE: &str = include_str!("files/Library/LaunchDaemons/smartdns-rs.plist");

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
    let service_file_path = SERVICE_FILE_PATH;

    let installer = Installer::builder()
        .install_current_exe_to(BIN_PATH)
        .add_item((CONF_DIR, RemoveIfEmpty))
        .add_item((CONF_PATH, crate::DEFAULT_CONF, 0o644, Preserve, Keep))
        .add_item((SERVICE_FILE_PATH, SERVICE_FILE, 0o644))
        .add_item((
            std::path::PathBuf::from(CONF_DIR).join("managed"),
            RemoveIfEmpty,
        ))
        .build();

    let launch_ctl = "launchctl";

    let commands = ServiceCommands {
        install: None,
        uninstall: None,
        start: ServiceCommand {
            program: launch_ctl.into(),
            args: vec!["load".into(), service_file_path.into()],
        },
        stop: ServiceCommand {
            program: launch_ctl.into(),
            // 🌟 核心修复 2：使用与 load 完美配对的 unload，保证所有 macOS 版本 100% 兼容卸载
            args: vec!["unload".into(), service_file_path.into()],
        },
        restart: None,
        status: Some(ServiceCommand {
            program: launch_ctl.into(),
            args: vec!["list".into(), SERVICE_NAME.into()],
        }),
    };

    ServiceDefinition::new(crate::NAME.to_string(), installer, commands)
}
