//!
//! Service Manager
//!
//! ref: https://rtc.datacentric.sg/docs/service.html

use self::{installer::InstallerBuilder, service_manager::ServiceManager};
use cfg_if::cfg_if;
use std::{env, path::Path};

pub const SERVICE_NAME: &str = "smartdns-rs";

/// 生成 launchd 的 plist 内容（macOS）。
///
/// 🌟 P1-8 修复：这份 plist 原来是 `include_str!` 静态嵌进二进制的，文件里写死了
/// `/usr/local/sbin/smartdns` 与 `/usr/local/etc/smartdns/smartdns.conf`。
/// 而 Apple Silicon 上二进制被装到 `/opt/homebrew/sbin/...`，于是 launchd 去启动一个
/// 并不存在的可执行文件、`-c` 指向一个并不存在的配置 —— 服务启动即失败。
/// 现在按当前架构的真实路径生成，不再存在"二进制的路径"和"plist 里的路径"两套说法。
///
/// 放在这个"所有平台都会编译"的模块里，是为了让单测在任何平台上都能跑到
/// （`mod macos` 只在 macOS 上编译）。
pub fn render_launchd_plist(bin_path: &str, conf_path: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>KeepAlive</key>
        <true/>
        <key>Label</key>
        <string>{name}</string>
        <key>LimitLoadToSessionType</key>
        <array>
                <string>Aqua</string>
                <string>Background</string>
                <string>LoginWindow</string>
                <string>StandardIO</string>
                <string>System</string>
        </array>
        <key>ProgramArguments</key>
        <array>
                <string>{bin_path}</string>
                <string>run</string>
                <string>-c</string>
                <string>{conf_path}</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
</dict>
</plist>
"#,
        name = SERVICE_NAME,
        bin_path = bin_path,
        conf_path = conf_path,
    )
}

mod installer;
mod service_manager;

pub use service_manager::ServiceStatus;

cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;
        use linux::create_service_definition;
        pub use linux::CONF_PATH;
    } else if #[cfg(target_os = "macos")] {
        mod macos;
        use self::macos::create_service_definition;
        pub use macos::CONF_PATH;
    } else if #[cfg(target_os = "windows")] {
        pub mod windows;
        use self::windows::create_service_definition;
        pub use self::windows::CONF_PATH;

pub fn service_manager() -> ServiceManager {
    create_service_definition().into()
}

impl InstallerBuilder {
    fn install_current_exe_to<P: AsRef<Path>>(self, path: P) -> Self {
        let cmd_path = path.as_ref();
        let current_exe =
            env::current_exe().unwrap_or_else(|e| panic!("failed to get current exe path: {e}"));

        if current_exe != cmd_path {
            self.add_item((current_exe, cmd_path))
        } else {
            self
        }
    }
}
    } else {
        unimplemented!();
    }
}

#[cfg(test)]
mod plist_tests {
    use super::*;

    #[test]
    fn launchd_plist_uses_the_paths_it_is_given() {
        // Apple Silicon 的真实路径
        let plist = render_launchd_plist(
            "/opt/homebrew/sbin/smartdns",
            "/opt/homebrew/etc/smartdns/smartdns.conf",
        );
        assert!(
            plist.contains("<string>/opt/homebrew/sbin/smartdns</string>"),
            "{plist}"
        );
        assert!(
            plist.contains("<string>/opt/homebrew/etc/smartdns/smartdns.conf</string>"),
            "{plist}"
        );
        // 🌟 P1-8 的回归点：不能再有任何写死的 /usr/local（Apple Silicon 上它不存在）
        assert!(
            !plist.contains("/usr/local"),
            "plist 不应再写死 /usr/local：{plist}"
        );
    }

    #[test]
    fn launchd_plist_keeps_the_original_shape() {
        let plist = render_launchd_plist(
            "/usr/local/sbin/smartdns",
            "/usr/local/etc/smartdns/smartdns.conf",
        );
        // 老 Intel Mac 路径仍可用
        assert!(
            plist.contains("<string>/usr/local/sbin/smartdns</string>"),
            "{plist}"
        );
        // 其余关键项与被替换掉的静态文件保持一致
        assert!(plist.contains("<string>smartdns-rs</string>"), "{plist}");
        assert!(plist.contains("<key>RunAtLoad</key>"), "{plist}");
        assert!(plist.contains("<key>KeepAlive</key>"), "{plist}");
        assert!(plist.contains("<string>StandardIO</string>"), "{plist}");
        assert!(plist.contains("<string>run</string>"), "{plist}");
        assert!(plist.contains("<string>-c</string>"), "{plist}");
        assert_eq!(plist.matches("<dict>").count(), 1, "只应有一个顶层 dict");
        assert_eq!(plist.matches("</plist>").count(), 1);
    }
}
