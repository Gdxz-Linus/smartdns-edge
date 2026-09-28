//!
//! sysvinit

use std::path::Path;

use super::*;

mod debian;
mod others;

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
    // 🔐 问题 45：OpenWrt **不在支持范围**，这里给出明确报错而不是继续安装。
    //
    // 背景：原先这套代码带一份 OpenWrt 专用的 procd 脚本，而那个脚本把 `uci` 里的取值
    // 直接拼进生成的配置行 —— 取值里只要含空格、换行或单引号，就能**凭空插入任意配置项**
    // （例如 `address`、`log-file`、`conf-file`），进而放大配置劫持面。
    //
    // 已核实：本项目的正式「支持的操作系统」只有 Windows / Linux / macOS / Docker，
    // 文档里明确写着面向企业级核心网关、OpenWrt 用户请使用 C 版。
    // 也就是说这份脚本既不在支持范围内、又带着可利用的拼接缺陷 —— 直接移除，
    // 并对 OpenWrt 上的安装请求给出明确说明（而不是悄悄装一个不受支持的脚本进去）。
    //
    // ⚠️ 真机测试补漏：这段检查原先**只在这里**（sysvinit 分支），
    // 而带 systemd 的 OpenWrt/第三方固件根本走不到本分支，检查被完全绕过。
    // 现已提到 `linux/mod.rs` 的 `refuse_on_openwrt()`，在**分支选择之前**统一拦截。
    // 这里保留一次调用作为第二道防线（幂等：非 OpenWrt 时直接返回）。
    super::refuse_on_openwrt();

    let (service_file_path, service_file) = {
        if debian::is_debian() {
            (debian::SERVICE_FILE_PATH, debian::SERVICE_FILE)
        } else {
            (others::SERVICE_FILE_PATH, others::SERVICE_FILE)
        }
    };

    let installer = Installer::builder()
        .install_current_exe_to(BIN_PATH)
        .add_item((CONF_DIR, RemoveIfEmpty))
        .add_item((CONF_PATH, crate::DEFAULT_CONF, 0o644, Preserve, Keep))
        .add_item((service_file_path, service_file, 0o755))
        .add_item((
            std::path::PathBuf::from(CONF_DIR).join("managed"),
            RemoveIfEmpty,
        ))
        .build();

    let service_ctl = "service";

    let commands = ServiceCommands {
        install: Some(ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "enable".into()],
        }),
        uninstall: Some(ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "disable".into()],
        }),
        start: ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "start".into()],
        },
        stop: ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "stop".into()],
        },
        restart: Some(ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "restart".into()],
        }),
        status: Some(ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "status".into()],
        }),
    };

    ServiceDefinition::new(crate::NAME.to_string(), installer, commands)
}

pub fn is_initd() -> bool {
    Path::new("/etc/init.d").exists()
}

#[cfg(test)]
mod problem_45_tests {
    /// 🔐 问题 45：OpenWrt 支持必须已被移除 —— 不能再有任何 procd 专用脚本被安装。
    ///
    /// 原先 `initd/openwrt/files/etc/init.d/smartdns-rs` 是一份把 `uci` 取值**直接拼进**
    /// 配置行的脚本：取值里含空格/换行/单引号即可凭空插入任意配置项。既然 OpenWrt 本就
    /// 不在支持范围（正式支持仅 Windows/Linux/macOS/Docker），整份脚本直接删掉最干净。
    ///
    /// 这条断言"源码树里不再有 openwrt 安装脚本"，防止日后被重新引入而无人察觉。
    #[test]
    fn openwrt_service_script_is_gone() {
        let openwrt_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/service/linux/initd/openwrt");

        assert!(
            !openwrt_dir.exists(),
            "🔐 问题 45：OpenWrt 服务脚本目录必须已被删除（它把 uci 取值直接拼进配置行，\
             且 OpenWrt 不在支持范围），但它又出现了: {}",
            openwrt_dir.display()
        );
    }

    /// 🔐 问题 45：识别 OpenWrt 的**能力**必须保留 —— 它正是「拒绝安装并明确报错」的依据。
    ///
    /// 删脚本 ≠ 删识别。如果连识别一起去掉，OpenWrt 上就会掉进"其它发行版"分支，
    /// 把不受支持的 sysvinit 脚本装进去，等于把明确报错又变回了静默误装。
    #[test]
    fn openwrt_detection_is_still_available() {
        use crate::infra::os_release::OsRelease;

        let openwrt = r#"
NAME="OpenWrt"
ID="openwrt"
ID_LIKE="lede openwrt"
PRETTY_NAME="OpenWrt 22.03.0"
"#;
        let os: OsRelease = openwrt.parse().unwrap();
        assert!(
            os.is_openwrt(),
            "必须仍然能识别出 OpenWrt（否则拒绝逻辑会失效，退回静默误装）"
        );

        // 反向：普通发行版不能被误判成 OpenWrt（否则会误拒正常安装）
        let debian = r#"
NAME="Ubuntu"
ID="ubuntu"
ID_LIKE="debian"
"#;
        let os: OsRelease = debian.parse().unwrap();
        assert!(!os.is_openwrt(), "正常发行版不得被误判为 OpenWrt");
    }
}
