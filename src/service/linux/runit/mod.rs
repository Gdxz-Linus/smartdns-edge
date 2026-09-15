//!
//! https://wiki.termux.com/wiki/Termux-services

use super::*;

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
    // 🔐 同类修复：这里原来是 todo!() —— 在 Termux/runit 环境下执行 `service install`
    // 会直接 panic。该平台暂未提供专属实现，改为复用 initd 的定义（行为接近，
    // Termux 上更常见的做法是用 sv 手工管理，见本文件顶部链接），绝不崩溃。
    crate::log::warn!(
        "runit/Termux 环境没有专属的服务定义，已退回 initd 的实现；如需精细控制请参考 Termux 文档手工配置"
    );
    super::initd::create_service_definition()
}

pub fn is_systemd() -> bool {
    false
}
