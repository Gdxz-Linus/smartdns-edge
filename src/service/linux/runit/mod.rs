//!
//! https://wiki.termux.com/wiki/Termux-services

use super::*;

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
    // 🔐 同类修复：这里原来是 todo!() —— 在 Termux/runit 环境下执行 `service install`
    // 会直接 panic。该平台暂未提供专属实现，改为复用 initd 的定义（行为接近，
    // Termux 上更常见的做法是用 sv 手工管理，见本文件顶部链接），绝不崩溃。
    crate::log::warn!(
        "the runit/Termux environment has no dedicated service definition; falling back to the initd implementation. For finer control, configure it manually as described in the Termux documentation"
    );
    super::initd::create_service_definition()
}

pub fn is_systemd() -> bool {
    false
}
