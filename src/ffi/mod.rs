// 🔐 B-②：nftset 原本是 `include/nftset.c`（C）＋ build.rs 的 cc/bindgen，
// 现已是**纯 Rust**（与 ipset 一样是裸 libc 走 nfnetlink）。
// 仍挂 `feature = "nft"` + `target_os = "linux"`：
// **去掉这层 gating 属于独立的行为变更，不在 B-② 范围内**（会让非 Linux 平台的提示行为变化）。
#[cfg(all(feature = "nft", target_os = "linux"))]
pub mod nftset;

// 🔐 Q1：写 Linux 的 ipset。**不挂 feature、也不挂平台** ——
// 配置在任何平台都要能被认出来，非 Linux 上由它明确回"不支持"（调用方限流告警一次）。
pub mod ipset;
