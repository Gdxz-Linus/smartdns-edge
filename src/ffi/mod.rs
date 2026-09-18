#[cfg(all(feature = "nft", target_os = "linux"))]
mod nftset_sys;

#[cfg(all(feature = "nft", target_os = "linux"))]
pub mod nftset;

// 🔐 Q1：写 Linux 的 ipset。**不挂 feature、也不挂平台** ——
// 配置在任何平台都要能被认出来，非 Linux 上由它明确回"不支持"（调用方限流告警一次）。
pub mod ipset;
