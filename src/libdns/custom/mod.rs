pub mod connection_provider;
// 🔐 问题 46：`warmup` 模块已删除 —— 它只用来在（重）建连时发一条固定的
// `example.com` 查询并据此判定上游可用，会把内网上游永久判死。
// 现在以协议层握手成功为判据，详见 `connection_provider.rs` 里的说明。
