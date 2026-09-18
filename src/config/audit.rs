use std::path::PathBuf;

use byte_unit::Byte;
use serde::{Deserialize, Serialize};

use crate::{infra::file_mode::FileMode, third_ext::serde_opt_str};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditConfig {
    /// dns audit
    ///
    /// enable or disable audit.
    pub enable: Option<bool>,

    /// audit file
    ///
    /// ```
    /// example 1:
    ///   audit-file /var/log/smartdns-audit.log
    ///
    /// example 2:
    ///   audit-file /var/log/smartdns-audit.csv
    /// ```
    pub file: Option<PathBuf>,

    /// audit-size size of each audit file, support k,m,g
    pub size: Option<Byte>,

    /// number of audit files.
    pub num: Option<usize>,

    /// audit file mode
    #[serde(with = "serde_opt_str")]
    pub file_mode: Option<FileMode>,

    /// 🔐 Q8 `audit-syslog [yes|no]`：审计行送**系统日志**（Linux syslog）。
    ///
    /// 与 C 版一致（`src/dns_server/audit.c:145-166`）：开着的时候审计**改送 syslog、不再写文件**，
    /// 且行首**不带时间戳**（系统日志自己会加）；级别固定 LOG_INFO。
    pub syslog: Option<bool>,

    /// 🔐 Q9：`audit-console [yes|no]` —— 审计行**同时**打到控制台（stdout）。
    ///
    /// 用途：前台跑着调试、或者跑在容器里的时候，不用去翻文件就能看到审计。
    /// 默认关：审计本身是给"事后查账"用的，不该默认往屏幕上刷。
    pub console: Option<bool>,
}
