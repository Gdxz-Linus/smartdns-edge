use std::{env, fmt, io, path::Path, sync::OnceLock};

/// 同一把"配置类"告警只报一次。
///
/// 🔐 P2（用户定策）：组名不存在属于配置问题，一次就够 —— 但它在解析热路径上，
/// 不收敛的话每个查询打一行，日志会被刷爆。返回 true 表示这次是第一次（该打）。
pub fn warn_once(key: &str) -> bool {
    static WARNED: OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = OnceLock::new();

    let warned = WARNED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut warned = warned.lock().unwrap_or_else(|e| e.into_inner());
    warned.insert(key.to_string())
}

pub use tracing::dispatcher::set_default;
use tracing::field::{Field, Visit};
pub use tracing::*;
use tracing::{Dispatch, Event, Subscriber, subscriber::DefaultGuard};
use tracing_subscriber::{
    EnvFilter, Layer,
    fmt::{
        FmtContext, FormatEvent, FormatFields, FormattedFields, MakeWriter, format,
        writer::MakeWriterExt,
    },
    layer::Context,
    prelude::__tracing_subscriber_SubscriberExt,
    registry::LookupSpan,
};

static INIT_CONSOLE_LEVEL: OnceLock<Level> = OnceLock::new();

type MappedFile = crate::infra::mapped_file::MutexMappedFile;

#[allow(clippy::too_many_arguments)]
pub fn make_dispatch<P: AsRef<Path>>(
    path: P,
    enabled: bool,
    level: Option<Level>,
    filter: Option<&str>,
    size: u64,
    num: u64,
    mode: Option<u32>,
    to_console: bool,
    // 🔐 Q7 `log-syslog`：是否同时送系统日志（只在 Linux 上真正生效）
    syslog: bool,
) -> Dispatch {
    let cli_level = INIT_CONSOLE_LEVEL.get().cloned();
    let level = match (level, cli_level) {
        (Some(cfg), Some(cli)) => cfg.max(cli),
        (Some(cfg), None) => cfg,
        (None, Some(cli)) => cli,
        (None, None) => Level::ERROR,
    };

    // 🔐 P3：打开日志文件之前，先把它的目录准备好。
    // 以前这步是在 `build.rs` 里建 `./logs`（源码树只读时连构建都过不去），跟源码树无关的
    // 真实需求其实是"把配置里那个日志文件的目录建出来"。
    let _ = crate::infra::mapped_file::ensure_parent_dir(path.as_ref());

    let file = MappedFile::open(path.as_ref(), size, Some(num as usize), mode);

    // 🔐 P3：文件日志到底开没开、为什么没开，必须说出来。
    // 原来失败被静默吞掉（`unwrap_or_else(|_| false)`），再叠加 main.rs 里
    // `set_global_default(...).ok()`，结果就是"服务活着、没有任何日志、也没人告诉为什么" ——
    // 排障时最要命。这里用 eprintln!（此刻 tracing 还没装好，日志宏发不出去），
    // 且只在用户确实配了文件日志（enabled）时才抱怨。
    let file_open_err: Option<String> = if enabled {
        match file.inner.lock().unwrap_or_else(|e| e.into_inner()).touch() {
            Ok(_) => None,
            Err(err) => Some(err.to_string()),
        }
    } else {
        None
    };
    let writable = enabled && file_open_err.is_none();

    if let Some(err) = &file_open_err {
        eprintln!(
            "⚠️ 日志文件打不开（{}）：{err}；本次只输出到控制台。请检查该路径所在目录是否存在、是否可写。",
            path.as_ref().display()
        );
    }

    let console_level = if to_console {
        level
    } else {
        cli_level.unwrap_or(Level::ERROR)
    };

    let console_writer = io::stdout.with_max_level(console_level);

    if syslog {
        #[cfg(not(target_os = "linux"))]
        crate::log::warn_once("log-syslog-non-linux");

        #[cfg(not(target_os = "linux"))]
        eprintln!("⚠️ `log-syslog` 只在 Linux 上有效（其它平台没有系统日志），本次已忽略。");
    }

    if writable {
        // 🌟 1. 手动将横幅瞬间写入文件，弥补配置解析的时间差
        use std::io::Write;
        let now = chrono::Local::now();
        let msg = format!(
            "{}.{:03}:INFO: {} 🐋 {} starting\n",
            now.format("%Y-%m-%d %H:%M:%S"),
            now.timestamp_millis() % 1000,
            crate::NAME,
            crate::BUILD_VERSION
        );
        let mut writer = &file;
        let _ = writer.write_all(msg.as_bytes());

        // 🌟 2. 核心修复：直接使用原生的 MappedFile！
        // 因为它是内存映射，速度比任何 Channel 都快，绝对不会丢弃你的 cfg.summary() 日志！
        let file_writer = file.with_max_level(level);

        if to_console {
            internal_make_dispatch(
                level.max(console_level),
                filter,
                file_writer.and(console_writer),
                true,
                syslog,
            )
        } else {
            internal_make_dispatch(level.max(console_level), filter, file_writer, true, syslog)
        }
    } else if to_console {
        internal_make_dispatch(console_level, filter, console_writer, true, syslog)
    } else if syslog {
        // 既不写文件也不打控制台，只送系统日志 —— 用 `io::sink()` 当占位写入端
        internal_make_dispatch(level, filter, || io::sink(), false, true)
    } else {
        Dispatch::none()
    }
}

pub fn console(console_level: Level) -> DefaultGuard {
    INIT_CONSOLE_LEVEL.get_or_init(|| console_level);
    let console_writer = io::stdout.with_max_level(console_level);
    set_default(&internal_make_dispatch(
        console_level,
        None,
        console_writer,
        false,
        false,
    ))
}

#[inline]
fn internal_make_dispatch<W: for<'writer> MakeWriter<'writer> + 'static + Send + Sync>(
    level: tracing::Level,
    filter: Option<&str>,
    writer: W,
    diagnostic: bool,
    syslog: bool,
) -> Dispatch {
    let layer = tracing_subscriber::fmt::layer()
        .event_format(TdnsFormatter)
        .with_writer(writer);

    // 🔐 Q7：`log-syslog` 打开时额外挂一层，把日志也送进系统日志。
    // 关掉时用 `Option::None` 占位 —— 完全不产生开销（tracing 对 Option<Layer> 有实现）。
    let syslog_layer = syslog.then_some(SyslogLayer);

    let subscriber = tracing_subscriber::registry()
        .with(layer)
        .with(syslog_layer)
        .with(make_filter(level, filter));

    if diagnostic {
        #[cfg(feature = "future-diagnostic")]
        let subscriber = subscriber.with({
            // console_subscriber::init();
            let console_layer = console_subscriber::ConsoleLayer::builder()
                .with_default_env()
                .spawn();
            console_layer
        });

        Dispatch::new(subscriber)
    } else {
        Dispatch::new(subscriber)
    }
}

#[inline]
fn make_filter(level: tracing::Level, filter: Option<&str>) -> EnvFilter {
    EnvFilter::builder()
        .with_default_directive(tracing::Level::WARN.into())
        .parse(all_smart_dns(level, filter))
        .expect("failed to configure tracing/logging")
}

#[inline]
fn all_smart_dns(level: impl ToString, filter: Option<&str>) -> String {
    filter
        .unwrap_or("named={level},smartdns={level},{env}")
        .replace("{level}", level.to_string().to_uppercase().as_str())
        .replace("{env}", get_env().as_str())
}

#[inline]
fn get_env() -> String {
    env::var("RUST_LOG").unwrap_or_default()
}

// ───────────────────────── 🔐 Q7 `log-syslog`：运行日志也送系统日志 ─────────────────────────
//
// 与 C 版对齐（`src/smartdns.c:525` 的 syslog 回调 + `src/dns_conf/dns_conf.c:534` 的 openlog）：
//   * 标识（ident）用 `smartdns`，facility 用 `LOG_USER`，选项带 `LOG_CONS`；
//   * 级别映射：error → LOG_ERR、warn → LOG_WARNING、info → LOG_INFO、debug/trace → LOG_DEBUG；
//   * 是**追加**一路输出（文件/控制台照旧），不是替代。
//
// 只在 Linux 上有效：其它平台没有 syslog，配置了会由 `dns_conf::summary()` 明确提示"不会生效"。

/// 把运行日志送进系统日志的那一层（关掉时用 `Option::None` 占位，不产生任何开销）
pub(crate) struct SyslogLayer;

impl<S: Subscriber> Layer<S> for SyslogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut message = String::new();
        event.record(&mut MessageVisitor(&mut message));

        if message.is_empty() {
            return;
        }

        syslog_write(event.metadata().level(), &message);
    }
}

/// 只捞 `message` 字段（syslog 那边不需要我们的日期前缀 —— 系统日志自己会加）
struct MessageVisitor<'a>(&'a mut String);

impl Visit for MessageVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0.push_str(&format!("{value:?}"));
        } else if self.0.is_empty() {
            self.0.push_str(&format!("{}={value:?}", field.name()));
        }
    }
}

/// 级别 → syslog 优先级（与 C 版 `src/smartdns.c:525-545` 一致）
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn syslog_priority(level: &tracing::Level) -> i32 {
    #[cfg(target_os = "linux")]
    {
        match *level {
            tracing::Level::ERROR => libc::LOG_ERR,
            tracing::Level::WARN => libc::LOG_WARNING,
            tracing::Level::INFO => libc::LOG_INFO,
            tracing::Level::DEBUG | tracing::Level::TRACE => libc::LOG_DEBUG,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // 非 Linux 平台没有 syslog；这里只需要编译得过（真正的写入口是空操作）
        let _ = level;
        0
    }
}

#[cfg(target_os = "linux")]
fn syslog_write(level: &tracing::Level, message: &str) {
    use std::ffi::CString;

    static OPENLOG: std::sync::Once = std::sync::Once::new();
    OPENLOG.call_once(|| unsafe {
        libc::openlog(c"smartdns".as_ptr(), libc::LOG_CONS, libc::LOG_USER);
    });

    if let Ok(message) = CString::new(message) {
        unsafe {
            libc::syslog(syslog_priority(level), c"%s".as_ptr(), message.as_ptr());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn syslog_write(_level: &tracing::Level, _message: &str) {
    // 非 Linux：没有系统日志可写（启动时会提示用户这条配置不会生效）
}

/// 🔐 Q8 `audit-syslog`：把**审计行**送进系统日志（级别固定 LOG_INFO，与 C 版 `audit.c:155` 一致）
pub(crate) fn audit_to_syslog(line: &str) {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;

        static OPENLOG: std::sync::Once = std::sync::Once::new();
        OPENLOG.call_once(|| unsafe {
            libc::openlog(c"smartdns".as_ptr(), libc::LOG_CONS, libc::LOG_USER);
        });

        if let Ok(line) = CString::new(line) {
            unsafe {
                libc::syslog(libc::LOG_INFO, c"%s".as_ptr(), line.as_ptr());
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = line;
    }
}

struct TdnsFormatter;

impl<S, N> FormatEvent<S, N> for TdnsFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let now = chrono::Local::now();
        let now_msecs = now.timestamp_millis() % 1000;
        let date = now.format("%Y-%m-%d %H:%M:%S");

        // Format values from the event's's metadata:
        let metadata = event.metadata();

        if metadata.level() == &tracing::Level::INFO {
            write!(&mut writer, "{}.{}:{}", date, now_msecs, metadata.level())?;
        } else {
            write!(&mut writer, "{}.{}:{}", date, now_msecs, metadata.level())?;
            if let Some(line) = metadata.line() {
                write!(&mut writer, ":{line}")?;
            }
        }

        // Format all the spans in the event's span context.
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, ":{}", span.name())?;

                let ext = span.extensions();
                let fields = &ext
                    .get::<FormattedFields<N>>()
                    .expect("will never be `None`");

                // Skip formatting the fields if the span had no fields.
                if !fields.is_empty() {
                    write!(writer, "{{{fields}}}")?;
                }
            }
        }

        // Write fields on the event
        write!(writer, ": ")?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

impl<'a> MakeWriter<'a> for MappedFile {
    type Writer = &'a MappedFile;
    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_log_level_cmp() {
        assert_eq!(Level::INFO.max(Level::DEBUG), Level::DEBUG);
    }
}
