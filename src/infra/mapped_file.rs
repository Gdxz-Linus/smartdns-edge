use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Local;

const DATE_FMT: &str = "%Y%m%d-%H%M%S%f";

pub struct MappedFile {
    num: Option<usize>,
    size: u64,
    path: PathBuf,
    file: Option<File>,
    len: u64,
    mode: Option<u32>,
    peamble_bytes: Option<Box<[u8]>>,
}

impl MappedFile {
    pub fn open<P: AsRef<Path>>(path: P, size: u64, num: Option<usize>, mode: Option<u32>) -> Self {
        let path = path.as_ref().to_path_buf();
        Self {
            path,
            size,
            num,
            file: None,
            len: 0,
            mode,
            peamble_bytes: None,
        }
    }

    pub fn peamble(&self) -> Option<&[u8]> {
        self.peamble_bytes.as_ref().map(|x| &x[..])
    }

    pub fn set_peamble(&mut self, bytes: Option<Box<[u8]>>) {
        self.peamble_bytes = bytes;
    }

    #[inline]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    #[inline]
    pub fn extension(&self) -> Option<&OsStr> {
        self.path.extension()
    }

    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    #[inline]
    pub fn len(&self) -> u64 {
        if self.len > 0 || self.file.is_some() {
            self.len
        } else {
            fs::metadata(self.path.as_path())
                .map(|m| m.len())
                .unwrap_or_default()
        }
    }

    #[inline]
    pub fn touch(&mut self) -> io::Result<()> {
        if !self.path().exists() {
            let dir = self
                .path()
                .parent()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            fs::create_dir_all(dir)?;
        }
        let file = self.get_active_file()?;
        file.sync_all()?;
        Ok(())
    }

    pub fn mapped_files(&self) -> io::Result<Vec<PathBuf>> {
        match (
            self.path
                .file_stem()
                .map(|s| s.to_str().map(|s| s.to_string())),
            self.path.parent(),
        ) {
            (Some(Some(base_name)), Some(parent)) => {
                let mut files = fs::read_dir(parent)?
                .filter_map(|o| o.ok())
                .filter_map(|o| {
                    if self.path.extension() == o.path().extension() &&
                        matches!(o.file_name().to_str(), Some(s) if s.starts_with(base_name.as_str())) {
                        Some(o.path())
                    } else {
                        None
                    }
                } )
                .collect::<Vec<_>>();
                files.sort_by(|a, b| b.cmp(a));
                Ok(files)
            }
            _ => Ok(Default::default()),
        }
    }

    pub fn set_num(&mut self, num: Option<usize>) {
        self.num = num;
    }

    pub fn remove_files(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }

        for f in self.mapped_files()? {
            fs::remove_file(f)?;
        }

        Ok(())
    }

    fn is_full(&self) -> bool {
        self.len() >= self.size
    }

    fn get_active_file(&mut self) -> io::Result<&mut File> {
        if self.is_full() {
            self.backup_files()?;
        }

        match self.file {
            Some(ref mut file) => Ok(file),
            None => {
                    let res = {
                        let mut opt = File::options();

                        #[cfg(unix)]
                        if let Some(mode) = self.mode {
                            use std::os::unix::fs::OpenOptionsExt;
                            opt.mode(mode);
                        }

                        // 🌟 核心修复 1：Windows 文件被打开时，强行赋予共享删除与读取权限！
                        // 否则在 backup_files() 中执行 fs::rename 时必报 OS Error 32 (Sharing Violation)
                        #[cfg(windows)]
                        {
                            use std::os::windows::fs::OpenOptionsExt;
                            // 0x00000004 (FILE_SHARE_DELETE) | 0x00000001 (FILE_SHARE_READ) | 0x00000002 (FILE_SHARE_WRITE) = 7
                            opt.share_mode(7);
                        }

                        opt.create(true).write(true);

                    if self.path.exists() {
                        if self.is_full() {
                            opt.truncate(true);
                        } else {
                            opt.append(true);
                        }
                    }
                    opt.open(self.path.as_path())
                };
                match res {
                    Ok(mut file) => {
                        self.len = file.metadata().unwrap().len();
                        if self.len == 0 && self.peamble_bytes.is_some() {
                            let bytes = self.peamble().unwrap();
                            self.len = file.write(bytes)? as u64;
                        }
                        self.file = Some(file);
                        Ok(self.file.as_mut().unwrap())
                    }
                    Err(err) => Err(err),
                }
            }
        }
    }

    fn backup_files(&mut self) -> io::Result<()> {
        if let (Some(base_name), Some(parent)) = (self.path.file_stem(), self.path.parent()) {
            let new_name = {
                let mut n = base_name.to_os_string();
                n.push("-");
                n.push(Local::now().format(DATE_FMT).to_string());
                n
            };
            let mut new_path = parent.join(new_name);
            if let Some(ext) = self.path.extension() {
                new_path = new_path.with_extension(ext);
            }
            
            // 🌟 核心修复：在对旧文件执行 rename 重命名归档之前，必须先将当前打开的文件句柄 take() 出去并 drop 释放！
            // 否则在 Windows 下，一个正在被打开写入的文件直接执行 rename 会引发句柄锁冲突（OS Error 32）。
            if let Some(mut file) = self.file.take() {
                let _ = file.flush();
                drop(file);
            }

            std::fs::rename(self.path.as_path(), new_path)?;
        }

        let files = self.mapped_files()?;
        match self.num {
            Some(n) if n <= files.len() => {
                for f in &files[n..] {
                    fs::remove_file(f)?;
                }
            }
            _ => (),
        }

        Ok(())
    }
}

impl Write for MappedFile {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let file = self.get_active_file()?;
        let len = file.write(buf)?;
        self.len += len as u64;
        if self.is_full() {
            self.flush()?;
        }
        Ok(len)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
            if self.is_full() {
                drop(file)
            } else {
                self.file = Some(file);
            }
        }
        Ok(())
    }
}

/// 🌟 P1-14：因队列写满（或消费者已退出）而被迫丢弃的日志条数。
///
/// 原来这些日志是**静默**丢掉的：不计数、不告警，运维完全不知道日志缺了哪一段。
/// 现在计数，并可从 `/api/system/status` 的 `log_dropped` 看到。
static LOG_DROPPED: AtomicU64 = AtomicU64::new(0);

/// 🌟 P1-14：`flush()` 未能在超时内把队列排空的次数（正常应为 0）。
static LOG_FLUSH_FAILED: AtomicU64 = AtomicU64::new(0);

/// 进程内所有日志消费者（每建一个日志文件就登记一个）。
///
/// 只存 `Weak`：当 Dispatch 被丢弃（例如配置热重载）后，发送端随之释放，
/// 消费线程会把队列里剩下的日志写完再自然退出，不会因为全局登记而泄漏线程。
static LOG_CONSUMERS: Mutex<Vec<Weak<LogConsumer>>> = Mutex::new(Vec::new());

/// 至今被迫丢弃的日志条数（P1-14 的可观测项）。
pub fn log_dropped_total() -> u64 {
    LOG_DROPPED.load(Ordering::Relaxed)
}

/// 至今 flush 未能在超时内排空队列的次数（P1-14 的可观测项）。
pub fn log_flush_failed_total() -> u64 {
    LOG_FLUSH_FAILED.load(Ordering::Relaxed)
}

enum LogMsg {
    Data(Vec<u8>),
    /// 排空标记：消费者处理到它时，排在它前面的日志都已写进文件，然后回一个 ack。
    Flush(mpsc::Sender<()>),
}

struct LogConsumer {
    tx: mpsc::SyncSender<LogMsg>,
}

impl LogConsumer {
    /// 非阻塞投递一条日志。队列满时丢弃，但**一定计数**，并按万分之一限流喊一声。
    fn send_data(&self, buf: &[u8]) {
        match self.tx.try_send(LogMsg::Data(buf.to_vec())) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                let n = LOG_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
                // 注意：这里绝不能调用 crate::log::*（正处在日志写入路径上），只能直接写 stderr。
                if n == 1 || n % 10_000 == 0 {
                    eprintln!(
                        "[smartdns] WARN: log queue is full, {n} log line(s) dropped so far \
                         (raise log-size/log-num or lower the log level to avoid this)"
                    );
                }
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// 把当前队列里排在它之前的日志**真正写进文件**。超时返回 false。
    ///
    /// 有界队列可能已经写满，所以投递排空标记本身也要带重试；
    /// 一旦标记入队，消费者是 FIFO 处理的 —— 它处理到标记时，之前的数据必然已写出。
    fn flush_blocking(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (ack_tx, ack_rx) = mpsc::channel();
        let mut msg = LogMsg::Flush(ack_tx);

        loop {
            match self.tx.try_send(msg) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Full(returned)) => {
                    msg = returned;
                    if Instant::now() >= deadline {
                        LOG_FLUSH_FAILED.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    LOG_FLUSH_FAILED.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
        }

        let remain = deadline.saturating_duration_since(Instant::now());
        let ok = ack_rx.recv_timeout(remain).is_ok();
        if !ok {
            LOG_FLUSH_FAILED.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }
}

impl Drop for LogConsumer {
    fn drop(&mut self) {
        // 消费者要下线了（例如日志热重载）：尽力把已入队的日志先写完。
        // 之后 tx 随之释放，消费线程会把队列里剩下的内容处理干净再退出
        // （mpsc 的 recv 只在"队列空且发送端全没了"时才报错），所以不需要 join。
        let _ = self.flush_blocking(Duration::from_millis(500));
    }
}

/// 把所有日志消费者排空 —— **关机/重启前必须调用**。
///
/// 🌟 P1-14：日志 dispatch 是进程的全局默认值，进程正常退出时它并不会被 Drop，
/// 于是队列里还没落盘的日志会随进程一起消失（正是"关机/重启前后的关键日志最容易被吞掉"）。
/// 退出路径上显式调用本函数即可把它们写出去。
///
/// 返回 `(成功排空的消费者数, 消费者总数)`。
pub fn flush_all(timeout: Duration) -> (usize, usize) {
    let consumers: Vec<Arc<LogConsumer>> = {
        let mut list = LOG_CONSUMERS.lock().unwrap_or_else(|e| e.into_inner());
        let mut alive: Vec<Weak<LogConsumer>> = Vec::with_capacity(list.len());
        let mut upgraded: Vec<Arc<LogConsumer>> = Vec::with_capacity(list.len());
        for weak in list.drain(..) {
            if let Some(consumer) = weak.upgrade() {
                alive.push(weak);
                upgraded.push(consumer);
            }
        }
        *list = alive;
        upgraded
    };

    let total = consumers.len();
    let flushed = consumers
        .iter()
        .filter(|consumer| consumer.flush_blocking(timeout))
        .count();
    (flushed, total)
}

pub struct MutexMappedFile {
    pub inner: Arc<Mutex<MappedFile>>,
    consumer: Arc<LogConsumer>,
}

impl MutexMappedFile {
    #[inline]
    pub fn open<P: AsRef<Path>>(path: P, size: u64, num: Option<usize>, mode: Option<u32>) -> Self {
        let inner = Arc::new(Mutex::new(MappedFile::open(path, size, num, mode)));
        let inner_clone = inner.clone();

        // 🌟 核心修复：10240 条日志缓冲池，再猛烈的爆发也不会 OOM（容量保持原值不变）
        let (tx, rx) = mpsc::sync_channel::<LogMsg>(10240);

        // 🌟 修复：无论锁是否被毒化，强行解毒获取内部数据，保证日志无论如何都要落盘！
        // 🌟 P1-14：消费者除了写数据，还要处理"排空标记"，让 flush() 有真实语义。
        thread::spawn(move || {
            while let Ok(msg) = rx.recv() {
                match msg {
                    LogMsg::Data(bytes) => {
                        let mut file = inner_clone.lock().unwrap_or_else(|e| e.into_inner());
                        let _ = file.write(&bytes);
                    }
                    LogMsg::Flush(ack) => {
                        {
                            let mut file = inner_clone.lock().unwrap_or_else(|e| e.into_inner());
                            let _ = file.flush();
                        }
                        let _ = ack.send(());
                    }
                }
            }
            // 所有发送端都释放后，recv() 已把队列排空；这里再 flush 一次收尾。
            let mut file = inner_clone.lock().unwrap_or_else(|e| e.into_inner());
            let _ = file.flush();
        });

        let consumer = Arc::new(LogConsumer { tx });

        // 登记到全局，供关机路径的 flush_all() 使用（只存 Weak，见 LOG_CONSUMERS 的说明）
        {
            let mut list = LOG_CONSUMERS.lock().unwrap_or_else(|e| e.into_inner());
            list.retain(|weak| weak.strong_count() > 0);
            list.push(Arc::downgrade(&consumer));
        }

        Self { inner, consumer }
    }

    /// 显式排空（等价于 `Write::flush`，但可以自定义超时并拿到结果）。
    pub fn flush_timeout(&self, timeout: Duration) -> bool {
        self.consumer.flush_blocking(timeout)
    }
}

impl io::Write for MutexMappedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // 🌟 核心修复：try_send 非阻塞发送，哪怕日志堵车也直接丢弃，绝不卡死主业务！
        // 🌟 P1-14：丢弃不再静默 —— 会计数并按万分之一限流告警。
        self.consumer.send_data(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // 🌟 P1-14：这里原来是 `Ok(())` 空操作，退出前排在队列里的日志根本不会落盘。
        // 现在真的把队列排空；排不掉就如实返回错误（同时计入 log_flush_failed）。
        if self.consumer.flush_blocking(Duration::from_secs(2)) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "log queue flush timed out: the log consumer thread did not drain the queue in time",
            ))
        }
    }
}

impl io::Write for &MutexMappedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.consumer.send_data(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.consumer.flush_blocking(Duration::from_secs(2)) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "log queue flush timed out: the log consumer thread did not drain the queue in time",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    /// 本模块的测试都要读写**进程级**的计数器与全局消费者列表，
    /// 而 Rust 默认并行跑测试 —— 不串行化就会互相看到对方的丢弃数，导致随机失败。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn test_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "smartdns-mapped-file-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir.join("smartdns.log")
    }

    #[test]
    fn full_queue_drops_are_counted() {
        let _guard = lock();

        // 自己造一个"暂时没人消费"的消费者：容量 2，投 10 条 → 必然丢 8 条。
        // _rx 保持在作用域内，确保失败原因是 Full（而不是 Disconnected）。
        let (tx, _rx) = mpsc::sync_channel::<LogMsg>(2);
        let consumer = LogConsumer { tx };

        let before = log_dropped_total();
        for i in 0..10 {
            consumer.send_data(format!("x{i}").as_bytes());
        }
        // 🌟 P1-14 的回归点：丢弃必须可计数（原来是静默丢弃，事后无法统计）
        assert_eq!(log_dropped_total() - before, 8);
    }

    #[test]
    fn flush_blocking_waits_until_the_consumer_processed_the_marker() {
        let _guard = lock();

        let (tx, rx) = mpsc::sync_channel::<LogMsg>(1024);
        let consumer = LogConsumer { tx };
        let processed = Arc::new(Mutex::new(Vec::<String>::new()));

        let processed_in_thread = processed.clone();
        let handle = thread::spawn(move || {
            while let Ok(msg) = rx.recv() {
                match msg {
                    LogMsg::Data(bytes) => {
                        // 故意当个"慢消费者"：如果 flush 不等，就不可能看到标记排在最后
                        thread::sleep(Duration::from_millis(20));
                        processed_in_thread
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(String::from_utf8_lossy(&bytes).into_owned());
                    }
                    LogMsg::Flush(ack) => {
                        processed_in_thread
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push("FLUSH".to_string());
                        let _ = ack.send(());
                    }
                }
            }
        });

        for i in 0..3 {
            consumer.send_data(format!("d{i}").as_bytes());
        }

        // 🌟 P1-14 的回归点：flush 必须"真的等到队列排空"（原来是直接 `Ok(())` 返回）
        assert!(
            consumer.flush_blocking(Duration::from_secs(5)),
            "flush 必须等到消费者处理完排空标记"
        );
        assert_eq!(
            &*processed.lock().unwrap_or_else(|e| e.into_inner()),
            &["d0", "d1", "d2", "FLUSH"],
            "排空标记必须排在它前面的所有数据之后被处理"
        );

        drop(consumer);
        let _ = handle.join();
    }

    #[test]
    fn flush_blocking_times_out_and_is_counted_when_consumer_is_stuck() {
        let _guard = lock();

        // 没人消费：标记能入队，但永远等不到 ack → 必须超时返回 false，并计入失败数
        let (tx, _rx) = mpsc::sync_channel::<LogMsg>(8);
        let consumer = LogConsumer { tx };

        let before = log_flush_failed_total();
        assert!(!consumer.flush_blocking(Duration::from_millis(50)));
        assert_eq!(log_flush_failed_total() - before, 1);
    }

    #[test]
    fn burst_writes_account_for_every_line() {
        let _guard = lock();

        let path = test_path("flush");
        let writer = MutexMappedFile::open(&path, 1 << 20, Some(3), None);

        let total: u64 = 20_000;
        let before = log_dropped_total();
        let before_failed = log_flush_failed_total();
        for i in 0..total {
            let mut w = &writer;
            w.write_all(format!("line-{i}\n").as_bytes()).unwrap();
        }

        // 🌟 P1-14 的回归点：flush() 必须真的把队列排空（原来是 `Ok(())` 空操作）
        let mut w = &writer;
        w.flush().expect("flush should drain the queue");

        let content = fs::read_to_string(&path).expect("read log file");
        let persisted = content.lines().count() as u64;
        let dropped = log_dropped_total() - before;

        // 核心不变式：写进文件的行 + 被丢弃的行 = 提交的总行数 —— 没有任何一行"凭空消失"
        assert_eq!(
            persisted + dropped,
            total,
            "日志丢失必须能对上账（persisted={persisted}, dropped={dropped}）"
        );

        // 一条都没丢的情况下，最后一行必然已经落盘 —— 这正是"flush 真的排空了队列"
        if dropped == 0 {
            assert!(
                content.contains("line-19999"),
                "没有丢弃时，flush 之后最后一行必须在文件里"
            );
        }

        // 正常路径不该出现 flush 超时
        assert_eq!(log_flush_failed_total(), before_failed);
    }

    #[test]
    fn drop_of_writer_persists_queued_lines() {
        let _guard = lock();

        let path = test_path("drop");
        {
            let writer = MutexMappedFile::open(&path, 1 << 20, Some(3), None);
            for i in 0..2_000 {
                let mut w = &writer;
                w.write_all(format!("bye-{i}\n").as_bytes()).unwrap();
            }
        } // writer 在这里被 drop：LogConsumer::drop 会把队列排空，消费者线程再退出

        // 消化的顺序是 FIFO：排空标记之后写出的内容一定是完整的
        let content = fs::read_to_string(&path).expect("read log file");
        assert_eq!(content.lines().count(), 2_000);
    }

    #[test]
    fn flush_all_drains_a_real_log_dispatch_like_the_shutdown_path() {
        let _guard = lock();

        let path = test_path("dispatch");

        // 与 main.rs 建立日志系统的方式完全一致（只是不往控制台输出）
        let dispatch = crate::log::make_dispatch(
            &path,
            true,
            Some(crate::log::Level::INFO),
            None,
            1 << 20,
            2,
            None,
            false,
        );

        crate::log::dispatcher::with_default(&dispatch, || {
            for i in 0..500 {
                crate::log::info!("dispatch-line-{i}");
            }
        });

        // 🌟 模拟 main.rs 的退出路径：dispatch（日志系统）此刻仍然活着，
        // 进程退出时它不会被 Drop —— 必须靠 flush_all 才能把队列里的日志写出去。
        let (flushed, total) = flush_all(Duration::from_secs(5));
        assert!(total >= 1, "make_dispatch 之后应当登记了一个日志消费者");
        assert_eq!(flushed, total, "关机路径必须能把每一个日志消费者都排空");

        let content = fs::read_to_string(&path).expect("read log file");
        let logged = content
            .lines()
            .filter(|line| line.contains("dispatch-line-"))
            .count();
        assert_eq!(logged, 500, "flush_all 之后 500 行日志必须一行不少地落盘");
        assert!(content.contains("dispatch-line-499"), "{content}");
    }

    #[test]
    fn flush_all_is_safe_with_no_consumer() {
        let _guard = lock();

        // 即使一个日志消费者都没有（未开启文件日志），也不能 panic
        let (flushed, total) = flush_all(Duration::from_millis(50));
        assert!(flushed <= total);
    }
}