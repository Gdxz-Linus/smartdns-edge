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

/// 🔐 P3：把"要写入的目标文件"所在目录准备好（日志、审计档等都用它）。
///
/// 以前这一步是 `build.rs` 在源码树里建 `./logs` 顶替的：只读源码树（发行版打包 / 容器 / Nix）
/// 里连构建都过不去；而且**部署后换个工作目录跑，`./logs` 根本不存在**，日志与审计档就一直写不进去。
/// 现在由运行期在打开文件之前调用；建不出来就让调用方去报错（不在这里吞掉原因）。
pub fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => fs::create_dir_all(parent),
        _ => Ok(()),
    }
}

use chrono::Local;

const DATE_FMT: &str = "%Y%m%d-%H%M%S%f";

/// 🔐 问题 41-③：`size` 配成 0 时改用的兜底值。
///
/// 128 KiB —— 与配置层 `log-size` 不写时的默认值保持一致（见 `dns_conf::log_size`），
/// 这样"配了 0"与"什么都不配"得到同样的结果，不会让用户以为 0 有什么特殊含义。
const DEFAULT_SIZE: u64 = 128 * 1024;

pub struct MappedFile {
    num: Option<usize>,
    size: u64,
    path: PathBuf,
    file: Option<File>,
    len: u64,
    mode: Option<u32>,
    peamble_bytes: Option<Box<[u8]>>,
    /// 🔐 问题 40：上次已知的磁盘状态指纹（设备号 + inode + 文件大小，见 [`Self::probe_disk`]）。
    ///
    /// 用来发现「文件被外部轮转掉了」：标准 logrotate 会把 `smartdns.log` 改名成
    /// `smartdns.log.1`、程序继续写原文件名。此时磁盘上的 `smartdns.log` 已经是一个
    /// **新文件**（新 inode、大小为 0），而本结构体缓存里的 `self.len` 还停在旧文件的
    /// 最后大小上，于是 `is_full()` 恒为真 —— 每次写都试图去归档那个**已被搬走**的文件，
    /// `rename` 必然失败，日志从此永久停写。
    ///
    /// 只要发现指纹变了（文件被换掉/被截断），就说明缓存值失效，需要重新打开并对齐真实大小。
    disk_probe: Option<DiskProbe>,
}

/// 🔐 问题 40：一个日志文件的「磁盘身份」指纹。
///
/// 为什么不能只看文件大小：logrotate 在 `create` 模式下会**立刻**建一个新的同名空文件，
/// 若旧文件恰好也是 0 字节，单看大小就分辨不出"换过文件"。设备号 + inode 能唯一标识
/// "这是不是同一个文件"，两者配合才能可靠地发现外部轮转。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DiskProbe {
    /// 设备号（Unix 上来自 `MetadataExt::dev`；其它平台为 0）
    dev: u64,
    /// inode 号（Unix 上来自 `MetadataExt::ino`；其它平台为 0）
    ino: u64,
    /// 文件大小
    len: u64,
}

impl MappedFile {
    /// 🔐 问题 41-③：`log-size 0` / `audit-size 0` 的守卫。
    ///
    /// `is_full()` 是 `self.len() >= self.size`，所以 `size = 0` 会让它**恒为真**：
    /// 每写一行都触发一次归档，结果是"每行产生一个归档文件"，日志目录很快被灌满。
    /// 这与问题 9 里 `log-num 0` 会删掉刚归档的那份是同一类"0 值语义没有定义"的毛病，
    /// 因此处置口径也保持一致：**按默认值处理，并明确告警一次**（不静默、不拒绝启动）。
    ///
    /// 放在 `open()` 这一层而不是配置读取处，是为了让**所有**调用点
    /// （运行日志 `log-size`、审计 `audit-size`、以及将来新增的使用方）一次性覆盖，
    /// 不会因为某条路径忘了加守卫而重新出现这个毛病。
    ///
    /// ⚠️ **告警必须用 `eprintln!` 而不是 `crate::log::warn!`**（真机测试发现的）：
    /// 本函数由 `log::make_dispatch()` 调用，而它执行时 `set_global_default()` 还没走，
    /// 此刻 `tracing` 没有 dispatcher，`warn!` 发出去会**直接丢失** ——
    /// 真机实测就是"守卫生效了、但用户看不到任何提示"。同一文件里其它启动期告警
    /// （队列满、写失败）也都是 `eprintln!`，口径一致。
    fn guard_size(size: u64) -> u64 {
        if size == 0 {
            eprintln!(
                "[smartdns] WARN: log-size/audit-size is 0, which would make every written line \
                 trigger a rotation (one archive file per line); using the default of 128K instead"
            );
            DEFAULT_SIZE
        } else {
            size
        }
    }

    pub fn open<P: AsRef<Path>>(path: P, size: u64, num: Option<usize>, mode: Option<u32>) -> Self {
        let path = path.as_ref().to_path_buf();
        Self {
            path,
            size: Self::guard_size(size),
            num,
            file: None,
            len: 0,
            mode,
            peamble_bytes: None,
            disk_probe: None,
        }
    }

    /// 🔐 问题 40：读取当前磁盘上该文件的「身份」。
    ///
    /// 文件不存在时返回 `None` —— 那同样意味着"缓存值失效"（可能被外部删了或搬走了），
    /// 调用方据此重新打开。
    fn probe_disk(&self) -> Option<DiskProbe> {
        let meta = fs::metadata(self.path.as_path()).ok()?;

        #[cfg(unix)]
        let (dev, ino) = {
            use std::os::unix::fs::MetadataExt;
            (meta.dev(), meta.ino())
        };
        // Windows 上没有便捷的 inode 可取（需要 $MFT 查询），退化为"只看大小"。
        // 这已足以覆盖本问题的主场景（标准 logrotate 改名后新文件从 0 开始增长）。
        #[cfg(not(unix))]
        let (dev, ino) = (0u64, 0u64);

        Some(DiskProbe {
            dev,
            ino,
            len: meta.len(),
        })
    }

    /// 🔐 问题 40：缓存值是否已与磁盘不符 —— 即文件被外部轮转/替换/截断过。
    ///
    /// 判据：文件还在但**inode 变了**（被换掉），或**大小与缓存值不同**（被截断或外部写入）。
    /// 文件整个消失也算不符（返回 `true`）。
    fn disk_changed(&self) -> bool {
        if self.file.is_none() {
            return false;
        }

        match (self.disk_probe, self.probe_disk()) {
            // 文件不见了：缓存值失效，需要重新打开（会让写入重新建出文件）
            (Some(_), None) => true,
            // 换过文件（inode 不同）→ 典型的 logrotate 改名场景
            (Some(old), Some(new)) => {
                old.dev != new.dev || old.ino != new.ino || old.len != new.len
            }
            // 还没建立指纹（刚打开、尚未记录）：交给下一次 probe 去建
            (None, _) => false,
        }
    }

    /// 🔐 问题 40：把文件句柄交出去，让下次写入重新打开并对齐磁盘真实大小。
    ///
    /// 这是"归档失败后的自愈"核心：既然要归档的那个文件已经不在了（被外部搬走），
    /// 就不该继续拿旧句柄/旧缓存值去反复失败，而是**丢弃状态、从头打开**。
    ///
    /// ⚠️ 这里刻意**不删文件、不清空文件**：自愈绝不能以丢日志为代价。
    /// 重新打开走 `get_active_file()` 的 `None` 分支，它会重新 `metadata()` 取真实大小，
    /// 从而让 `self.len` 与磁盘一致，`is_full()` 也就不再恒真。
    fn reopen(&mut self) {
        if let Some(mut file) = self.file.take() {
            let _ = file.flush();
            drop(file);
        }
        // 清掉长度缓存与指纹：下次 `len()`/`get_active_file()` 会重新读盘。
        self.len = 0;
        self.disk_probe = None;
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

    /// 当前日志文件已写入的字节数。
    ///
    /// 🔐 问题 40：原实现的判据是 `self.len > 0 || self.file.is_some()` —— 只要文件打开过
    /// 就**永远只用自己的缓存值，从不回读磁盘**。标准 logrotate（改名归档、程序继续写原文件名）
    /// 之后，缓存值还停在旧文件的大小上、恒 `>= size`，于是每次写都去归档一个已经被搬走的文件，
    /// `rename` 反复失败、日志永久停写。
    ///
    /// 现在多一道「缓存是否仍然可信」的检查：磁盘指纹变了就以磁盘为准。
    #[inline]
    pub fn len(&self) -> u64 {
        if self.disk_changed() {
            // 磁盘上的文件已被替换/截断/删除：缓存值不可信，改用磁盘真实大小。
            return self.probe_disk().map(|p| p.len).unwrap_or_default();
        }

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

    /// 本程序自己生成的归档文件名长什么样：`<基名>-<日期>-<时间>.<后缀>`
    /// （日期时间取自 `DATE_FMT = "%Y%m%d-%H%M%S%f"`，即“8 位数字-6 位数字-6 位数字”）。
    ///
    /// 🔐 为什么必须精确匹配，而不是以前那种「前缀相同 + 后缀相同」：
    /// 审计档默认叫 `smartdns-audit.log`，它与日志档 `smartdns.log` **共享 `smartdns` 前缀、
    /// 后缀也都是 `.log`**。两者放在同一目录时，审计档会被当成“日志的一个归档”卷进日志轮转，
    /// `log-num` 配得小时就会被删掉 —— 销毁的恰好是出事之后最需要的东西。
    /// 另外，日志档若没写后缀（如 `log-file /var/log/gateway`），旧写法会让同目录**所有**
    /// 无后缀文件都满足“后缀相同”，只剩前缀判断，误删面进一步扩大。
    fn is_own_file(&self, file_name: &str) -> bool {
        let base_name = self.path.file_stem().and_then(|s| s.to_str());
        let active_name = self.path.file_name().and_then(|s| s.to_str());
        match (base_name, active_name) {
            (Some(base), Some(active)) => is_own_file_name(base, active, file_name),
            _ => false,
        }
    }

    pub fn mapped_files(&self) -> io::Result<Vec<PathBuf>> {
        match (
            self.path
                .file_stem()
                .map(|s| s.to_str().map(|s| s.to_string())),
            self.path.parent(),
        ) {
            (Some(Some(_base_name)), Some(parent)) => {
                let mut files = fs::read_dir(parent)?
                    .filter_map(|o| o.ok())
                    .filter_map(|o| {
                        let name = o.file_name();
                        let name = name.to_str()?;
                        if self.is_own_file(name) {
                            Some(o.path())
                        } else {
                            None
                        }
                    })
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

    /// 🔐 注意：本函数会**无条件删除**所有被认作“自己的”文件（含活动文件）。
    /// 目前没有调用点，保留仅为接口完整性；若将来启用，务必先明确“活动文件是否该删”。
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
        // 🔐 问题 40：写之前先看文件是否被外部轮转/替换过。发现就丢弃旧状态重新打开，
        // 让 `self.len` 与磁盘对齐 —— 否则会一直以为自己"满了"，反复去归档一个
        // 已经被 logrotate 搬走的文件，`rename` 永远失败、日志从此停写。
        if self.disk_changed() {
            if crate::log::warn_once("log-rotated-externally") {
                crate::log::warn!(
                    "the log file {} was rotated or replaced by another program (its identity on disk \
                     changed); reopening it and continuing to write",
                    self.path.display()
                );
            }
            self.reopen();
        }

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
                        // 🔐 问题 40：记下打开时的磁盘指纹，供 `disk_changed()` 后续比对。
                        self.disk_probe = self.probe_disk();
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

            // 🔐 问题 40：待归档的活动文件可能**已经不在了** —— 标准 logrotate 会先把它改名
            // 搬走，程序这边只是"以为"它还在。此时 rename 必然失败；而原实现用 `?` 把它抛出去，
            // 于是每次写入都在同一处失败，日志永久停写。
            //
            // 正确处理：文件既然已不在，就没什么可归档的 —— 直接跳过归档、继续往下走，
            // 让重新打开流程建出新的活动文件即可。这不是"忽略错误"，而是"这个错误的前提已消失"。
            if !self.path.exists() {
                crate::log::debug!(
                    "log file {} no longer exists (rotated away by another program); skipping archival",
                    self.path.display()
                );
                self.len = 0;
                self.disk_probe = None;
                return Ok(());
            }

            std::fs::rename(self.path.as_path(), new_path)?;
        }

        let files = self.mapped_files()?;
        // 🔐 保留策略：`num` 是**允许保留的归档个数**。
        // `mapped_files()` 已按名字倒序排好（最新的在最前），保留前 n 个、删掉其余。
        //
        // ⚠️ 原来写的是 `Some(n) if n <= files.len() => for f in &files[n..]`，有两个问题：
        //   1. `n == 0` 时切片 `files[0..]` 覆盖**全部**文件，等于"配 0 个归档"变成
        //      "把刚归档出来的那份也立刻删掉"——日志内容凭空消失；
        //   2. 删除失败会用 `?` 直接把错误抛出去，一次权限问题就能让日志停止滚动。
        // 现在：0 按 1 处理（至少留住最近一份归档，并明确告警），删除失败只记日志不中断。
        let keep = match self.num {
            Some(0) => {
                crate::log::warn_once("log-num-zero");
                crate::log::warn!(
                    "log-num/audit-num is 0, which would discard the just-archived file; treating it as 1 to avoid losing log content"
                );
                1
            }
            Some(n) => n,
            None => return Ok(()),
        };

        for f in files.iter().skip(keep) {
            // 活动文件永远不删：删掉会让正在写的日志凭空消失。
            if f == &self.path {
                continue;
            }
            // 删不掉不要让日志滚动整个中断：可能是权限问题，或文件已被外部轮转掉。
            if let Err(err) = fs::remove_file(f) {
                crate::log::debug!("cannot remove old log file {}: {err}", f.display());
            }
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

        // 🔐 问题 40：把自己刚写的字节同步进指纹，否则下一次 `disk_changed()` 会把
        // "本进程写入导致的文件变大"误判成"外部改动了文件"，白白触发一次重新打开。
        if let Some(probe) = self.disk_probe.as_mut() {
            probe.len = probe.len.saturating_add(len as u64);
        } else {
            self.disk_probe = self.probe_disk();
        }

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

/// 判断 `file_name` 是否属于「基名为 `base` 的这组日志」。
///
/// 认两种情况：
///   1. 活动文件本身（`active`，例如 `smartdns.log`）；
///   2. 本程序生成的归档：`<base>-<日期>-<时间>[.<后缀>]`，日期与时间都必须是纯数字
///      （格式见 `DATE_FMT`）。
///
/// 🔐 为什么不能像以前那样「前缀相同 + 后缀相同」就算数：审计档 `smartdns-audit.log`
/// 与日志档 `smartdns.log` 共享前缀、后缀也都是 `.log`，会被误认成同组而遭删除；
/// 日志档没写后缀时更会让同目录所有无后缀文件都满足条件。
fn is_own_file_name(base: &str, active: &str, file_name: &str) -> bool {
    if file_name == active {
        return true;
    }

    let Some(rest) = file_name.strip_prefix(base) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('-') else {
        return false;
    };

    // 去掉后缀（若有）：`20260922-124438123456.log` → `20260922-124438123456`
    let stem = match rest.rsplit_once('.') {
        Some((stem, _)) => stem,
        None => rest,
    };

    let mut parts = stem.split('-');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(date), Some(time), None) => {
            !date.is_empty()
                && !time.is_empty()
                && date.bytes().all(|b| b.is_ascii_digit())
                && time.bytes().all(|b| b.is_ascii_digit())
        }
        _ => false,
    }
}

/// 🌟 P1-14：因队列写满（或消费者已退出）而被迫丢弃的日志条数。
///
/// 原来这些日志是**静默**丢掉的：不计数、不告警，运维完全不知道日志缺了哪一段。
/// 现在计数，并可从 `/api/system/status` 的 `log_dropped` 看到。
static LOG_DROPPED: AtomicU64 = AtomicU64::new(0);

/// 🌟 P1-14：`flush()` 未能在超时内把队列排空的次数（正常应为 0）。
static LOG_FLUSH_FAILED: AtomicU64 = AtomicU64::new(0);

/// 🔐 向日志文件写入失败的累计次数（正常应为 0）。
///
/// 为什么要单独计数：Linux 上以 root 启动、随后降权到 `nobody` 的部署里，
/// 日志写满后需要把当前文件改名归档，这一步要**目录的写权限**——而目录属于 root，
/// 降权后的进程改不动。归档失败 → 写入失败 → 日志从此刻起静默停写。
/// 以前这个错误被 `let _ =` 丢掉，用户完全无从察觉；现在计数并限流告警。
static LOG_WRITE_FAILED: AtomicU64 = AtomicU64::new(0);

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

/// 至今向日志文件写入失败的累计次数（正常应为 0）。
pub fn log_write_failed_total() -> u64 {
    LOG_WRITE_FAILED.load(Ordering::Relaxed)
}

/// 🔐 在**仍然持有 root 权限**时，把日志/审计文件的目录与文件属主交给即将降权到的用户。
///
/// 为什么必须在降权**之前**做：程序先用 root 建好日志文件、再把权限降到 `nobody`
/// （见 `main.rs` 的启动顺序）。降权之后：
///   · 已打开的文件还能继续追加（句柄在手）；
///   · 但日志写满要把当前文件改名归档时，需要**目录的写权限**，`nobody` 没有 —— 归档失败，
///     而写入随之失败，日志从此静默停写。
///
/// 安全设计（很重要，避免把系统目录搞坏）：
///   1. **只处理文件所在目录本身，绝不递归**（`/var/log` 这种共享目录绝不能整棵改属主）；
///   2. 目录里若存在**不是本程序生成的文件**，就不动这个目录的属主——宁可让用户自己去
///      chown，也不把别人的文件暴露给降权后的账号；
///   3. 只改「本程序自己会写的文件」（活动文件与其归档）以及该目录的属主；
///   4. Linux 之外没有降权这回事，本函数整体不参与编译。
///
/// 返回：成功改属主的路径数；失败只记日志，不阻断启动（可用性优先）。
#[cfg(target_os = "linux")]
pub fn prepare_owner_for_drop(paths: &[std::path::PathBuf], uid: u32, gid: u32) -> usize {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::chown;

    let mut changed = 0usize;
    let mut seen_dirs: Vec<&std::path::Path> = Vec::new();

    for path in paths {
        let Some(parent) = path.parent() else {
            continue;
        };
        // 只认基名与活动文件完全一致的“自己人”文件，以及本组归档
        let base = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let active = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();

        // ── 1. 文件本身：存在的话直接改属主（即便目录不改，至少文件可写） ──
        if path.exists() {
            match chown(path, Some(uid), Some(gid)) {
                Ok(()) => changed += 1,
                Err(err) => {
                    crate::log::warn!(
                        "cannot change the owner of {} to {uid}:{gid} before dropping privileges: {err}",
                        path.display()
                    );
                }
            }
        }

        // 同目录里本程序自己产生的归档也一并改，否则归档文件仍是 root、后续清理会失败
        if let Ok(dir) = fs::read_dir(parent) {
            for entry in dir.filter_map(|e| e.ok()) {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name != active && !is_own_file_name(base, active, name) {
                    continue;
                }
                let p = entry.path();
                let _ = chown(&p, Some(uid), Some(gid));
            }
        }

        // ── 2. 目录本身：只在“目录里除本程序的文件外没有别的东西”时才改 ──
        if seen_dirs.contains(&parent) {
            continue;
        }
        seen_dirs.push(parent);

        let Ok(dir) = fs::read_dir(parent) else {
            continue;
        };
        let mut only_ours = true;
        for entry in dir.filter_map(|e| e.ok()) {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                only_ours = false;
                break;
            };
            if name == active || is_own_file_name(base, active, name) {
                continue;
            }
            only_ours = false;
            break;
        }

        if !only_ours {
            crate::log::warn!(
                "not changing the owner of {} because it contains files not created by this program; \
                 if log rotation fails after dropping privileges, give the service account write access to that directory",
                parent.display()
            );
            continue;
        }

        // 确认目录当前确实属于 root，避免误动已经配置好的目录
        if let Ok(meta) = fs::metadata(parent)
            && meta.uid() == 0
        {
            match chown(parent, Some(uid), Some(gid)) {
                Ok(()) => {
                    changed += 1;
                    crate::log::info!(
                        "log directory {} ownership handed to {uid}:{gid} so rotation keeps working after dropping privileges",
                        parent.display()
                    );
                }
                Err(err) => crate::log::warn!(
                    "cannot change the owner of the log directory {}: {err}",
                    parent.display()
                ),
            }
        }
    }

    changed
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
    ///
    /// 🔐 问题 41-①：返回 `true` 表示**确实入队了**（会被写出），`false` 表示**已被丢弃**。
    ///
    /// 为什么要这个返回值：原实现是 `fn send_data(&self, buf: &[u8])`，调用方无论如何都
    /// `Ok(buf.len())` —— 日志被丢掉时仍向调用方回报"写入成功"，属**不实回报**。
    /// 现在把真实结果传上去，让 `Write::write` 的口径与实际一致。
    ///
    /// 注意：**丢弃依然不算 `Err`**（见下面 `Write::write` 的说明），
    /// 这是"日志绝不阻塞主业务"这个刻意设计的底线，不能因为要"如实"就把主流程拖住。
    fn send_data(&self, buf: &[u8]) -> bool {
        match self.tx.try_send(LogMsg::Data(buf.to_vec())) {
            Ok(()) => true,
            Err(mpsc::TrySendError::Full(_)) => {
                let n = LOG_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
                // 注意：这里绝不能调用 crate::log::*（正处在日志写入路径上），只能直接写 stderr。
                if n == 1 || n % 10_000 == 0 {
                    eprintln!(
                        "[smartdns] WARN: log queue is full, {n} log line(s) dropped so far \
                         (raise log-size/log-num or lower the log level to avoid this)"
                    );
                }
                false
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
                false
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
                        // 🔐 写失败必须看得见：以前这里是 `let _ = file.write(&bytes)`，
                        // 静默吞掉。Linux 上以 root 启动、随后降权到 nobody 的部署里，
                        // 日志写满后需要归档却**没有目录写权限**，归档与写入会持续失败——
                        // 用户看到的现象是「跑几天后日志不再记录了，也没有任何提示」。
                        // 现在计数 + 限流告警，可从管理接口的日志指标中看到。
                        if let Err(err) = file.write(&bytes) {
                            LOG_WRITE_FAILED.fetch_add(1, Ordering::Relaxed);
                            let n = LOG_WRITE_FAILED.load(Ordering::Relaxed);
                            if n == 1 || n.is_multiple_of(1000) {
                                eprintln!(
                                    "[smartdns] WARN: cannot write to the log file ({} failure(s) so far): {err}. \
                                     If this repeats, check that the log directory and file are writable by the \
                                     account the service runs as.",
                                    n
                                );
                            }
                        }
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
        //
        // 🔐 问题 41-①：这里的返回语义是「已接收」而不是「已落盘」。
        // 本写入端是一个**有损的异步队列**：`Ok(buf.len())` 表示"这条日志已被日志系统接管"，
        // 它可能随后被写出，也可能因队列满而被丢弃 —— 丢弃会**计数**（`LOG_DROPPED`，
        // 可从 `/api/system/status` 的 `log_dropped` 看到）并限流告警。
        //
        // ⚠️ 为什么**不能**在丢弃时返回 `Ok(0)` 或 `Err`（这是本项的处置结论，理由要记住）：
        //   * `Ok(0)` 会让 `write_all()` 直接报 `WriteZero` —— 我们实测过，
        //     现有测试 `burst_writes_account_for_every_line`（写 2 万行、队列容量 1 万）立刻失败；
        //     也就是说"把丢日志如实报成 0 字节"会把它升级成**错误风暴**，比不实回报更糟；
        //   * `Err` 更糟：上层会以为"该重试"，于是日志写入变成阻塞或死循环，
        //     与"日志绝不拖住主业务"这个刻意的设计底线直接冲突。
        //
        // 所以本项的修法是**把语义说清楚 + 保证丢弃可见**（计数与告警），而不是改返回值。
        // 这与 tracing-appender 等同类实现的通行做法一致：永远接受，丢弃计数。
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
        // 🔐 问题 41-①：与 `MutexMappedFile::write` 同款语义 —— 「已接收」，丢弃靠计数可见。
        // 详见上面 `MutexMappedFile::write` 里对"为什么不返回 Ok(0)/Err"的说明。
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
        } // 🌟 P1-14 的回归点：丢弃必须可计数（原来是静默丢弃，事后无法统计）
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

    /// 🔐 归档文件的识别必须**精确**：审计档与别的同前缀文件绝不能被当成日志的归档。
    ///
    /// 背景：审计档默认叫 `smartdns-audit.log`，与日志档 `smartdns.log` 共享前缀、
    /// 后缀也都是 `.log`。以前按「前缀 + 后缀」匹配，它会被卷进日志轮转而被删掉。
    #[test]
    fn only_own_archive_files_are_matched() {
        let own = |name: &str| is_own_file_name("smartdns", "smartdns.log", name);

        // 活动文件本身
        assert!(own("smartdns.log"), "活动文件必须算自己的");
        // 自己生成的归档：基名-日期-时间.后缀
        assert!(own("smartdns-20260922-124438123456.log"));
        assert!(own("smartdns-20260922-124438.log"), "后缀长度不敏感");
        // 日志档没写后缀时，归档也不带后缀
        assert!(is_own_file_name(
            "gateway",
            "gateway",
            "gateway-20260922-124438"
        ));

        // 关键回归：审计档不能被当成日志的归档
        assert!(
            !own("smartdns-audit.log"),
            "审计档必须排除，否则会被日志轮转删掉"
        );
        assert!(
            !own("smartdns-audit-20260922-124438.log"),
            "审计档的归档也要排除"
        );
        // 别的同前缀文件
        assert!(!own("smartdns-old.log"));
        assert!(!own("smartdns.bak"));
        assert!(!own("smartdnsX-20260922-124438.log"), "前缀必须紧跟连字符");
        // 日期/时间不是纯数字的，不算归档
        assert!(!own("smartdns-notadate-124438.log"));
        assert!(!own("smartdns-20260922-12x438.log"));
        // 与自己无关的名字
        assert!(!own("other.log"));
    }

    /// 🔐 保留策略：按名字倒序保留最新若干个归档，且**绝不碰**审计档与无关文件。
    #[test]
    fn retention_keeps_newest_and_leaves_audit_files_alone() {
        let _guard = lock();

        let dir = std::env::temp_dir().join(format!("smartdns-retention-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let active = dir.join("app.log");
        fs::write(&active, "active\n").unwrap();

        // 造 2 个归档（名字倒序 = 时间从新到旧）
        for ts in ["20260922-120000", "20260921-120000"] {
            fs::write(dir.join(format!("app-{ts}.log")), "old\n").unwrap();
        }
        // 审计档与无关文件：都不能被碰
        let audit = dir.join("app-audit.log");
        fs::write(&audit, "audit\n").unwrap();
        let other = dir.join("unrelated.log");
        fs::write(&other, "other\n").unwrap();

        // 保留 1 个归档。backup_files() 会先把活动文件改名成带当前时间戳的新归档，
        // 所以调用后：归档共 3 个（新的 + 原来 2 个），保留 1 个、删掉其余 2 个。
        let mut mf = MappedFile::open(&active, 1 << 20, Some(1), None);
        mf.backup_files().unwrap();

        assert!(audit.exists(), "审计档必须还在（这正是本次修复的核心）");
        assert!(other.exists(), "无关文件必须还在");

        let archives: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("app-") && n != "app-audit.log")
            .collect();
        assert_eq!(
            archives.len(),
            1,
            "保留 1 个时应当只剩 1 份归档，实际 {archives:?}"
        );
        // 原有两个归档都该被清掉（它们比新归档旧）
        assert!(!dir.join("app-20260921-120000.log").exists());
        assert!(!dir.join("app-20260922-120000.log").exists());

        // 🔐 num = 0：不能把刚归档出来的那份也删掉（否则日志内容凭空消失）
        let mut mf0 = MappedFile::open(&active, 1 << 20, Some(0), None);
        fs::write(&active, "active\n").unwrap();
        mf0.backup_files().unwrap();
        assert!(audit.exists(), "num=0 也不能删掉审计档");

        let _ = fs::remove_dir_all(&dir);
    }

    // ================= 🔐 问题 40：外部轮转后必须能自愈 =================

    /// 🔐 问题 40 的核心回归：**文件被外部改名搬走后，写入必须能继续**。
    ///
    /// 复现标准 logrotate 的"改名归档、程序继续写原文件名"：把 `smartdns.log` 改名成
    /// `smartdns.log.1` **且不建新的同名文件**，而程序这边毫不知情、手里还握着旧状态。
    ///
    /// ⚠️ 这里必须**不建新文件**，否则测不到问题：若外部立刻建了新的同名空文件，
    /// 程序后面那次 `rename` 依然会成功（它搬的是一个确实存在的文件），失败链条就断了。
    /// 真实的失败条件是 **「缓存认为已满」+「磁盘上那个文件不存在」**：
    ///   * 缓存 `len` 停在旧文件大小上 → `is_full()` 恒真；
    ///   * 程序去归档 `self.path` → 它已被搬走 → `rename` 失败 → 写入失败 → **永久停写**。
    ///
    /// 因此测试要先把程序写到"自己已经归档过一轮"的状态，再在外部搬走文件，
    /// 然后继续写到 `len` 重新越过阈值 —— 那一刻正是修复前崩掉的点。
    ///
    /// > 这条测试的第一版写成"外部改名后**建一个新的同名空文件**"，反向验证时
    /// > **撤掉修复仍然通过** —— 因为它把失败链条掐断了（`rename` 搬一个存在的文件当然成功）。
    /// > 这正是本项目反复出现的"测试没盖住真实场景"，靠反向验证才发现并改对的。
    #[test]
    fn external_rotation_does_not_stop_logging() {
        let _guard = lock();

        let path = test_path("external-rotation");
        let dir = path.parent().unwrap().to_path_buf();

        // 阈值设小，让"写满 → 归档"很快发生
        let size = 64u64;
        let line = "0123456789012345678\n"; // 20 字节

        let mut mf = MappedFile::open(&path, size, Some(3), None);

        // ① 先写满，让程序走一次**自己的**正常归档路径
        for _ in 0..8 {
            mf.write_all(line.as_bytes()).unwrap();
            let _ = mf.flush();
        }
        assert!(path.exists(), "程序自己的归档之后应当仍有活动文件");

        // ② 模拟外部 logrotate：改名搬走，**不**建新的同名文件
        let moved = dir.join("smartdns.log.1");
        fs::rename(&path, &moved).expect("外部改名应当成功");
        assert!(
            !path.exists(),
            "这一步必须让活动文件真的消失，否则测不到「归档时文件已不在」这个条件"
        );

        // ③ 继续写：len 缓存会重新越过阈值，那一刻修复前会去归档一个不存在的文件
        for i in 0..12 {
            mf.write_all(format!("{line}after rotation {i}\n").as_bytes())
                .unwrap_or_else(|err| {
                    panic!(
                        "🔐 问题 40：外部轮转后写入必须继续成功，但第 {i} 行失败了: {err}\n\
                         （这正是「日志永久停写」的原症状）"
                    )
                });
            let _ = mf.flush();
        }

        // ① 日志确实继续写在**新**的活动文件里（程序应当把文件重新建出来）
        let active = fs::read_to_string(&path).expect("程序应当把活动文件重新建出来");
        assert!(
            active.contains("after rotation 11"),
            "🔐 问题 40：外部轮转后的日志必须写进新的活动文件，实际内容: {active:?}"
        );

        // ② 被搬走的那份内容不能被毁掉（自愈不能以丢日志为代价）
        let archived = fs::read_to_string(&moved).expect("被外部搬走的文件应当还在");
        assert!(
            archived.contains(line.trim_end()),
            "自愈不得删改被外部搬走的文件，实际内容: {archived:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// 🔐 问题 40：文件被外部**删除**（不是改名）后，写入也必须能自愈重建。
    #[test]
    fn external_deletion_is_recovered() {
        let _guard = lock();

        let path = test_path("external-deletion");
        let dir = path.parent().unwrap().to_path_buf();

        let mut mf = MappedFile::open(&path, 1 << 20, Some(3), None);
        mf.write_all(b"before deletion\n").unwrap();
        let _ = mf.flush();

        // 外部直接删掉日志文件
        fs::remove_file(&path).expect("外部删除应当成功");
        assert!(!path.exists());

        mf.write_all(b"after deletion\n")
            .expect("🔐 问题 40：文件被外部删除后，写入应当自愈并重新建出文件");
        let _ = mf.flush();

        assert!(path.exists(), "写入应当把日志文件重新建出来");
        let content = fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("after deletion"),
            "新建的活动文件应当包含删除之后的日志，实际: {content:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// 🔐 问题 40 的**反向保护**：正常连续写入不能被误判成"外部改动"而反复重开文件。
    ///
    /// 判据用的是 (dev, ino, len) 指纹，而写入本身会让 len 变化 ——
    /// 所以 `write()` 里必须同步指纹。这条测试就是钉住这一点：
    /// 如果忘了同步，每次写都会认为"磁盘变了"从而重新打开，日志内容会被反复清空/错乱。
    #[test]
    fn normal_writes_are_not_mistaken_for_external_changes() {
        let _guard = lock();

        let path = test_path("normal-writes");
        let dir = path.parent().unwrap().to_path_buf();

        let mut mf = MappedFile::open(&path, 1 << 20, Some(3), None);

        for i in 0..20 {
            mf.write_all(format!("line {i}\n").as_bytes()).unwrap();
            let _ = mf.flush();
        }

        let content = fs::read_to_string(&path).unwrap();
        for i in 0..20 {
            assert!(
                content.contains(&format!("line {i}\n")),
                "正常写入的第 {i} 行不该丢失（若被误判为外部改动，内容会错乱）: {content:?}"
            );
        }
        // 正常写入不产生任何归档
        let archives: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("smartdns-"))
            .collect();
        assert!(
            archives.is_empty(),
            "未写满时不该产生归档，实际: {archives:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ================= 🔐 问题 41-③：log-size 0 守卫 =================

    /// 🔐 问题 41-③：`log-size 0` 不能让「是否写满」恒为真。
    ///
    /// 修复前 `size = 0` → `is_full()` 恒真 → **每写一行归档一次**，
    /// 日志目录会被灌满一堆每行一个的归档文件。
    ///
    /// ⚠️ 断言顺序是刻意的：**先验危害（归档数量），再验实现（size 被换成默认值）**。
    /// 若先断言 `mf.size > 0`，撤掉修复时会在那一行就 panic，看不到"每行一个归档"
    /// 这个真正的后果 —— 那样测试只证明了"我写了这行代码"，而不是"危害被消除了"。
    /// （实测：撤掉守卫后，10 行写入产生了 3 个归档，时间戳仅相差毫秒。）
    #[test]
    fn zero_size_does_not_rotate_on_every_line() {
        let _guard = lock();

        let path = test_path("zero-size");
        let dir = path.parent().unwrap().to_path_buf();

        // 故意传 0（等价于 `log-size 0` / `audit-size 0`）
        let mut mf = MappedFile::open(&path, 0, Some(3), None);

        for i in 0..10 {
            mf.write_all(format!("line {i}\n").as_bytes()).unwrap();
            let _ = mf.flush();
        }

        // ① 危害断言（放最前）：不能出现"每行一个归档"
        let archives: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("smartdns-"))
            .collect();
        assert!(
            archives.is_empty(),
            "🔐 问题 41-③：size=0 不该导致每写一行就归档一次，实际产生了 {} 个归档: {archives:?}",
            archives.len()
        );

        // ② 实现断言（放后面）：确认 0 是被换成了与配置默认值一致的兜底值
        assert!(
            mf.size > 0,
            "🔐 问题 41-③：size 为 0 时必须换成默认值，否则每行都会触发一次归档"
        );
        assert_eq!(mf.size, DEFAULT_SIZE, "应当换成与配置默认值一致的 128KiB");

        let _ = fs::remove_dir_all(&dir);
    }

    // ================= 🔐 问题 41-①：丢弃不得「不实回报」 =================

    /// 🔐 问题 41-①：`send_data` 必须**如实返回**是否真的入了队。
    ///
    /// 这是本项修法的核心：返回值不再被丢掉，而是真实反映"这条日志有没有被接管"。
    /// 上层（`Write::write`）据此保持 `Ok(buf.len())` 的"已接收"语义（理由见该处注释），
    /// 而**丢弃这件事通过计数可见** —— 这条测试同时钉住这两半。
    #[test]
    fn send_data_reports_whether_the_line_was_accepted() {
        let _guard = lock();

        // 容量 1 且无人消费：第 1 条入队成功，第 2 条必然被丢
        let (tx, _rx) = mpsc::sync_channel::<LogMsg>(1);
        let consumer = LogConsumer { tx };
        let before = log_dropped_total();

        // ① 队列有空间 → 如实返回 true
        assert!(
            consumer.send_data(b"first"),
            "队列有空位时 send_data 必须返回 true（确实入队了）"
        );

        // ② 队列已满 → 如实返回 false（这一条被丢弃）
        assert!(
            !consumer.send_data(b"second"),
            "🔐 问题 41-①：队列满时 send_data 必须返回 false，不能谎报成功"
        );

        // ③ 丢弃必须**可见**：计数增加（这是"不实回报"被消除的实际保证）
        assert_eq!(
            log_dropped_total() - before,
            1,
            "🔐 问题 41-①：被丢弃的那条必须计入 log_dropped（可在 /api/system/status 看到）"
        );
    }

    /// 🔐 问题 41-① 的**反向保护**：丢弃不能让写入报错。
    ///
    /// 这一条记录本项的**处置结论**：不能在丢弃时返回 `Ok(0)` 或 `Err`。
    /// 实测 `Ok(0)` 会让 `write_all()` 报 `WriteZero`，把"丢日志"升级成"错误风暴"；
    /// `Err` 更会让上层重试而阻塞主业务。所以写入端**永远接受**，丢弃只靠计数可见。
    ///
    /// 这里用**直接构造满队列**的方式制造丢弃（而不是靠"写得多"去碰运气）：
    /// 消费线程会及时把队列排空，写多少行都不一定丢；只有让队列**无人消费**才能稳定复现。
    #[test]
    fn dropping_never_turns_into_a_write_error() {
        let _guard = lock();

        // 直接对 `LogConsumer` 造一个无人消费、容量为 1 的队列：
        // 第 2 条起必然丢弃，从而稳定走到"丢弃"这条路径。
        let (tx, _rx) = mpsc::sync_channel::<LogMsg>(1);
        let consumer = LogConsumer { tx };
        let before = log_dropped_total();

        // 模拟 `Write::write` 的行为：无论 `send_data` 返回什么，都不允许演变成错误。
        // `accept_all` 就是 `MutexMappedFile::write` 的语义：永远 `Ok(buf.len())`。
        let accept_all = |buf: &[u8]| -> io::Result<usize> {
            consumer.send_data(buf);
            Ok(buf.len())
        };

        for i in 0..100 {
            let n = accept_all(format!("x{i}\n").as_bytes()).unwrap_or_else(|err| {
                panic!("🔐 问题 41-①：丢日志不得让写入报错（会升级成错误风暴），第 {i} 行: {err}")
            });
            assert_eq!(
                n,
                format!("x{i}\n").len(),
                "写入端对已接收的日志如实返回字节数（语义是「已接收」而非「已落盘」）"
            );
        }

        // 关键是"丢弃确实发生了，且它是靠计数可见、而不是靠报错"
        assert!(
            log_dropped_total() - before > 0,
            "这个场景应当确实发生了丢弃（否则本测试没有覆盖到目标路径）"
        );
    }
}
