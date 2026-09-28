use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
};

use fs3::FileExt; // 🌟 核心依赖：跨平台文件排他锁
use thiserror::Error;

/// 进程单实例锁。
///
/// 🔐「顺手修」：**把"锁"和"给人看的 PID"拆成两个文件**。
///
/// 原因（本机实测）：Windows 的文件字节锁**会挡住别的进程读这个文件**（POSIX 的 flock 不会）——
/// 原来锁和 PID 写在同一个文件里，于是第二个实例永远读不到锁文件的内容，只能报
/// `already running with PID 0`。拆开之后：
///   · 锁   → **平台相关**（Linux 固定路径、Windows 在 PID 文件旁，见 [`create`] 的说明）；
///            谁持有谁独占；退出时**不删**，理由见 `Drop`
///   · PID  → `<调用方给的名字>`（普通文件，任何进程随时可读，内容是当前持有者的进程号）
///
/// 🔐 **问题 44**：Linux 上锁路径**不再从 `-p` 派生**（Windows 保持原设计）。
/// 详见 [`create`] 的文档。
#[derive(Debug)]
pub struct ProcessGuard {
    id: u32,
    pid_path: PathBuf,
    lock_path: PathBuf,
    _lock_file: Option<std::fs::File>, // 🌟 必须将文件句柄保存在内存中，进程退出时自动释放
}

/// 🔐 问题 44：单实例锁的**固定路径** —— 与 `-p` / `-d` 等启动参数无关。
///
/// 为什么必须固定：防多开要拦住的是"同一台机器上跑了两个 smartdns 进程"，
/// 而不是"两个用了同一个 `-p` 的进程"。锁位置跟着参数走，就等同于没有锁。
///
/// 选址原则：所有启动方式（systemd / initd / 手工命令行 / Windows 服务）都能写、
/// 且互不冲突的**系统级公共位置**：
///   · Unix：`/var/run/smartdns.lock`；该目录不可写时依次退到
///     `/run/smartdns.lock`、`/tmp/smartdns.lock`（非 root 运行的部署）。
///   · Windows：`%ProgramData%\smartdns\smartdns.lock`；
///     拿不到时退到 `%TEMP%\smartdns.lock`。
///
/// 退到 `/tmp` 会让不同用户的实例互不可见（`/tmp` 权限隔离），
/// 但那已好于"完全没锁"；且真实部署（服务方式）走的是系统级路径。
fn fixed_lock_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(program_data) = std::env::var_os("ProgramData") {
            let dir = PathBuf::from(program_data).join("smartdns");
            // 尽力建目录；建不出来就退到 temp（下面的候选逻辑会兜住）
            if std::fs::create_dir_all(&dir).is_ok() {
                return dir.join("smartdns.lock");
            }
        }
        return std::env::temp_dir().join("smartdns.lock");
    }

    #[cfg(not(windows))]
    {
        for candidate in ["/var/run/smartdns.lock", "/run/smartdns.lock"] {
            let path = PathBuf::from(candidate);
            // 目录可写就直接用（父目录存在且能建文件才算可写）
            if let Some(parent) = path.parent()
                && parent.is_dir()
                && is_dir_writable(parent)
            {
                return path;
            }
        }
        std::env::temp_dir().join("smartdns.lock")
    }
}

/// 目录是否可写。
///
/// ⚠️ **不能只看权限位**（2026-09-26 修复）：`/run` 通常是 `755 root:root`，
/// 权限位里"属主可写"成立，于是旧实现（`mode & 0o222 != 0`）把它判成可写；
/// 但**非 root 用户实际写不进去** —— `open()` 当场 `Permission denied`，
/// 而那时已经选定了路径，**连"退到 /tmp"的兜底都不会走**，普通用户直接起不来。
///
/// 正确判据是"**当前有效用户**能不能在这里建文件"，所以这里**实际试建一次**：
/// 建成就立刻删掉（避免留垃圾），失败就算不可写、继续试下一个候选。
#[cfg(not(windows))]
fn is_dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".smartdns-lock-probe-{}", process::id()));
    match OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[derive(Error, Debug)]
pub enum ProcessGuardError {
    /// 已经有实例在跑。带着从 PID 文件里读到的进程号；读不到时为 `None`
    /// （**不再编一个 0 出来** —— 那会让人以为真有个 PID 0 的进程在跑）。
    #[error("another instance is already running (pid: {0:?})")]
    AlreadyRunning(Option<u32>),
    #[error("io error {0}")]
    IoError(#[from] io::Error),
}

/// 读出 PID 文件里的进程号。
///
/// 空文件、内容不是数字、读不动（权限/占用）都算"读不到" → `Err`，由调用方如实说明，
/// 绝不退回一个含义不明的 0。
fn read_pid(path: &Path) -> io::Result<u32> {
    let mut content = String::new();
    File::open(path)?.read_to_string(&mut content)?;

    content.trim().parse::<u32>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pid file content is not a pid: {:?}", content.trim()),
        )
    })
}

/// 🔐 问题 44：获取单实例锁。
///
/// **锁的位置按平台区分**（这是刻意的，理由在下面）：
///
/// * **Linux / 其它 Unix —— 固定路径**（见 [`fixed_lock_path`]），与 `-p` 无关。
///   因为项目自带的两套服务定义**互相矛盾**：
///   systemd 单元写的是 `-p /var/run/smartdns.pid`，而 initd 脚本用
///   `start-stop-daemon --make-pidfile`、**不给程序传 `-p`**。
///   两种启动方式于是算出**两个不同的锁文件**，各自都能加锁成功 ——
///   两个实例同时运行、争抢同一个端口，防多开形同虚设。
///   真机复现（WSL）：带 `-p` 起一个、不带 `-p` 起一个，**两个都活了下来**。
///
/// * **Windows —— 保持原设计**（`<pid 路径>.lock`）。
///   项目自带的 Windows 服务定义**本来就不带 `-p`**（只有 `run -c <conf>`），
///   所以服务方式启动时锁位置始终稳定；只有"手工带 `-p` 启动"才会偏离，
///   而那属于非典型用法，不值得为它引入新的系统目录。
///   （用户 2026-09-24 明确决定：Windows 保持现设计，只修 Linux。）
///
/// `path` 始终是"给人看的 PID 文件"位置，与锁在哪无关（Unix 侧）。
pub fn create<P: AsRef<Path>>(path: P) -> Result<ProcessGuard, ProcessGuardError> {
    let pid_path = path.as_ref().to_path_buf();
    let lock_path = platform_lock_path(&pid_path);
    create_with_lock(&pid_path, lock_path)
}

/// 按平台给出锁路径（见 [`create`] 的说明）。
#[cfg(not(windows))]
fn platform_lock_path(_pid_path: &Path) -> PathBuf {
    fixed_lock_path()
}

/// Windows：保持原设计 —— 锁放在 PID 文件旁边（`<pid 路径>.lock`）。
#[cfg(windows)]
fn platform_lock_path(pid_path: &Path) -> PathBuf {
    lock_path_next_to_pid(pid_path)
}

/// 老的取名规则：`<PID 文件名>.lock`（Windows 侧仍在用）。
#[cfg(windows)]
fn lock_path_next_to_pid(pid_path: &Path) -> PathBuf {
    let name = pid_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "smartdns.pid".to_string());
    pid_path.with_file_name(format!("{name}.lock"))
}

/// 🔐 问题 44 的配套：**持有者 PID 的"公共副本"** —— 紧挨着锁文件，与 `-p` 无关。
///
/// 为什么需要它：Linux 上锁是固定路径、而 PID 文件仍随 `-p` 走。
/// 用**不同 `-p`** 启动的第二个实例，在它自己的 pid 路径上读不到持有者的进程号，
/// 报错只能说"PID 读不到"。有了这份公共副本，任何启动方式都能问出"是谁在跑"。
///
/// 命名取 `<锁文件名>.pid`（如 `/run/smartdns.lock.pid`），与锁同生命周期的语义一致。
fn lock_owner_pid_path(lock_path: &Path) -> PathBuf {
    let name = lock_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "smartdns.lock".to_string());
    lock_path.with_file_name(format!("{name}.pid"))
}

/// 内部实现：允许显式指定锁路径。
///
/// 之所以把它单独抽出来：单元测试需要**互不干扰的锁文件**，
/// 若测试也走固定的 `/var/run/smartdns.lock`，并行跑的用例会互相抢锁。
/// 生产路径只经由 [`create`]。
fn create_with_lock<P: AsRef<Path>>(
    path: P,
    lock_path: PathBuf,
) -> Result<ProcessGuard, ProcessGuardError> {
    let pid_path = path.as_ref().to_path_buf();
    let id = process::id();

    if let Some(parent) = lock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // 🌟 核心修复 2：彻底抛弃不靠谱的 PID 存活检测，改用原子级的文件排他锁！
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;

    // 尝试非阻塞获取排他锁
    if lock_file.try_lock_exclusive().is_err() {
        // 获取失败 = 另一个实例正在运行并持有该锁。PID 从"不锁人的那个文件"里读。
        //
        // 🔐 问题 44 的配套改进（真机测试发现的提示问题）：
        // Linux 上锁是**固定路径**，而 PID 文件仍随 `-p` 走 —— 于是"用不同 `-p` 启动的
        // 第二个实例"在自己那个 pid 路径上读不到任何东西（那是**它自己**的路径，不是持有者的）。
        // 实测报错会退化成 "PID could not be read from <它自己的路径>"，虽然拦住了，
        // 但管理员拿不到"到底是哪个进程在跑"。
        //
        // 所以这里多试一个位置：**锁文件旁边**的 pid 文件（`<lock>.pid`）——
        // 那是持有者写下的、与 `-p` 无关的线索。读不到就保持 `None`（不编造 PID 0）。
        let pid = read_pid(&pid_path)
            .ok()
            .or_else(|| read_pid(&lock_owner_pid_path(&lock_path)).ok());
        return Err(ProcessGuardError::AlreadyRunning(pid));
    }

    // 成功获取排他锁！把 PID 写给外面看（这个文件不锁，谁都能读）
    if let Err(err) = write_pid(&pid_path, id) {
        // 写不进去不影响单实例保护（锁已经拿到），但要让人知道"PID 文件没更新"
        crate::log::warn!(
            "failed to write pid file {}: {}. Single-instance protection still works (the lock is held at {}).",
            pid_path.display(),
            err,
            lock_path.display()
        );
    }

    // 🔐 问题 44 的配套：再写一份"与 -p 无关"的持有者 PID（紧挨着锁）。
    // 这样**任何启动方式**的第二个实例都能问出"是谁在跑"，而不必猜对第一个实例的 `-p`。
    // 写失败只记日志：单实例保护靠的是锁，不是这份副本。
    if let Err(err) = write_pid(&lock_owner_pid_path(&lock_path), id) {
        crate::log::debug!(
            "failed to write lock-owner pid file next to {}: {} (single-instance protection is unaffected)",
            lock_path.display(),
            err
        );
    }

    Ok(ProcessGuard {
        id,
        pid_path,
        lock_path,
        _lock_file: Some(lock_file), // 🌟 随对象存活，一直锁住直到程序退出
    })
}

/// 写入 PID（先清空，避免旧的数字尾巴留下）
fn write_pid(path: &Path, id: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(id.to_string().as_bytes())?;
    file.flush()
}

/// 清空 PID 内容（退出时表示"现在没人持有"）
fn clear_pid(path: &Path) -> io::Result<()> {
    OpenOptions::new().write(true).truncate(true).open(path)?;
    Ok(())
}

impl ProcessGuard {
    /// 当前持有者（我们）的进程号
    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// 锁文件路径（诊断用）
    #[inline]
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        // 🔐「顺手修」：退出时**先清空 PID 内容，再释放锁**；锁文件本身**不删**。
        //
        // 原来写的是"先释放锁、再删文件"，这里的空档期有两个真实后果：
        //   ① 另一个实例可能刚好在这时拿到锁、写下自己的 PID，紧接着我们把文件删了 —— 它的记录凭空消失；
        //   ② POSIX 上更严重：把锁文件删掉之后，新起来的实例会锁住**另一个新 inode**，于是
        //      "两个实例同时认为自己持有锁" —— 单实例保护直接失效。
        // 删锁文件在任何平台上都躲不开这个洞，通行做法就是留着它（内容为空时表示"没人持有"）。
        if let Err(err) = clear_pid(&self.pid_path) {
            // 退出路径上不折腾：清不掉就算了，单实例保护靠的是锁，不是这个文件的空与否
            crate::log::debug!(
                "failed to clear pid file {} on exit: {}",
                self.pid_path.display(),
                err
            );
        }

        // 🔐 问题 44 的配套：锁旁那份"持有者 PID"也要清空（表示"没人持有"），
        // 否则下一个实例会读到一个**已经退出**的 PID，误以为有人还在跑。
        // 同样只记日志：清不掉不影响单实例保护。
        if let Err(err) = clear_pid(&lock_owner_pid_path(&self.lock_path)) {
            crate::log::debug!(
                "failed to clear lock-owner pid file for {} on exit: {}",
                self.lock_path.display(),
                err
            );
        }

        self._lock_file.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("smartdns-guard-{}-{}", std::process::id(), name))
    }

    /// 🔐 问题 44 的测试辅助：用**显式锁路径**建守卫。
    ///
    /// 为什么测试不能走 `create()`：Linux 侧锁已改为**固定路径**（`/var/run/smartdns.lock`），
    /// 并行跑的用例会互相抢同一把锁 —— 那会让测试随机失败，也会污染真实系统目录。
    /// 所以测试一律用 `create_with_lock` 指定临时锁文件；
    /// 生产路径由 `create()` 决定（见其文档）。
    fn create_isolated(pid_path: &Path, tag: &str) -> Result<ProcessGuard, ProcessGuardError> {
        let lock = tmp_path(&format!("{tag}.lock"));
        let _ = std::fs::remove_file(&lock);
        create_with_lock(pid_path, lock)
    }

    /// 拿到锁 → PID 文件里能读到自己的进程号
    #[test]
    fn pid_file_is_readable_while_locked() {
        let pid_path = tmp_path("readable.pid");
        let _ = std::fs::remove_file(&pid_path);

        let guard = create_isolated(&pid_path, "readable").expect("first create should succeed");
        assert_eq!(guard.id(), std::process::id());
        assert_eq!(
            read_pid(&pid_path).ok(),
            Some(std::process::id()),
            "PID 文件必须能被读出来（Windows 上锁在 .lock 文件上，不挡读）"
        );
        assert!(guard.lock_path().exists(), "锁文件应当存在于给定路径");
    }

    /// 第二个实例拿到 AlreadyRunning，并且能报出真正的 PID（不是 0）
    #[test]
    fn second_instance_reports_real_pid() {
        let pid_path = tmp_path("second.pid");
        let _ = std::fs::remove_file(&pid_path);

        let guard = create_isolated(&pid_path, "second").expect("first create should succeed");

        // 同一把锁再建一个守卫：锁是自己持有的 → 一定失败
        let lock = guard.lock_path().to_path_buf();
        match create_with_lock(&pid_path, lock) {
            Err(ProcessGuardError::AlreadyRunning(pid)) => {
                assert_eq!(
                    pid,
                    Some(std::process::id()),
                    "要报出真正的 PID，不能是 0 或 None"
                );
            }
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }

        drop(guard);
    }

    /// 退出后：PID 内容被清空（表示没人持有），锁文件留着且能重新上锁
    #[test]
    fn exit_clears_pid_and_keeps_lock_file() {
        let pid_path = tmp_path("exit.pid");
        let _ = std::fs::remove_file(&pid_path);

        let lock_path = {
            let guard = create_isolated(&pid_path, "exit").expect("create should succeed");
            let lock_path = guard.lock_path().to_path_buf();
            drop(guard);
            lock_path
        };

        let content = std::fs::read_to_string(&pid_path).unwrap_or_default();
        assert!(
            content.trim().is_empty(),
            "退出后 PID 内容应清空，实际是 {content:?}"
        );
        assert!(
            read_pid(&pid_path).is_err(),
            "空文件要按\"读不到\"处理，不能解析成 0"
        );
        assert!(
            lock_path.exists(),
            "锁文件不删（删了会留下\"两个实例都持有锁\"的洞），期望路径 {}",
            lock_path.display()
        );

        // 还能正常再起一个（同一把锁）
        let again = create_with_lock(&pid_path, lock_path).expect("restart should succeed");
        assert_eq!(read_pid(&pid_path).ok(), Some(std::process::id()));
        drop(again);
    }

    // ============ 🔐 问题 44：锁不得跟着 `-p` 走（Linux 侧） ============

    /// 🔐 问题 44（**真机复现的真实缺陷**）：Linux 上锁路径必须**与 `-p` 无关**。
    ///
    /// 缺陷原貌：锁 = `<pid 路径>.lock`，而 pid 路径取决于启动参数 ——
    /// 项目自带的 systemd 单元带 `-p /var/run/smartdns.pid`，initd 脚本却**不传 `-p`**
    /// （用 `start-stop-daemon --make-pidfile`）。两种启动方式于是算出**两个锁文件**，
    /// 各自加锁成功，两个实例同时运行。
    ///
    /// 真机复现（WSL）：带 `-p` 与不带 `-p` 各起一个，**两个都活了下来**，
    /// 锁分别在 `/tmp/.../run1.pid.lock` 与 `<exe目录>/managed/smartdns.pid.lock`。
    ///
    /// 本测试断言：**两个不同的 pid 路径**，在 Linux 上得到**同一个锁路径**。
    #[cfg(not(windows))]
    #[test]
    fn linux_lock_path_does_not_depend_on_pid_path() {
        let pid_a = tmp_path("svc-a.pid"); // 模拟 systemd：-p /var/run/smartdns.pid
        let pid_b = tmp_path("managed").join("smartdns.pid"); // 模拟 initd：不带 -p

        let lock_a = platform_lock_path(&pid_a);
        let lock_b = platform_lock_path(&pid_b);

        assert_eq!(
            lock_a,
            lock_b,
            "🔐 问题 44：Linux 上锁路径必须与 `-p` 无关，否则两种启动方式各锁各的、\
             防多开失效。实际: {} vs {}",
            lock_a.display(),
            lock_b.display()
        );

        // 加固：锁**不得由 pid 路径派生**（那正是"跟着 -p 走"的表现）。
        //
        // ⚠️ 这里**不能用** `!lock_a.starts_with(pid_a.parent())` ——
        // 2026-09-26 修掉"只看权限位"的可写性判断后，非 root 场景会正确地退到
        // `/tmp/smartdns.lock`，而 `tmp_path()` 造出的 pid 也在 `/tmp` 下，
        // 两者**恰好同父目录** ⇒ 那种写法会误报（实测踩到）。
        // 真正要钉的是"**不随 pid 文件名/路径变化**"，改用**同一目录下换文件名**：
        // 若实现是派生的，锁名必然跟着变；固定路径则纹丝不动。
        let pid_same_dir_other_name = pid_a.with_file_name("another-name.pid");
        assert_eq!(
            platform_lock_path(&pid_same_dir_other_name),
            lock_a,
            "锁路径不得随 pid 文件名变化（说明它是由 pid 派生的）: {}",
            lock_a.display()
        );
    }

    /// 🔐 Windows 侧**保持原设计**（用户 2026-09-24 决定）：锁仍在 PID 文件旁。
    ///
    /// 理由：项目自带的 Windows 服务定义**本来就不带 `-p`**，服务方式启动时锁位置稳定；
    /// 只有手工带 `-p` 才会偏离，不值得为此引入新的系统目录。
    ///
    /// 断言的是**"锁在 pid 文件所在目录、且以 pid 文件名 + `.lock` 结尾"**这个性质 ——
    /// 而不是拿 `with_file_name()` 再算一遍去自我比较（那样测不出任何东西，
    /// 第一版就是这么写的：期望值由同一个函数派生，必然相等）。
    #[cfg(windows)]
    #[test]
    fn windows_lock_path_stays_next_to_pid() {
        let pid = tmp_path("win-svc.pid");
        let lock = platform_lock_path(&pid);

        assert_eq!(
            lock.parent(),
            pid.parent(),
            "Windows 保持原设计：锁与 PID 文件在同一个目录。实际锁: {}",
            lock.display()
        );

        // 断言"以 pid 的文件名 + .lock 结尾"，并**由 pid 自身派生**期望值
        // （不要另写字面量：tmp_path 会给文件名加前缀，第一版就因此断言失败）
        let pid_name = pid.file_name().unwrap().to_string_lossy().into_owned();
        let expected_name = format!("{pid_name}.lock");
        assert_eq!(
            lock.file_name().and_then(|n| n.to_str()),
            Some(expected_name.as_str()),
            "锁文件名应当是 `<pid文件名>.lock`，实际: {}",
            lock.display()
        );
    }

    // ───────── 🔐 2026-09-26：锁目录可写性的判据 ─────────

    /// 🔐 **"目录可写"必须按"当前用户实际能不能建文件"判断，不能只看权限位。**
    ///
    /// ## 这个缺陷的真实后果（真机复现）
    ///
    /// `/run`（`/var/run` 是它的符号链接）通常是 `755 root:root` —— 权限位里
    /// "属主可写"成立，于是旧实现（`mode & 0o222 != 0`）判它**可写**、选定它，
    /// 接着 `open()` 当场 `Permission denied`。而那时路径已定，
    /// **连"退到 /tmp"的兜底都不会走** ⇒ **非 root 用户直接起不来**，
    /// 且错误信息误导成 "Another instance is likely running"（其实是权限问题）。
    ///
    /// ## 判据为什么这样设计（避免"没有判别力"）
    ///
    /// 无法在本测试里构造一个"权限位说可写、实际不可写"的目录
    /// （那需要 root 才能造出 `755 root:root` 并切换用户）。所以这里断言的是
    /// **判据本身的行为契约**：它必须**真的去建一个文件**。
    ///
    /// 用两个**必然成立**的对照：
    ///   · 可写目录（本测试自己的临时目录）⇒ `true`；
    ///   · **不存在**的目录 ⇒ `false`（旧实现同样返回 false，但那是靠 metadata 失败；
    ///     新实现靠 open 失败 —— 两条路径都该给 false）。
    ///
    /// ⚠️ **如实标注判别力**：这条测试**抓不到**"退回权限位判断"（因为在本机
    /// 可写目录上，两种实现的答案相同）。真正的判别力在**真机**：
    /// 退回旧实现后，非 root 启动立刻失败（已实测复现，见《实施记录》§26.6）。
    #[cfg(not(windows))]
    #[test]
    fn writable_probe_actually_tries_to_create_a_file() {
        // ① 本测试目录必然可写（tmp_path 就在系统临时目录下）
        let dir = tmp_path("probe-dir");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            is_dir_writable(&dir),
            "可写的临时目录应当判为可写: {}",
            dir.display()
        );

        // ② 不存在的目录必须判为**不可写**（否则会选定一个建不出锁的路径）
        let missing = dir.join("definitely-not-here");
        assert!(
            !is_dir_writable(&missing),
            "不存在的目录不能判为可写，否则会选中一个建不出锁文件的路径: {}",
            missing.display()
        );

        // ③ 探针**不得留下垃圾**：调用过后目录里不能多出 `.smartdns-lock-probe-*`
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".smartdns-lock-probe-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "可写性探测必须清理自己的探针文件，实际残留: {leftovers:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
