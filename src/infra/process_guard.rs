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
///   · 锁   → `<调用方给的名字>.lock`（谁持有谁独占；退出时**不删**，理由见 `Drop`）
///   · PID  → `<调用方给的名字>`（普通文件，任何进程随时可读，内容是当前持有者的进程号）
#[derive(Debug)]
pub struct ProcessGuard {
    id: u32,
    pid_path: PathBuf,
    lock_path: PathBuf,
    _lock_file: Option<std::fs::File>, // 🌟 必须将文件句柄保存在内存中，进程退出时自动释放
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

pub fn create<P: AsRef<Path>>(path: P) -> Result<ProcessGuard, ProcessGuardError> {
    let pid_path = path.as_ref().to_path_buf();
    let lock_path = {
        let name = pid_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "smartdns.pid".to_string());
        pid_path.with_file_name(format!("{name}.lock"))
    };

    let id = process::id();

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
        return Err(ProcessGuardError::AlreadyRunning(read_pid(&pid_path).ok()));
    }

    // 成功获取排他锁！把 PID 写给外面看（这个文件不锁，谁都能读）
    if let Err(err) = write_pid(&pid_path, id) {
        // 写不进去不影响单实例保护（锁已经拿到），但要让人知道"PID 文件没更新"
        crate::log::warn!(
            "failed to write pid file {}: {}. Single-instance protection still works (the lock is held).",
            pid_path.display(),
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

        self._lock_file.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("smartdns-guard-{}-{}", std::process::id(), name))
    }

    /// 拿到锁 → PID 文件里能读到自己的进程号
    #[test]
    fn pid_file_is_readable_while_locked() {
        let pid_path = tmp_path("readable.pid");
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(pid_path.with_file_name("readable.pid.lock"));

        let guard = create(&pid_path).expect("first create should succeed");
        assert_eq!(guard.id(), std::process::id());
        assert_eq!(
            read_pid(&pid_path).ok(),
            Some(std::process::id()),
            "PID 文件必须能被读出来（Windows 上锁在 .lock 文件上，不挡读）"
        );
        assert!(
            guard.lock_path().exists(),
            "锁应该加在同名的 .lock 文件上"
        );
    }

    /// 第二个实例拿到 AlreadyRunning，并且能报出真正的 PID（不是 0）
    #[test]
    fn second_instance_reports_real_pid() {
        let pid_path = tmp_path("second.pid");
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(pid_path.with_file_name("second.pid.lock"));

        let guard = create(&pid_path).expect("first create should succeed");

        // 同一个进程内再建一个守卫：锁是自己持有的 → 一定失败
        match create(&pid_path) {
            Err(ProcessGuardError::AlreadyRunning(pid)) => {
                assert_eq!(pid, Some(std::process::id()), "要报出真正的 PID，不能是 0 或 None");
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
        let _ = std::fs::remove_file(pid_path.with_file_name("exit.pid.lock"));

        let lock_path = {
            let guard = create(&pid_path).expect("create should succeed");
            let lock_path = guard.lock_path().to_path_buf();
            drop(guard);
            lock_path
        };

        let content = std::fs::read_to_string(&pid_path).unwrap_or_default();
        assert!(content.trim().is_empty(), "退出后 PID 内容应清空，实际是 {content:?}");
        assert!(
            read_pid(&pid_path).is_err(),
            "空文件要按\"读不到\"处理，不能解析成 0"
        );
        assert!(
            lock_path.exists(),
            "锁文件不删（删了会留下\"两个实例都持有锁\"的洞），期望路径 {}",
            lock_path.display()
        );

        // 还能正常再起一个
        let again = create(&pid_path).expect("restart should succeed after exit");
        assert_eq!(read_pid(&pid_path).ok(), Some(std::process::id()));
        drop(again);
    }
}
