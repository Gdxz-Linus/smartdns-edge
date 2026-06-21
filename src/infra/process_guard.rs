use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
};

use fs3::FileExt; // 🌟 核心依赖：跨平台文件排他锁
use thiserror::Error;

pub struct ProcessGuard {
    id: u32,
    path: PathBuf,
    _lock_file: Option<std::fs::File>, // 🌟 必须将文件句柄保存在内存中，进程退出时自动释放
}

#[derive(Error, Debug)]
pub enum ProcessGuardError {
    #[error("the process id {0} already running!!!")]
    AlreadyRunning(u32),
    #[error("io error {0}")]
    IoError(#[from] io::Error),
}

pub fn create<P: AsRef<Path>>(path: P) -> Result<ProcessGuard, ProcessGuardError> {
    let path = path.as_ref();
    let id = process::id();

    // 🌟 核心修复 2：彻底抛弃不靠谱的 PID 存活检测，改用原子级的文件排他锁！
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    // 尝试非阻塞获取排他锁
    if let Err(_) = file.try_lock_exclusive() {
        // 如果获取失败，说明另一个实例正在运行并持有该锁
        let mut id_str = String::new();
        let _ = file.read_to_string(&mut id_str);
        let prev_id = id_str.trim().parse::<u32>().unwrap_or(0);
        return Err(ProcessGuardError::AlreadyRunning(prev_id));
    }

    // 成功获取排他锁！安全清空文件并写入自己的 PID
    file.set_len(0)?;
    file.write_all(id.to_string().as_bytes())?;
    file.flush()?;

    Ok(ProcessGuard {
        id,
        path: path.to_path_buf(),
        _lock_file: Some(file), // 🌟 随对象存活，一直锁住直到程序退出
    })
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        // 🌟 核心修复 3：先主动 Drop 关闭文件句柄从而释放锁，然后再删除文件。
        // 否则在 Windows 下直接删除自己正在打开（且没有 Share_Delete 权限）的文件会报错。
        self._lock_file.take();
        
        if self.path.exists() {
            fs::remove_file(self.path.as_path()).unwrap_or_default()
        }
    }
}