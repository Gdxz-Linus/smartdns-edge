use std::{
    ffi::OsString,
    fmt::Display,
    io,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

// use regex::Regex;

use super::installer::Installer;
use crate::log::debug;

#[derive(Debug)]
pub struct ServiceDefinition {
    name: String,
    installer: Installer,
    commands: ServiceCommands,
}

impl ServiceDefinition {
    pub fn new(name: String, installer: Installer, commands: ServiceCommands) -> Self {
        Self {
            name,
            installer,
            commands,
        }
    }
}

#[derive(Debug)]
pub struct ServiceCommands {
    pub install: Option<ServiceCommand>,
    pub uninstall: Option<ServiceCommand>,
    pub status: Option<ServiceCommand>,
    pub start: ServiceCommand,
    pub stop: ServiceCommand,
    pub restart: Option<ServiceCommand>,
}

#[derive(Debug)]
pub struct ServiceManager {
    definition: ServiceDefinition,
}

impl From<ServiceDefinition> for ServiceManager {
    fn from(definition: ServiceDefinition) -> Self {
        Self { definition }
    }
}

impl ServiceManager {
    pub fn install(&self) -> io::Result<()> {
        // 🌟 智能防呆：安装前先探针，如果存在直接提示，绝不重复破坏现场！
        if let Ok(status) = self.status() {
            if matches!(status, ServiceStatus::Running(_) | ServiceStatus::Dead(_)) {
                println!("💡 SmartDNS service is already installed.");
                return Ok(());
            }
        }

        let _ = self.uninstall(false, true);

        // install files.
        self.definition.installer.install()?;

        if let Some(install) = self.definition.commands.install.as_ref() {
            if let Err(e) = install.spawn() {
                return Err(e);
            }
        }

        self.start()?;
        Ok(())
    }

    pub fn uninstall(&self, purge: bool, quiet: bool) -> io::Result<()> {
        // 🌟 统一拦截：卸载空服务直接报错返回，绝不执行后续 PowerShell
        if matches!(self.status(), Ok(ServiceStatus::NotInstalled)) {
            if !quiet {
                eprintln!("❌ SmartDNS service is NOT installed.");
            }
            return Ok(());
        }

        self.try_stop().unwrap_or_default();

        if let Some(uninstall) = self.definition.commands.uninstall.as_ref() {
            if quiet {
                let _ = uninstall.output();
            } else {
                let _ = uninstall.spawn();
            }
        }

        let _ = self.definition.installer.uninstall(purge)?;
        Ok(())
    }

    pub fn start(&self) -> io::Result<()> {
        match self.status() {
            Ok(ServiceStatus::Running(_)) => {
                println!("▶️ Service {} already started", self.definition.name);
            }
            Ok(ServiceStatus::NotInstalled) => {
                // 🌟 统一拦截：启动空服务，给出提示并指导安装
                eprintln!("❌ SmartDNS service is NOT installed.");
                eprintln!("💡 Hint: Please install it via 'smartdns service install' first.");
            }
            _ => {
                self.definition.commands.start.spawn()?;
            }
        }
        Ok(())
    }

    pub fn stop(&self) -> io::Result<()> {
        match self.status() {
            Ok(ServiceStatus::NotInstalled) => {
                // 🌟 统一拦截：停止空服务，直接报错，不需要加安装提示
                eprintln!("❌ SmartDNS service is NOT installed.");
				eprintln!("💡 Hint: Please install it via 'smartdns service install' first.");
            }
            Ok(ServiceStatus::Dead(_)) => {
                println!("⏹️ Service {} already stopped", self.definition.name);
            }
            _ => {
                self.definition.commands.stop.spawn()?;
            }
        }
        Ok(())
    }

    pub fn try_stop(&self) -> io::Result<()> {
        // 🌟 核心修正：只在“运行中”才去执行停止动作，避免多重报错！
        if matches!(self.status(), Ok(ServiceStatus::Running(_))) {
            self.definition.commands.stop.spawn()?;
        }
        Ok(())
    }

    pub fn restart(&self) -> io::Result<()> {
        if matches!(self.status(), Ok(ServiceStatus::NotInstalled)) {
            // 🌟 统一拦截：重启空服务，给出提示并指导安装
            eprintln!("❌ SmartDNS service is NOT installed.");
            eprintln!("💡 Hint: Please install it via 'smartdns service install' first.");
            return Ok(());
        }

        match self.definition.commands.restart.as_ref() {
            Some(restart) => {
                restart.spawn()?;
            }
            None => {
                self.try_stop().unwrap_or_default();
                std::thread::sleep(Duration::from_millis(500));
                self.start()?;
            }
        }
        Ok(())
    }
	
    pub fn status(&self) -> io::Result<ServiceStatus> {
        let status = match self.definition.commands.status.as_ref() {
            Some(cmd) => {
                let output = cmd.output()?;
                // 🌟 精准感知：直接读取底层的退出码 2 来断定服务不存在
                match output.status.code() {
                    Some(0) => ServiceStatus::Running(output),
                    Some(1) => ServiceStatus::Dead(output),
                    Some(2) => ServiceStatus::NotInstalled,
                    _ => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        if stdout.contains("NOT installed") {
                            ServiceStatus::NotInstalled
                        } else if output.status.success() {
                            ServiceStatus::Running(output)
                        } else {
                            ServiceStatus::Dead(output)
                        }
                    }
                }
            }
            None => ServiceStatus::Unknown,
        };
        Ok(status)
    }
}

#[derive(Debug)]
pub struct ServiceCommand {
    /// Path to the service manager program to run
    ///
    /// E.g. `/usr/local/bin/my-program`
    pub program: PathBuf,

    /// Arguments to use for the program
    ///
    /// E.g. `--arg`, `value`, `--another-arg`
    pub args: Vec<OsString>,
}

impl Display for ServiceCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.program.display())?;
        for arg in self.args.iter() {
            write!(f, " {}", arg.to_string_lossy())?
        }
        Ok(())
    }
}

impl ServiceCommand {
    #[inline]
    pub fn spawn(&self) -> io::Result<()> {
        let output = self.output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            if !stdout.trim().is_empty() {
                println!("{}", stdout.trim());
            }
            Ok(())
        } else {
            let mut msg = String::new();
            if !stdout.trim().is_empty() {
                msg.push_str(stdout.trim());
            }
            if !stderr.trim().is_empty() {
                if !msg.is_empty() { msg.push('\n'); }
                msg.push_str(stderr.trim());
            }
            if msg.trim().is_empty() {
                msg = "Failed".to_string();
            }
            
            // 🌟 核心修复 3：彻底拔除那个丑陋的 ❌ Error executing ... 前缀！
            // 让终端直接原汁原味地输出我们在 PowerShell 里精心排版的指导语！
            eprintln!("{}", msg);
            Err(io::Error::other("Command failed"))
        }
    }

    #[inline]
    pub fn output(&self) -> io::Result<std::process::Output> {
        debug!("># {}", self);
        self.to_command().output()
    }

    fn to_command(&self) -> Command {
        let mut command: Command = self.into();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

impl From<&ServiceCommand> for Command {
    fn from(cmd: &ServiceCommand) -> Self {
        let mut command = Command::new(cmd.program.as_path());
        command.args(cmd.args.iter());
        command
    }
}

impl From<ServiceCommand> for Command {
    #[inline]
    fn from(cmd: ServiceCommand) -> Self {
        Self::from(&cmd)
    }
}

#[derive(Debug)]
pub enum ServiceStatus {
    Running(std::process::Output),
    Dead(std::process::Output),
    NotInstalled, // 🌟 新增：专门识别未安装状态
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfg_if::cfg_if;

    #[test]
    fn test_service_command() {
        let cmd = {
            cfg_if! {
                if #[cfg(target_os="windows")] {
                    ServiceCommand {
                        program: "powershell.exe".into(),
                        args: vec![
                                "-NoProfile".into(),
                                "-Command".into(),
                                "Write-Output 'Windows'".into()
                            ],
                    }
                } else {
                    ServiceCommand {
                        program: "uname".into(),
                        args: vec![
                            "-a".into(),
                        ],
                    }
                }
            }
        };

        let output = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(output.stdout.as_slice()).to_string();

        #[cfg(unix)]
        assert_eq!(format!("{cmd}"), "uname -a");

        cfg_if! {
            if #[cfg(target_os="windows")] {
                assert!(stdout.contains("Windows"));
            } else if #[cfg(target_os="linux")] {
                assert!(stdout.contains("Linux"));
            } else if #[cfg(target_os="macos")] {
                assert!(stdout.contains("Darwin"));
            } else if #[cfg(target_os="android")] {
                assert!(stdout.contains("Android"));
            } else {
                unimplemented!()
            }
        }
    }
}
