use clap::Parser;
use clap::Subcommand;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use std::ffi::OsString;
use std::str::FromStr;

use crate::log::{self, warn};
#[cfg(feature = "resolve-cli")]
use crate::resolver::ResolveCommand;

type LogLevelDefault = InfoLevel;

/// SmartDNS.
///
#[derive(Parser, Debug)]
// 🌟 终极视觉净化：加上 disable_help_subcommand = true。
// 直接砍掉 clap 自动生成的冗余 help 命令，彻底抹除 subcommands 的刺眼文案！
// 用户只需使用底部的 -h 或 --help 即可，让核心命令列表保持极致纯净！
#[command(author, version=build_version(), about, long_about = None, disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[command(flatten)]
    verbose: Verbosity<LogLevelDefault>,
}

impl Cli {
    pub fn parse() -> Self {
        #[cfg(feature = "resolve-cli")]
        if ResolveCommand::is_resolve_cli() {
            return ResolveCommand::parse().into();
        }

        #[cfg(feature = "resolve-cli")]
        {
            // 🌟 核心修复 3：强行拦截 smartdns resolve 命令，让它走原作者写的“高级解析器”，
            // 否则 clap 遇到 @8.8.8.8 这种 dig 语法会直接报错崩溃！
            let args: Vec<String> = std::env::args().collect();
            if args.len() >= 2 && args[1] == "resolve" && !args.contains(&"--help".to_string()) && !args.contains(&"-h".to_string()) {
                if let Ok(resolve_command) = ResolveCommand::try_parse_from(args) {
                    return resolve_command.into();
                }
            }
        }

        match Self::try_parse() {
            Ok(cli) => cli,
            Err(e) => {
                // 🌟 核心修复 1：如果是请求帮助 (help) 或版本号 (--version)，立刻打印并退出！
                // 绝不允许这些系统指令流向下方“贪婪”的兼容域名解析器。
                if matches!(
                    e.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) {
                    e.exit();
                }

                if let Ok(cli) = CompatibleCli::try_parse() {
                    return cli.into();
                }
                // Since this is more of a development-time error, we aren't doing as fancy of a quit
                // as `get_matches`
                e.exit()
            }
        }
    }

    /// Parse from iterator, exit on error
    pub fn parse_from<I, T>(itr: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let itr = itr.into_iter().collect::<Vec<_>>();
        match Self::try_parse_from(itr.clone()) {
            Ok(cli) => cli,
            Err(e) => {
                // 🌟 核心修复 2：同理，拦截测试/特定入口传来的 Help 信号
                if matches!(
                    e.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) {
                    e.exit();
                }

                if let Ok(cli) = CompatibleCli::try_parse_from(itr) {
                    return cli.into();
                }

                e.exit()
            }
        }
    }

    pub fn log_level(&self) -> Option<log::Level> {
        self.verbose
            .log_level()
            .map(|s| s.to_string())
            .and_then(|s| log::Level::from_str(&s).ok())
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the SmartDNS server.
    Run {
        /// Configuration file
        #[arg(short = 'c', long)]
        conf: Option<std::path::PathBuf>,

        /// Base directory for configuration and managed files
        #[arg(short = 'd', long, value_name = "DIR")]
        directory: Option<std::path::PathBuf>,

        /// Pid file
        #[arg(short = 'p', long)]
        pid: Option<std::path::PathBuf>,
    },

    /// Manage the SmartDNS service (install, uninstall, start, stop, restart).
    Service {
        #[command(subcommand)]
        command: ServiceCommands,
    },

    /// Perform DNS resolution.
    #[cfg(feature = "resolve-cli")]
    Resolve(ResolveCommand),

    /// Create a symbolic link to the SmartDNS binary (drop-in replacement for `dig`, `nslookup`, `resolve` etc.)
    #[cfg(feature = "resolve-cli")]
    Symlink {
        /// The target name or path for the symlink (e.g. dig.exe, nslookup.exe)
        #[arg(value_name = "TARGET_NAME")]
        link: std::path::PathBuf,
    },

    /// Test configuration and exit
    Test {
        /// Config file
        #[arg(short = 'c', long)]
        conf: Option<std::path::PathBuf>,

        /// Base directory for configuration and managed files
        #[arg(short = 'd', long, value_name = "DIR")]
        directory: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommands {
    /// Install the SmartDNS as service.
    Install,

    /// Uninstall the SmartDNS service.
    Uninstall {
        /// Purge both the binary and config files.
        #[arg(short = 'p', long)]
        purge: bool,
    },

    /// Start the SmartDNS service.
    Start,

    /// Stop the SmartDNS service.
    Stop,

    /// Restart the SmartDNS service.
    Restart,

    /// Print the service status of SmartDNS
    Status,
}

/// Cli Compatible with [](https://github.com/pymumu/smartdns)
#[derive(Parser, Debug)]
struct CompatibleCli {
    /// Config file
    #[arg(short = 'c', long)]
    conf: Option<std::path::PathBuf>,

    /// Pid file
    #[arg(short = 'p', long)]
    pid: Option<std::path::PathBuf>,

    /// Run foreground.
    #[arg(short = 'f', long)]
    foreground: bool,

    /// Verbose screen.
    #[arg(short = 'x', long)]
    verbose: bool,

    /// ignore segment fault signal
    #[arg(short = 'S')]
    segment_fault_signal: bool,
}

impl From<CompatibleCli> for Cli {
    fn from(
        CompatibleCli {
            conf,
            pid,
            verbose,
            foreground,
            segment_fault_signal: _,
        }: CompatibleCli,
    ) -> Self {
        if !foreground {
            warn!("not support running as a daemon, run foreground instead.")
        }

        let verbose0 = if verbose {
            Verbosity::new(10, 0)
        } else {
            Default::default()
        };
        Self {
            command: Commands::Run {
                conf,
                pid,
                directory: None,
            },
            verbose: verbose0,
        }
    }
}

#[cfg(feature = "resolve-cli")]
impl From<ResolveCommand> for Cli {
    fn from(value: ResolveCommand) -> Self {
        Self {
            command: Commands::Resolve(value),
            verbose: Default::default(),
        }
    }
}

fn build_version() -> &'static str {
    static VERSION: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!(
            "{} 🕙 {}",
            env!("CARGO_PKG_VERSION"),
            crate::BUILD_DATE.with_timezone(&chrono::Local)
        )
    });
    &VERSION
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_cli_args_parse_run() {
        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        let cli = Cli::parse_from(["smartdns", "run", "--conf", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_run_verbose() {
        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf"]);
        assert_eq!(cli.log_level(), Some(log::Level::INFO));

        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "-q"]);
        assert_eq!(cli.log_level(), Some(log::Level::WARN));

        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "-v"]);
        assert_eq!(cli.log_level(), Some(log::Level::DEBUG));

        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "-qqqqq"]);
        assert_eq!(cli.log_level(), None);
    }

    #[test]
    fn test_cli_args_parse_run_debug_on() {
        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "-v"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        assert_eq!(cli.log_level(), Some(log::Level::DEBUG));
    }

    #[test]
    fn test_cli_args_parse_install() {
        let cli = Cli::parse_from(["smartdns", "service", "install"]);
        assert!(matches!(
            cli.command,
            Commands::Service {
                command: ServiceCommands::Install
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_uninstall() {
        let cli = Cli::parse_from(["smartdns", "service", "uninstall"]);
        assert!(matches!(
            cli.command,
            Commands::Service {
                command: ServiceCommands::Uninstall { purge: false }
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_compatible_run() {
        let cli = Cli::parse_from(["smartdns", "-c", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        let cli = Cli::parse_from(["smartdns", "--conf", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_compatible_run_2() {
        let cli = Cli::parse_from(["smartdns", "-c", "/etc/smartdns.conf", "-x"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        assert_eq!(cli.log_level(), Some(log::Level::TRACE));

        let cli = Cli::parse_from(["smartdns", "--conf", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_compatible_run_3() {
        let cli = Cli::parse_from(["smartdns", "-f", "-c", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        assert_eq!(cli.log_level(), Some(log::Level::INFO));
    }

    #[test]
    fn test_cli_args_parse_compatible_run_4() {
        let cli = Cli::parse_from(["smartdns", "-f", "-c", "/etc/smartdns.conf", "-S"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        assert_eq!(cli.log_level(), Some(log::Level::INFO));
    }
}
