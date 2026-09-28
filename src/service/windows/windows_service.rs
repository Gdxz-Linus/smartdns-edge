use super::SERVICE_NAME;
use std::{ffi::OsString, time::Duration};

use windows_service::service::{ServiceControlAccept, ServiceExitCode, ServiceState, ServiceType};
use windows_service::{
    Result, define_windows_service,
    service::{ServiceControl, ServiceStatus},
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

define_windows_service!(ffi_service_main, service_main);

fn service_main(args: Vec<OsString>) {
    // 🌟 核心修复 4：直接删除危险且容易导致假死的 AllocConsole
    let _ = run_service(args);
}

pub fn run() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn run_service(_args: Vec<OsString>) -> Result<()> {
    // 🔐 问题 47：事件处理器需要在**注册之后**才能拿到 `status_handle`
    // （`register()` 的返回值），但它在注册时就要被传进去 —— 循环依赖。
    // 用一个共享槽位打破：处理器只从槽里**读**句柄，注册完成后由本函数填入。
    //
    // 为什么值得这么做：Windows 服务规范要求在收到 Stop 后**尽快上报
    // STOP_PENDING**，否则服务管理器只能干等、超时后强杀 ——
    // 强杀会让"日志排空 / 缓存落盘"来不及做，正是问题 47 的后果。
    // 原来的实现收到 Stop 后一个状态都不报。
    //
    // 用 `OnceLock` 而不是 `Mutex`：只需要"注册后读一次"，没有并发写的需求，
    // 且 `OnceLock` 的读取无锁开销（Stop 处理发生在系统回调线程里，越快越好）。
    static STATUS_HANDLE: std::sync::OnceLock<
        windows_service::service_control_handler::ServiceStatusHandle,
    > = std::sync::OnceLock::new();

    /// 上报"正在停止（收尾中）"。
    ///
    /// `checkpoint` 递增符合服务规范（表示还在推进，不是卡死）；
    /// `wait_hint` 给 10 秒，覆盖"排空日志队列 + 写缓存文件"的收尾时间
    /// （缓存落盘的超时是 5 秒，见 `app.rs`，这里留一倍余量）。
    fn report_stop_pending() {
        if let Some(handle) = STATUS_HANDLE.get() {
            let _ = handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::StopPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 1,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            });
        }
    }

    // Define system service event handler that will be receiving service events.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // Notifies a service to report its current status information to the service
            // control manager. Always return NoError even if not implemented.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

            // Handle stop
            ServiceControl::Stop => {
                // 🔐 问题 47：**必须用 `request_shutdown()`，不能用 `notify_waiters()`**。
                //
                // 原来这里直接调 `SHUTDOWN_NOTIFY.notify_waiters()` ——
                // 只唤醒"此刻已经在等"的任务、**不保留许可**。
                // 系统要求停止服务时，主流程很可能还没走到等待点
                // （正在启动、正在加载配置、正要进入等待），这条通知就**丢了**：
                // 服务不响应停止，只能等系统强杀 ——
                // 而强杀路径下退出前"排空日志队列"这步不会执行，
                // 恰好是代码里最担心的"关机前后日志被吞"。
                //
                // `request_shutdown()` 会**先置一个永久可查的标志位**，
                // 再唤醒当前等待者：无论通知来得多早，等待方都能在
                // 自己的下一轮看到"该退出了"。（详见 `signal` 模块的说明。）
                let first = crate::signal::request_shutdown();

                if first {
                    crate::log::info!("service stop requested, shutting down gracefully...");
                }

                // 按服务规范上报 STOP_PENDING（见 `report_stop_pending` 的说明）。
                report_stop_pending();

                ServiceControlHandlerResult::NoError
            }

            // 🔐 问题 47：系统将要关机/重启时同样要**优雅退出**，
            // 否则日志与缓存都来不及落盘（与 Stop 是同一类后果）。
            ServiceControl::Shutdown => {
                let first = crate::signal::request_shutdown();

                if first {
                    crate::log::info!("system shutdown requested, shutting down gracefully...");
                }

                report_stop_pending();

                ServiceControlHandlerResult::NoError
            }

            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler.
    // The returned status handle should be used to report service status changes to the system.
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // 🔐 问题 47：把句柄放进共享槽位，供**已注册的事件处理器**上报状态使用。
    // 放在"已运行"状态上报**之前**：此后任何 Stop 通知都能立刻上报 STOP_PENDING。
    let _ = STATUS_HANDLE.set(status_handle.clone());

    let service_type = ServiceType::OWN_PROCESS;

    // Tell the system that service is running
    //
    // 🔐 问题 47：这里同时把 **STOP 与 SHUTDOWN** 都声明为"接受的控制"。
    // 原来只声明了 `STOP`，于是系统关机时发出的 SHUTDOWN 会被服务管理器
    // 判为"该服务不接受此控制"而不投递 —— 服务被直接强杀，
    // 缓存与日志同样来不及落盘。
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    {
        use crate::cli::*;

        let args = std::env::args()
            .filter(|s| s != "--ws7642ea814a90496daaa54f2820254f12")
            .collect::<Vec<_>>();
        Cli::parse_from(args).run();
    }

    // Tell the system that service has stopped.
    status_handle.set_service_status(ServiceStatus {
        service_type,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}
