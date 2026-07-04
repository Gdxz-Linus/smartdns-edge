# 下载资源

SmartDNS Edge 提供了全平台的高性能原生可执行文件。对于标准的 Windows、Linux 和 macOS 系统，推荐直接下载本项目的最新 Release 版本。

对于需要集成 LuCI 等可视化路由管理界面的 OpenWrt 软路由系统，您可以参考使用原始 C 语言生态的路由器专属软件包。

## 1. SmartDNS Edge 官方下载 (推荐)

SmartDNS Edge 为全平台提供零依赖、极致优化的预编译压缩包。

👉 **[前往 GitHub Releases 页面下载最新版](https://github.com/Gdxz-Linus/smartdns-edge/releases)**

| 支持系统（架构） | 预编译发布包名称 | 说明 |
| :--- | :--- | :--- |
| **Windows** (x86_64) | `smartdns-x86_64-pc-windows-msvc.zip` | 64位 Windows 桌面与服务器 |
| **Windows** (ARM64) | `smartdns-aarch64-pc-windows-msvc.zip` | 搭载骁龙等 ARM 芯片的 Windows 笔电 |
| **macOS** (Intel) | `smartdns-x86_64-apple-darwin.zip` | 搭载 Intel 处理器的老款 Mac |
| **macOS** (Apple Silicon) | `smartdns-aarch64-apple-darwin.zip` | 搭载 M1/M2/M3/M4 芯片的新款 Mac |
| **Linux** (x86_64) | `smartdns-x86_64-generic-linux-gnu.tar.gz` | 标准 64位 Linux 桌面、服务器、WSL |
| **Linux** (ARM64) | `smartdns-aarch64-generic-linux-gnu.tar.gz` | ARM64 Linux 服务器、树莓派等边缘设备 |

**Docker 容器镜像：**
原生的多架构双端镜像（amd64 / arm64），可直接通过 CLI 拉取：

```shell
docker pull ghcr.io/gdxz-linus/smartdns-edge:latest
```

## 2. 软路由与嵌入式生态 (互补资源)

由于目前 SmartDNS Edge 主要提供跨平台的底层核心网关程序，如果您在 OpenWrt、DD-WRT 等路由器固件上需要原生的 luci-app 网页控制界面，您可以继续使用pymumu提供的原C语言版包管理器进行安装：

| 系统 / 环境 | 获取方式与说明 |
| :--- | :--- |
| **OpenWrt** | 24.10 之后系统使用 `apk` 命令：<br/>`apk add luci-app-smartdns`<br/><br/>22.03 及之前系统使用 `opkg`：<br/>`opkg update && opkg install luci-app-smartdns` |
| **DD-WRT** | 官方最新固件 Services 页面 -> SmartDNS Resolver -> 启用。 |
| **Entware** | `ipkg update`<br/>`ipkg install smartdns` |
| **LuCI App** | `luci-app-smartdns` 或 `luci-app-smartdns-lite`<br/>*注：LuCI 界面可以直接驱动后端的 SmartDNS 进程。* |

**请注意：**

- 静态编译的软件包未强制判断 CPU 架构，安装不正确的软件包将会导致服务无法启动，请确保正确安装对应的版本。
