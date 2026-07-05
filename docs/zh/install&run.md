# 安装与运行

本程序为**纯净绿色软件**，无任何外部系统依赖。

## 🪟 Windows (企业服务器 & 个人桌面)

将下载的 `.zip` 文件解压到一个固定目录（如 `D:\SmartDNS`）。

### 方式一：前台测试运行（适合测试排障）

```powershell
.\smartdns.exe run -c .\smartdns.conf -v
```
*(注：`-v` 表示开启调试日志输出，方便直观查看解析过程)*

### 方式二：后台服务运行（推荐，开机自启）

请以管理员身份运行终端（PowerShell），执行以下命令，系统将全自动注册为服务并配置好防火墙规则：

```powershell
# 1. 安装服务
.\smartdns.exe service install

# 2. 启动服务
.\smartdns.exe service start

# 3. 随时查看运行状态 (带 🟢/🔴 指示灯)
.\smartdns.exe service status
```
*(如需彻底清理，执行 `.\smartdns.exe service uninstall` 即可)*

---

## 🐧 Linux & 🍎 macOS (系统服务 & 通用运行)

将下载的压缩包解压到目标目录。打开终端，首先赋予执行权限：

```bash
chmod +x ./smartdns
```

### 方式一：前台测试运行（适合排障）

```bash
sudo ./smartdns run -c /etc/smartdns/smartdns.conf
```
*(注：Linux 系统绑定 53 等特权端口需要 sudo/root 权限)*

### 方式二：后台服务运行（推荐，开机自启）

执行以下命令，程序将全自动注册为系统后台守护服务（支持 Linux systemd 与 macOS launchd）：

```bash
# 1. 安装服务
sudo ./smartdns service install

# 2. 启动服务
sudo ./smartdns service start

# 3. 随时查看运行状态 (带 🟢/🔴 指示灯)
sudo ./smartdns service status
```
*(如需彻底清理，执行 `sudo ./smartdns service uninstall` 即可)*

---

## 🐳 Docker / NAS (容器化一键部署)

我们提供原生支持 amd64 与 arm64 双架构的极简容器镜像。极其适合部署在群晖 (Synology) 等支持 Docker 的环境中。使用 CLI 快速一键启动：

```bash
docker run -d \
  --name smartdns \
  --restart always \
  --network host \
  -v /你的本地路径/smartdns.conf:/etc/smartdns/smartdns.conf \
  ghcr.io/gdxz-linus/smartdns-edge:lastest
```
