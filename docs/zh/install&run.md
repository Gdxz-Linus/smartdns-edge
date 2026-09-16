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
  ghcr.io/gdxz-linus/smartdns-edge:latest
```


## 从旧版本升级：一件你需要知道的事

管理后台的访问口令**不再有默认值**（旧版本里那个默认口令已经作废，用不了）。升级后按你的配置分三种情况：

1. **没开管理后台**（配置里没有 `bind-http` / `bind-https` / `bind-h3`）
   → 什么都不用做，DNS 解析服务不受任何影响。

2. **开了管理后台，且只绑在本机**（例如 `bind-http 127.0.0.1:6080`）
   → 启动后到日志里找一行随机口令，用它登录即可。
   如果你希望口令固定下来，在配置里加一行：`api-token 你的口令`。

3. **开了管理后台，且绑在对外地址**（例如 `bind-http 0.0.0.0:6080`）
   → 如果你没有在配置里设置 `api-token`，**服务会拒绝启动**并给出中文提示。
   这是有意为之：管理后台可以修改解析规则、增删自定义域名，绝不能在没有口令的情况下对全网开放。
   解决办法：先设置 `api-token 你的口令`，或者按下面的方式用 SSH 隧道访问。

**更安全的做法（推荐）**：不要把后台端口暴露到公网，改用 SSH 隧道：

```bash
ssh -L 6080:127.0.0.1:6080 你的服务器     # 然后本机浏览器访问 http://127.0.0.1:6080
```

### 容器（Docker / NAS）部署注意

容器里的行为跟上面完全一致：如果挂载进容器的配置把管理后台绑到了 `0.0.0.0` 却没有 `api-token`，
容器会**拒绝启动**（退出码 2）。这种情况下用环境变量注入口令最方便：

```bash
docker run -d --name smartdns --restart always --network host \
  -e SMARTDNS_API_TOKEN=你的口令 \
  -v /你的路径/smartdns.conf:/etc/smartdns/smartdns.conf \
  ghcr.io/gdxz-linus/smartdns-edge:latest
```

### 容器里的网页控制台（默认不开）

镜像内置网页控制台，默认不暴露端口。要用就在启动命令里加上端口映射，并确保口令已设置：

```bash
docker run -d --name smartdns --restart always --network host \
  -p 8000:8000 \
  -e SMARTDNS_API_TOKEN=你的口令 \
  -v /你的路径/smartdns.conf:/etc/smartdns/smartdns.conf \
  ghcr.io/gdxz-linus/smartdns-edge:latest
```

然后浏览器打开 `http://容器所在机器的IP:8000`。

⚠️ 这个控制台是**明文 HTTP**：口令在网络上明文传输。请只在可信内网使用；
需要跨网络访问时，请改用 `bind-https`（TLS）监听，或在前端加反向代理做 TLS 终结。
