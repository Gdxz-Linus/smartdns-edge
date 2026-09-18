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

## 🖥️ 网页控制台（管理后台）

网页控制台**不是容器专有的**：它挂在 `bind-http` / `bind-https` / `bind-h3` 这三种监听上 ——
配置里写了其中任意一个，对应端口上就同时提供 DNS 服务（DoH）与管理后台（`/api` 下的配置、上游、
地址规则、缓存、日志等接口，以及 `/api/docs` 接口文档）。

不想在某个监听上暴露后台（例如"这个端口只想对外提供 DoH"），给它加 `-no-api` 即可：

```
bind-https 0.0.0.0:8000 -ssl-certificate cert.pem -ssl-certificate-key key.pem -no-api
```

（`bind` 行上的 `-ssl-certificate` / `-ssl-certificate-key` 与配置表里的 `bind-cert-file` /
`bind-cert-key-file` 是同一件事的两种写法：前者写在 `bind*` 行上只对该监听生效，后者是全局默认。）

### 各平台怎么开

| 平台 | 做法 |
|---|---|
| Windows（服务方式） | 配置文件里加一行 `bind-http 127.0.0.1:6080`，`smartdns service restart`，浏览器打开 `http://127.0.0.1:6080` |
| Linux / macOS（服务方式） | 同上：配置里加 `bind-http 127.0.0.1:6080`，`smartdns service restart`，浏览器打开 `http://127.0.0.1:6080` |
| Docker / NAS | 除了配置里那一行，还要在启动命令里**把端口映射出来**（`-p 6080:6080`），再访问 `http://容器所在机器的IP:6080` |

```bash
# Docker 示例：映射控制台端口并注入口令
docker run -d --name smartdns --restart always --network host \
  -p 6080:6080 \
  -e SMARTDNS_API_TOKEN=你的口令 \
  -v /你的路径/smartdns.conf:/etc/smartdns/smartdns.conf \
  ghcr.io/gdxz-linus/smartdns-edge:latest
```

### 口令（必读）

口令按以下顺序取用：

1. 配置里的 `api-token <口令>`；
2. 环境变量 `SMARTDNS_API_TOKEN`；
3. 都没有时：**随机生成一个并打印在启动日志里**，提示形如 `api-token 3f9c...`，
   把它填进配置即可固定下来。

程序里**没有任何写死的默认口令**。后台被绑到非本机地址（例如 `bind-http 0.0.0.0:8000`）却没有口令时，
程序**直接拒绝启动**（**退出码 2**，便于服务管理器与脚本判断）——因为那等于把管理后台开放给整个网络。

### 怎么安全地用

| 场景 | 建议做法 |
|---|---|
| 只在本机管理 | `bind-http 127.0.0.1:8000`，浏览器开 `http://127.0.0.1:8000` |
| 远程管理（推荐） | **不要**对公网开放端口，用 SSH 隧道：`ssh -L 8000:127.0.0.1:8000 你的服务器`，然后本机浏览器开 `http://localhost:8000` |
| 必须长期远程访问 | 用 `bind-https 0.0.0.0:8000 -ssl-certificate 证书 -ssl-certificate-key 私钥`（口令仍要自己设置），并把来源限制在内网 |

⚠️ `bind-http` 是**明文 HTTP**：口令和内容在网络上不加密，因此除非走 SSH 隧道，否则请一律使用 `bind-https`。
