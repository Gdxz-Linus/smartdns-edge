# Installation & Running

This software is a clean, dependency-free utility. 

## 🪟 Windows (Enterprise Servers & Desktops)

Extract the downloaded `.zip` file to a fixed directory (e.g., `D:\SmartDNS`).

### Method 1: Foreground Test Execution (Best for troubleshooting)

```powershell
.\smartdns.exe run -c .\smartdns.conf -v
```
*(Note: `-v` enables debug log output to visually inspect the resolution process)*

### Method 2: Background Service Execution (Recommended, Autostart)

Run your terminal (PowerShell) as Administrator and execute the following commands. The system will automatically register the background process and configure local firewall rules:

```powershell
# 1. Install service
.\smartdns.exe service install

# 2. Start service
.\smartdns.exe service start

# 3. Inspect service status (with 🟢/🔴 indicators)
.\smartdns.exe service status
```
*(To uninstall, simply execute `.\smartdns.exe service uninstall`)*

---

## 🐧 Linux & 🍎 macOS (Generic Execution)

Extract the archive to your target directory. Open your terminal, grant execution permissions, and run:

```bash
chmod +x ./smartdns
```

### Method 1: Foreground Test Execution (Best for troubleshooting)

```bash
sudo ./smartdns run -c /etc/smartdns/smartdns.conf
```
*(Note: Binding to privileged ports like 53 on Linux requires sudo/root privileges)*

### Method 2: Background Service Execution (Recommended, Autostart)

Run your terminal and execute the following commands. The program will automatically register as a background system daemon (supports Linux systemd and macOS launchd):

```bash
# 1. Install service
sudo ./smartdns service install

# 2. Start service
sudo ./smartdns service start

# 3. Inspect service status (with 🟢/🔴 indicators)
sudo ./smartdns service status
```
*(To uninstall, simply execute `sudo ./smartdns service uninstall`)*

---

## 🐳 Docker / NAS (One-Click Container Deployment)

We provide minimal container images natively supporting both amd64 and arm64 architectures. Perfect for Synology Docker setups or similar environments. Quick start using the CLI:

```bash
docker run -d \
  --name smartdns \
  --restart always \
  --network host \
  -v /your/local/path/smartdns.conf:/etc/smartdns/smartdns.conf \
  ghcr.io/gdxz-linus/smartdns-edge:latest
```


## Upgrading from an older version: the one thing you need to know

The management console no longer ships a default password (the old default no longer works). After upgrading:

1. **Console not enabled** (no `bind-http` / `bind-https` / `bind-h3`) → nothing to do; DNS service is unaffected.
2. **Console bound to localhost only** (e.g. `bind-http 127.0.0.1:6080`) → a random token is printed in the
   startup log; use it to log in. To pin it, add `api-token <your-token>` to the configuration.
3. **Console bound to a public address** (e.g. `bind-http 0.0.0.0:6080`) → without an `api-token` in the
   configuration the service **refuses to start** (with a clear message). This is deliberate: the console can
   rewrite resolution rules, so it must never be exposed without a token. Set `api-token`, or use an SSH tunnel.

**Recommended**: keep the console port off the public network and use an SSH tunnel:
`ssh -L 6080:127.0.0.1:6080 your-server`, then open `http://127.0.0.1:6080` locally.

### Containers (Docker / NAS) note

The behaviour inside a container is identical: if the mounted configuration binds the console to
`0.0.0.0` without an `api-token`, the container **refuses to start** (exit code 2). Injecting the token
through the environment is the easiest fix:

```bash
docker run -d --name smartdns --restart always --network host \
  -e SMARTDNS_API_TOKEN=your-token \
  -v /your/path/smartdns.conf:/etc/smartdns/smartdns.conf \
  ghcr.io/gdxz-linus/smartdns-edge:latest
```

### Web console inside the container (off by default)

The image ships a web console but exposes no port for it by default. To use it, publish the port and
make sure a token is set:

```bash
docker run -d --name smartdns --restart always --network host \
  -p 8000:8000 \
  -e SMARTDNS_API_TOKEN=your-token \
  -v /your/path/smartdns.conf:/etc/smartdns/smartdns.conf \
  ghcr.io/gdxz-linus/smartdns-edge:latest
```

Then open `http://<host-ip>:8000`.

⚠️ The console is **plaintext HTTP**: the token travels unencrypted. Use it on a trusted LAN only;
for remote access use a `bind-https` (TLS) listener or terminate TLS in a reverse proxy.
