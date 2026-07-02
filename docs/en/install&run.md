# Installation & Running

This software is a clean, dependency-free utility. Please visit the [Releases page](https://github.com/Gdxz-Linus/smartdns-edge/releases) to download the latest archive corresponding to your system architecture.

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
  ghcr.io/gdxz-linus/smartdns-edge:v1.0.1
```
