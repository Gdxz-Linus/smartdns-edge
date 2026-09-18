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

## 🖥️ Web Console (management UI)

The web console is **not container-specific**: it is mounted on the `bind-http` / `bind-https` / `bind-h3`
listeners — whichever of those you configure also serves the DNS service (DoH) and the management console
on that port (the `/api` endpoints for config, upstreams, address rules, cache and logs, plus `/api/docs`
for the API reference).

To keep a listener DNS-only (for example "this port should only serve DoH"), add `-no-api` to it:

```
bind-https 0.0.0.0:8000 -ssl-certificate cert.pem -ssl-certificate-key key.pem -no-api
```

(`-ssl-certificate` / `-ssl-certificate-key` on a `bind*` line and the `bind-cert-file` /
`bind-cert-key-file` options are two ways of saying the same thing: the former applies to that listener
only, the latter is the global default.)

### How to enable it per platform

| Platform | What to do |
|---|---|
| Windows (service mode) | Add `bind-http 127.0.0.1:6080` to the config, run `smartdns service restart`, open `http://127.0.0.1:6080` |
| Linux / macOS (service mode) | Same: add `bind-http 127.0.0.1:6080`, `smartdns service restart`, open `http://127.0.0.1:6080` |
| Docker / NAS | Besides that config line, **publish the port** in the run command (`-p 6080:6080`), then open `http://<host-ip>:6080` |

```bash
# Docker example: publish the console port and inject a token
docker run -d --name smartdns --restart always --network host \
  -p 6080:6080 \
  -e SMARTDNS_API_TOKEN=your-token \
  -v /your/path/smartdns.conf:/etc/smartdns/smartdns.conf \
  ghcr.io/gdxz-linus/smartdns-edge:latest
```

### Token (must read)

The token is resolved in this order:

1. `api-token <token>` in the configuration file;
2. the `SMARTDNS_API_TOKEN` environment variable;
3. otherwise a random token is generated and printed to the console/log at startup,
   as a ready-to-paste `api-token <token>` line.

There is **no hard-coded default password**. If the console is bound to a non-local address without a
configured token, the daemon **refuses to start** (**exit code 2**, so service managers and scripts can
tell it apart from other failures) — that would expose the console to the whole network.

### How to use it safely

| Scenario | Recommendation |
|---|---|
| Local administration only | `bind-http 127.0.0.1:8000`, open `http://127.0.0.1:8000` |
| Remote administration (recommended) | do **not** expose the port; use an SSH tunnel: `ssh -L 8000:127.0.0.1:8000 your-server`, then open `http://localhost:8000` |
| Long-term remote access | use `bind-https 0.0.0.0:8000 -ssl-certificate ... -ssl-certificate-key ...` with a token you set yourself, and restrict the source network |

⚠️ `bind-http` is plain HTTP: the token and content travel unencrypted. Unless you use an SSH tunnel,
always use `bind-https`.
