# Downloads

SmartDNS Edge provides high-performance, native executables across all major platforms. For standard Windows, Linux, and macOS systems, we highly recommend downloading the latest releases directly from this project.

For soft-router systems like OpenWrt that require graphical web interfaces (such as LuCI), you may refer to the router-specific packages provided by the original C-version ecosystem.

## 1. Official SmartDNS Edge Releases (Recommended)

SmartDNS Edge provides zero-dependency, pre-compiled release packages optimized for all platforms.

| Supported OS (Arch) | Pre-compiled Package | Download Link | Description |
| :--- | :--- | :--- | :--- |
| **Windows** (x86_64) | `smartdns-x86_64-pc-windows-msvc.zip` | <span class="dl-link" data-file="windows-x64">Download</span> | 64-bit Windows Desktops & Servers |
| **Windows** (ARM64) | `smartdns-aarch64-pc-windows-msvc.zip` | <span class="dl-link" data-file="windows-arm64">Download</span> | Snapdragon ARM-based Windows Laptops |
| **macOS** (Intel) | `smartdns-x86_64-apple-darwin.zip` | <span class="dl-link" data-file="mac-intel">Download</span> | Intel-based Mac models |
| **macOS** (Apple Silicon) | `smartdns-aarch64-apple-darwin.zip` | <span class="dl-link" data-file="mac-arm64">Download</span> | Apple M1/M2/M3/M4 Macs |
| **Linux** (x86_64) | `smartdns-x86_64-generic-linux-gnu.tar.gz` | <span class="dl-link" data-file="linux-x64">Download</span> | Standard 64-bit Linux, VPS, WSL |
| **Linux** (ARM64) | `smartdns-aarch64-generic-linux-gnu.tar.gz` | <span class="dl-link" data-file="linux-arm64">Download</span> | ARM64 Linux, Raspberry Pi, Edge devices |

**Docker Container Image:**
Native multi-architecture image (amd64 / arm64), which can be pulled directly via CLI:

```shell
docker pull ghcr.io/gdxz-linus/smartdns-edge:latest
```

##  2. Soft-Router & Embedded Ecosystem (Complementary)
Since SmartDNS Edge currently focuses on providing the cross-platform core gateway daemon, if you require the native luci-app web GUI on router firmwares like OpenWrt or DD-WRT, you can continue to use the original C-version package manager provided by pymumu for installation:

| System / Environment | Installation Method & Details |
| :--- | :--- |
| **OpenWrt** | For 24.10+ use the `apk` command:<br/>`apk add luci-app-smartdns`<br/>For 22.03 and older use `opkg`:<br/>`opkg update && opkg install luci-app-smartdns` |
| **DD-WRT** | In the latest official firmware: Services Page -> SmartDNS Resolver -> Enable. |
| **Entware** | `ipkg update`<br/>`ipkg install smartdns` |
| **LuCI App** | `luci-app-smartdns` or `luci-app-smartdns-lite`<br/>*Note: The LuCI interface can be used to control the backend SmartDNS process.* |


- For the installation procedure, please refer to the following sections.
