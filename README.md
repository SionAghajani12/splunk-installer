# Splunk Automated Installer (Go)

A single-binary CLI tool that automates Splunk Enterprise and Universal Forwarder installation on Linux. Supports **x86_64** and **ARM64**.

## Build

```bash
cd splunk-installer

# Build for your current machine
go build -buildvcs=false -o splunk-installer .

# Cross-compile for ARM64 (from x86)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -buildvcs=false -o splunk-installer-arm64 .

# Cross-compile for x86_64 (from ARM)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -o splunk-installer-amd64 .
```

## Usage

```bash
# Install from a pre-downloaded package
sudo ./splunk-installer \
  --package-path /tmp/splunk-10.0.0-Linux-x86_64.tgz \
  --accept-license \
  --admin-password 'YourSecureP@ss'

# Install with a download URL
sudo ./splunk-installer \
  --download-url 'https://download.splunk.com/...' \
  --accept-license \
  --admin-password 'YourSecureP@ss'

# Universal Forwarder
sudo ./splunk-installer \
  --edition forwarder \
  --package-path /tmp/splunkforwarder-10.0.0-Linux-x86_64.tgz \
  --accept-license

# Dry run (preview without changes)
sudo ./splunk-installer --dry-run --accept-license --admin-password 'test12345'

# Uninstall
sudo ./splunk-installer --uninstall
```

## Options

| Flag | Default | Description |
|---|---|---|
| `--version` | `9.4.1` | Splunk version |
| `--edition` | `enterprise` | `enterprise` or `forwarder` |
| `--install-dir` | `/opt/splunk` | Installation directory |
| `--admin-user` | `admin` | Admin username |
| `--admin-password` | *(prompted)* | Admin password (min 8 chars) |
| `--accept-license` | `false` | Accept the Splunk license |
| `--enable-boot` | `true` | Enable systemd boot-start |
| `--configure-firewall` | `true` | Auto-configure firewall rules |
| `--package-path` | | Path to local .tgz/.deb/.rpm |
| `--download-url` | | Explicit download URL |
| `--dry-run` | `false` | Preview without changes |
| `--verbose` | `false` | Debug-level logging |
| `--uninstall` | `false` | Remove Splunk |

## What it does

1. **Preflight** — root, OS/arch, disk/RAM, ARM64 platform detection
2. **User setup** — creates `splunk` system user/group
3. **Package** — downloads or uses local Splunk package
4. **Install** — extracts .tgz or runs dpkg/rpm
5. **Ownership** — `chown -R splunk:splunk /opt/splunk`
6. **Configure & start** — admin credentials + first start
7. **System integration** — systemd boot-start + firewall (8000, 8089, 9997)
8. **Hardening** — ulimits, THP disabled, restricted permissions

## Requirements

- Linux (amd64 or arm64)
- Root / sudo
- Go 1.21+ to build
