# Splunk Automated Installer v1.0

A single Go binary that fully automates Splunk Enterprise and Universal Forwarder deployment on Linux.

---

## What This Script Does

The installer runs an **8-step automated pipeline**. Each step is logged with status indicators.

### Step 1 — Preflight Checks
- Verifies running as **root**
- Validates **Linux** OS (rejects macOS, Windows, etc.)
- Detects architecture: **x86_64** or **ARM64** (aarch64)
- On ARM64: checks kernel page size (warns on non-4K), identifies platform (Graviton, Ampere, Cortex-A, Apple Silicon VM), detects QEMU emulation
- Checks **disk space** (minimum 5 GB)
- Checks **RAM** (minimum 4 GB on x86, 2 GB on ARM64)
- Detects **existing Splunk installation** (blocks reinstall unless `--uninstall` first)
- Verifies required tools are present: `tar`, `useradd`, `groupadd`

### Step 2 — Splunk User/Group Creation (Hardened)
- Creates system group `splunk`
- Creates system user `splunk` with:
  - `/usr/sbin/nologin` shell (no interactive login)
  - Locked password (cannot `su` into the account)
- Removes `splunk` from `sudo`, `wheel`, and `admin` groups
- Drops `/etc/sudoers.d/99-splunk-deny` to **explicitly block sudo** — prevents accidental privilege escalation even if someone adds the user to a sudo group later

### Step 3 — Package Acquisition
- Uses a local `.tgz`, `.deb`, or `.rpm` via `--package-path` (recommended)
- Or downloads from a URL via `--download-url`
- Or auto-builds a download URL based on version + detected arch + distro
- Shows download progress with percentage and MB counters
- Computes **SHA-256 hash** of the downloaded file for verification
- Handles architecture-specific package naming (`.deb` uses `arm64`, `.tgz`/`.rpm` use `aarch64`)

### Step 4 — Installation
- **Tarball** (`.tgz`): extracts to `/opt/splunk`
- **Debian** (`.deb`): runs `dpkg -i`, auto-fixes broken dependencies with `apt-get install -f`
- **RPM** (`.rpm`): runs `rpm -ivh`
- Auto-detects format from file extension

### Step 5 — File Ownership
- Recursive `chown splunk:splunk /opt/splunk`
- Ensures the locked-down splunk user owns all files

### Step 6 — Configuration & First Start
- Writes `user-seed.conf` with admin credentials (file permissions 0600)
- Starts Splunk as the `splunk` user (never as root)
- Passes `--accept-license`, `--no-prompt`, `--answer-yes`

### Step 7 — System Integration
- **Boot start**: registers Splunk with systemd (`splunk enable boot-start -systemd-managed 1`)
- **Firewall**: auto-detects and configures the firewall tool present on the system:
  - `firewall-cmd` (firewalld) — RHEL, CentOS, Fedora, Rocky
  - `ufw` — Ubuntu, Debian, Kali
  - `iptables` — fallback
- Opens ports **8000** (Web UI), **8089** (management API), **9997** (indexer receiving)

### Step 8 — Security Hardening
- Restricts `/opt/splunk/etc` and `/opt/splunk/var` to mode `700`
- Disables **Transparent Huge Pages** (THP) — Splunk performance recommendation
- Configures **ulimits** via `/etc/security/limits.d/99-splunk.conf`:
  - `nofile` 65535 (open files)
  - `nproc` 20480 (processes)

### Uninstall
- Stops Splunk
- Disables boot-start and removes systemd unit
- Deletes the installation directory
- Cleans up the ulimits config file

---

## Additional Features

- **Dry run mode** (`--dry-run`): shows every step without touching the system
- **Verbose mode** (`--verbose`): debug-level logging
- **Interactive password prompt**: if `--admin-password` is omitted, prompts with confirmation
- **Distro auto-detection**: reads `/etc/os-release` to pick `.deb` vs `.rpm` vs `.tgz`
- **Splunk Enterprise + Universal Forwarder**: switch with `--edition`

---

## How to Install & Run

### 1. Prerequisites

- A Linux machine (x86_64 or ARM64)
- Root / sudo access
- Go 1.21 or newer

Install Go if you don't have it:
```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install -y golang

# RHEL / CentOS / Fedora
sudo dnf install -y golang

# Verify
go version
```

### 2. Get the Source Files

Place these two files in a folder:
```
~/splunk-installer/
├── main.go
└── go.mod
```

**Important**: make sure the filenames are exactly `main.go` and `go.mod` — no spaces or `(1)` in the names.

### 3. Build

```bash
cd ~/splunk-installer
go build -buildvcs=false -o splunk-installer .
```

Verify the binary:
```bash
file splunk-installer
# Should show: ELF 64-bit LSB executable, x86-64 (or ARM aarch64)
```

To cross-compile for ARM64 from an x86 machine:
```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -buildvcs=false -o splunk-installer-arm64 .
```

### 4. Download a Splunk Package

Go to https://www.splunk.com/en_us/download/splunk-enterprise.html, sign in, and download the `.tgz` for your architecture. Save it to `/tmp/`.

### 5. Run

```bash
sudo ./splunk-installer \
  --package-path /tmp/splunk-10.0.0-e8eb0c4654f8-Linux-x86_64.tgz \
  --accept-license \
  --admin-password 'YourP@ssword123'
```

### 6. Access Splunk

Open your browser to:
```
http://localhost:8000
```
Login: `admin` / the password you set.

---

## All CLI Flags

```
--version            Splunk version (default: 9.4.1)
--edition            enterprise or forwarder (default: enterprise)
--install-dir        Installation path (default: /opt/splunk)
--admin-user         Admin username (default: admin)
--admin-password     Admin password, min 8 chars (prompted if omitted)
--accept-license     Required — accept the Splunk license
--enable-boot        Enable systemd auto-start (default: true)
--configure-firewall Open firewall ports automatically (default: true)
--package-path       Path to a local .tgz / .deb / .rpm
--download-url       Direct download URL (overrides auto-detection)
--dry-run            Preview all steps without making changes
--verbose            Debug-level logging
--uninstall          Remove Splunk from --install-dir
```

---

## Usage Examples

```bash
# Install from local package
sudo ./splunk-installer \
  --package-path /tmp/splunk-10.0.0-Linux-x86_64.tgz \
  --accept-license \
  --admin-password 'S3cureP@ss!'

# Install from URL
sudo ./splunk-installer \
  --download-url 'https://download.splunk.com/...' \
  --accept-license \
  --admin-password 'S3cureP@ss!'

# Universal Forwarder
sudo ./splunk-installer \
  --edition forwarder \
  --package-path /tmp/splunkforwarder-10.0.0-Linux-x86_64.tgz \
  --accept-license

# Dry run
sudo ./splunk-installer --dry-run --accept-license --admin-password 'test12345'

# Uninstall
sudo ./splunk-installer --uninstall

# Help
./splunk-installer --help
```

---

## Ports Opened

| Port | Purpose                     |
|------|-----------------------------|
| 8000 | Splunk Web UI               |
| 8089 | Management / REST API       |
| 9997 | Indexer receiving (forwards) |

---

## Post-Install Commands

```bash
sudo -u splunk /opt/splunk/bin/splunk status
sudo -u splunk /opt/splunk/bin/splunk restart
sudo -u splunk /opt/splunk/bin/splunk stop
sudo -u splunk /opt/splunk/bin/splunk version
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `go: command not found` | Install Go — see step 1 above |
| `error obtaining VCS status` | Add `-buildvcs=false` to the build command |
| `cannot find main module` | Rename files — remove any `(1)` from filenames |
| `must be run as root` | Run with `sudo` |
| `password must be at least 8 characters` | Use a password with 8+ characters |
| `splunk already installed` | Run `--uninstall` first |
| `download returned HTTP 403` | Download manually from splunk.com, use `--package-path` |
| `Syntax error: "(" unexpected` | Wrong architecture binary or corrupt download — rebuild with `go build` |
| Splunk won't start on ARM64 | Make sure the `.tgz` matches your arch (`aarch64` not `amd64`) |

---

## Security Summary

| Measure | Detail |
|---|---|
| Splunk user shell | `/usr/sbin/nologin` |
| Splunk user password | Locked (`passwd -l`) |
| Sudo access | Explicitly denied via `/etc/sudoers.d/99-splunk-deny` |
| Sudo/wheel/admin groups | Removed on every run |
| `/opt/splunk/etc` | Mode 700 |
| `/opt/splunk/var` | Mode 700 |
| `user-seed.conf` | Mode 600 |
| Open file limit | 65535 |
| Process limit | 20480 |
| Transparent Huge Pages | Disabled |
