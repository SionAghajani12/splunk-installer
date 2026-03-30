package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ─── Configuration ──────────────────────────────────────────────────────────

// BuildVersion is set at compile time via -ldflags
var BuildVersion = "dev"

const (
	DefaultSplunkVersion = "9.4.1"
	DefaultInstallDir    = "/opt/splunk"
	SplunkUser           = "splunk"
	SplunkGroup          = "splunk"
	MinDiskSpaceMB       = 5120  // 5 GB
	MinRAMMB             = 4096  // 4 GB
	MinRAMMB_ARM64       = 2048  // 2 GB — ARM servers often have less
	SplunkWebPort        = 8000
	SplunkMgmtPort       = 8089
	SplunkIdxPort        = 9997
)

// SplunkEdition represents different Splunk packages
type SplunkEdition string

const (
	Enterprise        SplunkEdition = "enterprise"
	UniversalForwarder SplunkEdition = "forwarder"
)

// Config holds all installation parameters
type Config struct {
	Version       string
	Edition       SplunkEdition
	InstallDir    string
	AdminUser     string
	AdminPassword string
	AcceptLicense bool
	EnableBoot    bool
	ConfigureFirewall bool
	PackagePath   string // local .tgz or .deb/.rpm path
	DownloadURL   string // explicit URL override
	DryRun        bool
	Verbose       bool
	Uninstall     bool
}

// Logger provides leveled logging
type Logger struct {
	Verbose bool
}

func (l *Logger) Info(format string, args ...interface{}) {
	fmt.Printf("[INFO]  %s  %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func (l *Logger) Warn(format string, args ...interface{}) {
	fmt.Printf("[WARN]  %s  %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func (l *Logger) Error(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] %s  %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.Verbose {
		fmt.Printf("[DEBUG] %s  %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Step(step int, total int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("\n══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  Step %d/%d: %s\n", step, total, msg)
	fmt.Printf("══════════════════════════════════════════════════════════════\n\n")
}

var log = &Logger{}

// ─── System Checks ──────────────────────────────────────────────────────────

func checkRoot() error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("cannot determine current user: %w", err)
	}
	if u.Uid != "0" {
		return fmt.Errorf("this installer must be run as root (current uid=%s)", u.Uid)
	}
	return nil
}

func checkOS() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("this installer supports Linux only (detected: %s)", runtime.GOOS)
	}
	log.Info("Operating system: %s/%s", runtime.GOOS, runtime.GOARCH)
	return nil
}

func checkArch() (string, error) {
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	default:
		return "", fmt.Errorf("unsupported architecture: %s (need amd64 or arm64)", arch)
	}
}

// getARM64PlatformInfo detects ARM-specific details relevant to Splunk.
// Splunk on ARM requires specific kernel page sizes and has some feature
// differences compared to x86_64.
func getARM64PlatformInfo() {
	if runtime.GOARCH != "arm64" {
		return
	}

	log.Info("ARM64 platform detected — running additional checks...")

	// Kernel page size (Splunk works best with 4K pages; some ARM distros use 64K)
	out, err := exec.Command("getconf", "PAGESIZE").Output()
	if err == nil {
		pageSize := strings.TrimSpace(string(out))
		log.Info("  Kernel page size: %s bytes", pageSize)
		if pageSize != "4096" {
			log.Warn("  Non-4K page size detected (%s). Some Splunk features may behave differently.", pageSize)
			log.Warn("  If you encounter issues, consider a kernel with 4K pages (CONFIG_ARM64_4K_PAGES).")
		}
	}

	// Detect if running on common ARM platforms (AWS Graviton, Ampere, Apple Silicon VM, etc.)
	cpuInfo, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		content := strings.ToLower(string(cpuInfo))
		switch {
		case strings.Contains(content, "neoverse"):
			log.Info("  Platform: AWS Graviton / Ampere Altra (Neoverse cores)")
		case strings.Contains(content, "cortex-a"):
			log.Info("  Platform: ARM Cortex-A series")
		case strings.Contains(content, "apple"):
			log.Info("  Platform: Apple Silicon (VM)")
		default:
			log.Info("  Platform: Generic ARM64")
		}
	}

	// Check if running under QEMU emulation (common mistake — very slow)
	if _, err := os.Stat("/proc/sys/fs/binfmt_misc/qemu-aarch64"); err == nil {
		log.Warn("  QEMU user-mode emulation detected! This will be extremely slow.")
		log.Warn("  For production, run on native ARM64 hardware.")
	}
}

func getDistroInfo() (name string, packageMgr string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown", "tar"
	}
	content := string(data)
	id := ""
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			break
		}
	}
	switch id {
	case "ubuntu", "debian":
		return id, "deb"
	case "centos", "rhel", "rocky", "almalinux", "fedora", "amzn", "ol":
		return id, "rpm"
	default:
		return id, "tar"
	}
}

func getDiskSpaceMB(path string) (uint64, error) {
	// Use df as a portable approach
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		dir = "/"
	}
	out, err := exec.Command("df", "-BM", "--output=avail", dir).Output()
	if err != nil {
		return 0, fmt.Errorf("cannot check disk space: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected df output")
	}
	val := strings.TrimSuffix(strings.TrimSpace(lines[1]), "M")
	var mb uint64
	fmt.Sscanf(val, "%d", &mb)
	return mb, nil
}

func getTotalRAMMB() (uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			var kb uint64
			fmt.Sscanf(line, "MemTotal: %d kB", &kb)
			return kb / 1024, nil
		}
	}
	return 0, fmt.Errorf("could not parse /proc/meminfo")
}

func runPreflightChecks(cfg *Config) error {
	log.Info("Running preflight checks...")

	// 1. Root check
	if err := checkRoot(); err != nil {
		return err
	}
	log.Info("✓ Running as root")

	// 2. OS check
	if err := checkOS(); err != nil {
		return err
	}
	log.Info("✓ Operating system supported")

	// 3. Architecture
	arch, err := checkArch()
	if err != nil {
		return err
	}
	log.Info("✓ Architecture: %s", arch)

	// 3b. ARM64-specific platform checks
	getARM64PlatformInfo()

	// 4. Disk space
	diskMB, err := getDiskSpaceMB(cfg.InstallDir)
	if err != nil {
		log.Warn("Could not check disk space: %v", err)
	} else if diskMB < MinDiskSpaceMB {
		return fmt.Errorf("insufficient disk space: %d MB available, need %d MB", diskMB, MinDiskSpaceMB)
	} else {
		log.Info("✓ Disk space: %d MB available", diskMB)
	}

	// 5. RAM (lower threshold for ARM64 since those servers often have less)
	minRAM := uint64(MinRAMMB)
	if runtime.GOARCH == "arm64" {
		minRAM = MinRAMMB_ARM64
	}
	ramMB, err := getTotalRAMMB()
	if err != nil {
		log.Warn("Could not check RAM: %v", err)
	} else if ramMB < minRAM {
		log.Warn("Low RAM: %d MB (recommended: %d MB). Splunk may underperform.", ramMB, minRAM)
	} else {
		log.Info("✓ RAM: %d MB available", ramMB)
	}

	// 6. Check for existing installation
	if _, err := os.Stat(filepath.Join(cfg.InstallDir, "bin", "splunk")); err == nil {
		log.Warn("Existing Splunk installation detected at %s", cfg.InstallDir)
		if !cfg.Uninstall {
			return fmt.Errorf("splunk already installed at %s — use --uninstall first or choose a different --install-dir", cfg.InstallDir)
		}
	}

	// 7. Required tools
	for _, tool := range []string{"tar", "useradd", "groupadd"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("required tool not found: %s", tool)
		}
	}
	log.Info("✓ Required tools present")

	log.Info("All preflight checks passed!")
	return nil
}

// ─── Download / Package Handling ────────────────────────────────────────────

func buildDownloadURL(cfg *Config) string {
	if cfg.DownloadURL != "" {
		return cfg.DownloadURL
	}

	arch, _ := checkArch()
	_, pkgMgr := getDistroInfo()

	var product string
	if cfg.Edition == UniversalForwarder {
		product = "universalforwarder"
	} else {
		product = "splunk"
	}

	// Splunk uses different naming conventions per arch + package format:
	//   tgz:  splunk-9.4.1-Linux-x86_64.tgz       / splunk-9.4.1-Linux-aarch64.tgz
	//   deb:  splunk-9.4.1-linux-amd64.deb          / splunk-9.4.1-linux-arm64.deb  (NOTE: "arm64" not "aarch64")
	//   rpm:  splunk-9.4.1-linux-x86_64.rpm         / splunk-9.4.1-linux-aarch64.rpm
	var ext string
	switch pkgMgr {
	case "deb":
		// Debian packages use "arm64" naming, not "aarch64"
		debArch := arch
		if debArch == "aarch64" {
			debArch = "arm64"
		} else if debArch == "x86_64" {
			debArch = "amd64"
		}
		ext = fmt.Sprintf("linux-%s.deb", debArch)
	case "rpm":
		ext = fmt.Sprintf("linux-%s.rpm", arch)
	default:
		ext = fmt.Sprintf("Linux-%s.tgz", arch)
	}

	url := fmt.Sprintf("https://download.splunk.com/products/%s/releases/%s/linux/%s-%s-%s",
		product, cfg.Version, product, cfg.Version, ext)

	if runtime.GOARCH == "arm64" {
		log.Info("ARM64 download URL constructed — note that not all Splunk versions have ARM64 packages.")
		log.Info("If download fails, verify ARM64 availability for version %s at https://www.splunk.com/en_us/download.html", cfg.Version)
	}

	return url
}

func downloadFile(url, destPath string) error {
	log.Info("Downloading from: %s", url)
	log.Info("Saving to: %s", destPath)

	client := &http.Client{
		Timeout: 30 * time.Minute,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d — you may need to download manually from splunk.com and use --package-path", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("cannot create file: %w", err)
	}
	defer out.Close()

	// Progress tracking
	contentLength := resp.ContentLength
	reader := &progressReader{
		reader: resp.Body,
		total:  contentLength,
	}

	hasher := sha256.New()
	writer := io.MultiWriter(out, hasher)

	written, err := io.Copy(writer, reader)
	if err != nil {
		os.Remove(destPath)
		return fmt.Errorf("download incomplete: %w", err)
	}

	fmt.Println() // newline after progress
	log.Info("Downloaded %d bytes", written)
	log.Info("SHA-256: %s", hex.EncodeToString(hasher.Sum(nil)))
	return nil
}

type progressReader struct {
	reader  io.Reader
	total   int64
	current int64
	lastPct int
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.current += int64(n)
	if pr.total > 0 {
		pct := int(pr.current * 100 / pr.total)
		if pct != pr.lastPct && pct%5 == 0 {
			fmt.Printf("\r  Progress: %d%% (%d / %d MB)", pct, pr.current/1024/1024, pr.total/1024/1024)
			pr.lastPct = pct
		}
	}
	return n, err
}

// ─── Installation ───────────────────────────────────────────────────────────

func createSplunkUser() error {
	// Check if group exists
	if err := exec.Command("getent", "group", SplunkGroup).Run(); err != nil {
		log.Info("Creating group: %s", SplunkGroup)
		if err := exec.Command("groupadd", "-r", SplunkGroup).Run(); err != nil {
			return fmt.Errorf("failed to create group %s: %w", SplunkGroup, err)
		}
	}

	// Check if user exists
	if err := exec.Command("getent", "passwd", SplunkUser).Run(); err != nil {
		log.Info("Creating user: %s", SplunkUser)
		if err := exec.Command("useradd",
			"-r",                       // system account
			"-g", SplunkGroup,          // primary group
			"-d", DefaultInstallDir,    // home dir
			"-s", "/usr/sbin/nologin",  // no interactive login
			"-M",                       // no home directory
			SplunkUser,
		).Run(); err != nil {
			return fmt.Errorf("failed to create user %s: %w", SplunkUser, err)
		}

		// Lock the password so no one can su into this account
		exec.Command("passwd", "-l", SplunkUser).Run()
		log.Info("✓ Splunk user created with nologin shell and locked password")
	}

	// Ensure splunk user is NOT in sudo/wheel groups
	for _, sudoGroup := range []string{"sudo", "wheel", "admin"} {
		exec.Command("gpasswd", "-d", SplunkUser, sudoGroup).Run()
	}

	// Drop an explicit sudoers deny file so no one grants it later by accident
	sudoersDeny := fmt.Sprintf("# Splunk service account — no sudo access ever\n%s ALL=(ALL) !ALL\n", SplunkUser)
	sudoersFile := fmt.Sprintf("/etc/sudoers.d/99-splunk-deny")
	if _, err := os.Stat(sudoersFile); os.IsNotExist(err) {
		if err := os.WriteFile(sudoersFile, []byte(sudoersDeny), 0440); err != nil {
			log.Warn("Could not write sudoers deny file: %v", err)
		} else {
			log.Info("✓ Sudo access explicitly denied for %s", SplunkUser)
		}
	}

	log.Info("✓ Splunk user/group ready (no login, no sudo)")
	return nil
}

func installFromTarball(packagePath, installDir string) error {
	parentDir := filepath.Dir(installDir)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("cannot create parent directory: %w", err)
	}

	log.Info("Extracting tarball to %s ...", parentDir)
	cmd := exec.Command("tar", "-xzf", packagePath, "-C", parentDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	log.Info("✓ Extraction complete")
	return nil
}

func installFromDeb(packagePath string) error {
	log.Info("Installing .deb package...")
	cmd := exec.Command("dpkg", "-i", packagePath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Try fixing dependencies
		log.Warn("dpkg reported issues, attempting to fix dependencies...")
		fix := exec.Command("apt-get", "install", "-f", "-y")
		fix.Stdout = os.Stdout
		fix.Stderr = os.Stderr
		if fixErr := fix.Run(); fixErr != nil {
			return fmt.Errorf("installation failed: %w (fix attempt: %v)", err, fixErr)
		}
	}
	log.Info("✓ .deb package installed")
	return nil
}

func installFromRPM(packagePath string) error {
	log.Info("Installing .rpm package...")
	cmd := exec.Command("rpm", "-ivh", "--replacepkgs", packagePath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rpm installation failed: %w", err)
	}
	log.Info("✓ .rpm package installed")
	return nil
}

func installPackage(packagePath, installDir string) error {
	ext := strings.ToLower(packagePath)
	switch {
	case strings.HasSuffix(ext, ".tgz") || strings.HasSuffix(ext, ".tar.gz"):
		return installFromTarball(packagePath, installDir)
	case strings.HasSuffix(ext, ".deb"):
		return installFromDeb(packagePath)
	case strings.HasSuffix(ext, ".rpm"):
		return installFromRPM(packagePath)
	default:
		return fmt.Errorf("unsupported package format: %s (need .tgz, .deb, or .rpm)", packagePath)
	}
}

func setOwnership(installDir string) error {
	log.Info("Setting ownership to %s:%s on %s ...", SplunkUser, SplunkGroup, installDir)
	cmd := exec.Command("chown", "-R", fmt.Sprintf("%s:%s", SplunkUser, SplunkGroup), installDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ─── Post-Install Configuration ─────────────────────────────────────────────

func createAdminCredentials(installDir, adminUser, adminPassword string) error {
	seedFile := filepath.Join(installDir, "etc", "system", "local", "user-seed.conf")
	content := fmt.Sprintf("[user_info]\nUSERNAME = %s\nPASSWORD = %s\n", adminUser, adminPassword)

	if err := os.MkdirAll(filepath.Dir(seedFile), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(seedFile, []byte(content), 0600); err != nil {
		return err
	}
	// Set ownership
	exec.Command("chown", fmt.Sprintf("%s:%s", SplunkUser, SplunkGroup), seedFile).Run()
	log.Info("✓ Admin credentials configured")
	return nil
}

func startSplunk(installDir string, acceptLicense bool) error {
	splunkBin := filepath.Join(installDir, "bin", "splunk")

	args := []string{"start", "--no-prompt"}
	if acceptLicense {
		args = append(args, "--accept-license")
	}
	args = append(args, "--answer-yes")

	log.Info("Starting Splunk: %s %s", splunkBin, strings.Join(args, " "))

	// Use su -s /bin/sh instead of sudo -u because the splunk user has
	// nologin shell and sudo is explicitly denied. Since the installer
	// already runs as root, su works without a password.
	shellCmd := fmt.Sprintf("SPLUNK_HOME=%s %s %s", installDir, splunkBin, strings.Join(args, " "))
	cmd := exec.Command("su", "-s", "/bin/sh", SplunkUser, "-c", shellCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func enableBootStart(installDir string) error {
	splunkBin := filepath.Join(installDir, "bin", "splunk")
	log.Info("Enabling boot-start with systemd...")

	cmd := exec.Command(splunkBin, "enable", "boot-start",
		"-user", SplunkUser,
		"-systemd-managed", "1",
		"--accept-license",
		"--answer-yes",
		"--no-prompt",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("enable boot-start failed: %w", err)
	}

	log.Info("✓ Boot-start enabled (systemd)")
	return nil
}

func configureFirewall() error {
	ports := []int{SplunkWebPort, SplunkMgmtPort, SplunkIdxPort}

	// Try firewalld first
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		log.Info("Configuring firewalld...")
		for _, port := range ports {
			exec.Command("firewall-cmd", "--permanent", "--add-port", fmt.Sprintf("%d/tcp", port)).Run()
		}
		exec.Command("firewall-cmd", "--reload").Run()
		log.Info("✓ Firewalld rules added for ports %v", ports)
		return nil
	}

	// Try ufw
	if _, err := exec.LookPath("ufw"); err == nil {
		log.Info("Configuring ufw...")
		for _, port := range ports {
			exec.Command("ufw", "allow", fmt.Sprintf("%d/tcp", port)).Run()
		}
		log.Info("✓ UFW rules added for ports %v", ports)
		return nil
	}

	// Fall back to iptables
	if _, err := exec.LookPath("iptables"); err == nil {
		log.Info("Configuring iptables...")
		for _, port := range ports {
			exec.Command("iptables", "-A", "INPUT", "-p", "tcp", "--dport",
				fmt.Sprintf("%d", port), "-j", "ACCEPT").Run()
		}
		log.Info("✓ iptables rules added for ports %v", ports)
		return nil
	}

	log.Warn("No firewall tool found — please manually open ports %v", ports)
	return nil
}

func applySecurityHardening(installDir string) error {
	log.Info("Applying basic security hardening...")

	// Restrict file permissions
	exec.Command("chmod", "700", filepath.Join(installDir, "etc")).Run()
	exec.Command("chmod", "700", filepath.Join(installDir, "var")).Run()

	// Disable transparent huge pages (performance recommendation)
	thpPaths := []string{
		"/sys/kernel/mm/transparent_hugepage/enabled",
		"/sys/kernel/mm/transparent_hugepage/defrag",
	}
	for _, p := range thpPaths {
		if _, err := os.Stat(p); err == nil {
			os.WriteFile(p, []byte("never"), 0644)
		}
	}

	// Set ulimits via limits.d
	limitsContent := fmt.Sprintf(`# Splunk recommended ulimits
%s soft nofile 65535
%s hard nofile 65535
%s soft nproc  20480
%s hard nproc  20480
`, SplunkUser, SplunkUser, SplunkUser, SplunkUser)

	limitsFile := "/etc/security/limits.d/99-splunk.conf"
	if err := os.WriteFile(limitsFile, []byte(limitsContent), 0644); err != nil {
		log.Warn("Could not write ulimits file: %v", err)
	} else {
		log.Info("✓ ulimits configured in %s", limitsFile)
	}

	log.Info("✓ Security hardening applied")
	return nil
}

// ─── Uninstall ──────────────────────────────────────────────────────────────

func uninstallSplunk(installDir string) error {
	splunkBin := filepath.Join(installDir, "bin", "splunk")

	// Stop Splunk — try systemd first, fall back to su
	log.Info("Stopping Splunk...")
	if err := exec.Command("systemctl", "stop", "Splunkd.service").Run(); err != nil {
		// systemd didn't work, try direct stop via su
		shellCmd := fmt.Sprintf("%s stop", splunkBin)
		exec.Command("su", "-s", "/bin/sh", SplunkUser, "-c", shellCmd).Run()
	}

	// Disable boot-start
	exec.Command(splunkBin, "disable", "boot-start").Run()

	// Remove systemd unit
	exec.Command("systemctl", "disable", "Splunkd.service").Run()
	os.Remove("/etc/systemd/system/Splunkd.service")
	exec.Command("systemctl", "daemon-reload").Run()

	// Remove install directory
	log.Info("Removing %s ...", installDir)
	if err := os.RemoveAll(installDir); err != nil {
		return fmt.Errorf("removal failed: %w", err)
	}

	// Remove config files created by the installer
	os.Remove("/etc/security/limits.d/99-splunk.conf")
	os.Remove("/etc/sudoers.d/99-splunk-deny")

	log.Info("✓ Splunk uninstalled from %s", installDir)
	return nil
}

// ─── Interactive Password Prompt ────────────────────────────────────────────

func promptPassword() string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter Splunk admin password (min 8 chars): ")
		pass, _ := reader.ReadString('\n')
		pass = strings.TrimSpace(pass)
		if len(pass) >= 8 {
			fmt.Print("Confirm password: ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.TrimSpace(confirm)
			if pass == confirm {
				return pass
			}
			fmt.Println("Passwords do not match. Try again.")
		} else {
			fmt.Println("Password must be at least 8 characters.")
		}
	}
}

// ─── Main ───────────────────────────────────────────────────────────────────

func printBanner() {
	fmt.Printf(`
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ███████╗██████╗ ██╗     ██╗   ██╗███╗   ██╗██╗  ██╗           ║
║   ██╔════╝██╔══██╗██║     ██║   ██║████╗  ██║██║ ██╔╝           ║
║   ███████╗██████╔╝██║     ██║   ██║██╔██╗ ██║█████╔╝            ║
║   ╚════██║██╔═══╝ ██║     ██║   ██║██║╚██╗██║██╔═██╗            ║
║   ███████║██║     ███████╗╚██████╔╝██║ ╚████║██║  ╚██╗          ║
║   ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝        ║
║                                                                  ║
║   Automated Installer v%-40s ║
║   Platform: %-51s ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`, BuildVersion, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))
}

func printSummary(cfg *Config) {
	fmt.Printf(`
┌─────────────────────── Installation Summary ───────────────────────┐
│  Edition:       %-50s│
│  Version:       %-50s│
│  Install Dir:   %-50s│
│  Admin User:    %-50s│
│  Boot Start:    %-50s│
│  Firewall:      %-50s│
│  Dry Run:       %-50s│
└────────────────────────────────────────────────────────────────────┘
`,
		string(cfg.Edition),
		cfg.Version,
		cfg.InstallDir,
		cfg.AdminUser,
		fmt.Sprintf("%v", cfg.EnableBoot),
		fmt.Sprintf("%v", cfg.ConfigureFirewall),
		fmt.Sprintf("%v", cfg.DryRun),
	)
}

func main() {
	cfg := &Config{}

	flag.StringVar(&cfg.Version, "version", DefaultSplunkVersion, "Splunk version to install")
	edition := flag.String("edition", "enterprise", "Splunk edition: enterprise or forwarder")
	flag.StringVar(&cfg.InstallDir, "install-dir", DefaultInstallDir, "Installation directory")
	flag.StringVar(&cfg.AdminUser, "admin-user", "admin", "Splunk admin username")
	flag.StringVar(&cfg.AdminPassword, "admin-password", "", "Splunk admin password (prompted if empty)")
	flag.BoolVar(&cfg.AcceptLicense, "accept-license", false, "Accept Splunk license agreement")
	flag.BoolVar(&cfg.EnableBoot, "enable-boot", true, "Enable Splunk on system boot")
	flag.BoolVar(&cfg.ConfigureFirewall, "configure-firewall", true, "Configure firewall rules")
	flag.StringVar(&cfg.PackagePath, "package-path", "", "Path to local Splunk package (.tgz/.deb/.rpm)")
	flag.StringVar(&cfg.DownloadURL, "download-url", "", "Custom download URL (overrides auto-detection)")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "Show what would be done without making changes")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose/debug logging")
	flag.BoolVar(&cfg.Uninstall, "uninstall", false, "Uninstall Splunk from install-dir")

	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "\nUsage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  # Install from a pre-downloaded tarball
  sudo ./splunk-installer --package-path /tmp/splunk-9.4.1-Linux-x86_64.tgz --accept-license --admin-password 'MyP@ss123'

  # Install with a custom download URL
  sudo ./splunk-installer --download-url 'https://...' --accept-license --admin-password 'MyP@ss123'

  # Install Universal Forwarder
  sudo ./splunk-installer --edition forwarder --package-path /tmp/splunkforwarder.tgz --accept-license

  # Dry run to see what would happen
  sudo ./splunk-installer --dry-run --version 9.4.1

  # Uninstall
  sudo ./splunk-installer --uninstall
`)
	}

	flag.Parse()

	log.Verbose = cfg.Verbose

	cfg.Edition = SplunkEdition(*edition)
	if cfg.Edition != Enterprise && cfg.Edition != UniversalForwarder {
		log.Error("Invalid edition: %s (use 'enterprise' or 'forwarder')", *edition)
		os.Exit(1)
	}

	printBanner()

	// ── Uninstall path ──
	if cfg.Uninstall {
		log.Step(1, 2, "Preflight checks")
		if err := checkRoot(); err != nil {
			log.Error("%v", err)
			os.Exit(1)
		}
		log.Step(2, 2, "Uninstalling Splunk")
		if cfg.DryRun {
			log.Info("[DRY RUN] Would uninstall Splunk from %s", cfg.InstallDir)
			return
		}
		if err := uninstallSplunk(cfg.InstallDir); err != nil {
			log.Error("%v", err)
			os.Exit(1)
		}
		log.Info("Uninstall complete!")
		return
	}

	// ── Install path ──
	totalSteps := 8
	if !cfg.AcceptLicense {
		log.Error("You must pass --accept-license to proceed (see https://www.splunk.com/en_us/legal/splunk-software-license-agreement.html)")
		os.Exit(1)
	}

	// Prompt for password if not provided
	if cfg.AdminPassword == "" && cfg.Edition == Enterprise {
		cfg.AdminPassword = promptPassword()
	}

	printSummary(cfg)

	// Step 1: Preflight
	log.Step(1, totalSteps, "Preflight checks")
	if err := runPreflightChecks(cfg); err != nil {
		log.Error("Preflight failed: %v", err)
		os.Exit(1)
	}

	// Step 2: Create splunk user
	log.Step(2, totalSteps, "Creating Splunk user/group")
	if cfg.DryRun {
		log.Info("[DRY RUN] Would create user=%s group=%s", SplunkUser, SplunkGroup)
	} else {
		if err := createSplunkUser(); err != nil {
			log.Error("%v", err)
			os.Exit(1)
		}
	}

	// Step 3: Obtain package
	log.Step(3, totalSteps, "Obtaining Splunk package")
	packagePath := cfg.PackagePath
	if packagePath == "" {
		url := buildDownloadURL(cfg)
		packagePath = filepath.Join("/tmp", filepath.Base(url))

		if cfg.DryRun {
			log.Info("[DRY RUN] Would download from: %s", url)
		} else {
			if err := downloadFile(url, packagePath); err != nil {
				log.Error("%v", err)
				log.Info("Tip: Download manually from https://www.splunk.com/en_us/download.html and use --package-path")
				os.Exit(1)
			}
		}
	} else {
		if _, err := os.Stat(packagePath); os.IsNotExist(err) {
			log.Error("Package file not found: %s", packagePath)
			os.Exit(1)
		}
		log.Info("Using local package: %s", packagePath)
	}

	// Step 4: Install
	log.Step(4, totalSteps, "Installing Splunk")
	if cfg.DryRun {
		log.Info("[DRY RUN] Would install package %s to %s", packagePath, cfg.InstallDir)
	} else {
		if err := installPackage(packagePath, cfg.InstallDir); err != nil {
			log.Error("%v", err)
			os.Exit(1)
		}
	}

	// Step 5: Set ownership
	log.Step(5, totalSteps, "Setting file ownership")
	if cfg.DryRun {
		log.Info("[DRY RUN] Would chown %s to %s:%s", cfg.InstallDir, SplunkUser, SplunkGroup)
	} else {
		if err := setOwnership(cfg.InstallDir); err != nil {
			log.Error("Failed to set ownership: %v", err)
			os.Exit(1)
		}
		log.Info("✓ Ownership set")
	}

	// Step 6: Configure + start
	log.Step(6, totalSteps, "Configuring and starting Splunk")
	if cfg.DryRun {
		log.Info("[DRY RUN] Would configure admin credentials and start Splunk")
	} else {
		if cfg.Edition == Enterprise && cfg.AdminPassword != "" {
			if err := createAdminCredentials(cfg.InstallDir, cfg.AdminUser, cfg.AdminPassword); err != nil {
				log.Error("Failed to set admin credentials: %v", err)
				os.Exit(1)
			}
		}
		if err := startSplunk(cfg.InstallDir, cfg.AcceptLicense); err != nil {
			log.Error("Failed to start Splunk: %v", err)
			os.Exit(1)
		}
		log.Info("✓ Splunk started successfully")
	}

	// Step 7: Boot start + firewall
	log.Step(7, totalSteps, "System integration")
	if cfg.DryRun {
		log.Info("[DRY RUN] Would enable boot-start=%v, configure-firewall=%v", cfg.EnableBoot, cfg.ConfigureFirewall)
	} else {
		if cfg.EnableBoot {
			if err := enableBootStart(cfg.InstallDir); err != nil {
				log.Warn("Boot-start configuration failed: %v", err)
			}
		}
		if cfg.ConfigureFirewall {
			if err := configureFirewall(); err != nil {
				log.Warn("Firewall configuration failed: %v", err)
			}
		}
	}

	// Step 8: Hardening
	log.Step(8, totalSteps, "Security hardening")
	if cfg.DryRun {
		log.Info("[DRY RUN] Would apply security hardening (ulimits, THP, permissions)")
	} else {
		if err := applySecurityHardening(cfg.InstallDir); err != nil {
			log.Warn("Some hardening steps failed: %v", err)
		}
	}

	// Done!
	fmt.Printf(`
╔══════════════════════════════════════════════════════════════════╗
║                    Installation Complete!                         ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Splunk Web:     http://localhost:%d                            ║
║  Management:     https://localhost:%d                           ║
║  Admin User:     %-47s ║
║                                                                  ║
║  Useful commands (run as root):                                  ║
║    su -s /bin/sh %s -c '%s/bin/splunk status'    ║
║    su -s /bin/sh %s -c '%s/bin/splunk restart'   ║
║    su -s /bin/sh %s -c '%s/bin/splunk stop'      ║
║                                                                  ║
║  Or use systemd:                                                 ║
║    systemctl status Splunkd                                      ║
║    systemctl restart Splunkd                                     ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`,
		SplunkWebPort,
		SplunkMgmtPort,
		cfg.AdminUser,
		SplunkUser, cfg.InstallDir,
		SplunkUser, cfg.InstallDir,
		SplunkUser, cfg.InstallDir,
	)
}
