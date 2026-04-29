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

const (
	DefaultSplunkVersion = "10.0.0"
	DefaultInstallDir    = "/opt/splunk"
	SplunkUser           = "splunk"
	SplunkGroup          = "splunk"
	MinDiskSpaceMB       = 5120 // 5 GB
	MinRAMMB             = 4096 // 4 GB
	SplunkWebPort        = 8000
	SplunkMgmtPort       = 8089
	SplunkIdxPort        = 9997

	RunAsSplunk = "splunk" // dedicated splunk user (default, hardened)
	RunAsRoot   = "root"   // run as root, no splunk user
)

// KnownRelease is a pinned Splunk download (URL contains a build hash,
// so we can't construct it from version alone — we hardcode known-good builds).
type KnownRelease struct {
	Version  string
	Format   string // "tgz" or "rpm"
	Arch     string // "amd64"
	URL      string
	Filename string
}

// KnownReleases — add new versions here as they are published.
// Default is the first entry.
var KnownReleases = []KnownRelease{
	{
		Version:  "10.0.0",
		Format:   "tgz",
		Arch:     "amd64",
		Filename: "splunk-10.0.0-e8eb0c4654f8-linux-amd64.tgz",
		URL:      "https://download.splunk.com/products/splunk/releases/10.0.0/linux/splunk-10.0.0-e8eb0c4654f8-linux-amd64.tgz",
	},
	{
		Version:  "9.4.10",
		Format:   "tgz",
		Arch:     "amd64",
		Filename: "splunk-9.4.10-3673ab0c12ee-linux-amd64.tgz",
		URL:      "https://download.splunk.com/products/splunk/releases/9.4.10/linux/splunk-9.4.10-3673ab0c12ee-linux-amd64.tgz",
	},
	{
		Version:  "9.4.9",
		Format:   "rpm",
		Arch:     "amd64",
		Filename: "splunk-9.4.9-03bb451d4e07.x86_64.rpm",
		URL:      "https://download.splunk.com/products/splunk/releases/9.4.9/linux/splunk-9.4.9-03bb451d4e07.x86_64.rpm",
	},
	{
		Version:  "9.4.8",
		Format:   "tgz",
		Arch:     "amd64",
		Filename: "splunk-9.4.8-c543277b24fa-linux-amd64.tgz",
		URL:      "https://download.splunk.com/products/splunk/releases/9.4.8/linux/splunk-9.4.8-c543277b24fa-linux-amd64.tgz",
	},
	{
		Version:  "9.4.3",
		Format:   "tgz",
		Arch:     "amd64",
		Filename: "splunk-9.4.3-237ebbd22314-linux-amd64.tgz",
		URL:      "https://download.splunk.com/products/splunk/releases/9.4.3/linux/splunk-9.4.3-237ebbd22314-linux-amd64.tgz",
	},
}

func findRelease(version string) (*KnownRelease, bool) {
	for i := range KnownReleases {
		if KnownReleases[i].Version == version {
			return &KnownReleases[i], true
		}
	}
	return nil, false
}

func listReleases() {
	fmt.Println("Available pinned Splunk versions:")
	for i, r := range KnownReleases {
		marker := "  "
		if i == 0 {
			marker = "* " // default
		}
		fmt.Printf("  %s%-8s  %s  %s\n", marker, r.Version, r.Format, r.Filename)
	}
	fmt.Println("\n  * = default")
	fmt.Println("  Use --version <ver>, --download-url <url>, or --package-path <file>.")
}

// SplunkEdition represents different Splunk packages
type SplunkEdition string

const (
	Enterprise        SplunkEdition = "enterprise"
	UniversalForwarder SplunkEdition = "forwarder"
)

// Config holds all installation parameters
type Config struct {
	Version           string
	Edition           SplunkEdition
	InstallDir        string
	AdminUser         string
	AdminPassword     string
	AcceptLicense     bool
	EnableBoot        bool
	ConfigureFirewall bool
	PackagePath       string // local .tgz or .deb/.rpm path
	DownloadURL       string // explicit URL override
	DryRun            bool
	Verbose           bool
	Uninstall         bool
	// RunAs controls whether Splunk runs as a dedicated locked-down splunk user
	// ("splunk", default) or directly as root ("root").
	RunAs string
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

	if err := checkRoot(); err != nil {
		return err
	}
	log.Info("✓ Running as root")

	if err := checkOS(); err != nil {
		return err
	}
	log.Info("✓ Operating system supported")

	arch, err := checkArch()
	if err != nil {
		return err
	}
	log.Info("✓ Architecture: %s", arch)

	diskMB, err := getDiskSpaceMB(cfg.InstallDir)
	if err != nil {
		log.Warn("Could not check disk space: %v", err)
	} else if diskMB < MinDiskSpaceMB {
		return fmt.Errorf("insufficient disk space: %d MB available, need %d MB", diskMB, MinDiskSpaceMB)
	} else {
		log.Info("✓ Disk space: %d MB available", diskMB)
	}

	ramMB, err := getTotalRAMMB()
	if err != nil {
		log.Warn("Could not check RAM: %v", err)
	} else if ramMB < MinRAMMB {
		log.Warn("Low RAM: %d MB (recommended: %d MB). Splunk may underperform.", ramMB, MinRAMMB)
	} else {
		log.Info("✓ RAM: %d MB available", ramMB)
	}

	if _, err := os.Stat(filepath.Join(cfg.InstallDir, "bin", "splunk")); err == nil {
		log.Warn("Existing Splunk installation detected at %s", cfg.InstallDir)
		if !cfg.Uninstall {
			return fmt.Errorf("splunk already installed at %s — use --uninstall first or choose a different --install-dir", cfg.InstallDir)
		}
	}

	required := []string{"tar"}
	if cfg.RunAs == RunAsSplunk {
		required = append(required, "useradd", "groupadd")
	}
	for _, tool := range required {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("required tool not found: %s", tool)
		}
	}
	log.Info("✓ Required tools present")

	log.Info("All preflight checks passed!")
	return nil
}

// ─── Download / Package Handling ────────────────────────────────────────────

func buildDownloadURL(cfg *Config) (string, bool) {
	if cfg.DownloadURL != "" {
		return cfg.DownloadURL, true
	}
	if r, ok := findRelease(cfg.Version); ok {
		return r.URL, true
	}
	return "", false
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

	fmt.Println()
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
	if err := exec.Command("getent", "group", SplunkGroup).Run(); err != nil {
		log.Info("Creating group: %s", SplunkGroup)
		if err := exec.Command("groupadd", "-r", SplunkGroup).Run(); err != nil {
			return fmt.Errorf("failed to create group %s: %w", SplunkGroup, err)
		}
	}

	if err := exec.Command("getent", "passwd", SplunkUser).Run(); err != nil {
		log.Info("Creating user: %s", SplunkUser)
		if err := exec.Command("useradd",
			"-r",
			"-g", SplunkGroup,
			"-d", DefaultInstallDir,
			"-s", "/bin/bash",
			"--no-create-home",
			SplunkUser,
		).Run(); err != nil {
			return fmt.Errorf("failed to create user %s: %w", SplunkUser, err)
		}
	}

	// Lock password and remove from privilege groups so the account can only
	// be entered via `sudo -u splunk` — not via su or login.
	exec.Command("passwd", "-l", SplunkUser).Run()
	for _, grp := range []string{"sudo", "wheel", "admin"} {
		exec.Command("gpasswd", "-d", SplunkUser, grp).Run()
	}
	sudoersFile := "/etc/sudoers.d/99-splunk-deny"
	content := fmt.Sprintf("# Deny splunk user sudo access\n%s ALL=(ALL) !ALL\n", SplunkUser)
	os.WriteFile(sudoersFile, []byte(content), 0440)

	log.Info("✓ Splunk user/group ready (locked, no sudo)")
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

// repairOwnership re-applies splunk:splunk ownership after a start/restart.
// When the splunk binary is invoked via sudo (even as -u splunk), some internal
// Splunk processes may write files as root inside etc/ or var/. This corrects that.
func repairOwnership(installDir string) error {
	log.Info("Repairing file ownership after start...")
	return exec.Command("chown", "-R", fmt.Sprintf("%s:%s", SplunkUser, SplunkGroup), installDir).Run()
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
	exec.Command("chown", fmt.Sprintf("%s:%s", SplunkUser, SplunkGroup), seedFile).Run()
	log.Info("✓ Admin credentials configured")
	return nil
}

// startSplunk starts the Splunk daemon.
//
// runAs == RunAsSplunk: invoked as `sudo -E -u splunk <splunkBin> start ...`
//   -E preserves the caller's environment so SPLUNK_HOME is inherited.
//
// runAs == RunAsRoot: invoked directly with SPLUNK_HOME set in the process env.
func startSplunk(installDir string, acceptLicense bool, runAs string) error {
	splunkBin := filepath.Join(installDir, "bin", "splunk")

	args := []string{"start", "--no-prompt"}
	if acceptLicense {
		args = append(args, "--accept-license")
	}
	args = append(args, "--answer-yes")

	env := append(os.Environ(), fmt.Sprintf("SPLUNK_HOME=%s", installDir))

	var cmd *exec.Cmd
	if runAs == RunAsSplunk {
		// -E: preserve environment (passes SPLUNK_HOME through sudo)
		cmd = exec.Command("sudo", append([]string{"-E", "-u", SplunkUser, splunkBin}, args...)...)
	} else {
		cmd = exec.Command(splunkBin, args...)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	log.Info("Starting Splunk as %s ...", runAs)
	return cmd.Run()
}

// enableBootStart registers Splunk with systemd.
// In splunk-user mode it adds -user splunk so systemd starts the process as
// the splunk user. In root mode no -user flag is passed.
func enableBootStart(installDir string, runAs string) error {
	splunkBin := filepath.Join(installDir, "bin", "splunk")
	log.Info("Enabling boot-start with systemd...")

	args := []string{"enable", "boot-start"}
	if runAs == RunAsSplunk {
		args = append(args, "-user", SplunkUser)
	}
	args = append(args, "-systemd-managed", "1", "--accept-license", "--answer-yes", "--no-prompt")

	cmd := exec.Command(splunkBin, args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("SPLUNK_HOME=%s", installDir))
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

	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		log.Info("Configuring firewalld...")
		for _, port := range ports {
			exec.Command("firewall-cmd", "--permanent", "--add-port", fmt.Sprintf("%d/tcp", port)).Run()
		}
		exec.Command("firewall-cmd", "--reload").Run()
		log.Info("✓ Firewalld rules added for ports %v", ports)
		return nil
	}

	if _, err := exec.LookPath("ufw"); err == nil {
		log.Info("Configuring ufw...")
		for _, port := range ports {
			exec.Command("ufw", "allow", fmt.Sprintf("%d/tcp", port)).Run()
		}
		log.Info("✓ UFW rules added for ports %v", ports)
		return nil
	}

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

// applySecurityHardening applies OS-level hardening.
// In root mode the chmod 700 steps are skipped — Splunk runs as root and owns
// all files, so restricting directory bits would only break root's own access
// after future writes.
func applySecurityHardening(installDir string, runAs string) error {
	log.Info("Applying basic security hardening...")

	if runAs == RunAsSplunk {
		exec.Command("chmod", "700", filepath.Join(installDir, "etc")).Run()
		exec.Command("chmod", "700", filepath.Join(installDir, "var")).Run()
	}

	thpPaths := []string{
		"/sys/kernel/mm/transparent_hugepage/enabled",
		"/sys/kernel/mm/transparent_hugepage/defrag",
	}
	for _, p := range thpPaths {
		if _, err := os.Stat(p); err == nil {
			os.WriteFile(p, []byte("never"), 0644)
		}
	}

	user := "root"
	if runAs == RunAsSplunk {
		user = SplunkUser
	}
	limitsContent := fmt.Sprintf(`# Splunk recommended ulimits
%s soft nofile 65535
%s hard nofile 65535
%s soft nproc  20480
%s hard nproc  20480
`, user, user, user, user)

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

	log.Info("Stopping Splunk...")
	exec.Command(splunkBin, "stop").Run()

	exec.Command(splunkBin, "disable", "boot-start").Run()

	exec.Command("systemctl", "disable", "Splunkd.service").Run()
	os.Remove("/etc/systemd/system/Splunkd.service")
	exec.Command("systemctl", "daemon-reload").Run()

	log.Info("Removing %s ...", installDir)
	if err := os.RemoveAll(installDir); err != nil {
		return fmt.Errorf("removal failed: %w", err)
	}

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
	fmt.Println(`
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ███████╗██████╗ ██╗     ██╗   ██╗███╗   ██╗██╗  ██╗           ║
║   ██╔════╝██╔══██╗██║     ██║   ██║████╗  ██║██║ ██╔╝           ║
║   ███████╗██████╔╝██║     ██║   ██║██╔██╗ ██║█████╔╝            ║
║   ╚════██║██╔═══╝ ██║     ██║   ██║██║╚██╗██║██╔═██╗            ║
║   ███████║██║     ███████╗╚██████╔╝██║ ╚████║██║  ╚██╗          ║
║   ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝        ║
║                                                                  ║
║              Automated Installer v3 (Go Edition)                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝`)
}

func printSummary(cfg *Config) {
	fmt.Printf(`
┌─────────────────────── Installation Summary ───────────────────────┐
│  Edition:       %-50s│
│  Version:       %-50s│
│  Install Dir:   %-50s│
│  Admin User:    %-50s│
│  Run As:        %-50s│
│  Boot Start:    %-50s│
│  Firewall:      %-50s│
│  Dry Run:       %-50s│
└────────────────────────────────────────────────────────────────────┘
`,
		string(cfg.Edition),
		cfg.Version,
		cfg.InstallDir,
		cfg.AdminUser,
		cfg.RunAs,
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
	flag.StringVar(&cfg.RunAs, "run-as", RunAsSplunk,
		`Process identity for Splunk:
    splunk  — create a locked-down splunk system user; Splunk runs as that user (default, recommended)
    root    — skip user creation; Splunk runs as root (simpler, less secure)`)
	listVersions := flag.Bool("list-versions", false, "List pinned Splunk versions and exit")

	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "\nUsage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  # Install as dedicated splunk user (default, hardened)
  sudo ./splunk-installer --package-path /tmp/splunk-10.0.0-e8eb0c4654f8-linux-amd64.tgz --accept-license --admin-password 'MyP@ss123'

  # Install running as root (simpler, automation-friendly)
  sudo ./splunk-installer --run-as root --package-path /tmp/splunk-10.0.0-e8eb0c4654f8-linux-amd64.tgz --accept-license --admin-password 'MyP@ss123'

  # Install with a custom download URL
  sudo ./splunk-installer --download-url 'https://...' --accept-license --admin-password 'MyP@ss123'

  # Install Universal Forwarder
  sudo ./splunk-installer --edition forwarder --package-path /tmp/splunkforwarder.tgz --accept-license

  # Dry run to preview steps
  sudo ./splunk-installer --dry-run --version 9.4.10 --accept-license --admin-password test12345

  # Uninstall
  sudo ./splunk-installer --uninstall
`)
	}

	flag.Parse()

	if *listVersions {
		listReleases()
		return
	}

	log.Verbose = cfg.Verbose

	cfg.Edition = SplunkEdition(*edition)
	if cfg.Edition != Enterprise && cfg.Edition != UniversalForwarder {
		log.Error("Invalid edition: %s (use 'enterprise' or 'forwarder')", *edition)
		os.Exit(1)
	}

	if cfg.RunAs != RunAsSplunk && cfg.RunAs != RunAsRoot {
		log.Error("Invalid --run-as value: %q (use 'splunk' or 'root')", cfg.RunAs)
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

	// Step 2: Create splunk user (splunk mode only)
	log.Step(2, totalSteps, "User/group setup")
	if cfg.RunAs == RunAsSplunk {
		if cfg.DryRun {
			log.Info("[DRY RUN] Would create user=%s group=%s (locked, no sudo)", SplunkUser, SplunkGroup)
		} else {
			if err := createSplunkUser(); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		}
	} else {
		log.Info("--run-as root: skipping splunk user creation, Splunk will run as root")
	}

	// Step 3: Obtain package
	log.Step(3, totalSteps, "Obtaining Splunk package")
	packagePath := cfg.PackagePath
	if packagePath == "" {
		url, ok := buildDownloadURL(cfg)
		if !ok {
			log.Error("No pinned release for version %q and no --download-url given.", cfg.Version)
			log.Info("Run with --list-versions to see pinned builds, or pass --download-url / --package-path.")
			os.Exit(1)
		}
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

	// Step 5: Set ownership (splunk mode only)
	log.Step(5, totalSteps, "File ownership")
	if cfg.RunAs == RunAsSplunk {
		if cfg.DryRun {
			log.Info("[DRY RUN] Would chown %s to %s:%s", cfg.InstallDir, SplunkUser, SplunkGroup)
		} else {
			if err := setOwnership(cfg.InstallDir); err != nil {
				log.Error("Failed to set ownership: %v", err)
				os.Exit(1)
			}
			log.Info("✓ Ownership set to splunk:splunk")
		}
	} else {
		log.Info("--run-as root: skipping chown, files remain root-owned")
	}

	// Step 6: Configure + start
	log.Step(6, totalSteps, "Configuring and starting Splunk")
	if cfg.DryRun {
		log.Info("[DRY RUN] Would configure admin credentials and start Splunk as %s", cfg.RunAs)
	} else {
		if cfg.Edition == Enterprise && cfg.AdminPassword != "" {
			if err := createAdminCredentials(cfg.InstallDir, cfg.AdminUser, cfg.AdminPassword); err != nil {
				log.Error("Failed to set admin credentials: %v", err)
				os.Exit(1)
			}
		}
		if err := startSplunk(cfg.InstallDir, cfg.AcceptLicense, cfg.RunAs); err != nil {
			log.Error("Failed to start Splunk: %v", err)
			os.Exit(1)
		}
		log.Info("✓ Splunk started successfully")

		// After start, some Splunk internal processes may have written files as
		// root even in splunk-user mode. Re-apply ownership to fix that.
		if cfg.RunAs == RunAsSplunk {
			if err := repairOwnership(cfg.InstallDir); err != nil {
				log.Warn("Ownership repair failed (non-fatal): %v", err)
			}
		}
	}

	// Step 7: Boot start + firewall
	log.Step(7, totalSteps, "System integration")
	if cfg.DryRun {
		log.Info("[DRY RUN] Would enable boot-start=%v, configure-firewall=%v", cfg.EnableBoot, cfg.ConfigureFirewall)
	} else {
		if cfg.EnableBoot {
			if err := enableBootStart(cfg.InstallDir, cfg.RunAs); err != nil {
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
		if err := applySecurityHardening(cfg.InstallDir, cfg.RunAs); err != nil {
			log.Warn("Some hardening steps failed: %v", err)
		}
	}

	// Done — print mode-appropriate management commands
	var statusCmd, restartCmd string
	if cfg.RunAs == RunAsSplunk {
		statusCmd = fmt.Sprintf("sudo -u %s %s/bin/splunk status", SplunkUser, cfg.InstallDir)
		restartCmd = fmt.Sprintf("sudo -u %s %s/bin/splunk restart", SplunkUser, cfg.InstallDir)
	} else {
		statusCmd = fmt.Sprintf("SPLUNK_HOME=%s %s/bin/splunk status", cfg.InstallDir, cfg.InstallDir)
		restartCmd = fmt.Sprintf("SPLUNK_HOME=%s %s/bin/splunk restart", cfg.InstallDir, cfg.InstallDir)
	}

	fmt.Printf(`
╔══════════════════════════════════════════════════════════════════╗
║                    Installation Complete!                         ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Splunk Web:  http://localhost:%d                               ║
║  Management:  https://localhost:%d                              ║
║  Admin User:  %-51s║
║  Run As:      %-51s║
║                                                                  ║
║  Useful commands:                                                ║
║    %-61s║
║    %-61s║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`,
		SplunkWebPort,
		SplunkMgmtPort,
		cfg.AdminUser,
		cfg.RunAs,
		statusCmd,
		restartCmd,
	)
}
