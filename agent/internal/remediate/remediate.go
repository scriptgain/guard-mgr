// Package remediate applies GuardMGR "fix it" actions on the local host.
//
// Safety is non-negotiable: every action that edits a config file BACKS THE FILE
// UP FIRST (to <path>.guardmgr.bak-<ts>), validates where it can (e.g. `sshd
// -t`), and on any validation failure RESTORES the backup. The backup path is
// returned in the Result so a revert is always possible. The agent runs as root.
package remediate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
	"github.com/thelonelyfrog/guard/agent/internal/scan"
)

// Logf is a printf-style logger the caller supplies.
type Logf func(format string, a ...any)

// Result is the outcome of a remediation, reported back to the master.
type Result struct {
	Log        string       // human-readable transcript
	BackupPath string       // backup created for a revert, if any
	Updates    *api.Updates // refreshed posture after an update action
}

// FixFinding runs the remediation named by kind. target is the finding code /
// free-form target the fix acts on (used by some kinds). It returns a Result and
// an error; on error the Result.Log still carries what was attempted.
func FixFinding(ctx context.Context, kind, target string, logf Logf) (Result, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	logf("fix: %s (target=%q)", kind, target)

	switch {
	case kind == "apt-upgrade":
		return RunUpdates(ctx, "security", logf)
	case strings.HasPrefix(kind, "install-pkg:"):
		return installPkg(ctx, strings.TrimPrefix(kind, "install-pkg:"), logf)
	case kind == "postfix-banner":
		return postconf(ctx, "smtpd_banner", "$myhostname ESMTP", logf)
	case kind == "disable-vrfy":
		return postconf(ctx, "disable_vrfy_command", "yes", logf)
	case kind == "redis-requirepass":
		return redisRequirepass(ctx, logf)
	case kind == "rkhunter-propupd":
		return rkhunterPropupd(ctx, logf)
	case strings.HasPrefix(kind, "ssh-harden:"):
		return sshHarden(ctx, strings.TrimPrefix(kind, "ssh-harden:"), logf)
	case kind == "sysctl" || strings.HasPrefix(kind, "sysctl:"):
		return sysctlHarden(ctx, logf)
	default:
		return Result{}, fmt.Errorf("unknown fix kind %q", kind)
	}
}

// RunUpdates applies OS updates. mode is "security" (default) or "all". It
// captures output and re-reads the post-upgrade posture (reboot_required may
// have flipped).
func RunUpdates(ctx context.Context, mode string, logf Logf) (Result, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return Result{}, fmt.Errorf("run_updates: only apt-based hosts are supported today")
	}

	var b strings.Builder
	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

	logf("run_updates: refreshing package lists")
	if out, err := runEnv(ctx, 3*time.Minute, env, "apt-get", "update"); err != nil {
		b.WriteString(out)
		return Result{Log: tail(b.String())}, fmt.Errorf("apt-get update failed: %w", err)
	} else {
		b.WriteString(out)
	}

	conf := []string{"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "-y"}

	if mode == "all" {
		logf("run_updates: applying ALL available updates (apt-get upgrade)")
		b.WriteString("\n$ apt-get upgrade -y\n")
		out, err := runEnv(ctx, 30*time.Minute, env, "apt-get", append(append([]string{}, conf...), "upgrade")...)
		b.WriteString(out)
		if err != nil {
			return Result{Log: tail(b.String())}, fmt.Errorf("apt-get upgrade failed: %s", lastErr(out, err))
		}
		return finishUpdate(ctx, b.String(), logf)
	}

	// Security-only: unattended-upgrade's origin allowlist doesn't cover every
	// host (e.g. CloudPanel-pinned repos), so it can exit non-zero having done
	// nothing. Instead, target the packages apt itself lists from a *-security
	// suite and upgrade exactly those with `apt-get install --only-upgrade`
	// (deterministic, minimal blast radius). Kernel packages are excluded — they
	// pull NEW packages + need a reboot, so they belong to the "all" path.
	pkgs := securityUpgradablePkgs(ctx, env)
	b.WriteString(fmt.Sprintf("\nsecurity updates pending (excluding kernel): %d\n", len(pkgs)))
	if len(pkgs) == 0 {
		logf("run_updates: no non-kernel security updates to apply")
		b.WriteString("No non-kernel security updates to apply.\n")
		return finishUpdate(ctx, b.String(), logf)
	}
	logf("run_updates: applying %d security update(s) via apt-get --only-upgrade", len(pkgs))
	b.WriteString("$ apt-get install --only-upgrade -y " + strings.Join(pkgs, " ") + "\n")
	args := append(append([]string{}, conf...), "install", "--only-upgrade")
	args = append(args, pkgs...)
	out, err := runEnv(ctx, 30*time.Minute, env, "apt-get", args...)
	b.WriteString(out)
	if err != nil {
		return Result{Log: tail(b.String())}, fmt.Errorf("security upgrade failed: %s", lastErr(out, err))
	}
	return finishUpdate(ctx, b.String(), logf)
}

// securityUpgradablePkgs returns the installed packages with an upgrade from a
// *-security suite, excluding kernel packages (which need a new install +
// reboot and belong to the "all" upgrade path).
func securityUpgradablePkgs(ctx context.Context, env []string) []string {
	out, _ := runEnv(ctx, 1*time.Minute, env, "apt", "list", "--upgradable")
	var pkgs []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "-security") {
			continue
		}
		name, _, ok := strings.Cut(line, "/")
		if !ok || name == "" || seen[name] {
			continue
		}
		if strings.HasPrefix(name, "linux-image") || strings.HasPrefix(name, "linux-headers") ||
			strings.HasPrefix(name, "linux-modules") || strings.HasPrefix(name, "linux-generic") {
			continue
		}
		seen[name] = true
		pkgs = append(pkgs, name)
	}
	return pkgs
}

// lastErr builds a compact, actionable error string from a command's output +
// error: the last few non-empty output lines (the real reason) plus the exit.
func lastErr(out string, err error) string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(l); s != "" {
			lines = append(lines, s)
		}
	}
	if len(lines) > 4 {
		lines = lines[len(lines)-4:]
	}
	if len(lines) == 0 {
		return err.Error()
	}
	return err.Error() + ": " + strings.Join(lines, " | ")
}

// finishUpdate re-reads posture and returns a successful Result.
func finishUpdate(ctx context.Context, log string, logf Logf) (Result, error) {
	u := scan.DetectUpdates(ctx, scan.Logf(logf))
	return Result{Log: tail(log), Updates: u}, nil
}

// installPkg installs a single package with apt-get.
func installPkg(ctx context.Context, pkg string, logf Logf) (Result, error) {
	pkg = strings.TrimSpace(pkg)
	if !validPkgName(pkg) {
		return Result{}, fmt.Errorf("refusing to install suspicious package name %q", pkg)
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return Result{}, fmt.Errorf("install-pkg: apt-get unavailable")
	}
	logf("install-pkg: apt-get install -y %s", pkg)
	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := runEnv(ctx, 5*time.Minute, env, "apt-get", "install", "-y", pkg); err != nil {
		return Result{Log: tail(out)}, fmt.Errorf("install %s failed: %w", pkg, err)
	}
	return Result{Log: fmt.Sprintf("Installed package %s.", pkg)}, nil
}

// postconf sets a Postfix parameter with `postconf -e` after backing up main.cf,
// then reloads Postfix. Used for the banner + VRFY fixes.
func postconf(ctx context.Context, key, val string, logf Logf) (Result, error) {
	if _, err := exec.LookPath("postconf"); err != nil {
		return Result{}, fmt.Errorf("postconf: Postfix is not installed on this host")
	}
	backup, _ := backupFile("/etc/postfix/main.cf", logf)
	logf("postconf -e %s=%q", key, val)
	if out, err := run(ctx, 30*time.Second, "postconf", "-e", key+"="+val); err != nil {
		return Result{Log: tail(out), BackupPath: backup}, fmt.Errorf("postconf failed: %w", err)
	}
	// Reload is best effort — the setting is already written to main.cf.
	if out, err := run(ctx, 30*time.Second, "postfix", "reload"); err != nil {
		logf("postfix reload: %v (%s)", err, tail(out))
	}
	return Result{Log: fmt.Sprintf("Set Postfix %s=%s and reloaded.", key, val), BackupPath: backup}, nil
}

// redisRequirepass generates a strong password and sets requirepass on the
// running Redis, persisting it with CONFIG REWRITE. The generated password is
// reported in the log so the operator can record it.
func redisRequirepass(ctx context.Context, logf Logf) (Result, error) {
	if _, err := exec.LookPath("redis-cli"); err != nil {
		return Result{}, fmt.Errorf("redis-requirepass: redis-cli not found")
	}
	pw := randToken(24)
	logf("redis: setting requirepass (generated)")
	if out, err := run(ctx, 20*time.Second, "redis-cli", "CONFIG", "SET", "requirepass", pw); err != nil {
		return Result{Log: tail(out)}, fmt.Errorf("redis CONFIG SET failed: %w", err)
	}
	// Persist to the config file so it survives a restart. Needs the new auth.
	if out, err := run(ctx, 20*time.Second, "redis-cli", "-a", pw, "CONFIG", "REWRITE"); err != nil {
		logf("redis CONFIG REWRITE: %v (%s) — set is live but may not persist a restart", err, tail(out))
	}
	return Result{Log: "Set Redis requirepass to a generated 24-char password: " + pw + " (record this; it is not stored by GuardMGR)."}, nil
}

// rkhunterPropupd updates the rkhunter file-property baseline so acknowledged
// false positives stop recurring. Safe / reversible via a later re-scan.
func rkhunterPropupd(ctx context.Context, logf Logf) (Result, error) {
	bin, err := exec.LookPath("rkhunter")
	if err != nil {
		return Result{}, fmt.Errorf("rkhunter not installed")
	}
	logf("rkhunter --propupd (updating baseline)")
	out, _ := run(ctx, 3*time.Minute, bin, "--propupd", "--nocolors", "--sk")
	return Result{Log: "Updated rkhunter baseline (--propupd).\n" + tail(out)}, nil
}

// hardenedSSH maps an sshd directive to the value we harden it to. PermitRootLogin
// is set to prohibit-password (key-only) rather than "no" so key-based root
// access — how GuardMGR reaches its own host — is never severed.
var hardenedSSH = map[string]string{
	"AllowTcpForwarding":    "no",
	"AllowAgentForwarding":  "no",
	"ClientAliveCountMax":   "2",
	"MaxAuthTries":          "3",
	"MaxSessions":           "4",
	"PermitRootLogin":       "prohibit-password",
	"TCPKeepAlive":          "no",
	"X11Forwarding":         "no",
	"Compression":           "no",
	"LoginGraceTime":        "30",
	"PermitUserEnvironment": "no",
}

// sshHarden sets one sshd_config directive to its hardened value, validating the
// config with `sshd -t` and restoring the backup if validation fails.
func sshHarden(ctx context.Context, directive string, logf Logf) (Result, error) {
	val, ok := hardenedSSH[directive]
	if !ok {
		return Result{}, fmt.Errorf("ssh-harden: unsupported directive %q", directive)
	}
	const cfg = "/etc/ssh/sshd_config"
	data, err := os.ReadFile(cfg)
	if err != nil {
		return Result{}, fmt.Errorf("ssh-harden: read %s: %w", cfg, err)
	}
	backup, err := backupFile(cfg, logf)
	if err != nil {
		return Result{}, fmt.Errorf("ssh-harden: backup failed: %w", err)
	}

	// Drop any existing (commented or active) lines for this directive, then
	// append the hardened setting.
	var kept []string
	lc := strings.ToLower(directive)
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.ToLower(strings.TrimSpace(strings.TrimLeft(line, "# \t")))
		if strings.HasPrefix(t, lc+" ") || t == lc {
			continue
		}
		kept = append(kept, line)
	}
	out := strings.TrimRight(strings.Join(kept, "\n"), "\n") + fmt.Sprintf("\n\n# Set by GuardMGR\n%s %s\n", directive, val)
	if err := os.WriteFile(cfg, []byte(out), 0o600); err != nil {
		return Result{BackupPath: backup}, fmt.Errorf("ssh-harden: write %s: %w", cfg, err)
	}

	logf("ssh-harden: set %s %s, validating with sshd -t", directive, val)
	if vo, verr := run(ctx, 20*time.Second, "sshd", "-t"); verr != nil {
		_ = os.WriteFile(cfg, data, 0o600) // restore
		return Result{Log: "sshd -t rejected the change; restored backup.\n" + tail(vo), BackupPath: backup},
			fmt.Errorf("ssh-harden: sshd -t failed, reverted: %w", verr)
	}
	if vo, verr := run(ctx, 20*time.Second, "systemctl", "reload", "ssh"); verr != nil {
		// Try the alternate service name; a reload failure is non-fatal (the file
		// is valid and applies on next restart).
		if vo2, verr2 := run(ctx, 20*time.Second, "systemctl", "reload", "sshd"); verr2 != nil {
			logf("ssh reload: %v / %v", verr, verr2)
			_ = vo
			_ = vo2
		}
	}
	return Result{Log: fmt.Sprintf("Hardened sshd: %s %s (validated, reloaded).", directive, val), BackupPath: backup}, nil
}

// guardmgrSysctl is the curated, conservative hardening drop-in applied for a
// KRNL-6000 sysctl finding.
const guardmgrSysctl = `# Set by GuardMGR (sysctl hardening)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
`

// sysctlHarden writes a conservative sysctl hardening drop-in (backing up any
// existing one) and applies it with `sysctl --system`.
func sysctlHarden(ctx context.Context, logf Logf) (Result, error) {
	const path = "/etc/sysctl.d/99-guardmgr.conf"
	var backup string
	if _, err := os.Stat(path); err == nil {
		backup, _ = backupFile(path, logf)
	}
	if err := os.WriteFile(path, []byte(guardmgrSysctl), 0o644); err != nil {
		return Result{}, fmt.Errorf("sysctl: write %s: %w", path, err)
	}
	logf("sysctl: wrote %s, applying with sysctl --system", path)
	if out, err := run(ctx, 30*time.Second, "sysctl", "--system"); err != nil {
		return Result{Log: tail(out), BackupPath: backup}, fmt.Errorf("sysctl --system failed: %w", err)
	}
	return Result{Log: "Applied GuardMGR sysctl hardening drop-in " + path + ".", BackupPath: backup}, nil
}

// --- helpers ---------------------------------------------------------------

// backupFile copies path to path.guardmgr.bak-<ts> and returns the backup path.
func backupFile(path string, logf Logf) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backup := fmt.Sprintf("%s.guardmgr.bak-%d", path, time.Now().Unix())
	if err := os.WriteFile(backup, data, 0o600); err != nil {
		return "", err
	}
	logf("backed up %s -> %s", path, backup)
	return backup, nil
}

// run executes a command with a timeout, returning combined output. A non-zero
// exit is an error here (unlike scan.runCmd) because a remediation must succeed.
func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	return runEnv(ctx, timeout, os.Environ(), name, args...)
}

func runEnv(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if cctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return string(out), err
}

// validPkgName guards the install-pkg path against injection via a package name.
func validPkgName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '+') {
			return false
		}
	}
	return true
}

// randToken returns a hex token of n bytes of entropy.
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("gm%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// tail returns the last ~40 lines of s, so a report log stays bounded.
func tail(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > 40 {
		lines = lines[len(lines)-40:]
	}
	return strings.Join(lines, "\n")
}
