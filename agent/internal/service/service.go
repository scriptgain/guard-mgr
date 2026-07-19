// Package service installs the GuardMGR agent as an always-on systemd service,
// so enrolling a host turns it into a persistent worker that polls the master
// every ~30s and runs due scans automatically — no hand-crafted unit per host.
package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// UnitPath is the systemd unit the agent manages.
	UnitPath = "/etc/systemd/system/guard-agent.service"
	// BinPath is where the agent installs its own binary for the service.
	BinPath = "/usr/local/bin/guard-agent"
	// ServiceName is the systemd unit name (without the .service suffix).
	ServiceName = "guard-agent"
)

// Logf is a printf-style logger the caller supplies.
type Logf func(format string, a ...any)

// unitTemplate is the systemd unit. ExecStart is filled with the resolved config
// path so the service reads the same credentials enrollment wrote.
const unitTemplate = `[Unit]
Description=GuardMGR security scan agent
Documentation=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run -config %s
Restart=always
RestartSec=10
User=root
# Scans run read tooling as root; no extra privileges needed beyond that.

[Install]
WantedBy=multi-user.target
`

// Install drops the agent binary to BinPath, writes the systemd unit pointing at
// configPath, reloads systemd, enables + starts the service, and verifies it is
// active. Idempotent: re-running it refreshes the unit and restarts the service.
// masterURL is used only for the unit's Documentation line (best effort).
func Install(configPath, masterURL string, logf Logf) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("install must run as root")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemd (systemctl) not found; cannot install the service")
	}
	if configPath == "" {
		return fmt.Errorf("install: empty config path")
	}
	configPath, _ = filepath.Abs(configPath)

	if err := installBinary(logf); err != nil {
		return err
	}

	if masterURL == "" {
		masterURL = "https://guard.allenjenkins.dev/docs"
	}
	unit := fmt.Sprintf(unitTemplate, masterURL, BinPath, configPath)
	logf("writing %s", UnitPath)
	if err := os.WriteFile(UnitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}

	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", "--now", ServiceName},
	} {
		logf("systemctl %s", strings.Join(args, " "))
		if out, err := run("systemctl", args...); err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
		}
	}

	if out, err := run("systemctl", "is-active", ServiceName); err != nil || strings.TrimSpace(out) != "active" {
		return fmt.Errorf("service did not become active (state=%q): %v", strings.TrimSpace(out), err)
	}
	logf("guard-agent service installed and active")
	return nil
}

// Uninstall stops + disables the service, removes the unit, and reloads systemd.
// Best effort: a missing unit is not an error. The binary is left in place.
func Uninstall(logf Logf) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must run as root")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemd (systemctl) not found")
	}
	logf("systemctl disable --now %s", ServiceName)
	_, _ = run("systemctl", "disable", "--now", ServiceName)
	if err := os.Remove(UnitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit: %w", err)
	}
	_, _ = run("systemctl", "daemon-reload")
	logf("guard-agent service removed")
	return nil
}

// installBinary copies the running executable to BinPath when it is not already
// there, so `guard-agent install` from a downloaded binary lands it in the
// canonical location the unit references.
func installBinary(logf Logf) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	self, _ = filepath.EvalSymlinks(self)
	target, _ := filepath.EvalSymlinks(BinPath)
	if self == BinPath || (target != "" && self == target) {
		return nil // already running from the install location
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return fmt.Errorf("read self: %w", err)
	}
	logf("installing binary to %s", BinPath)
	if err := os.MkdirAll(filepath.Dir(BinPath), 0o755); err != nil {
		return err
	}
	// Write to a temp file then rename, so we never truncate a running binary.
	tmp := BinPath + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return fmt.Errorf("write binary: %w", err)
	}
	if err := os.Rename(tmp, BinPath); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	return nil
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}
