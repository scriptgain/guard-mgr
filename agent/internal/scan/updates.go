package scan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// runUpdates reports the host's OS/package update posture: how many package
// updates are available (and how many are security), whether a kernel update is
// pending, and whether a reboot is required (either the distro's reboot-required
// flag or a running-vs-installed kernel mismatch). It is READ-ONLY — it never
// installs anything; the run_updates action does that.
func runUpdates(ctx context.Context, _ Options, logf Logf) (engineResult, error) {
	u := DetectUpdates(ctx, logf)
	res := engineResult{
		updates: u,
		log:     fmt.Sprintf("[updates] %d available (%d security), kernel_update=%v, reboot_required=%v", u.Available, u.Security, u.KernelUpdate, u.RebootRequired),
	}

	if u.Available > 0 {
		sev := "low"
		if u.Security > 0 {
			sev = "medium"
		}
		res.findings = append(res.findings, api.Finding{
			Severity:    sev,
			Engine:      "updates",
			Code:        "updates-available",
			Title:       fmt.Sprintf("%d Package Update%s Available (%d Security)", u.Available, plural(u.Available), u.Security),
			Detail:      fmt.Sprintf("The system has %d upgradable package(s), %d of them security updates.", u.Available, u.Security),
			Remediation: "Use Update Now to apply security updates (or all), or run the package manager upgrade on the host.",
		})
	}

	if u.KernelUpdate {
		res.findings = append(res.findings, api.Finding{
			Severity:    "high",
			Engine:      "updates",
			Code:        "kernel-update",
			Title:       "Kernel Update Available",
			Detail:      "A newer kernel package is available. Installing it and rebooting closes kernel-level vulnerabilities.",
			Remediation: "Apply updates (Update Now), then schedule a reboot to run the new kernel.",
		})
	}

	if u.RebootRequired {
		res.findings = append(res.findings, api.Finding{
			Severity:    "high",
			Engine:      "updates",
			Code:        "reboot-required",
			Title:       "Reboot Required",
			Detail:      "The host needs a reboot to finish applying updates (a new kernel or libraries are staged but not running).",
			Remediation: "Schedule a maintenance reboot; mark this finding fixed once the host is back with the new kernel running.",
		})
	}

	return res, nil
}

// DetectUpdates gathers the host's update posture without changing anything.
// Exported so the run_updates remediation can re-read posture after upgrading.
func DetectUpdates(ctx context.Context, logf Logf) *api.Updates {
	if _, err := exec.LookPath("apt-get"); err == nil {
		return detectApt(ctx, logf)
	}
	if _, err := exec.LookPath("yum"); err == nil {
		return detectYum(ctx, logf)
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		return detectYum(ctx, logf) // dnf is yum-compatible for our purposes
	}
	logf("updates: no supported package manager (apt/yum/dnf) found")
	return &api.Updates{}
}

// detectApt reads the update posture on Debian/Ubuntu.
func detectApt(ctx context.Context, logf Logf) *api.Updates {
	u := &api.Updates{}

	// Refresh package lists (read-only w.r.t. installed packages). Best effort —
	// a stale-but-present list still yields a useful count if this fails.
	logf("updates: refreshing apt package lists")
	_, _ = runCmd(ctx, 3*time.Minute, "apt-get", "update", "-qq")

	out, _ := runCmd(ctx, 1*time.Minute, "apt", "list", "--upgradable")
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// Rows look like: "pkg/jammy-security 1.2 amd64 [upgradable from: 1.1]".
		name, _, ok := strings.Cut(line, "/")
		if !ok || strings.HasPrefix(line, "Listing") {
			continue
		}
		u.Available++
		if strings.Contains(line, "-security") {
			u.Security++
		}
		if strings.HasPrefix(name, "linux-image") {
			u.KernelUpdate = true
		}
	}

	u.RebootRequired = rebootRequiredFlag() || kernelDrift(ctx, logf)
	return u
}

// detectYum reads a coarse update posture on RHEL/CentOS/Fedora. Security-update
// counting is best effort (needs the security plugin / updateinfo metadata).
func detectYum(ctx context.Context, logf Logf) *api.Updates {
	u := &api.Updates{}
	logf("updates: checking yum/dnf for available updates")

	// `check-update` exits 100 when updates are available; runCmd treats a
	// non-zero exit as normal and returns the output.
	out, _ := runCmd(ctx, 3*time.Minute, "yum", "-q", "check-update")
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 3 || strings.HasPrefix(line, "Obsoleting") || !strings.Contains(f[0], ".") {
			continue
		}
		u.Available++
		if strings.HasPrefix(f[0], "kernel") {
			u.KernelUpdate = true
		}
	}

	sec, _ := runCmd(ctx, 2*time.Minute, "yum", "-q", "updateinfo", "list", "security")
	for _, line := range strings.Split(sec, "\n") {
		if strings.Contains(strings.ToLower(line), "sec") && len(strings.Fields(line)) >= 2 {
			u.Security++
		}
	}

	// needs-restarting -r exits non-zero when a reboot is advised.
	if p, err := exec.LookPath("needs-restarting"); err == nil {
		if out, _ := runCmd(ctx, 1*time.Minute, p, "-r"); strings.Contains(strings.ToLower(out), "reboot is required") {
			u.RebootRequired = true
		}
	}
	return u
}

// rebootRequiredFlag reports the Debian/Ubuntu reboot-required flag file.
func rebootRequiredFlag() bool {
	_, err := os.Stat("/var/run/reboot-required")
	return err == nil
}

// kernelDrift reports whether the running kernel is older than the newest
// installed linux-image, i.e. a reboot would switch to a newer kernel.
func kernelDrift(ctx context.Context, logf Logf) bool {
	out, err := runCmd(ctx, 15*time.Second, "uname", "-r")
	if err != nil {
		return false
	}
	running := strings.TrimSpace(out)
	if running == "" {
		return false
	}

	q, err := runCmd(ctx, 30*time.Second, "dpkg-query", "-W", "-f=${Package}\n", "linux-image-[0-9]*")
	if err != nil {
		return false
	}
	var versions []string
	for _, line := range strings.Split(q, "\n") {
		line = strings.TrimSpace(line)
		if v := strings.TrimPrefix(line, "linux-image-"); v != line && v != "" {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		return false
	}
	sort.Strings(versions) // lexical is close enough to flag drift; exact compare not needed
	newest := versions[len(versions)-1]
	if newest != running {
		logf("updates: running kernel %s, newest installed %s (reboot switches kernels)", running, newest)
		return true
	}
	return false
}

// plural returns "s" unless n == 1.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
