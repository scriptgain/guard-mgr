package scan

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// maldetHitRe matches a hit row in an LMD scan report, e.g.
//
//	{HEX}php.cmdshell.r57.317 : /home/site/htdocs/x.php
//	{YARA}webshell_php : /var/www/shell.php
var maldetHitRe = regexp.MustCompile(`^\{[A-Z]+\}[^:]+:\s+(/\S+)`)

// runMaldet runs Linux Malware Detect (maldet / LMD) over the host's web/data
// dirs. LMD is not in apt, so install is best-effort via its official
// installer; if it is not present and cannot be installed, this records a single
// low finding ("maldet not installed") and returns cleanly — ClamAV covers
// malware in the meantime. It never hard-fails the scan.
func runMaldet(ctx context.Context, _ Options, logf Logf) (engineResult, error) {
	bin := maldetBin()
	if bin == "" {
		bin = installMaldet(ctx, logf)
	}
	if bin == "" {
		return engineResult{
			log: "[maldet] not installed and could not be auto-installed",
			findings: []api.Finding{{
				Severity: "low", Engine: "maldet", Code: "maldet-not-installed",
				Title:       "Linux Malware Detect Not Installed",
				Detail:      "maldet (LMD) is not installed and could not be installed automatically in this environment. ClamAV still provides malware coverage for this scan.",
				Remediation: "Install LMD manually from https://www.rfxn.com/projects/linux-malware-detect/ to enable its signature set, or rely on the ClamAV engine.",
			}},
		}, nil
	}

	dirs := malwareScanDirs()
	if len(dirs) == 0 {
		return engineResult{log: "[maldet] no web/data directories present to scan"}, nil
	}

	logf("maldet: scanning %d path(s)", len(dirs))
	out, err := runCmd(ctx, 20*time.Minute, bin, "-a", strings.Join(dirs, ","))
	if err != nil {
		return engineResult{log: tailLog("maldet", out)}, err
	}

	res := engineResult{log: "[maldet] scan complete"}
	report := maldetReport(ctx, bin, out, logf)
	seen := map[string]bool{}
	for _, line := range strings.Split(report, "\n") {
		m := maldetHitRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		hit := strings.TrimSpace(line)
		if seen[hit] {
			continue
		}
		seen[hit] = true
		res.findings = append(res.findings, api.Finding{
			Severity:    "high",
			Engine:      "maldet",
			Code:        truncate(m[1], 120),
			Title:       "Malware: " + truncate(hit, 180),
			Detail:      "Linux Malware Detect flagged " + m[1] + " (" + hit + ").",
			Remediation: "Review the file and remove/quarantine it. Audit the site for how it was planted and rotate exposed credentials.",
		})
	}
	if len(res.findings) == 0 {
		res.log = "[maldet] scan complete — no hits"
	}
	return res, nil
}

// maldetBin returns the maldet executable path, or "" if absent.
func maldetBin() string {
	if p, err := exec.LookPath("maldet"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/local/sbin/maldet", "/usr/local/maldetect/maldet"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// installMaldet attempts the official LMD installer (best effort). Returns the
// binary path on success, "" otherwise. Bounded and never fatal.
func installMaldet(ctx context.Context, logf Logf) string {
	if _, err := exec.LookPath("curl"); err != nil {
		return ""
	}
	logf("maldet: attempting best-effort install of Linux Malware Detect")
	tar := "/tmp/guard-maldet.tar.gz"
	if _, err := runCmd(ctx, 3*time.Minute, "curl", "-fsSL", "-o", tar, "https://www.rfxn.com/downloads/maldetect-current.tar.gz"); err != nil {
		return ""
	}
	dir := "/tmp/guard-maldet-src"
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	if _, err := runCmd(ctx, 1*time.Minute, "tar", "-xzf", tar, "-C", dir, "--strip-components=1"); err != nil {
		return ""
	}
	if _, err := runCmd(ctx, 5*time.Minute, "bash", dir+"/install.sh"); err != nil {
		return ""
	}
	return maldetBin()
}

// maldetReport returns the LMD hit list. LMD prints a "report SCANID" hint at
// the end of a scan; if we can find the SCANID we fetch the full report,
// otherwise we fall back to the scan's own stdout.
func maldetReport(ctx context.Context, bin, scanOut string, logf Logf) string {
	re := regexp.MustCompile(`--report\s+(\S+)`)
	if m := re.FindStringSubmatch(scanOut); m != nil {
		if out, err := runCmd(ctx, 1*time.Minute, bin, "--report", m[1]); err == nil && strings.TrimSpace(out) != "" {
			return out
		}
	}
	return scanOut
}
