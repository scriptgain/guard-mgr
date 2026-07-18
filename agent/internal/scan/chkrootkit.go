package scan

import (
	"context"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// runChkrootkit installs and runs chkrootkit as a second-opinion rootkit
// scanner alongside rkhunter. It runs `chkrootkit -q` (quiet — only prints
// lines of interest) and turns each INFECTED / "Warning" line into a
// high-severity finding. A clean host produces no findings.
func runChkrootkit(ctx context.Context, _ Options, logf Logf) (engineResult, error) {
	bin, err := ensureInstalled(ctx, "chkrootkit", "chkrootkit", logf)
	if err != nil {
		return engineResult{}, err
	}

	logf("chkrootkit: scanning for rootkits and infections")
	out, err := runCmd(ctx, 8*time.Minute, bin, "-q")
	if err != nil {
		return engineResult{}, err
	}

	res := engineResult{log: "[chkrootkit] scan complete"}
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		lower := strings.ToLower(line)
		// -q still emits benign notes on some systems; keep only lines that
		// signal an actual detection.
		if !strings.Contains(lower, "infected") && !strings.HasPrefix(lower, "warning") {
			continue
		}
		// chkrootkit's own false-positive footgun: the "Vulnerable but disabled"
		// SSH note is informational, not an infection. Skip it.
		if strings.Contains(lower, "vulnerable but disabled") {
			continue
		}
		seen[line] = true
		res.findings = append(res.findings, api.Finding{
			Severity:    "high",
			Engine:      "chkrootkit",
			Title:       truncate(line, 200),
			Detail:      line,
			Remediation: "Investigate this chkrootkit detection. Confirm against a second scanner (rkhunter/ClamAV); if legitimate, whitelist it, otherwise treat the host as compromised.",
		})
	}
	if len(res.findings) == 0 {
		res.log = "[chkrootkit] no infections found — clean"
	}
	return res, nil
}
