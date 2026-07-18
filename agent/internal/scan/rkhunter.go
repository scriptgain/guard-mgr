package scan

import (
	"context"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// runRkhunter runs `rkhunter --check --sk --nocolors --rwo` (report-warnings-
// only) and turns each warning line into a high-severity finding. A clean run
// produces no findings.
func runRkhunter(ctx context.Context, logf Logf) (engineResult, error) {
	bin, err := ensureInstalled(ctx, "rkhunter", "rkhunter", logf)
	if err != nil {
		return engineResult{}, err
	}

	// A freshly installed rkhunter has no baseline file properties database, which
	// makes it warn about every checked binary. Seed it once so warnings reflect
	// real anomalies rather than "no known-good baseline". Best effort.
	logf("rkhunter: updating file-property baseline")
	_, _ = runCmd(ctx, 3*time.Minute, bin, "--propupd", "--nocolors", "--sk")

	logf("rkhunter: checking for rootkits and local exploits")
	out, err := runCmd(ctx, 8*time.Minute, bin, "--check", "--sk", "--nocolors", "--rwo")
	if err != nil {
		return engineResult{}, err
	}

	res := engineResult{log: "[rkhunter] rootkit check complete"}
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// --rwo emits lines like "Warning: The file '/usr/bin/…' ...".
		if !strings.HasPrefix(strings.ToLower(line), "warning:") {
			continue
		}
		msg := strings.TrimSpace(line[len("warning:"):])
		if msg == "" || seen[msg] {
			continue
		}
		seen[msg] = true
		res.findings = append(res.findings, api.Finding{
			Severity:    "high",
			Engine:      "rkhunter",
			Title:       truncate(msg, 200),
			Detail:      msg,
			Remediation: "Investigate this rkhunter warning; if the change is legitimate, update the baseline with `rkhunter --propupd`.",
		})
	}
	if len(res.findings) == 0 {
		res.log = "[rkhunter] no warnings — system clean"
	}
	return res, nil
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
