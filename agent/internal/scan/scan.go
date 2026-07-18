// Package scan runs local security scanners on the host the agent lives on and
// turns their output into a hardening score plus a set of findings.
//
// The agent runs as root on the scanned server, so each engine is a read-only
// audit executed in-place:
//
//   - Lynis       — system hardening audit; its hardening_index is the score.
//   - rkhunter    — rootkit / local-exploit warnings.
//   - chkrootkit  — second-opinion rootkit / infection scanner.
//   - ClamAV      — on-disk malware scan of web/data dirs.
//   - maldet      — Linux Malware Detect scan (best effort).
//   - ufw         — host firewall state and exposed ports.
//   - fail2ban    — brute-force jail status (read only).
//   - wordpress   — per-site WordPress core/plugin/theme + webshell audit.
//
// A missing engine binary is installed via apt-get when possible; if it still
// cannot run, that engine records an informational finding and the scan carries
// on. One failed engine never fails the whole scan.
package scan

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// Logf is a simple printf-style logger the caller supplies.
type Logf func(format string, a ...any)

// Options carries scan-wide inputs an engine may need beyond the host itself.
// It is passed to every engine runner; most ignore it.
type Options struct {
	// WPScanToken enables the WPScan vulnerability API in the wordpress engine.
	// Empty falls back to update-available heuristics — the token is optional.
	WPScanToken string
}

// engineResult is one engine's contribution to a scan.
type engineResult struct {
	findings []api.Finding
	score    *int // non-nil only for score-bearing engines (e.g. Lynis)
	log      string
}

// engineFunc runs one engine and returns its findings (+ optional score).
type engineFunc func(ctx context.Context, opts Options, logf Logf) (engineResult, error)

// registry maps an engine key to its runner. Adding a new engine is a single
// entry here plus its run function — no change to the dispatch loop. Keep keys
// in sync with the master's engine list (JobController::ENGINES).
var registry = map[string]engineFunc{
	"lynis":      runLynis,
	"rkhunter":   runRkhunter,
	"chkrootkit": runChkrootkit,
	"clamav":     runClamAV,
	"maldet":     runMaldet,
	"ufw":        runUfw,
	"fail2ban":   runFail2ban,
	"wordpress":  runWordPress,
}

// Supported reports whether an engine key has a runner registered.
func Supported(key string) bool {
	_, ok := registry[key]
	return ok
}

// Run executes the requested engines and assembles a single scan report. The
// returned Report always carries a score and (possibly empty) findings; status
// is left as "success" for the master to downgrade to "warn" on high findings.
func Run(ctx context.Context, engines []string, opts Options, logf Logf) api.Report {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	var findings []api.Finding
	var log strings.Builder
	var lynisScore *int
	engineErrored := false

	for _, engine := range engines {
		run, ok := registry[engine]
		if !ok {
			logf("engine %s: unknown, skipping", engine)
			continue
		}
		res, err := run(ctx, opts, logf)

		if err != nil {
			// Fail-soft on the scan as a whole, but an engine that could not
			// finish means INCOMPLETE coverage — surface it as a high-severity
			// warning (so the run rolls up to "warn", never a clean success) and
			// keep running the other engines.
			engineErrored = true
			logf("engine %s: %v", engine, err)
			log.WriteString(fmt.Sprintf("[%s] error: %v\n", engine, err))
			findings = append(findings, api.Finding{
				Severity:    "high",
				Engine:      engine,
				Code:        engine + "-incomplete",
				Title:       capitalizeWord(engine) + " Scan Did Not Complete (Results Incomplete)",
				Detail:      "The " + engine + " engine did not finish (" + err.Error() + "), so its coverage for this scan is incomplete and may have missed issues.",
				Remediation: "Re-run the scan; if it keeps failing, narrow the scope (for malware scans, tighten the target directories) or investigate the engine on the host.",
			})
			continue
		}

		findings = append(findings, res.findings...)
		// Adopt an engine-reported hardening index (Lynis today) as the score.
		if res.score != nil {
			lynisScore = res.score
		}
		if res.log != "" {
			log.WriteString(res.log)
			log.WriteByte('\n')
		}
	}

	// Score: prefer Lynis's own hardening index; otherwise derive one from the
	// severity mix so a scan without Lynis still yields a meaningful number.
	score := lynisScore
	if score == nil {
		s := scoreFromFindings(findings)
		score = &s
	}

	// An engine that errored means the scan is incomplete: report "warn" so the
	// master never rolls a partial scan up to a clean success. (High findings
	// also drive warn on the master; this covers the case where the only issue
	// is an engine that could not finish.)
	status := api.RunSuccess
	if engineErrored {
		status = api.RunWarn
	}

	return api.Report{
		Status:   status,
		Score:    score,
		Findings: findings,
		Log:      strings.TrimSpace(log.String()),
	}
}

// capitalizeWord upper-cases the first letter of s (ASCII), for titles.
func capitalizeWord(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// scoreFromFindings computes a 0-100 hardening score from finding severities,
// used only when Lynis did not run. Starts at 100 and deducts per finding.
func scoreFromFindings(findings []api.Finding) int {
	score := 100
	weight := map[string]int{"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 0}
	for _, f := range findings {
		score -= weight[severityKey(f.Severity)]
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// severityKey normalizes a severity string for weight lookup.
func severityKey(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	default:
		return "info"
	}
}

// runCmd runs a command with a timeout and returns its combined stdout+stderr.
// A non-zero exit status is NOT treated as an error (scanners routinely exit
// non-zero when they find something); only a failure to start is returned.
func runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	out, err := cmd.CombinedOutput()
	if cctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("%s timed out after %s", name, timeout)
	}
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// Non-zero exit — expected for scanners; return output, no error.
			return string(out), nil
		}
		return string(out), err
	}
	return string(out), nil
}

// ensureInstalled makes sure a binary is on PATH, installing pkg with apt-get
// when it is missing. Returns the absolute binary path or an error.
func ensureInstalled(ctx context.Context, bin, pkg string, logf Logf) (string, error) {
	if p, err := exec.LookPath(bin); err == nil {
		return p, nil
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return "", fmt.Errorf("%s not installed and apt-get unavailable to install %s", bin, pkg)
	}
	logf("installing %s (apt-get install -y %s)", bin, pkg)
	ictx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	install := exec.CommandContext(ictx, "apt-get", "install", "-y", pkg)
	install.Env = append(install.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := install.CombinedOutput(); err != nil {
		return "", fmt.Errorf("apt-get install %s failed: %v: %s", pkg, err, strings.TrimSpace(lastLines(string(out), 3)))
	}
	p, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("%s still not found after installing %s", bin, pkg)
	}
	return p, nil
}

// lastLines returns the last n non-empty lines of s, joined by "; ".
func lastLines(s string, n int) string {
	lines := []string{}
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "; ")
}
