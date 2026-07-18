package scan

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// lynisReport is where Lynis writes its machine-readable results.
const lynisReport = "/var/log/lynis-report.dat"

// runLynis runs `lynis audit system` and parses /var/log/lynis-report.dat:
//
//   - hardening_index=<n>  -> the scan's hardening score (0-100)
//   - warning[]=id|text|.. -> a high-severity finding
//   - suggestion[]=id|txt| -> a low-severity finding
//
// The control id (first pipe-delimited field) becomes the finding code so the
// UI can link it back to the Lynis control.
func runLynis(ctx context.Context, logf Logf) (engineResult, error) {
	bin, err := ensureInstalled(ctx, "lynis", "lynis", logf)
	if err != nil {
		return engineResult{}, err
	}

	logf("lynis: auditing system (this can take a minute)")
	out, err := runCmd(ctx, 8*time.Minute, bin, "audit", "system", "--quiet", "--no-colors")
	if err != nil {
		return engineResult{}, err
	}

	data, rerr := os.ReadFile(lynisReport)
	if rerr != nil {
		return engineResult{log: tailLog("lynis", out)}, fmt.Errorf("lynis ran but no report at %s: %w", lynisReport, rerr)
	}

	res := engineResult{log: fmt.Sprintf("[lynis] audited system; parsed %s", lynisReport)}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "hardening_index":
			if n, e := strconv.Atoi(strings.TrimSpace(val)); e == nil && n >= 0 && n <= 100 {
				score := n
				res.score = &score
			}
		case "warning[]":
			code, title, detail := parseLynisEntry(val)
			res.findings = append(res.findings, api.Finding{
				Severity:    "high",
				Engine:      "lynis",
				Code:        code,
				Title:       title,
				Detail:      detail,
				Remediation: "Review the Lynis control " + code + " and apply the suggested hardening.",
			})
		case "suggestion[]":
			code, title, detail := parseLynisEntry(val)
			res.findings = append(res.findings, api.Finding{
				Severity:    "low",
				Engine:      "lynis",
				Code:        code,
				Title:       title,
				Detail:      detail,
				Remediation: "Consider Lynis suggestion " + code + " to raise the hardening index.",
			})
		}
	}
	return res, nil
}

// parseLynisEntry splits a warning[]/suggestion[] value ("ID|text|extra|extra")
// into a control code, a title, and any remaining detail.
func parseLynisEntry(val string) (code, title, detail string) {
	parts := strings.Split(val, "|")
	clean := func(s string) string {
		s = strings.TrimSpace(s)
		if s == "-" {
			return ""
		}
		return s
	}
	if len(parts) > 0 {
		code = clean(parts[0])
	}
	if len(parts) > 1 {
		title = clean(parts[1])
	}
	if title == "" {
		title = code
	}
	extras := []string{}
	for _, p := range parts[2:] {
		if c := clean(p); c != "" {
			extras = append(extras, c)
		}
	}
	detail = strings.Join(extras, " — ")
	return code, title, detail
}

// tailLog returns a short, prefixed tail of an engine's stdout for the log pane.
func tailLog(engine, out string) string {
	return fmt.Sprintf("[%s] %s", engine, lastLines(out, 5))
}
