package scan

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// chkFPSingle are chkrootkit's well-known single-line false positives on modern
// kernels/containers. Matched as lowercase substrings. These stay VISIBLE and
// dismissable but are down-ranked to medium with context — never auto-hidden
// (we must never suppress a possible-malware detection) and never left at high
// without the operator confirming against a second scanner.
var chkFPSingle = []string{"rh-sharpe", "sharpe", "xor.ddos", "bpfdoor", "suckit", "promisc"}

const chkFPRemediation = "chkrootkit reports this as a false positive on modern kernels and containers. Confirm against rkhunter and ClamAV/maldet before treating the host as compromised; dismiss if unconfirmed."

// runChkrootkit installs and runs chkrootkit as a second-opinion rootkit scanner
// alongside rkhunter (`chkrootkit -q` — quiet, only prints lines of interest).
//
// chkrootkit emits two shapes of output:
//   - single "INFECTED" / "Possible ... installed" / "Warning:" lines, and
//   - MULTI-LINE blocks — a header like "WARNING: The following suspicious PHP
//     files were found:" or "WARNING: Output from ifpromisc:" followed by the
//     offending paths/output on the NEXT lines.
//
// Both are handled: block content is gathered into the finding detail so it
// actually names the files/output, and chkrootkit's infamous false positives are
// down-ranked (visible + dismissable) so they don't drown real signal. A clean
// host produces no findings.
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
	lines := strings.Split(out, "\n")

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)

		// --- multi-line block: "The following ... were found:" / "Output from ...:"
		if subject, kind, ok := chkBlockHeader(lower); ok {
			var content []string
			for j := i + 1; j < len(lines); j++ {
				c := strings.TrimSpace(lines[j])
				if c == "" {
					break
				}
				if chkIsHeaderLine(strings.ToLower(c)) {
					break
				}
				content = append(content, c)
				i = j
			}
			// Contentless block: suppress rather than emit a finding that names
			// nothing (a header with no paths/output is noise).
			if len(content) == 0 {
				logf("chkrootkit: %q block had no content lines; suppressed", subject)
				continue
			}
			// chkrootkit's "suspicious PHP files" check is pure false-positive
			// noise on any PHP/WordPress/Laravel host — it flags legitimate app
			// code. Real PHP malware is covered by ClamAV, maldet, and the
			// WordPress engine, so we consume its lines (so they don't leak into
			// the next block) but emit NOTHING.
			if strings.Contains(strings.ToLower(subject), "php") {
				logf("chkrootkit: suppressing crude PHP-files check (%d paths) — covered by ClamAV/maldet/WordPress", len(content))
				continue
			}
			sev, code, title, rem := chkBlockMeta(subject, kind, len(content))
			res.findings = append(res.findings, api.Finding{
				Severity:    sev,
				Engine:      "chkrootkit",
				Code:        code,
				Title:       title,
				Detail:      "chkrootkit reported:\n" + strings.Join(content, "\n"),
				Remediation: rem,
			})
			continue
		}

		// --- single-line detections
		if !strings.Contains(lower, "infected") && !strings.HasPrefix(lower, "warning") && !strings.Contains(lower, "possible") {
			continue
		}
		// chkrootkit's own footgun: "Vulnerable but disabled" is informational.
		if strings.Contains(lower, "vulnerable but disabled") {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true

		// A stable code keeps a dismissal sticking across re-scans (the master
		// dedupes on engine|code). Known FPs get a code from the matched keyword;
		// other detections get one from the normalized line text.
		sev, rem := "high", "Investigate this chkrootkit detection. Confirm against a second scanner (rkhunter/ClamAV); if legitimate, whitelist it, otherwise treat the host as compromised."
		code := "chkrootkit-" + chkSlug(line)
		if fp := chkMatchFP(lower); fp != "" {
			sev, rem = "medium", chkFPRemediation
			code = "chkrootkit-fp-" + fp
		}
		res.findings = append(res.findings, api.Finding{
			Severity:    sev,
			Engine:      "chkrootkit",
			Code:        code,
			Title:       truncate(chkCleanTitle(line), 200),
			Detail:      line,
			Remediation: rem,
		})
	}

	if len(res.findings) == 0 {
		res.log = "[chkrootkit] no infections found — clean"
	}
	return res, nil
}

// chkBlockHeader detects a multi-line block header and returns its subject.
// kind is "found" for "the following <subject> were found:" or "output" for
// "output from <subject>:".
func chkBlockHeader(lower string) (subject, kind string, ok bool) {
	if i := strings.Index(lower, "the following "); i >= 0 {
		rest := lower[i+len("the following "):]
		if j := strings.Index(rest, " were found"); j >= 0 {
			return strings.TrimSpace(rest[:j]), "found", true
		}
	}
	if i := strings.Index(lower, "output from "); i >= 0 {
		rest := strings.TrimSpace(lower[i+len("output from "):])
		return strings.TrimSuffix(rest, ":"), "output", true
	}
	return "", "", false
}

// chkIsHeaderLine reports whether a line starts a new chkrootkit section (so
// block-content capture stops there rather than swallowing the next check).
func chkIsHeaderLine(lower string) bool {
	if strings.HasPrefix(lower, "warning") || strings.HasPrefix(lower, "checking") {
		return true
	}
	if strings.Contains(lower, "infected") || strings.Contains(lower, "not found") || strings.Contains(lower, "not infected") {
		return true
	}
	if strings.Contains(lower, "output from ") {
		return true
	}
	if strings.Contains(lower, "the following ") && strings.Contains(lower, "were found") {
		return true
	}
	return false
}

// chkMatchFP returns the known-FP keyword a single-line detection matches, or ""
// if none. The keyword is used to build a stable finding code.
func chkMatchFP(lower string) string {
	for _, fp := range chkFPSingle {
		if strings.Contains(lower, fp) {
			return strings.Trim(strings.ReplaceAll(fp, ".", "-"), " ")
		}
	}
	return ""
}

// chkCleanTitle strips chkrootkit's "WARNING:" prefix and trailing colon so the
// finding title reads cleanly.
func chkCleanTitle(line string) string {
	s := strings.TrimSpace(line)
	if len(s) >= 8 && strings.EqualFold(s[:8], "warning:") {
		s = strings.TrimSpace(s[8:])
	}
	return strings.TrimSuffix(s, ":")
}

// chkSlug builds a short, stable slug from a detection line (lowercase, hyphen-
// separated, first few words) for use as a finding code.
func chkSlug(line string) string {
	s := strings.ToLower(chkCleanTitle(line))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '/':
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	if len(slug) > 60 {
		slug = strings.Trim(slug[:60], "-")
	}
	if slug == "" {
		slug = "detection"
	}
	return slug
}

// chkBlockMeta maps a block subject to its severity, code, title, and
// remediation. Hidden-dir noise is low; the promiscuous-interface check is
// medium (visible, dismissable). The PHP-files block is suppressed upstream.
func chkBlockMeta(subject, kind string, n int) (sev, code, title, rem string) {
	s := strings.ToLower(subject)
	count := " (" + strconv.Itoa(n) + ")"

	switch {
	case strings.Contains(s, "ifpromisc") || strings.Contains(s, "promisc"):
		return "medium", "chkrootkit-ifpromisc", "Promiscuous Interface Check",
			chkFPRemediation + " Promiscuous mode is common on virtualized/bridged hosts and is usually benign."
	case strings.Contains(s, "files and directories") || strings.Contains(s, "suspicious files"):
		return "low", "chkrootkit-suspicious-files", "Suspicious Hidden Files/Directories" + count,
			"These are usually benign hidden directories created by packages/build tools (e.g. /usr/lib/.build-id, /etc/.git). Verify each listed path; if legitimate, dismiss this as a false positive."
	default:
		// Any other captured block: keep visible with its content.
		label := chkTitleCase(subject)
		if kind == "output" {
			return "low", "chkrootkit-output", "Output From " + label + count, chkFPRemediation
		}
		return "medium", "chkrootkit-block", label + count,
			"chkrootkit reported the listed items. Review each and confirm against rkhunter/ClamAV; dismiss if legitimate."
	}
}

// chkTitleCase upper-cases the first letter of each word in s.
func chkTitleCase(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if w != "" {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
