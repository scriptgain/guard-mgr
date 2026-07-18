package scan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// runClamAV runs an on-disk malware scan of the host's web/data directories.
//
// It installs clamav + clamav-freshclam, makes sure a virus database is present
// (a first `freshclam` pulls ~200MB and can take a few minutes), then runs
// `clamscan -ri --no-summary` recursively over the bounded set of web/data dirs
// from malwareScanDirs(). Every "<file>: <Signature> FOUND" line becomes a
// high-severity finding carrying the path + signature. Detect-only — quarantine
// / removal is Phase 5.
func runClamAV(ctx context.Context, _ Options, logf Logf) (engineResult, error) {
	bin, err := ensureInstalled(ctx, "clamscan", "clamav", logf)
	if err != nil {
		return engineResult{}, err
	}
	// freshclam is a separate package; needed only to populate/refresh the DB.
	_, _ = ensureInstalled(ctx, "freshclam", "clamav-freshclam", logf)

	if err := ensureClamDB(ctx, logf); err != nil {
		// No DB means clamscan cannot run meaningfully — surface as info, not fail.
		return engineResult{
			log: "[clamav] " + err.Error(),
			findings: []api.Finding{{
				Severity: "info", Engine: "clamav", Code: "clamav-no-db",
				Title:  "ClamAV Virus Database Unavailable",
				Detail: "ClamAV is installed but its signature database could not be prepared (" + err.Error() + "), so no malware scan was performed.",
			}},
		}, nil
	}

	dirs := malwareScanDirs()
	if len(dirs) == 0 {
		return engineResult{
			log: "[clamav] no web/data directories present to scan",
			findings: []api.Finding{{
				Severity: "info", Engine: "clamav", Code: "clamav-no-targets",
				Title:  "No Scan Targets",
				Detail: "None of the common web/data directories were present on this host, so ClamAV had nothing to scan.",
			}},
		}, nil
	}

	logf("clamav: scanning %d path(s): %s", len(dirs), strings.Join(dirs, ", "))
	// -r recursive, -i print infected only, --no-summary keep output to FOUND lines.
	// --max-filesize/--max-scansize keep a single huge archive from stalling the scan.
	// Skip dependency/VCS/cache trees: they are managed by package managers and
	// balloon the scan (a full-fleet vendor sweep times out) without adding real
	// coverage — web-shell malware lands in uploads/webroots, not composer deps.
	args := []string{"-ri", "--no-summary", "--max-filesize=200M", "--max-scansize=400M",
		"--exclude-dir=(^|/)(\\.git|node_modules|vendor|storage/framework|bootstrap/cache)($|/)"}
	args = append(args, dirs...)
	out, err := runCmd(ctx, 20*time.Minute, bin, args...)
	if err != nil {
		return engineResult{log: tailLog("clamav", out)}, err
	}

	res := engineResult{log: "[clamav] scan complete"}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasSuffix(line, "FOUND") {
			continue
		}
		// Line shape: "/path/to/file: Signature.Name FOUND"
		path, sig := line, ""
		if i := strings.LastIndex(line, ": "); i >= 0 {
			path = strings.TrimSpace(line[:i])
			sig = strings.TrimSpace(strings.TrimSuffix(line[i+2:], "FOUND"))
		}
		res.findings = append(res.findings, api.Finding{
			Severity:    "high",
			Engine:      "clamav",
			Code:        truncate(path, 120),
			Title:       "Malware: " + sig,
			Detail:      "ClamAV matched signature '" + sig + "' in " + path + ".",
			Remediation: "Verify the file, then remove or quarantine it and audit how it was written. Rotate any credentials the affected site could expose.",
		})
	}
	if len(res.findings) == 0 {
		res.log = "[clamav] scanned " + strings.Join(dirs, ", ") + " — no malware found"
		res.findings = append(res.findings, api.Finding{
			Severity: "info", Engine: "clamav", Code: "clamav-clean",
			Title:  "ClamAV Scan Clean",
			Detail: "ClamAV scanned " + strings.Join(dirs, ", ") + " and found no malware.",
		})
	}
	return res, nil
}

// ensureClamDB makes sure ClamAV has a signature database. If the standard DB
// dir already holds a *.cvd/*.cld it is used as-is; otherwise a one-shot
// freshclam populates it. freshclam contends with the clamav-freshclam service
// for its lock, so a failure here is not fatal if a DB already exists.
func ensureClamDB(ctx context.Context, logf Logf) error {
	if clamDBPresent() {
		return nil
	}
	fresh, err := exec.LookPath("freshclam")
	if err != nil {
		return err
	}
	logf("clamav: no signature DB found; running freshclam (first pull is ~200MB, please wait)")
	// The packaged clamav-freshclam service may hold the lock; stop it best-effort.
	_, _ = runCmd(ctx, 20*time.Second, "systemctl", "stop", "clamav-freshclam")
	out, _ := runCmd(ctx, 15*time.Minute, fresh, "--stdout")
	if clamDBPresent() {
		logf("clamav: signature DB ready")
		return nil
	}
	detail := lastLines(out, 2)
	if detail == "" {
		detail = "freshclam did not produce a database"
	}
	return fmt.Errorf("freshclam failed: %s", detail)
}

// clamDBPresent reports whether a ClamAV signature DB exists on disk.
func clamDBPresent() bool {
	for _, dir := range []string{"/var/lib/clamav", "/usr/local/share/clamav"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if strings.HasSuffix(n, ".cvd") || strings.HasSuffix(n, ".cld") {
				return true
			}
		}
	}
	return false
}
