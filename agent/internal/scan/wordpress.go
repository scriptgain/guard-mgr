package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// wpRootGlobs are the docroots under which WordPress installs are searched for.
var wpRootGlobs = []string{
	"/home/*/htdocs",
	"/home/*/htdocs/*",
	"/home/*/public_html",
	"/var/www",
	"/var/www/*",
	"/srv/www",
	"/usr/share/nginx/html",
}

// wpWalkMaxDepth bounds how deep below a docroot a wp-config.php is looked for,
// so the walk stays fast on hosts with large trees.
const wpWalkMaxDepth = 4

// webshellPatterns are substrings whose presence in a PHP file under wp-content
// is a strong backdoor/webshell signal. Kept deliberately high-signal.
var webshellPatterns = []string{
	"eval(",
	"base64_decode(",
	"gzinflate(",
	"gzuncompress(",
	"str_rot13(",
	"assert(",
	"system(",
	"shell_exec(",
	"passthru(",
	"proc_open(",
	"FilesMan",   // common webshell (b374k / WSO) marker
	"c99shell",   // c99 shell
	"r57shell",   // r57 shell
	"$_POST[",    // paired with eval on the same line below
	"$_REQUEST[", // ditto
}

// evalOnDataRe flags the classic dynamic-exec-of-request-data webshell shape,
// e.g. eval($_POST['x']) / assert($_REQUEST[...]) / preg_replace with the /e
// modifier, which are almost never legitimate in theme/plugin code.
var evalOnDataRe = regexp.MustCompile(`(?i)(eval|assert|system|shell_exec|passthru|create_function)\s*\(\s*(\$_(POST|GET|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate|str_rot13)`)

// pregReplaceERe flags the deprecated preg_replace /e modifier (arbitrary code
// execution), a hallmark of injected backdoors.
var pregReplaceERe = regexp.MustCompile(`preg_replace\s*\(\s*['"].*/e['"]`)

// runWordPress locates every WordPress install on the host and audits each one:
// core version + checksum integrity, plugin/theme inventory + integrity +
// update status, known-vulnerability lookup (WPScan API when a token is set,
// else an outdated-version heuristic), and a webshell/backdoor grep of
// wp-content. Findings carry the site path in Code/Detail. A host with no WP
// installs yields a single info finding.
func runWordPress(ctx context.Context, opts Options, logf Logf) (engineResult, error) {
	sites := findWordPressInstalls(logf)
	if len(sites) == 0 {
		return engineResult{
			log: "[wordpress] no WordPress installs found",
			findings: []api.Finding{{
				Severity: "info", Engine: "wordpress", Code: "wp-none",
				Title:  "No WordPress Installs Found",
				Detail: "No wp-config.php was found under the common docroots (/home/*/htdocs, /home/*/public_html, /var/www). Nothing to scan for WordPress.",
			}},
		}, nil
	}

	wp := locateWpCli(ctx, logf) // "" when wp-cli/php unavailable
	res := engineResult{}
	var logLines []string
	for _, site := range sites {
		logf("wordpress: auditing %s", site)
		f := auditSite(ctx, wp, site, opts.WPScanToken, logf)
		res.findings = append(res.findings, f...)
		logLines = append(logLines, "[wordpress] "+site+": "+strconv.Itoa(len(f))+" finding(s)")
	}
	res.log = strings.Join(logLines, "\n")
	return res, nil
}

// findWordPressInstalls walks the docroots and returns the directory of every
// wp-config.php found (deduped, bounded depth).
func findWordPressInstalls(logf Logf) []string {
	seen := map[string]bool{}
	var sites []string
	roots := map[string]bool{}
	for _, g := range wpRootGlobs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() {
				roots[filepath.Clean(m)] = true
			}
		}
	}
	for root := range roots {
		base := strings.Count(root, string(os.PathSeparator))
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.Count(path, string(os.PathSeparator))-base > wpWalkMaxDepth {
					return filepath.SkipDir
				}
				// wp-content is huge and never holds wp-config.php; don't descend it.
				if d.Name() == "wp-content" || d.Name() == "node_modules" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Name() == "wp-config.php" {
				dir := filepath.Dir(path)
				if !seen[dir] {
					seen[dir] = true
					sites = append(sites, dir)
				}
			}
			return nil
		})
	}
	if len(sites) > 0 {
		logf("wordpress: found %d install(s)", len(sites))
	}
	return sites
}

// auditSite runs the full audit for one WordPress directory.
func auditSite(ctx context.Context, wp, site, token string, logf Logf) []api.Finding {
	owner := fileOwner(site)
	var findings []api.Finding

	// Resolve the core version — via wp-cli when available, else from
	// wp-includes/version.php on disk.
	version := ""
	if wp != "" {
		if out, ok := wpRun(ctx, wp, site, owner, "core", "version"); ok {
			version = strings.TrimSpace(out)
		}
	}
	if version == "" {
		version = coreVersionFromDisk(site)
	}
	if version != "" {
		findings = append(findings, api.Finding{
			Severity: "info", Engine: "wordpress", Code: "wp-core:" + site,
			Title:  "WordPress " + version,
			Detail: "WordPress core version " + version + " at " + site + ".",
		})
	}

	if wp == "" {
		// No wp-cli/php: fall back to the filesystem-only checks.
		findings = append(findings, api.Finding{
			Severity: "low", Engine: "wordpress", Code: "wp-nocli:" + site,
			Title:       "Limited WordPress Scan (wp-cli Unavailable)",
			Detail:      "PHP/wp-cli is not available on this host, so core/plugin checksum verification and update checks were skipped for " + site + ". The webshell scan still ran.",
			Remediation: "Install PHP CLI so the agent can run wp-cli for full WordPress integrity checks.",
		})
		findings = append(findings, webshellFindings(site)...)
		return findings
	}

	findings = append(findings, coreChecksumFindings(ctx, wp, site, owner)...)
	findings = append(findings, componentFindings(ctx, wp, site, owner, "plugin")...)
	findings = append(findings, componentFindings(ctx, wp, site, owner, "theme")...)
	findings = append(findings, vulnFindings(ctx, wp, site, owner, version, token, logf)...)
	findings = append(findings, webshellFindings(site)...)
	return findings
}

// coreChecksumFindings runs `wp core verify-checksums`. Any line naming a file
// that differs from the official checksum (tampered/injected/missing core file)
// becomes a high finding.
func coreChecksumFindings(ctx context.Context, wp, site, owner string) []api.Finding {
	out, ok := wpRun(ctx, wp, site, owner, "core", "verify-checksums")
	if !ok && strings.TrimSpace(out) == "" {
		return nil
	}
	var findings []api.Finding
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		if !strings.Contains(low, "warning:") && !strings.Contains(low, "error:") {
			continue
		}
		if !strings.Contains(low, "checksum") && !strings.Contains(low, "should not exist") && !strings.Contains(low, "doesn't verify") && !strings.Contains(low, "file was added") {
			continue
		}
		findings = append(findings, api.Finding{
			Severity: "high", Engine: "wordpress", Code: "wp-core-tamper:" + site,
			Title:       "Modified WordPress Core File",
			Detail:      site + ": " + line,
			Remediation: "A core file does not match the official checksum — a strong sign of compromise. Reinstall core (`wp core download --force`) after backing up and investigating.",
		})
	}
	if len(findings) == 0 && ok {
		findings = append(findings, api.Finding{
			Severity: "info", Engine: "wordpress", Code: "wp-core-ok:" + site,
			Title:  "Core Checksums Verified",
			Detail: site + ": all WordPress core files match the official checksums.",
		})
	}
	return findings
}

// componentFindings handles plugins or themes (kind = "plugin"|"theme"): it
// lists them as JSON, flags any with an available update as low/medium, and for
// plugins runs verify-checksums to flag modified files as high.
func componentFindings(ctx context.Context, wp, site, owner, kind string) []api.Finding {
	out, ok := wpRun(ctx, wp, site, owner, kind, "list", "--format=json", "--fields=name,status,version,update,update_version")
	if !ok {
		return nil
	}
	var items []struct {
		Name          string `json:"name"`
		Status        string `json:"status"`
		Version       string `json:"version"`
		Update        string `json:"update"`
		UpdateVersion string `json:"update_version"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &items); err != nil {
		return nil
	}
	var findings []api.Finding
	for _, it := range items {
		if it.Update == "available" {
			// An out-of-date active component is a bigger risk than an inactive one.
			sev := "low"
			if it.Status == "active" {
				sev = "medium"
			}
			findings = append(findings, api.Finding{
				Severity: sev, Engine: "wordpress", Code: "wp-outdated-" + kind + ":" + site + "/" + it.Name,
				Title:       "Outdated " + capitalizeWord(kind) + ": " + it.Name + " " + it.Version,
				Detail:      site + ": " + kind + " '" + it.Name + "' is at " + it.Version + "; " + it.UpdateVersion + " is available. Outdated components are the most common WordPress entry point.",
				Remediation: "Update the " + kind + " (`wp " + kind + " update " + it.Name + "`), or remove it if unused.",
			})
		}
	}
	// Plugin file integrity (themes have no checksum service).
	if kind == "plugin" {
		if vc, vok := wpRun(ctx, wp, site, owner, "plugin", "verify-checksums", "--all"); vok || strings.TrimSpace(vc) != "" {
			for _, line := range strings.Split(vc, "\n") {
				line = strings.TrimSpace(line)
				low := strings.ToLower(line)
				if !strings.Contains(low, "warning:") && !strings.Contains(low, "error:") {
					continue
				}
				if !strings.Contains(low, "checksum") && !strings.Contains(low, "verify") && !strings.Contains(low, "added") {
					continue
				}
				findings = append(findings, api.Finding{
					Severity: "high", Engine: "wordpress", Code: "wp-plugin-tamper:" + site,
					Title:       "Modified Plugin File",
					Detail:      site + ": " + line,
					Remediation: "A plugin file differs from the wordpress.org release — possible injected code. Reinstall the plugin from a trusted source after investigating.",
				})
			}
		}
	}
	return findings
}

// vulnFindings flags known-vulnerable components. With a WPScan API token it
// queries the WPScan v3 API for the core version and each plugin; without a
// token it falls back to the outdated-version heuristic already emitted by
// componentFindings and simply notes that a token would deepen the check.
func vulnFindings(ctx context.Context, wp, site, owner, version, token string, logf Logf) []api.Finding {
	if strings.TrimSpace(token) == "" {
		return []api.Finding{{
			Severity: "info", Engine: "wordpress", Code: "wp-vuln-heuristic:" + site,
			Title:       "Vulnerability Check: Heuristic Mode",
			Detail:      site + ": no WPScan API token is configured, so known-vulnerability lookups fell back to update-available heuristics (outdated = potential risk). Add a token under Settings → Integrations for CVE-level detail.",
			Remediation: "Set a WPScan API token to enable precise vulnerability matching against the WPScan database.",
		}}
	}

	var findings []api.Finding
	// Core.
	if version != "" {
		for _, v := range wpscanCore(ctx, token, version, logf) {
			findings = append(findings, api.Finding{
				Severity: "high", Engine: "wordpress", Code: "wp-vuln-core:" + site,
				Title:       "Vulnerable WordPress Core: " + version,
				Detail:      site + ": " + v,
				Remediation: "Update WordPress core to a fixed release (`wp core update`).",
			})
		}
	}
	// Plugins.
	if out, ok := wpRun(ctx, wp, site, owner, "plugin", "list", "--format=json", "--fields=name,version"); ok {
		var plugins []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(out)), &plugins) == nil {
			for _, p := range plugins {
				for _, v := range wpscanPlugin(ctx, token, p.Name, p.Version, logf) {
					findings = append(findings, api.Finding{
						Severity: "high", Engine: "wordpress", Code: "wp-vuln-plugin:" + site + "/" + p.Name,
						Title:       "Vulnerable Plugin: " + p.Name + " " + p.Version,
						Detail:      site + ": " + v,
						Remediation: "Update or remove the plugin '" + p.Name + "'.",
					})
				}
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, api.Finding{
			Severity: "info", Engine: "wordpress", Code: "wp-vuln-clean:" + site,
			Title:  "No Known Vulnerabilities (WPScan)",
			Detail: site + ": the WPScan database reported no known vulnerabilities for the installed core version and plugins.",
		})
	}
	return findings
}

// webshellFindings greps PHP files under wp-content for backdoor/webshell
// signatures and returns a high finding per hit (file + line number). Bounded:
// only *.php, only under wp-content, first hit per file.
func webshellFindings(site string) []api.Finding {
	root := filepath.Join(site, "wp-content")
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return nil
	}
	var findings []api.Finding
	count := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if count >= 200 { // hard cap so a compromised host can't flood the report
			return filepath.SkipAll
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".php") {
			return nil
		}
		if hit, line, lineNo := scanPHPForShell(path); hit != "" {
			count++
			findings = append(findings, api.Finding{
				Severity: "high", Engine: "wordpress", Code: "wp-shell:" + relPath(site, path),
				Title:       "Possible Webshell/Backdoor: " + filepath.Base(path),
				Detail:      site + ": " + relPath(site, path) + ":" + strconv.Itoa(lineNo) + " matched '" + hit + "' — " + truncate(strings.TrimSpace(line), 160),
				Remediation: "Inspect this file. Dynamic execution of request data or obfuscated payloads in wp-content is a classic backdoor; remove it and audit access logs.",
			})
		}
		return nil
	})
	return findings
}

// scanPHPForShell scans one PHP file and returns the first strong webshell
// signal (matched token, the offending line, line number), or ("",...) if clean.
func scanPHPForShell(path string) (string, string, int) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // allow long minified lines
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		// Highest-confidence patterns first.
		if evalOnDataRe.MatchString(line) {
			return "dynamic-exec-of-input", line, n
		}
		if pregReplaceERe.MatchString(line) {
			return "preg_replace /e", line, n
		}
		for _, p := range webshellPatterns {
			if strings.Contains(line, p) {
				// Lone base64_decode/eval is common in legit minified libs, so only
				// flag when it co-occurs with another suspicious token on the line.
				if suspiciousCompanions(line) >= 2 {
					return p, line, n
				}
			}
		}
	}
	return "", "", 0
}

// suspiciousCompanions counts how many distinct webshell patterns appear on a
// single line — two or more together is a strong obfuscation signal.
func suspiciousCompanions(line string) int {
	c := 0
	for _, p := range webshellPatterns {
		if strings.Contains(line, p) {
			c++
		}
	}
	return c
}

// ---- wp-cli plumbing ---------------------------------------------------------

// locateWpCli returns a command prefix for running wp-cli, or "" if PHP is not
// available. It prefers a `wp` on PATH, else downloads wp-cli.phar to /tmp.
func locateWpCli(ctx context.Context, logf Logf) string {
	if _, err := exec.LookPath("php"); err != nil {
		logf("wordpress: php not found; running filesystem-only checks")
		return ""
	}
	if p, err := exec.LookPath("wp"); err == nil {
		return p
	}
	phar := "/tmp/guard-wp-cli.phar"
	if fi, err := os.Stat(phar); err == nil && fi.Size() > 0 {
		return "php " + phar
	}
	if _, err := exec.LookPath("curl"); err != nil {
		logf("wordpress: wp-cli absent and curl unavailable to fetch it")
		return ""
	}
	logf("wordpress: fetching wp-cli to %s", phar)
	if _, err := runCmd(ctx, 2*time.Minute, "curl", "-fsSL", "-o", phar, "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"); err != nil {
		logf("wordpress: wp-cli download failed: %v", err)
		return ""
	}
	_ = os.Chmod(phar, 0o755)
	return "php " + phar
}

// wpRun executes a wp-cli command against a site path. The agent runs as root,
// which wp-cli refuses, so it runs as the site owner via sudo when possible and
// falls back to --allow-root. Returns (output, ok) where ok is a clean exit.
func wpRun(ctx context.Context, wp, site, owner string, args ...string) (string, bool) {
	base := strings.Fields(wp) // "php /tmp/..phar" or "wp"
	full := append([]string{}, base...)
	full = append(full, args...)
	full = append(full, "--path="+site, "--skip-plugins", "--skip-themes", "--no-color")

	// Prefer running as the file owner (avoids wp-cli's root refusal and keeps
	// file permissions intact). Fall back to --allow-root as root.
	if owner != "" && owner != "root" {
		if _, err := exec.LookPath("sudo"); err == nil {
			cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			defer cancel()
			// `sudo -n -u owner env HOME=/tmp <cmd>` — env sets HOME safely so
			// wp-cli has a writable home; -n never prompts.
			sudoArgs := append([]string{"-n", "-u", owner, "env", "HOME=/tmp"}, full...)
			cmd := exec.CommandContext(cctx, "sudo", sudoArgs...)
			out, err := cmd.CombinedOutput()
			if err == nil {
				return string(out), true
			}
			// sudo failed (no rule / etc.) — fall through to --allow-root.
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	rootArgs := append(full, "--allow-root")
	cmd := exec.CommandContext(cctx, rootArgs[0], rootArgs[1:]...)
	cmd.Env = append(cmd.Environ(), "HOME=/tmp")
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// ---- WPScan v3 API -----------------------------------------------------------

// wpscanCore returns human-readable titles of vulnerabilities affecting the
// given core version, per the WPScan API. Empty on no-vulns / any error.
func wpscanCore(ctx context.Context, token, version string, logf Logf) []string {
	slug := strings.ReplaceAll(version, ".", "")
	body := wpscanGet(ctx, token, "/wordpresses/"+slug, logf)
	if body == nil {
		return nil
	}
	var payload map[string]struct {
		Vulnerabilities []struct {
			Title string `json:"title"`
		} `json:"vulnerabilities"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return nil
	}
	var out []string
	for _, entry := range payload {
		for _, v := range entry.Vulnerabilities {
			out = append(out, v.Title)
		}
	}
	return out
}

// wpscanPlugin returns titles of vulnerabilities for a plugin that are NOT yet
// fixed at the installed version.
func wpscanPlugin(ctx context.Context, token, slug, version string, logf Logf) []string {
	body := wpscanGet(ctx, token, "/plugins/"+slug, logf)
	if body == nil {
		return nil
	}
	var payload map[string]struct {
		Vulnerabilities []struct {
			Title   string `json:"title"`
			FixedIn string `json:"fixed_in"`
		} `json:"vulnerabilities"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return nil
	}
	var out []string
	for _, entry := range payload {
		for _, v := range entry.Vulnerabilities {
			if v.FixedIn == "" || versionLess(version, v.FixedIn) {
				title := v.Title
				if v.FixedIn != "" {
					title += " (fixed in " + v.FixedIn + ")"
				}
				out = append(out, title)
			}
		}
	}
	return out
}

// wpscanGet performs an authenticated WPScan v3 GET. Returns nil on 404
// (unknown component), rate-limit, or any error — the caller degrades to
// heuristics rather than failing.
func wpscanGet(ctx context.Context, token, path string, logf Logf) []byte {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, "https://wpscan.com/api/v3"+path, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Token token="+token)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		logf("wordpress: wpscan request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		logf("wordpress: wpscan rate limit reached; remaining lookups skipped")
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil || len(buf) > 1<<20 {
			break
		}
	}
	return buf
}

// ---- small helpers -----------------------------------------------------------

// coreVersionFromDisk reads $wp_version from wp-includes/version.php.
func coreVersionFromDisk(site string) string {
	data, err := os.ReadFile(filepath.Join(site, "wp-includes", "version.php"))
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)
	if m := re.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// fileOwner returns the username owning path, or "" if it cannot be resolved.
func fileOwner(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	if u, err := user.LookupId(strconv.Itoa(int(st.Uid))); err == nil {
		return u.Username
	}
	return ""
}

// relPath returns path relative to the site's parent so findings read cleanly.
func relPath(site, path string) string {
	if r, err := filepath.Rel(filepath.Dir(site), path); err == nil {
		return r
	}
	return path
}

// versionLess reports whether dotted version a < b (numeric compare, missing
// parts treated as 0). Non-numeric parts stop the comparison conservatively.
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		na, nb := 0, 0
		if i < len(pa) {
			na, _ = strconv.Atoi(numericPrefix(pa[i]))
		}
		if i < len(pb) {
			nb, _ = strconv.Atoi(numericPrefix(pb[i]))
		}
		if na != nb {
			return na < nb
		}
	}
	return false
}

// numericPrefix returns the leading run of digits in s (e.g. "3beta" -> "3").
func numericPrefix(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}
