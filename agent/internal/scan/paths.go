package scan

import (
	"os"
	"path/filepath"
)

// scanDirGlobs are the common web/data roots a malware scan should cover on a
// typical Linux web host (CloudPanel, cPanel, plain nginx/apache). They are
// bounded to web content + a couple of dropzones — never "/", never system
// dirs — so a scan stays fast and relevant.
var scanDirGlobs = []string{
	"/home/*/htdocs",
	"/home/*/htdocs/*",
	"/home/*/public_html",
	"/var/www",
	"/var/www/*",
	"/srv/www",
	"/usr/share/nginx/html",
	"/tmp",
	"/var/tmp",
	"/dev/shm",
}

// malwareScanDirs resolves scanDirGlobs to directories that actually exist on
// this host, de-duplicated and with nested paths collapsed (a scanner recurses,
// so scanning /home/x/htdocs makes /home/x/htdocs/site redundant). Returns the
// tightest set of top-level directories to hand a recursive scanner.
func malwareScanDirs() []string {
	set := map[string]bool{}
	for _, g := range scanDirGlobs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() {
				set[filepath.Clean(m)] = true
			}
		}
	}
	// Drop any path whose ancestor is also in the set.
	var dirs []string
	for d := range set {
		covered := false
		for p := d; ; {
			parent := filepath.Dir(p)
			if parent == p {
				break
			}
			if set[parent] {
				covered = true
				break
			}
			p = parent
		}
		if !covered {
			dirs = append(dirs, d)
		}
	}
	return dirs
}
