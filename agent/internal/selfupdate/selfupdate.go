// Package selfupdate replaces the running agent binary with a newer build the
// master advertises, then re-execs. Downloads are outbound-only (the master
// never connects in), matching the agent's firewall-friendly model.
//
// A self-update is remote code the agent is about to run as root, so it is only
// installed when it is cryptographically proven to come from the vendor:
//
//   - the download URL must be https:// (no plaintext MITM),
//   - the downloaded bytes must hash to the advertised sha256, and
//   - the advertised signature must verify, against the compiled-in vendor
//     public key, over the canonical string "version|sha256".
//
// The canonical string binds the version to the exact bytes, so an attacker who
// controls the master's advertised {url,sha256,signature} still cannot install
// anything the vendor did not sign. If any check fails the download is
// discarded, the running binary is left in place, and a clear error is logged.
// The old "run the new binary to sanity-check it" step is deliberately gone: we
// never execute an unverified binary.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/license"
)

// Canonical is the exact string the vendor signs and the agent verifies for a
// self-update: the target version and the lowercase-hex sha256 of the new
// binary, joined by a pipe. The scriptgain `agent:sign` command must produce a
// signature over this identical string.
func Canonical(version, sha256hex string) string {
	return version + "|" + strings.ToLower(sha256hex)
}

// Apply downloads the binary at url, verifies it against the advertised sha256
// and vendor signature, and only then atomically swaps it over the currently
// running executable. It does not restart; call Restart to re-exec into the new
// binary. Any verification failure returns an error and leaves the current
// binary untouched.
func Apply(ctx context.Context, url, newVersion, sha256hex, signatureB64 string) error {
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return fmt.Errorf("refusing insecure update URL (must be https://): %q", url)
	}
	if sha256hex == "" || signatureB64 == "" {
		return fmt.Errorf("update offer missing sha256 or signature; refusing")
	}

	// Verify the vendor signature over version|sha256 BEFORE downloading a single
	// byte: if the offer itself is not vendor-signed, there is nothing to fetch.
	if err := license.VerifyVendorSignature(Canonical(newVersion, sha256hex), signatureB64); err != nil {
		return fmt.Errorf("update signature invalid, refusing: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}

	tmp := exe + ".new"
	// Best-effort cleanup if we bail before the rename.
	defer os.Remove(tmp)

	gotSum, err := download(ctx, url, tmp)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	// The downloaded bytes must be exactly what the vendor signed.
	want := strings.ToLower(sha256hex)
	if gotSum != want {
		return fmt.Errorf("checksum mismatch: downloaded %s, expected %s (tampered or wrong file)", gotSum, want)
	}

	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}

	// Renaming over a running executable is safe on Linux: the running process
	// keeps its open inode; new execs pick up the replacement.
	if err := os.Rename(tmp, exe); err != nil {
		return fmt.Errorf("swap: %w", err)
	}
	return nil
}

// Restart re-execs the current process image (now the new binary) with the same
// args and environment. On success it never returns.
func Restart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}

// download streams url to dst and returns the lowercase-hex sha256 of the bytes
// written, so the caller can compare it against the advertised digest without a
// second pass over the file.
func download(ctx context.Context, url, dst string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
