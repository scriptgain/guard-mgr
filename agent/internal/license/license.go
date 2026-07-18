// Package license is the agent's compiled license-enforcement point.
//
// The master control plane is PHP and source-available, so its own license
// checks can be patched out by a customer. To make enforcement real, the master
// relays the exact bytes scriptgain.com signed for this install, and the agent
// re-verifies that signature here against a public key compiled into the binary.
// Without scriptgain's private key nobody can forge a license this code accepts,
// and the agent refuses to run backups when verification fails.
package license

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Product is the vendor product slug this build is licensed as. A signed license
// for any other product is rejected.
const Product = "backup-manager"

// maxIssuedAge bounds how stale a signed license may be before the agent stops
// trusting it. The master re-validates online ~twice a day, so an issued_at that
// is weeks old means the master has not reached scriptgain in a long time (or is
// replaying an old blob). Treated as staleness (recoverable), not revocation.
const maxIssuedAge = 21 * 24 * time.Hour

// graceWindow is how long the agent keeps backing up on the last verified-valid
// license when heartbeats stop delivering a fresh one (transient outages).
const graceWindow = 14 * 24 * time.Hour

// vendorPublicKeyPEM is scriptgain.com's RSA-2048 public key, compiled in. It
// must match config/license.php on the master exactly.
const vendorPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzFrRFiXb2ClbB+YDkOTj
vwMwJCZ1hC65IJ2rbLNM2zdUzMB/eT/MJ7iL5fFEWFCKytAoAuLr0Gofx2CE3u7y
WILwb+ZUT2eFNctFrWJiL737Cgh3Dx1tQmkveVZvs8elvZ+Kh2Gh8tEbKZ7pW+pl
dZwlHY4gBo3+YiAaYns9mcZuHDNO7Dm6Vn8B3hxYMzJ6lr/qoH/f+ZiT67Lcjzsl
O64X+7D4A0nBGBOVk6h0n8ZkoToXply6Qe0tUz8YWcJ4VJkAnFNlaDPDAl+E4EmL
B8CwKpuG6rsQaopXKP2K+XGXge9oOB25RCTKcQyB0hOqeu61pxwquUkC/iVyxPzH
jwIDAQAB
-----END PUBLIC KEY-----`

// Signed is the vendor-signed license the master relays on each heartbeat: the
// exact canonical bytes scriptgain signed, plus the base64 signature over them.
type Signed struct {
	Canonical string `json:"canonical"`
	Signature string `json:"signature"`
}

// Claims are the fields the agent reads from a verified canonical payload.
type Claims struct {
	Valid     bool   `json:"valid"`
	Key       string `json:"key"`
	Product   string `json:"product"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at"`
	IssuedAt  string `json:"issued_at"`
}

var vendorKey = mustParseKey(vendorPublicKeyPEM)

func mustParseKey(pemStr string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		panic("license: bad embedded public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("license: parse embedded key: " + err.Error())
	}
	rk, ok := pub.(*rsa.PublicKey)
	if !ok {
		panic("license: embedded key is not RSA")
	}
	return rk
}

// VerifyVendorSignature checks that signatureB64 is a valid base64 RSA-SHA256
// (PKCS#1 v1.5) signature over canonical, produced by the vendor private key
// whose public half is compiled into this binary. It is the shared primitive
// behind both license verification and self-update verification, so any code
// path that trusts vendor-signed data goes through the one embedded key. A
// non-nil error means the bytes were not signed by scriptgain: treat as
// untrusted.
func VerifyVendorSignature(canonical, signatureB64 string) error {
	if canonical == "" || signatureB64 == "" {
		return errors.New("empty payload or signature")
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	sum := sha256.Sum256([]byte(canonical))
	if err := rsa.VerifyPKCS1v15(vendorKey, crypto.SHA256, sum[:], sig); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// Verify checks the signature over the canonical bytes with the embedded vendor
// key and returns the parsed claims. A non-nil error means the signature did not
// verify or the payload was unreadable: treat as untrusted, not merely invalid.
func Verify(s Signed) (*Claims, error) {
	if s.Canonical == "" || s.Signature == "" {
		return nil, errors.New("empty license")
	}
	if err := VerifyVendorSignature(s.Canonical, s.Signature); err != nil {
		return nil, err
	}
	var c Claims
	if err := json.Unmarshal([]byte(s.Canonical), &c); err != nil {
		return nil, fmt.Errorf("unreadable license payload: %w", err)
	}
	return &c, nil
}

// evaluate turns verified claims into a decision. authoritative is true when the
// vendor has definitively said this license is not usable (wrong product,
// inactive, expired) as opposed to merely stale.
func (c *Claims) evaluate(now time.Time) (ok, authoritative bool, reason string) {
	if !c.Valid || c.Status != "active" {
		st := c.Status
		if st == "" {
			st = "invalid"
		}
		return false, true, "license " + st
	}
	if c.Product != Product {
		return false, true, fmt.Sprintf("license is for %q, not %q", c.Product, Product)
	}
	if c.ExpiresAt != "" {
		if exp, err := time.Parse(time.RFC3339, c.ExpiresAt); err == nil && now.After(exp) {
			return false, true, "license expired " + c.ExpiresAt
		}
	}
	if c.IssuedAt != "" {
		if iss, err := time.Parse(time.RFC3339, c.IssuedAt); err == nil && now.Sub(iss) > maxIssuedAge {
			return false, false, "license not re-validated since " + c.IssuedAt
		}
	}
	return true, false, "active"
}

// Gate decides whether the agent may run backups, based on the most recent
// verification. It persists the last known-good time so a transient loss of the
// license blob does not immediately halt backups.
type Gate struct {
	path string
	now  func() time.Time // injectable clock (tests)
	mu   sync.Mutex
	st   state
}

type state struct {
	GoodAt  time.Time `json:"good_at"` // last verified-valid license
	Revoked bool      `json:"revoked"` // last authoritative response was unusable
	Reason  string    `json:"reason"`
}

// NewGate loads any persisted state from path (best effort).
func NewGate(path string) *Gate {
	g := &Gate{path: path, now: time.Now}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &g.st)
	}
	return g
}

// Update feeds the license blob from a heartbeat (raw may be nil, "null", or the
// {canonical,signature} object) and records the resulting decision.
func (g *Gate) Update(raw json.RawMessage) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()

	if len(raw) == 0 || string(raw) == "null" {
		g.st.Reason = "master delivered no license"
		g.save()
		return
	}

	var s Signed
	if err := json.Unmarshal(raw, &s); err != nil || s.Canonical == "" {
		g.st.Reason = "malformed license from master"
		g.save()
		return
	}

	claims, err := Verify(s)
	if err != nil {
		// Signature failed: possible tampering or a version mismatch. Do not mark
		// revoked (recoverable); the grace window on GoodAt governs from here.
		g.st.Reason = "unverifiable license: " + err.Error()
		g.save()
		return
	}

	ok, authoritative, reason := claims.evaluate(now)
	g.st.Reason = reason
	switch {
	case ok:
		g.st.GoodAt = now
		g.st.Revoked = false
	case authoritative:
		g.st.Revoked = true
	}
	g.save()
}

// Allow reports whether backups may run, with a human-readable reason when not.
func (g *Gate) Allow() (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.st.Revoked {
		return false, g.st.Reason
	}
	if g.st.GoodAt.IsZero() {
		return false, "no valid license (" + g.st.Reason + ")"
	}
	if g.now().Sub(g.st.GoodAt) > graceWindow {
		return false, "license grace period elapsed (" + g.st.Reason + ")"
	}
	return true, g.st.Reason
}

func (g *Gate) save() {
	if b, err := json.Marshal(g.st); err == nil {
		_ = os.WriteFile(g.path, b, 0o600)
	}
}
