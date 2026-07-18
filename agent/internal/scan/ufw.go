package scan

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// runUfw inspects the host firewall. With ufw present it parses `ufw status
// verbose`: an inactive firewall is a high finding, and each allow rule becomes
// an informational "exposed port" finding. When ufw is absent it falls back to
// firewalld (firewall-cmd) or nftables (nft) for a coarse active/inactive read,
// and records a low finding if no supported firewall is found at all.
func runUfw(ctx context.Context, logf Logf) (engineResult, error) {
	if _, err := exec.LookPath("ufw"); err != nil {
		return ufwFallback(ctx, logf)
	}

	logf("ufw: reading firewall status")
	out, err := runCmd(ctx, 1*time.Minute, "ufw", "status", "verbose")
	if err != nil {
		return engineResult{}, err
	}

	res := engineResult{log: "[ufw] firewall status read"}
	lower := strings.ToLower(out)
	if strings.Contains(lower, "status: inactive") {
		res.findings = append(res.findings, api.Finding{
			Severity:    "high",
			Engine:      "ufw",
			Code:        "ufw-inactive",
			Title:       "Firewall Inactive",
			Detail:      "ufw is installed but not active — the host has no packet filtering. All listening services are reachable from anywhere the network allows.",
			Remediation: "Enable the firewall with `ufw enable` after allowing the ports you need (e.g. `ufw allow OpenSSH`).",
		})
		return res, nil
	}

	// Active — list allow rules as informational exposed-port findings.
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		// Rule rows look like: "22/tcp    ALLOW    Anywhere" (skip the "(v6)" dupes).
		if len(fields) < 2 || !strings.EqualFold(fields[1], "ALLOW") {
			continue
		}
		if strings.Contains(line, "(v6)") {
			continue
		}
		port := fields[0]
		from := "Anywhere"
		if len(fields) >= 3 {
			from = strings.Join(fields[2:], " ")
		}
		res.findings = append(res.findings, api.Finding{
			Severity: "info",
			Engine:   "ufw",
			Code:     "ufw-allow",
			Title:    "Allowed: " + port,
			Detail:   "Firewall permits " + port + " from " + from + ".",
		})
	}
	return res, nil
}

// ufwFallback handles hosts without ufw: try firewalld, then nftables, else
// record ufw-not-present as a low finding.
func ufwFallback(ctx context.Context, logf Logf) (engineResult, error) {
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		logf("ufw absent; checking firewalld")
		out, _ := runCmd(ctx, 1*time.Minute, "firewall-cmd", "--state")
		if strings.Contains(strings.ToLower(out), "running") {
			return engineResult{log: "[firewalld] active"}, nil
		}
		return engineResult{
			log: "[firewalld] not running",
			findings: []api.Finding{{
				Severity: "high", Engine: "ufw", Code: "firewalld-inactive",
				Title:       "Firewall Inactive (firewalld)",
				Detail:      "firewalld is present but not running.",
				Remediation: "Start it with `systemctl enable --now firewalld`.",
			}},
		}, nil
	}

	if _, err := exec.LookPath("nft"); err == nil {
		logf("ufw absent; checking nftables ruleset")
		out, _ := runCmd(ctx, 1*time.Minute, "nft", "list", "ruleset")
		if strings.TrimSpace(out) == "" {
			return engineResult{
				log: "[nftables] empty ruleset",
				findings: []api.Finding{{
					Severity: "high", Engine: "ufw", Code: "nft-empty",
					Title:       "Firewall Ruleset Empty (nftables)",
					Detail:      "nftables is available but its ruleset is empty — no packet filtering is in effect.",
					Remediation: "Install a firewall front-end (e.g. ufw) or load an nftables ruleset.",
				}},
			}, nil
		}
		return engineResult{log: "[nftables] ruleset present"}, nil
	}

	return engineResult{
		log: "[ufw] no supported firewall found",
		findings: []api.Finding{{
			Severity: "low", Engine: "ufw", Code: "ufw-not-present",
			Title:       "No Supported Firewall Detected",
			Detail:      "Neither ufw, firewalld, nor nftables is present, so firewall posture could not be assessed.",
			Remediation: "Install and enable ufw: `apt-get install -y ufw && ufw enable`.",
		}},
	}, nil
}
