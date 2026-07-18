package scan

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
)

// runFail2ban reports the host's brute-force protection posture from fail2ban,
// read-only. It does NOT install or configure anything (jail management is
// Phase 4). Outcomes:
//
//   - fail2ban absent            -> one low finding (recommend installing it)
//   - installed but not running  -> one high finding (protection is off)
//   - running                    -> one info finding per active jail plus, if a
//     jail currently has bans, a low finding noting the count
func runFail2ban(ctx context.Context, _ Options, logf Logf) (engineResult, error) {
	client, err := exec.LookPath("fail2ban-client")
	if err != nil {
		return engineResult{
			log: "[fail2ban] not installed",
			findings: []api.Finding{{
				Severity: "low", Engine: "fail2ban", Code: "fail2ban-not-installed",
				Title:       "fail2ban Not Installed",
				Detail:      "fail2ban is not installed, so repeated failed logins (SSH, mail, web) are not throttled or banned automatically.",
				Remediation: "Install and enable fail2ban: `apt-get install -y fail2ban && systemctl enable --now fail2ban`.",
			}},
		}, nil
	}

	logf("fail2ban: reading jail status")
	out, err := runCmd(ctx, 1*time.Minute, client, "status")
	if err != nil {
		return engineResult{}, err
	}
	// When the daemon is down, fail2ban-client prints an error to connect to the socket.
	lower := strings.ToLower(out)
	if strings.Contains(lower, "failed to access socket") || strings.Contains(lower, "could not find server") || strings.Contains(lower, "connection refused") {
		return engineResult{
			log: "[fail2ban] installed but daemon not running",
			findings: []api.Finding{{
				Severity: "high", Engine: "fail2ban", Code: "fail2ban-down",
				Title:       "fail2ban Installed but Not Running",
				Detail:      "fail2ban is installed but its daemon is not running — no brute-force protection is active.",
				Remediation: "Start it with `systemctl enable --now fail2ban` and confirm with `fail2ban-client status`.",
			}},
		}, nil
	}

	jails := parseJailList(out)
	res := engineResult{log: "[fail2ban] active with " + strconv.Itoa(len(jails)) + " jail(s)"}
	if len(jails) == 0 {
		res.findings = append(res.findings, api.Finding{
			Severity: "low", Engine: "fail2ban", Code: "fail2ban-no-jails",
			Title:       "fail2ban Running but No Jails Enabled",
			Detail:      "fail2ban is running but has no active jails, so nothing is actually being protected.",
			Remediation: "Enable at least the sshd jail in /etc/fail2ban/jail.local.",
		})
		return res, nil
	}

	for _, jail := range jails {
		total, current := jailBans(ctx, client, jail)
		detail := "Jail '" + jail + "' is active."
		if total >= 0 {
			detail += " Total bans: " + strconv.Itoa(total) + "; currently banned: " + strconv.Itoa(current) + "."
		}
		res.findings = append(res.findings, api.Finding{
			Severity: "info", Engine: "fail2ban", Code: "fail2ban-jail:" + jail,
			Title:  "Jail Active: " + jail,
			Detail: detail,
		})
		if current > 0 {
			res.findings = append(res.findings, api.Finding{
				Severity: "low", Engine: "fail2ban", Code: "fail2ban-bans:" + jail,
				Title:       "Active Bans in Jail: " + jail,
				Detail:      "fail2ban currently holds " + strconv.Itoa(current) + " banned IP(s) in the '" + jail + "' jail — evidence of ongoing brute-force attempts.",
				Remediation: "Review the banned addresses (`fail2ban-client status " + jail + "`); persistent offenders can be added to the firewall permanently.",
			})
		}
	}
	return res, nil
}

// parseJailList extracts jail names from `fail2ban-client status`, whose jail
// line looks like "`- Jail list:	sshd, nginx-http-auth".
func parseJailList(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		l := strings.ToLower(line)
		if !strings.Contains(l, "jail list") {
			continue
		}
		_, list, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		var jails []string
		for _, j := range strings.Split(list, ",") {
			if j = strings.TrimSpace(j); j != "" {
				jails = append(jails, j)
			}
		}
		return jails
	}
	return nil
}

// jailBans reads `fail2ban-client status <jail>` and returns (totalBanned,
// currentlyBanned). Returns (-1,-1) when the numbers cannot be read.
func jailBans(ctx context.Context, client, jail string) (total, current int) {
	total, current = -1, -1
	out, err := runCmd(ctx, 30*time.Second, client, "status", jail)
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		_, val, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			continue
		}
		switch {
		case strings.Contains(l, "total banned"):
			total = n
		case strings.Contains(l, "currently banned"):
			current = n
		}
	}
	return
}
