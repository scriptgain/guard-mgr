// Command guard-agent is the GuardMGR scan agent.
//
// It runs on any Linux host, polls the master control plane over outbound HTTPS
// for due scan jobs, runs the selected security engines (Lynis, rkhunter,
// chkrootkit, ClamAV, maldet, ufw, fail2ban, and the WordPress scanner) locally
// as root, and reports a hardening score plus findings back. No inbound ports
// are required on the scanned host.
//
// Subcommands:
//
//	guard-agent version
//	guard-agent enroll -master URL -token TOKEN
//	guard-agent run
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
	"github.com/thelonelyfrog/guard/agent/internal/config"
	"github.com/thelonelyfrog/guard/agent/internal/remediate"
	"github.com/thelonelyfrog/guard/agent/internal/scan"
	"github.com/thelonelyfrog/guard/agent/internal/selfupdate"
	"github.com/thelonelyfrog/guard/agent/internal/service"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "run")
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "version", "-v", "--version":
		fmt.Printf("guard-agent %s\n", version)
	case "enroll":
		err = cmdEnroll(args)
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "run":
		err = cmdRun(args)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `guard-agent

usage:
  guard-agent version
  guard-agent enroll -master <url> -token <token>   (auto-installs the service)
  guard-agent install                               (install + enable systemd service)
  guard-agent uninstall                             (disable + remove systemd service)
  guard-agent run
`)
}

// cmdInstall installs the always-on systemd service pointing at the agent config.
func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "agent config path")
	fs.Parse(args)

	masterURL := ""
	if cfg, err := config.Load(*cfgPath); err == nil {
		masterURL = cfg.MasterURL
	}
	if err := service.Install(*cfgPath, masterURL, logf); err != nil {
		return err
	}
	fmt.Println("guard-agent service installed and running (systemctl status guard-agent).")
	return nil
}

// cmdUninstall removes the systemd service.
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	fs.Parse(args)
	if err := service.Uninstall(logf); err != nil {
		return err
	}
	fmt.Println("guard-agent service removed.")
	return nil
}

// logf is a simple stdout logger for the install/enroll commands.
func logf(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	master := fs.String("master", "", "master control-plane base URL")
	token := fs.String("token", "", "one-time enrollment token")
	cfgPath := fs.String("config", config.DefaultPath(), "agent config path")
	fs.Parse(args)

	if *master == "" || *token == "" {
		return errors.New("both -master and -token are required")
	}
	hostname, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := api.New(*master, "").Enroll(ctx, api.EnrollRequest{
		Token:        *token,
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		AgentVersion: version,
	})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	cfg := config.Default()
	cfg.MasterURL = *master
	cfg.APIKey = resp.APIKey
	cfg.HostID = resp.HostID
	if err := cfg.Save(*cfgPath); err != nil {
		return err
	}
	fmt.Printf("enrolled as host %s; config saved to %s\n", resp.HostID, *cfgPath)

	// Productized worker: enrolling a host turns it into an always-on poller.
	// Best effort — if systemd/root isn't available, the operator can still run
	// `guard-agent run` (or `guard-agent install`) manually.
	if os.Geteuid() == 0 {
		if err := service.Install(*cfgPath, *master, logf); err != nil {
			fmt.Fprintf(os.Stderr, "note: could not install the systemd service automatically (%v); run `guard-agent install` after fixing.\n", err)
		}
	} else {
		fmt.Println("run `sudo guard-agent install` to start the always-on service.")
	}
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "agent config path")
	once := fs.Bool("once", false, "poll once and exit (for testing)")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if errors.Is(err, config.ErrNotConfigured) || !cfg.Enrolled() {
		return fmt.Errorf("not enrolled: run `guard-agent enroll` first (config: %s)", *cfgPath)
	}
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client := api.New(cfg.MasterURL, cfg.APIKey)

	interval := time.Duration(cfg.PollInterval)
	intervalChanged := false
	fmt.Printf("guard-agent %s: polling %s every %s\n", version, cfg.MasterURL, interval)

	tick := func() {
		if hb, err := client.Heartbeat(ctx, version); err == nil {
			maybeSelfUpdate(ctx, hb.Update)
			if hb.PollIntervalSeconds > 0 {
				if d := time.Duration(hb.PollIntervalSeconds) * time.Second; d != interval {
					interval = d
					intervalChanged = true
				}
			}
		}
		job, err := client.Poll(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "poll:", err)
			return
		}
		if job != nil {
			fmt.Printf("run %s: job %s (action=%s)\n", job.RunID, job.JobID, jobAction(job))
			executeJob(ctx, client, job)
		}
	}

	tick()
	if *once {
		return nil
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("shutting down")
			return nil
		case <-t.C:
			tick()
			if intervalChanged {
				intervalChanged = false
				t.Reset(interval)
				fmt.Printf("poll interval updated to %s\n", interval)
			}
		}
	}
}

// jobAction returns the job's action, defaulting to "scan".
func jobAction(job *api.Job) string {
	if job.Action == "" {
		return "scan"
	}
	return job.Action
}

// executeJob dispatches a job on its action. Only "scan" is live; the other
// actions are reserved seams for later phases and report a clear failure so an
// out-of-date master can't leave a run stuck "running".
func executeJob(ctx context.Context, client *api.Client, job *api.Job) {
	_ = client.Report(ctx, job.RunID, api.Report{Status: api.RunRunning})

	switch jobAction(job) {
	case "scan":
		runScan(ctx, client, job)
	case "fix_finding":
		runFixFinding(ctx, client, job)
	case "run_updates":
		runUpdatesAction(ctx, client, job)
	case "apply_template", "firewall_apply", "quarantine":
		// Reserved seams for later phases — not implemented yet.
		msg := "Action '" + jobAction(job) + "' is not supported by this agent version (" + version + ")."
		fmt.Fprintln(os.Stderr, "job:", msg)
		_ = client.Report(ctx, job.RunID, api.Report{Status: api.RunFailed, Log: msg})
	default:
		msg := "Unknown job action '" + jobAction(job) + "'."
		fmt.Fprintln(os.Stderr, "job:", msg)
		_ = client.Report(ctx, job.RunID, api.Report{Status: api.RunFailed, Log: msg})
	}
}

// runFixFinding applies a single finding's remediation and reports the result.
// On success the master flips the finding to "applied". Every config edit is
// backed up by the remediate package; the backup path is included in the log.
func runFixFinding(ctx context.Context, client *api.Client, job *api.Job) {
	logf := func(f string, a ...any) { fmt.Printf("run %s: "+f+"\n", append([]any{job.RunID}, a...)...) }
	res, err := remediate.FixFinding(ctx, job.FixKind, job.Target, logf)
	log := res.Log
	if res.BackupPath != "" {
		log += "\n\nBackup (for revert): " + res.BackupPath
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fix_finding:", err)
		_ = client.Report(ctx, job.RunID, api.Report{Status: api.RunFailed, Log: strings.TrimSpace(log + "\n\nerror: " + err.Error())})
		return
	}
	_ = client.Report(ctx, job.RunID, api.Report{Status: api.RunSuccess, Log: strings.TrimSpace(log), Updates: res.Updates})
}

// runUpdatesAction applies OS updates (security-only or all) and reports the
// result plus the refreshed reboot-required posture.
func runUpdatesAction(ctx context.Context, client *api.Client, job *api.Job) {
	logf := func(f string, a ...any) { fmt.Printf("run %s: "+f+"\n", append([]any{job.RunID}, a...)...) }
	mode := job.UpdateMode
	if mode == "" {
		mode = "security"
	}
	res, err := remediate.RunUpdates(ctx, mode, logf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run_updates:", err)
		_ = client.Report(ctx, job.RunID, api.Report{Status: api.RunFailed, Log: strings.TrimSpace(res.Log + "\n\nerror: " + err.Error())})
		return
	}
	_ = client.Report(ctx, job.RunID, api.Report{Status: api.RunSuccess, Log: strings.TrimSpace(res.Log), Updates: res.Updates})
}

// runScan executes the requested engines and reports the result. While it runs
// it streams live progress to the master (percentage, current engine, and a
// rolling log tail) so the report page shows real-time activity instead of a
// bare "running". It never panics the loop: a total scan failure is reported as
// a failed run.
func runScan(ctx context.Context, client *api.Client, job *api.Job) {
	engines := job.Engines
	if len(engines) == 0 {
		engines = []string{"lynis"}
	}

	// Shared, mutex-guarded progress state: a rolling log tail plus the current
	// percentage and engine, flushed to the master on each engine boundary and
	// every ~12s (for long engines like ClamAV).
	var mu sync.Mutex
	logBuf := make([]string, 0, 64)
	pct := 0
	current := "starting"

	appendLog := func(line string) {
		mu.Lock()
		logBuf = append(logBuf, line)
		if len(logBuf) > 200 {
			logBuf = logBuf[len(logBuf)-200:]
		}
		mu.Unlock()
	}
	var sendMu sync.Mutex
	sendProgress := func() {
		sendMu.Lock()
		defer sendMu.Unlock()
		mu.Lock()
		p, eng, tail := pct, current, strings.Join(logBuf, "\n")
		mu.Unlock()
		_ = client.Report(ctx, job.RunID, api.Report{Status: api.RunRunning, Pct: &p, CurrentEngine: eng, Log: tail})
	}

	logf := func(f string, a ...any) {
		msg := fmt.Sprintf(f, a...)
		fmt.Printf("run %s: %s\n", job.RunID, msg)
		appendLog(msg)
	}
	onEngine := func(completed, total int, engine string) {
		mu.Lock()
		if total > 0 {
			pct = completed * 100 / total
		}
		current = engine
		mu.Unlock()
		appendLog(fmt.Sprintf("▶ %s (%d/%d)", engine, completed+1, total))
		sendProgress()
	}

	// Ticker to keep progress fresh during long-running engines.
	tickCtx, stopTick := context.WithCancel(ctx)
	defer stopTick()
	go func() {
		t := time.NewTicker(12 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-tickCtx.Done():
				return
			case <-t.C:
				sendProgress()
			}
		}
	}()

	report := scan.Run(ctx, engines, scan.Options{WPScanToken: job.WPScanToken}, logf, onEngine)
	stopTick() // stop interim updates before the final report

	if report.Score != nil {
		fmt.Printf("run %s: score=%d, %d finding(s)\n", job.RunID, *report.Score, len(report.Findings))
	}
	if err := client.Report(ctx, job.RunID, report); err != nil {
		fmt.Fprintln(os.Stderr, "report:", err)
	}
}

// maybeSelfUpdate installs a newer agent binary when the master advertises one
// (auto-update is gated server-side). On success it re-execs and never returns.
func maybeSelfUpdate(ctx context.Context, up *api.UpdateInfo) {
	if up == nil || up.Version == "" || up.URL == "" {
		return
	}
	if !versionNewer(up.Version, version) {
		return
	}
	fmt.Printf("self-update: %s -> %s (%s)\n", version, up.Version, up.URL)
	if err := selfupdate.Apply(ctx, up.URL, up.Version, up.SHA256, up.Signature); err != nil {
		fmt.Fprintln(os.Stderr, "self-update refused (keeping current binary):", err)
		return
	}
	fmt.Printf("self-update: installed %s, restarting\n", up.Version)
	if err := selfupdate.Restart(); err != nil {
		fmt.Fprintln(os.Stderr, "self-update restart failed:", err)
	}
}

// versionNewer reports whether offered is strictly greater than current
// (dotted numeric). An unparseable current accepts any real offer; an
// unparseable offer is refused.
func versionNewer(offered, current string) bool {
	o, ok1 := parseVersion(offered)
	if !ok1 {
		return false
	}
	c, ok2 := parseVersion(current)
	if !ok2 {
		return true
	}
	for i := 0; i < 3; i++ {
		if o[i] != c[i] {
			return o[i] > c[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if parts[0] == "" {
		return [3]int{}, false
	}
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}
