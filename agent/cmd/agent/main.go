// Command guard-agent is the GuardMGR scan agent.
//
// It runs on any Linux host, polls the master control plane over outbound HTTPS
// for due scan jobs, runs the selected security engines (Lynis, rkhunter, ufw)
// locally as root, and reports a hardening score plus findings back. No inbound
// ports are required on the scanned host.
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
	"syscall"
	"time"

	"github.com/thelonelyfrog/guard/agent/internal/api"
	"github.com/thelonelyfrog/guard/agent/internal/config"
	"github.com/thelonelyfrog/guard/agent/internal/scan"
	"github.com/thelonelyfrog/guard/agent/internal/selfupdate"
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
  guard-agent enroll -master <url> -token <token>
  guard-agent run
`)
}

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
	case "apply_template", "run_updates", "firewall_apply", "quarantine":
		// Phase 3-4 remediation actions — not implemented yet.
		msg := "Action '" + jobAction(job) + "' is not supported by this agent version (" + version + ")."
		fmt.Fprintln(os.Stderr, "job:", msg)
		_ = client.Report(ctx, job.RunID, api.Report{Status: api.RunFailed, Log: msg})
	default:
		msg := "Unknown job action '" + jobAction(job) + "'."
		fmt.Fprintln(os.Stderr, "job:", msg)
		_ = client.Report(ctx, job.RunID, api.Report{Status: api.RunFailed, Log: msg})
	}
}

// runScan executes the requested engines and reports the result. It never
// panics the loop: even a total scan failure is reported as a failed run.
func runScan(ctx context.Context, client *api.Client, job *api.Job) {
	engines := job.Engines
	if len(engines) == 0 {
		engines = []string{"lynis"}
	}
	report := scan.Run(ctx, engines, func(f string, a ...any) {
		fmt.Printf("run %s: "+f+"\n", append([]any{job.RunID}, a...)...)
	})
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
