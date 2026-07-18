package api

import "encoding/json"

// EnrollRequest is sent once to trade a one-time token for a permanent API key.
type EnrollRequest struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
}

// EnrollResponse carries the credentials the agent persists after enrollment.
type EnrollResponse struct {
	HostID string `json:"host_id"`
	APIKey string `json:"api_key"`
}

// Job is a single scan handed to the agent by the master. It names the run to
// report against and the security engines to run.
type Job struct {
	RunID     string   `json:"run_id"`
	JobID     string   `json:"job_id"`
	Type      string   `json:"type"`      // always "scan"
	Action    string   `json:"action"`    // scan (default) | apply_template | run_updates | ...
	Connector string   `json:"connector"` // agent
	Engines   []string `json:"engines"`   // lynis | rkhunter | ufw
}

// Finding is one security finding produced by a scan engine.
type Finding struct {
	Severity    string `json:"severity"` // critical|high|medium|low|info
	Engine      string `json:"engine"`   // lynis|rkhunter|ufw
	Code        string `json:"code,omitempty"`
	Title       string `json:"title"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// UpdateInfo advertises a newer agent build the master wants installed. The
// agent refuses any offer whose bytes do not match SHA256 or whose Signature
// does not verify against the embedded vendor key (see internal/selfupdate).
type UpdateInfo struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

// HeartbeatResponse is returned from /heartbeat. Update is non-nil when the
// master is offering a newer agent binary and auto-update is enabled.
type HeartbeatResponse struct {
	Update              *UpdateInfo     `json:"update"`
	PollIntervalSeconds int             `json:"poll_interval_seconds,omitempty"`
	License             json.RawMessage `json:"license,omitempty"`
}

// RunStatus is the lifecycle state reported back for a scan run.
type RunStatus string

const (
	RunRunning RunStatus = "running"
	RunSuccess RunStatus = "success"
	RunWarn    RunStatus = "warn"
	RunFailed  RunStatus = "failed"
)

// Report is progress or the final result of a scan, posted to the master. On a
// final report Score is the 0-100 hardening score and Findings is the full set
// of security findings the engines produced.
type Report struct {
	Status   RunStatus `json:"status"`
	Score    *int      `json:"score,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
	Log      string    `json:"log,omitempty"`
}
