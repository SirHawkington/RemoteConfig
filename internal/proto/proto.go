// Package proto holds the wire types shared by the agent and the server.
// It mirrors api/openapi.yaml; keep the two in sync.
package proto

import (
	"time"

	"remoteconfig/internal/signing"
)

type EnrollRequest struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
	Name         string `json:"name,omitempty"`
}

type EnrollResponse struct {
	DeviceID         string   `json:"device_id"`
	DeviceToken      string   `json:"device_token"`
	Project          string   `json:"project"`
	Tags             []string `json:"tags,omitempty"`
	CheckinIntervalS int      `json:"checkin_interval_s,omitempty"`
	// Signing is the server's current signing key. An agent that was not given the key
	// out of band may trust it on first use (see the agent's trust rules).
	Signing *KeyInfo `json:"signing,omitempty"`
}

// KeyInfo is one of the server's public signing keys.
type KeyInfo struct {
	KeyID  string `json:"kid"`
	Public string `json:"public"` // base64, 32 bytes
	// Endorsement is the previous key vouching for this one (nil for the first key).
	Endorsement *signing.Envelope `json:"endorsement,omitempty"`
}

// KeySet is every key the server has signed with, oldest first, with the endorsement
// chain that lets an agent trusting an old key accept the current one.
type KeySet struct {
	Current string    `json:"current"`
	Keys    []KeyInfo `json:"keys"`
}

// TrustReport is what an agent says about its own signature checking.
type TrustReport struct {
	// State is "strict" (a server key is trusted: unsigned or badly signed content is
	// refused) or "legacy" (no key yet: unsigned content is still accepted).
	State          string    `json:"state"`
	KeyID          string    `json:"key_id,omitempty"` // the key that signed the config in force
	KeysTrusted    int       `json:"keys_trusted,omitempty"`
	Pinned         bool      `json:"pinned,omitempty"`   // the key was given at install, not learned from the server
	Rejected       int       `json:"rejected,omitempty"` // signed things refused since the agent started
	LastRejected   string    `json:"last_rejected,omitempty"`
	LastRejectedAt time.Time `json:"last_rejected_at,omitempty"`
	// LastAcceptedAt: when a verified config last arrived from the server. A rejection older than
	// this means the device has recovered.
	LastAcceptedAt time.Time `json:"last_accepted_at,omitempty"`
}

// SignedConfig is the payload of a signed config (signing.TypeConfig). It is bound to one
// device and carries a strictly increasing IssuedAt, so a captured config cannot be replayed
// to another machine, or replayed later to roll a device back.
type SignedConfig struct {
	DeviceID string          `json:"device_id"`
	Project  string          `json:"project"`
	IssuedAt time.Time       `json:"issued_at"`
	Config   EffectiveConfig `json:"config"`
}

// SignedCommand is the payload of a signed command (signing.TypeCommand). An agent acts
// on these fields, never on the unsigned fields next to the envelope.
type SignedCommand struct {
	DeviceID  string         `json:"device_id"`
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Params    map[string]any `json:"params,omitempty"`
	ExpiresAt time.Time      `json:"expires_at"`
	IssuedAt  time.Time      `json:"issued_at"`
}

type AppStatus struct {
	State          string         `json:"state"`
	UptimeS        int64          `json:"uptime_s,omitempty"`
	Build          string         `json:"build,omitempty"`
	ConfigRevision int            `json:"config_revision,omitempty"`
	FPS            float64        `json:"fps,omitempty"`
	Message        string         `json:"message,omitempty"`
	Metrics        map[string]any `json:"metrics,omitempty"`
}

type SystemStats struct {
	CPUPct     float64 `json:"cpu_pct,omitempty"`
	MemUsedMB  int     `json:"mem_used_mb,omitempty"`
	MemTotalMB int     `json:"mem_total_mb,omitempty"`
	DiskFreeGB float64 `json:"disk_free_gb,omitempty"`
	UptimeS    int64   `json:"uptime_s,omitempty"`
	Network    string  `json:"network,omitempty"`
}

type Event struct {
	TS      time.Time      `json:"ts,omitempty"`
	Type    string         `json:"type"`
	Level   string         `json:"level,omitempty"`
	Message string         `json:"message,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
}

type Metric struct {
	TS    time.Time         `json:"ts,omitempty"`
	Name  string            `json:"name"`
	Value float64           `json:"value"`
	Tags  map[string]string `json:"tags,omitempty"`
}

type CheckinRequest struct {
	// Session identifies one run of the agent; Seq restarts from 1 when it changes.
	Session           string       `json:"session,omitempty"`
	Seq               int64        `json:"seq"`
	AgentVersion      string       `json:"agent_version"`
	ConfigRevision    int          `json:"config_revision,omitempty"`
	ConfigEtag        string       `json:"config_etag,omitempty"`
	App               *AppStatus   `json:"app,omitempty"`
	System            *SystemStats `json:"system,omitempty"`
	RestartsSinceLast int          `json:"restarts_since_last,omitempty"`
	LastHeartbeatAgeS int          `json:"last_heartbeat_age_s,omitempty"`
	// BytesIn/BytesOut are the bytes this device has moved over the network in the
	// current data-budget cycle (measured on the wire, TLS included), persisted by the agent.
	BytesIn  int64 `json:"bytes_in,omitempty"`
	BytesOut int64 `json:"bytes_out,omitempty"`
	// BudgetMB is the cycle budget (0 = none) and BudgetState one of none|ok|soft|exhausted.
	BudgetMB    int          `json:"budget_mb,omitempty"`
	BudgetState string       `json:"budget_state,omitempty"`
	Trust       *TrustReport `json:"trust,omitempty"`
	Events      []Event      `json:"events,omitempty"`
}

// ScreenshotPolicy controls scheduled and event-driven screen capture. Agent-consumed;
// it works offline from the cached config.
type ScreenshotPolicy struct {
	Enabled         bool `json:"enabled"`
	IntervalS       int  `json:"interval_s,omitempty"`        // scheduled capture period (min 10)
	MaxWidth        int  `json:"max_width,omitempty"`         // downscale each display to this width (default 1280)
	Quality         int  `json:"quality,omitempty"`           // JPEG quality 1-100 (default 60)
	OnEvent         bool `json:"on_event,omitempty"`          // also capture when the app hangs/crashes
	UploadUnchanged bool `json:"upload_unchanged,omitempty"`  // false: skip near-identical frames
	UnchangedEveryS int  `json:"unchanged_every_s,omitempty"` // but still send one this often (default 3600)
}

// BudgetPolicy is the per-device network data budget. Check-ins, config and command
// results always flow; bulk traffic (screenshots, artifacts, metrics) stops when exhausted.
type BudgetPolicy struct {
	MonthlyMB int `json:"monthly_mb,omitempty"` // 0 = unlimited
	ResetDay  int `json:"reset_day,omitempty"`  // day of month the carrier cycle restarts (1-28, default 1)
	SoftPct   int `json:"soft_pct,omitempty"`   // warn at this percentage (default 80)
}

type CheckinResponse struct {
	ServerTime      time.Time `json:"server_time"`
	DesiredRevision int       `json:"desired_revision,omitempty"`
	DesiredEtag     string    `json:"desired_etag,omitempty"`
	ConfigChanged   bool      `json:"config_changed,omitempty"`
	Commands        []Command `json:"commands,omitempty"`
	NextCheckinS    int       `json:"next_checkin_s,omitempty"`
	Profile         string    `json:"profile,omitempty"`
}

// ArtifactInit starts (or resumes, via ClientID) a resumable upload.
type ArtifactInit struct {
	ClientID    string         `json:"client_id"` // agent-generated; makes creation idempotent
	Kind        string         `json:"kind"`
	Size        int64          `json:"size"`
	ContentType string         `json:"content_type,omitempty"`
	SHA256      string         `json:"sha256"`
	CapturedAt  time.Time      `json:"captured_at,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
}

type ArtifactSession struct {
	ID       string `json:"id"`
	Offset   int64  `json:"offset"`
	Complete bool   `json:"complete"`
}

// ArtifactInfo describes a stored artifact in listings.
type ArtifactInfo struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Size        int64          `json:"size"`
	ContentType string         `json:"content_type"`
	CapturedAt  time.Time      `json:"captured_at"`
	CreatedAt   time.Time      `json:"created_at"`
	Meta        map[string]any `json:"meta,omitempty"`
}

// SupervisorConfig tells the agent how to supervise the app. Agent-consumed.
type SupervisorConfig struct {
	// Mode is "supervise" (default when Exe is set: launch and restart the app) or
	// "monitor" (observe heartbeats only; used while an old watch script still owns the app).
	Mode string `json:"mode,omitempty"`
	// ReloadURL is POSTed ({"revision":N}) for reload_mode "trigger". The app should
	// reload and acknowledge via POST /v1/config/ack on the local API.
	ReloadURL string `json:"reload_url,omitempty"`
	// QuitTimeoutS is how long the app gets to exit after being asked (default 10) before
	// it is killed. A hung app is only given min(this, 3) seconds.
	QuitTimeoutS int `json:"quit_timeout_s,omitempty"`
	// StopAppOnAgentExit makes the agent quit the app when the agent itself stops. The
	// default (false) leaves the app running, so upgrading or restarting the agent does not
	// interrupt the display; the next agent adopts the running app.
	Exe                string            `json:"exe,omitempty"`
	Args               []string          `json:"args,omitempty"`
	Workdir            string            `json:"workdir,omitempty"`
	Env                map[string]string `json:"env,omitempty"`
	HeartbeatTimeoutS  int               `json:"heartbeat_timeout_s,omitempty"`
	MaxRestarts        int               `json:"max_restarts,omitempty"`
	RestartWindowS     int               `json:"restart_window_s,omitempty"`
	ScheduledRestart   string            `json:"scheduled_restart,omitempty"`
	StopAppOnAgentExit bool              `json:"stop_app_on_agent_exit,omitempty"`
}

type EffectiveConfig struct {
	Revision    int               `json:"revision"`
	Etag        string            `json:"etag"`
	ReloadMode  string            `json:"reload_mode,omitempty"`
	Data        map[string]any    `json:"data"`
	Supervisor  *SupervisorConfig `json:"supervisor,omitempty"`
	Screenshots *ScreenshotPolicy `json:"screenshots,omitempty"`
	Budget      *BudgetPolicy     `json:"budget,omitempty"`
}

// ConfigDocument is what an admin stores for one scope (global, tag:x, device:id).
// Screenshots and Budget are kept as raw maps so a layer only overrides the fields it
// actually names; the server merges them field by field and validates them strictly
// against ScreenshotPolicy / BudgetPolicy. Supervisor is replaced whole.
type ConfigDocument struct {
	Data        map[string]any    `json:"data"`
	ReloadMode  string            `json:"reload_mode,omitempty"`
	Supervisor  *SupervisorConfig `json:"supervisor,omitempty"`
	Screenshots map[string]any    `json:"screenshots,omitempty"`
	Budget      map[string]any    `json:"budget,omitempty"`
}

type ConfigAck struct {
	Revision     int    `json:"revision"`
	OK           bool   `json:"ok"`
	Error        string `json:"error,omitempty"`
	RolledBackTo int    `json:"rolled_back_to,omitempty"`
}

type Command struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Params    map[string]any `json:"params,omitempty"`
	ExpiresAt time.Time      `json:"expires_at,omitempty"`
	Status    string         `json:"status,omitempty"`
	// Signed is the same command signed by the server. When the agent trusts a server key it
	// ignores the plain fields above and acts only on what is inside this envelope.
	Signed *signing.Envelope `json:"signed,omitempty"`
}

// ScriptInfo describes a script in a project's library. Versions are immutable; the hash is of
// the exact bytes an agent will run.
type ScriptInfo struct {
	ID          string    `json:"id"`
	Project     string    `json:"project"`
	Name        string    `json:"name"`
	Version     int       `json:"version"`
	Interpreter string    `json:"interpreter"` // powershell | cmd | bash | sh | python
	Description string    `json:"description,omitempty"`
	TimeoutS    int       `json:"timeout_s"`
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
}

type ScriptCreate struct {
	Name        string `json:"name"`
	Interpreter string `json:"interpreter"`
	Content     string `json:"content"`
	Description string `json:"description,omitempty"`
	TimeoutS    int    `json:"timeout_s,omitempty"`
}

// ReleaseInfo describes an uploaded build: an app (a zip of a folder) or an agent executable.
type ReleaseInfo struct {
	ID        string    `json:"id"`
	Project   string    `json:"project"`
	Kind      string    `json:"kind"` // app | agent
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"` // amd64, arm64, or "any" for an app build that is not tied to one
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// RolloutRequest sends one command (a release or a script) to many devices in stages: the
// first `Canary` devices of `Devices` get it first, and the rest only follow once those have
// succeeded and stayed healthy for `SoakS` seconds.
type RolloutRequest struct {
	Type    string         `json:"type"` // apply_release | run_script
	Params  map[string]any `json:"params"`
	Devices []string       `json:"devices"`          // device ids; the first Canary of them go first
	Canary  int            `json:"canary,omitempty"` // default 1
	SoakS   *int           `json:"soak_s,omitempty"` // default 120
	Batch   int            `json:"batch,omitempty"`  // devices per wave after the canary; 0 = all the rest
}

type RolloutDevice struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Stage   string `json:"stage"`             // canary | rest
	Status  string `json:"status"`            // waiting | queued | delivered | succeeded | failed | expired | removed
	Result  string `json:"result,omitempty"`  // what the device reported
	Command string `json:"command,omitempty"` // command id once sent
}

type Rollout struct {
	ID        string            `json:"id"`
	Project   string            `json:"project"`
	Type      string            `json:"type"`
	Params    map[string]any    `json:"params"`
	Targets   []string          `json:"targets"`
	Canary    int               `json:"canary"`
	SoakS     int               `json:"soak_s"`
	Batch     int               `json:"batch"`
	State     string            `json:"state"` // canary | soaking | rolling | done | halted
	Reason    string            `json:"reason,omitempty"`
	Sent      map[string]string `json:"sent,omitempty"` // device id -> command id
	SoakStart time.Time         `json:"soak_start,omitempty"`
	SoakUntil time.Time         `json:"soak_until,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	CreatedBy string            `json:"created_by,omitempty"`
	Devices   []RolloutDevice   `json:"devices,omitempty"` // filled in when listing
}

type CommandRequest struct {
	Type   string         `json:"type"`
	Params map[string]any `json:"params,omitempty"`
	TTLS   int            `json:"ttl_s,omitempty"`
}

type CommandResult struct {
	OK         bool   `json:"ok"`
	Output     string `json:"output,omitempty"`
	ArtifactID string `json:"artifact_id,omitempty"`
}

// DeviceStatus is what the local agent API returns for GET /v1/status.
type DeviceStatus struct {
	DeviceID          string     `json:"device_id,omitempty"`
	Connected         bool       `json:"connected"`
	LastCheckinAt     time.Time  `json:"last_checkin_at,omitempty"`
	ConfigRevision    int        `json:"config_revision,omitempty"`
	App               *AppStatus `json:"app,omitempty"`
	LastHeartbeatAgeS int        `json:"last_heartbeat_age_s,omitempty"`
	ProcessRunning    bool       `json:"process_running"`
	Restarts          int        `json:"restarts"`
}

type DeviceSummary struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Hostname         string    `json:"hostname"`
	OS               string    `json:"os"`
	Tags             []string  `json:"tags,omitempty"`
	AgentVersion     string    `json:"agent_version"`
	Reachability     string    `json:"reachability"`
	AppState         string    `json:"app_state,omitempty"`
	LastSeenAt       time.Time `json:"last_seen_at,omitempty"`
	DesiredRevision  int       `json:"desired_revision"`
	ReportedRevision int       `json:"reported_revision"`
	InSync           bool      `json:"in_sync"`
	AppMessage       string    `json:"app_message,omitempty"`
	Restarts         int       `json:"restarts"`
	BudgetState      string    `json:"budget_state,omitempty"`
	// SignatureState: strict | legacy | rejecting (strict, and refused something recently) | unknown
	SignatureState string `json:"signature_state,omitempty"`
}

// DeviceDetail is the dashboard's view of one device.
type DeviceDetail struct {
	DeviceSummary
	Arch       string             `json:"arch,omitempty"`
	EnrolledAt time.Time          `json:"enrolled_at"`
	App        *AppStatus         `json:"app,omitempty"`
	System     *SystemStats       `json:"system,omitempty"`
	BytesIn    int64              `json:"bytes_in"` // current data-budget cycle
	BytesOut   int64              `json:"bytes_out"`
	BudgetMB   int                `json:"budget_mb,omitempty"`
	Effective  EffectiveConfig    `json:"effective"`
	Trust      *TrustReport       `json:"trust,omitempty"`
	Events     []Event            `json:"events"` // newest first
	Commands   []Command          `json:"commands"`
	Metrics    map[string]float64 `json:"metrics"` // latest value per metric name
}

// DevicePatch changes editable device fields; nil means unchanged.
type DevicePatch struct {
	Name *string   `json:"name,omitempty"`
	Tags *[]string `json:"tags,omitempty"`
}

// Overview is everything the agent's desktop UI shows, served by the agent's local API at
// GET /v1/ui/overview. It mirrors what the agent
// reports to the server, plus local-only detail (supervisor state, queues, data budget).
type Overview struct {
	Version  string `json:"version"`
	Enrolled bool   `json:"enrolled"`
	DeviceID string `json:"device_id,omitempty"`
	Project  string `json:"project,omitempty"`
	Server   string `json:"server,omitempty"`

	Connected     bool      `json:"connected"`
	LastCheckinAt time.Time `json:"last_checkin_at,omitempty"`
	StartedAt     time.Time `json:"started_at"`

	ConfigRevision int `json:"config_revision,omitempty"`
	ConfigAcked    int `json:"config_acked,omitempty"` // newest revision the app confirmed

	App          *AppStatus `json:"app,omitempty"`
	HeartbeatAge int        `json:"heartbeat_age_s,omitempty"`

	Supervisor OverviewSupervisor `json:"supervisor"`
	Data       OverviewData       `json:"data"`

	PendingEvents     int `json:"pending_events"`
	QueuedScreenshots int `json:"queued_screenshots"`
}

type OverviewSupervisor struct {
	Managing  bool   `json:"managing"`
	State     string `json:"state"`
	Running   bool   `json:"running"`
	PID       int    `json:"pid,omitempty"`
	Restarts  int    `json:"restarts"`
	UptimeS   int64  `json:"uptime_s,omitempty"`
	LastExit  string `json:"last_exit,omitempty"`
	CrashLoop bool   `json:"crash_loop"`
}

type OverviewData struct {
	InBytes  int64  `json:"in_bytes"`
	OutBytes int64  `json:"out_bytes"`
	LimitMB  int    `json:"limit_mb,omitempty"`
	UsedPct  int    `json:"used_pct,omitempty"`
	State    string `json:"state,omitempty"`
}
