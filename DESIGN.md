# RemoteConfig — Design Doc (Draft v0.1)

> **Implementation status (see README.md):** Phases 0 and 1 are built. Deviations from this
> document so far: the dashboard is dependency-free vanilla JS embedded in the server (no
> Svelte/React build step; revisit if it outgrows that), and the server keeps its working set in
> memory with write-through to SQLite, which is plenty at <50 devices. Decisions made while
> building: the app is independent of the agent (a restarted agent adopts the process the previous
> one recorded, verified by PID + start time + image path) so agent upgrades never interrupt the
> display; stopping the app is always polite first (lifecycle message + WM_CLOSE, then kill after a
> grace period); auto-start is a Task Scheduler task (logon trigger + restart on failure + a
> one-minute watchdog trigger, because restart-on-failure alone did not revive an externally
> killed agent); dashboard access is per-user accounts with per-project roles (viewer / operator / admin)
> plus a server-admin flag, rather than one shared token, with the `supervisor` config section reserved to
> project admins because it decides which program runs on the machines. Known gaps against this design: no MSI yet, maintenance windows for disruptive
> restarts are not implemented, adoption and graceful quit are Windows-only so far, and the
> offline *event* queue is memory-only (the screenshot outbox is on disk).

## 1. Goals

Remotely manage and monitor PCs in public installations running Unity apps (and potentially other apps).

**Primary capabilities**
1. **Config management**: push Unity settings / game config to machines, per-device or per-group, with versioning and rollback.
2. **Monitoring**: online status, app/process health, "is script X running", system stats, logs.
3. **Screenshots**: on-demand and scheduled, bandwidth-aware.
4. **Remote actions**: restart app, reboot, run approved scripts.

**Hard constraints (drive the whole design)**
- **Unreliable / metered connectivity**: machines may be offline for days; data caps are possible. The system must be *offline-first* and *bandwidth-frugal*.
- **Low-end clients**: agent must idle at ~0% CPU and roughly <30 MB RAM. It must never compete with the Unity app.
- **Mixed OS**: Windows first, but macOS (and likely Linux) supported. Core is portable, with thin per-OS adapters.
- **Hosting-agnostic server**: runs identically on a VPS, a cloud container, or a local box on a LAN.
- **Scale**: dozens of devices (<50). Simplicity beats horizontal scale. Don't over-engineer, but don't design ourselves into a corner.

**Non-goals (v1)**: remote desktop / live video, full RMM feature set, multi-tenant SaaS billing, auto-updating Unity app builds (considered for v2, see §12).

## 2. Key Principles

1. **Device is autonomous.** The device always holds a full, valid, locally-cached desired config and enforces it with no server contact. The server is a source of *changes*, not a runtime dependency.
2. **Pull, not push.** The agent makes outbound-only HTTPS requests. No inbound ports, works behind NAT/firewalls/cellular routers.
3. **Declarative desired state + reported state.** Server stores *desired*; agent reports *actual*. Reconciliation is the agent's job. Commands (one-offs) are a separate, explicit, queued mechanism.
4. **Everything is cheap by default, expensive on demand.** Heartbeats are tiny; screenshots, logs, and large files are opt-in/triggered/rate-limited.
5. **Safe by default.** Changes are validated, signed, health-checked after apply, and auto-rolled back on failure.

## 3. Architecture Overview

```
┌──────────────────────────┐        HTTPS (outbound only)        ┌─────────────────────────────┐
│ Client machine           │ ─────────────────────────────────▶ │ Server (single binary)       │
│                          │   check-in / poll / upload          │  - REST + WebSocket API      │
│  ┌────────────────────┐  │ ◀───────────────────────────────── │  - Web dashboard (embedded)  │
│  │ Agent (service)    │  │   desired config / commands         │  - SQLite (default)/Postgres │
│  │  - config cache    │  │                                     │  - Blob store (disk/S3)      │
│  │  - reconciler      │  │                                     └─────────────────────────────┘
│  │  - watchdog        │  │                                                  ▲
│  │  - outbound queue  │  │                                                  │ browser
│  │  - local status UI │  │                                          ┌───────┴────────┐
│  └─────▲──────────────┘  │                                          │ Operator (web) │
│        │ localhost / file│                                          └────────────────┘
│  ┌─────┴──────────────┐  │
│  │ Unity app          │  │
│  │  (RemoteConfig SDK)│  │
│  └────────────────────┘  │
└──────────────────────────┘
```

Three components:
- **Agent**: small native background service on each client.
- **Server**: one self-contained binary + a database file; serves API and web dashboard.
- **Unity SDK (optional package)**: C# package so apps read config, hot-reload on change, and report app-level health/custom metrics.

## 4. Technology Choices

The requirement was "a clean UI on server/client side, plus performance". That splits cleanly: *performance matters in the agent; UI matters in the server*. They don't need the same stack.

| Component | Choice | Why |
|---|---|---|
| **Agent** | **Go** | Single static binary (~8–12 MB), ~10–20 MB RSS idle, trivial cross-compile to Win/macOS/Linux, great stdlib HTTP/TLS, easy service install. Rust is leaner but slower to build; .NET/Electron/Tauri are heavier for a resident low-end process. |
| **Server** | **Go** | Share types/protocol code with the agent; single binary deployment runs anywhere (VPS, container, Raspberry Pi, Windows box). |
| **Server DB** | **SQLite** (WAL) by default; Postgres optional later | <50 devices: SQLite is more than enough, zero ops, backup = copy a file. Keep data layer behind an interface. |
| **Blob store** | Local disk by default; S3-compatible interface | Screenshots, logs, script bundles. Keeps hosting agnostic. |
| **Web dashboard** | **Svelte (or React) SPA**, built and embedded in the server binary | The "clean UI". Live updates via WebSocket/SSE. Mobile-friendly for on-site use. |
| **Client local UI** | Agent serves a tiny **localhost-only status page** (same web tech) | Lets an on-site tech see status/config/connection and trigger "check in now" without installing a GUI toolkit. No resident GUI process = no resource cost. |
| **Unity SDK** | C# UPM package (no native deps) | Works in any Unity version; Mono/IL2CPP safe. |

> Alternative worth considering: a tray-icon GUI (Wails/Tauri) for the client. Rejected for v1 because a resident webview costs 80–200 MB RAM. The localhost page gives 90% of the value at ~0 cost, and we can add a tray stub later.

## 5. Data Model

- **Project (Application)**: top-level scope owning devices, profiles, scripts, releases, API keys and user roles. Generic: nothing Unity-specific lives here.
- **Device**: id, project, name, hostname, OS/arch, agent version, tags, group(s), enrolled-at, last-seen, state (online/stale/offline), desired-config revision, reported-config revision.
- **Group / Tag**: e.g. `site:museum-a`, `kiosk-type:touch`. Devices can have multiple tags.
- **Config Profile**: named, versioned JSON document (+ optional schema). Applied at scopes: **global → group → device**, with deep-merge and device-level overrides. Server computes the *effective config* per device and stamps it with a content hash/revision.
- **Config Target**: how a config reaches an app (see §6.2): JSON file path, INI, registry key, env var, PlayerPrefs-equivalent file, or "delivered via SDK".
- **Command**: id, target device(s), type (restart-app, reboot, run-script, capture-screenshot, fetch-logs, check-in-now), params, expiry/TTL, status (queued → delivered → running → succeeded/failed/expired), result.
- **Script**: named, versioned, **signed** bundle from an allowlisted library (no arbitrary shell from the UI in v1; see §9).
- **Monitor (Check)**: declarative health rules per profile (process X running, file Y fresh, port Z open, disk > N%).
- **Telemetry**: heartbeat snapshots, events, check results (short retention, rolled up).
- **Artifact**: screenshot / log blob with metadata + retention.
- **Audit log**: who changed what, when.

## 6. Core Mechanisms

### 6.1 Agent ↔ Server Protocol (low-bandwidth, offline-tolerant)

- **Transport**: HTTPS with persistent keep-alive when available; exponential backoff + jitter on failure. Optional WebSocket upgrade for near-real-time operator actions on well-connected sites (off by default for metered links).
- **Check-in** (`POST /v1/checkin`), a single small request containing:
  - device id, agent version, effective config revision the device is *running*, compact status (uptime, app up/down, CPU/RAM/disk summary, last N events since last ack), queued-upload manifest.
  - Body is compact (CBOR or gzipped JSON). Typical size: **< 1 KB** compressed.
- **Response** contains only what changed:
  - `desired_revision` (+ download only if differs from local; delta/etag-based),
  - pending commands,
  - server-directed schedule (next check-in interval, screenshot policy, bandwidth mode).
- **Check-in interval** is server-configurable per device/profile (default 5 min; 1 h for metered; adaptive back-off when idle). "Check-in now" is only instant if a persistent connection exists; otherwise it applies at next interval. The UI makes this explicit ("will apply at next check-in, ~3 min").
- **Idempotency & ordering**: every config has a monotonic revision; commands have ids and are deduplicated; results are acked so retries are safe.
- **Store-and-forward**: events, command results, and artifacts go to an on-disk outbound queue (bounded size, oldest-low-priority dropped first) and drain when connected. Priority: command results/alerts > events > heartbeat samples > screenshots > logs.
- **Clock skew**: the agent stamps events with local time + monotonic offset; server records receive time and corrects.

### 6.2 Config Delivery to Unity & other apps

Three delivery modes — a profile picks one or more per app:

1. **File target (zero app changes)**: agent writes a JSON/INI/XML file at a configured path atomically (write temp → fsync → rename), optionally templated from the effective config. Works with *any* app. App picks it up at next launch (agent can restart it) or via its own file-watching.
2. **Unity SDK (recommended)**: SDK watches a local config source and raises events on change. Enables hot-reload with no restart for values that can change live.
3. **Env / registry / args**: agent sets launch args, env vars, or registry values when it (re)launches the managed process.

**Unity SDK ↔ agent link**: local only. Default is a **file + named-event/localhost HTTP** pairing:
- The agent atomically writes `effective-config.json` (+ revision) to a known per-user directory.
- SDK watches that file (cheap `FileSystemWatcher`/poll) and optionally queries `http://127.0.0.1:<port>` for status, to push custom metrics/events (`RemoteConfig.ReportMetric("visitors_today", 42)`) and to acknowledge "config applied OK".
- Fallback if the agent is absent: SDK uses the last-known-good file shipped inside StreamingAssets, so the app always starts.

Config apply flow on the agent:
1. Download/verify (hash + signature) → 2. validate against schema → 3. stage → 4. apply atomically, keep previous as **last-known-good** → 5. if `restart_required`, restart app (respecting maintenance windows) → 6. run post-apply health check (grace period) → 7. report success, **or auto-rollback** to last-known-good and report failure.

**Reload modes** (declared per profile, optionally per config key group), because some apps hot-reload and some don't:
- `none` — file is written; app picks it up on its own next launch.
- `watch` — app watches the file / polls `GET /v1/config` and reloads itself (SDK raises an event).
- `trigger` — after applying, the agent sends an explicit reload trigger: HTTP callback to an app-declared local URL, a named signal/event file, or a launch-arg-less command hook. App acks via `POST /v1/config/ack`. If no ack within a timeout, the agent falls back to `restart`.
- `restart` — agent gracefully restarts the app (in the maintenance window if one is configured).

### 6.3 Monitoring & Health

- **Heartbeat**: two layers, see §6.10. Summary: the app reports to the agent often and cheaply (locally); the agent reports a compact status to the server on the check-in interval.
- **Watchdog** (local, no server needed): declarative rules in the config, e.g. "process `kiosk.exe` must run → restart on exit, max 3 restarts per 10 min, then alert", "no window responding for 60 s → kill & relaunch", "script heartbeat file updated within 2 min".
- **Checks**: process running, script/service running, file exists/age, TCP/HTTP probe, disk space, scheduled-time-window ("must be running 09:00–18:00").
- **Server-side state**: device is `online` / `stale` / `offline` based on last-seen vs. its *expected* check-in interval, so a metered 1-hour-interval device isn't falsely "offline" after 10 minutes.
- **Alerting**: webhook / email / Slack-style integration on offline, app-down, check failure, config-apply failure. Alerts are *edge-triggered with debounce* to avoid spam from flaky links.
- **Logs**: agent keeps a rotated local log ring; operator can request "fetch last N lines / since T" (compressed, on demand). App `Debug.Log` forwarding is opt-in via SDK with level filtering and a per-day byte cap.

### 6.4 Screenshots

- Captured by the agent, which runs in the **interactive user session** (see §6.7): installs are always auto-logged-in with the screen on, so no Session-0 helper is needed. macOS needs Screen Recording permission granted once at install.
- Modes: **on demand** (command), **scheduled** (e.g. every 30 min), **on event** (app crash / check fail).
- Bandwidth control: downscale (default ≤ 1280 px wide) + JPEG/WebP quality ~60 (typically 40–120 KB), optional change-detection to skip identical frames, **per-device daily data budget** with the queue deferring/dropping when exceeded, and a "thumbnail first, full-res on request" option.
- Server keeps a rolling history per device with retention (e.g. last 50 or 7 days), shown as a gallery/timeline in the UI.
- Capture is throttled/niced so it doesn't cause frame hitches on a running Unity app.

### 6.5 Remote Actions & Scripts

- Built-in actions: restart app, reboot, shutdown, clear cache folders, check-in now, capture screenshot, fetch logs.
- **Scripts**: operator picks from an uploaded, versioned, signed **script library** (PowerShell/bash/Python if present) with typed parameters. Agent verifies signature + hash, runs with timeout and resource limits (low priority), captures stdout/stderr (size-capped), reports result. No free-form remote shell in v1.
- Commands have a TTL: a "restart" queued while the device was offline for 3 days is **expired**, not blindly executed on reconnect (configurable per command).
- Maintenance windows: disruptive actions can be restricted to "outside opening hours".

### 6.6 Bandwidth & Data-Cap Management

**Known deployment profile**: 4G prepaid SIMs with ~20 GB/month caps and frequently poor reception. 20 GB is generous for config + monitoring (baseline is tens of MB), so the real design problem is *flaky links*, not volume: requests must be tiny, resumable, and tolerant of connections that drop mid-transfer. Prepaid also means running out of data silently kills connectivity, so the agent self-limits to a **default budget of ~3 GB/month** (configurable per device, leaving headroom for other traffic on the SIM).

- Per-device **Connectivity Profile**: `normal` | `metered` (default for 4G sites) | `minimal`, setting check-in interval, whether screenshots/logs are allowed, size caps, compression, and a **monthly data budget** with soft/hard limits.
- **Flaky-link behaviour**: short request timeouts, small payloads (single request < ~2 KB for check-ins), all uploads chunked and resumable (so a 100 KB screenshot survives a dropped connection without restarting), retry with jittered backoff, and reachability-gated sending (don't burn battery/CPU hammering a dead link; probe cheaply, then send).
- Agent counts its own bytes in/out and reports them; the dashboard shows usage per device against budget.
- Large payloads (config bundles, scripts, app assets) use **conditional requests (ETag)**, **resumable ranged downloads**, and optional off-hours-only scheduling. Optional LAN sharing / local file-drop (USB "sneakernet") update path for sites with no connectivity (stretch).

### 6.10 Heartbeat

The heartbeat is how the system knows the app is *actually working*, not just that a process exists (the old script only checked the latter).

**Layer 1: app → agent (local, cheap, frequent).** The app calls `PUT /v1/status` on `127.0.0.1` every ~5–15 s (interval set by config; the SDK does this automatically, any other app can use `curl` or a heartbeat file touch). Payload is small and generic:
```json
{ "state": "running|loading|idle|error", "uptime_s": 3600, "build": "1.4.2",
  "config_revision": 12, "fps": 58.2, "metrics": { "custom_key": 42 },
  "message": "optional short text" }
```
The agent uses it for **hang detection** (process alive but no heartbeat for N seconds → treat as frozen → restart per policy) and keeps the latest value plus a short history. Cost is local only; no network.

**Layer 2: agent → server (compact, on the check-in interval).** The agent folds the latest app status + process/OS stats into the check-in (§6.1): app state, uptime, restart count, config revision, CPU/RAM/disk, last-heartbeat age, bytes used, plus any threshold-crossing events since the last check-in. It does *not* forward every layer-1 beat; it sends the latest and notable changes, so data stays tiny on 4G.

**Server-side interpretation**: device status is derived from check-in recency against the *expected* interval, and app status from the reported app state and last-heartbeat age. Missing check-ins ≠ app down (could be 4G dropout), so the dashboard distinguishes "device unreachable" (unknown) from "app reported down/frozen" (known bad). Direct-to-server apps (no agent) send the same `PUT /v1/status` straight to the server at a slower interval.

### 6.7 Process Supervision (replaces the existing watch/restart script)

The agent takes over what the current restart script does, and does it better:
- **Runs in the logged-in user session** (Windows: Task Scheduler "at logon" with auto-restart on failure, or a Startup entry; macOS: LaunchAgent). Since machines are always logged in with the screen on, this gives the agent access to the desktop for screenshots and lets it launch the Unity app in the correct session/GUI context. A tiny optional Windows service can act as a second-level watchdog that restarts the agent itself if it dies.
- **Agent launches and owns the app**: the supervised app is part of the config (exe path, args, working dir, env, expected run window). Restart policy: restart on exit, restart on hang (window not responding / heartbeat file stale / optional SDK heartbeat), exponential backoff with a crash-loop limit (e.g. >3 restarts in 10 min → alert, stop thrashing, optionally fall back to the previous config/app version).
- **Graceful restarts** (implemented): every stop first asks the app to quit, through the SDK lifecycle long-poll and WM_CLOSE to its windows, waits `quit_timeout_s` (hung apps: at most 3 s), then kills.
- **The app outlives the agent** (implemented): the agent persists which process it launched; a new agent adopts it rather than launching a duplicate. Verified that Task Scheduler does not kill the app or keep the task "running" when the agent is killed or its task ended, so the watchdog still relaunches the agent. `stop_app_on_agent_exit` opts into the old behaviour.
- **Migration path**: the agent can run in *monitor-only* mode alongside the old script first, then switch to *supervise* mode per device once trusted. Don't run both supervisors at once.
- **Scope for v1: one supervised app per machine** (the data model keeps an `apps[]` list so more can be added later without a redesign). The app is assumed to be always running; there is no scheduling of power/wake.
- **Scheduled app restarts**: optional restart windows in config (e.g. "restart the app daily at 04:00"; also used for `restart`-mode config changes). Reboot of the whole PC can be scheduled the same way. Operators can still disable it per device.
- Crash evidence: on each crash the agent records exit code, uptime, and recent log tail, and attaches a screenshot if configured, so "why did it restart overnight" is answerable from the dashboard.

### 6.8 OTA Updates (bonus scope)

> **Status:** built in a first, simpler form (see README, "Scripts and releases"): whole-file releases with
> resumable ranged downloads instead of content-addressed chunks, hash-pinned in the signed command, app
> rollback on a failed health check, agent self-update with smoke test and trial-boot rollback, operator-chosen
> canary instead of automatic staging. The chunked/delta design below remains the intended next step if build
> sizes make whole-file transfers too expensive on metered links.

Config + monitoring is the core product. OTA is treated as an optional module that reuses the same machinery, so it adds little new surface area:
- **Artifact = versioned release** (app build folder or asset pack) split into **content-addressed chunks** (e.g. 1–4 MB, zstd-compressed, hashed). The agent downloads only chunks it doesn't already have, so a new build that changes 10% of files costs ~10% of the data (poor-man's delta, no binary-diff tooling needed).
- **Resumable & flaky-link safe**: chunks are fetched independently with ranged/conditional requests; progress is persisted, so a dropped connection loses at most one chunk.
- **Budgeted & scheduled**: downloads count against the data budget, can be restricted to off-hours, and are low priority/throttled (cap bandwidth and disk I/O so the running app doesn't stutter). A 1–2 GB build is feasible on a 20 GB plan if done occasionally; the UI shows an estimated data cost before rollout.
- **Staged, atomic install**: download into a staging dir → verify hashes + server signature → swap during a maintenance window (stop app, switch a `current` pointer/junction, start app) → post-start health check → **auto-rollback** to the previous release on failure. Keep N previous releases on disk (disk-space aware).
- **Staged rollout** via the same group/canary mechanism as config; releases are immutable and referenced by the effective config (`app.release = 1.4.2`), so "what version is running where" is just part of the reported state.
- **Agent self-update** uses the identical flow (signed, staged, rollback), with the OS service/Task Scheduler restarting into the new binary.
- Offline alternative: stage a release from a USB stick or LAN peer into the same chunk store.

### 6.9 Open Backend & Generic App Integration

The server is a **generic, open backend**, not a Unity-specific tool. Unity is just the first SDK. Any app can integrate in one of three ways, and a single installation may mix them:

1. **Direct to server**: the app speaks the public HTTP API itself (config fetch, event/metric reporting) using a per-app API key/device token. Useful for apps on machines with no agent, or for cloud/mobile apps. Thin SDKs (Unity C#, plus later JS/Python/etc.) wrap the API; the OpenAPI spec is the contract.
2. **Relayed through the agent (preferred on installs)**: the app talks only to the agent on `127.0.0.1` (same local API the Unity SDK uses). The agent caches, batches, queues offline, applies the data budget, and forwards. The app never needs to know about connectivity, auth, or retry. Same endpoints as direct mode, so an app can switch with a base-URL change.
3. **File/launch-arg only**: no code in the app at all (§6.2 file targets).

**One REST contract, two base URLs.** The local agent API and the remote server API expose the *same* app-facing REST endpoints (JSON over HTTP). An app only chooses a base URL: `http://127.0.0.1:<port>/v1` (relayed via the agent) or `https://<server>/v1` (direct). Switching is a config change, not a code change, and an app can fall back from local to remote if the agent isn't running. No SDK is required: any language with an HTTP client can integrate. SDKs are thin convenience wrappers only.

App-facing endpoints (sketch, finalised in the OpenAPI spec):
- `GET  /v1/config` — effective config for this device/app (`ETag`/`If-None-Match`, so a poll with no change returns a bodyless `304`; optional long-poll `?wait=30` for change notification)
- `POST /v1/config/ack` — report applied revision / apply failure
- `POST /v1/events` — batched events and logs
- `POST /v1/metrics` — batched key/value metrics
- `PUT  /v1/status` — app-reported health/heartbeat (also usable by scripts via `curl`)
- `GET  /v1/commands` / `POST /v1/commands/{id}/result` — app-handled commands (optional)
- `POST /v1/artifacts` — upload screenshots/files (chunked, resumable)

Auth differs by path, the contract doesn't: local calls use a per-install localhost token; direct-remote calls use a per-device or per-app API key issued at enrollment. The admin/management API (`/v1/admin/...`) is separate and only on the server.

Design consequences:
- **Unity 6 baseline** for the first SDK (UnityWebRequest + `Awaitable`, Unity's built-in JSON); kept free of version-specific APIs so older versions work with minor changes. The SDK is just a typed wrapper plus a config-changed event and sensible offline fallback.
- **Public, versioned, documented API** (`/v1`, OpenAPI) is a first-class deliverable, not an internal detail. The agent is just one client of it.
- **Generic payloads**: config is schemaless JSON validated by an optional per-app JSON Schema; metrics/events are free-form key/values with typed hints; nothing in the server core assumes Unity.
- **Projects (a.k.a. Applications) as the top-level scope**: every device, profile, script, release and API key belongs to a Project (e.g. "Museum Kiosk App"). Permissions are per project, which is also what lets third-party app admins see only their own fleet.
- **Server location is per-agent config**: an agent points at one server base URL (cloud or LAN), with an optional ordered fallback list (e.g. LAN server first, then cloud). Local and cloud servers are the same binary; a local server can optionally sync up to a cloud one later (not v1).

## 7. Server & Operator UI

**Two dashboards, two audiences**
- **Local client dashboard** (served by the agent on `127.0.0.1`, no cloud needed): for the installer/on-site person doing first-time setup (enter server URL + enrollment token, pick the app to supervise, test connectivity, view logs/screenshot, edit a local override) and for troubleshooting when something goes wrong. Also reachable by an admin who has remoted into the machine. Works fully offline. Read-mostly by default; edits sit behind a local PIN/token.
- **Remote admin dashboard** (served by the server): used by admins of the target app to manage their fleet: config, monitoring, screenshots, commands, releases. Scoped per Project and role. Specifics below.

**Dashboard views**
- **Fleet overview**: grid/list with status badges (online/stale/offline), last seen, app state, config in-sync indicator, alerts, filter by tag/group/site.
- **Device detail**: live status, effective config (with *source of each value* — global/group/device), config history & diff, recent events/log, screenshot gallery with "capture now", commands history, data usage, quick actions.
- **Config editor**: JSON editor with schema validation, form view when a schema is provided, side-by-side diff, **preview effective config for a device**, staged rollout ("apply to 1 test device → group → all"), one-click rollback.
- **Commands / scripts**: library, run on selection, results table.
- **Audit & alerts**: who did what, alert rules.
- **Enrollment**: generate one-time enrollment token / pre-baked installer.

**Auth**: local users with roles (owner / project admin / operator / viewer), assigned **per Project**, so app admins only see their own devices; optional OIDC later. HTTPS terminated by built-in ACME (Let's Encrypt) or by a reverse proxy; also supports plain HTTP + self-signed/own CA for LAN-only deployments.

**Hosting-agnostic packaging**: single binary + `config.yaml`; Docker image; Windows service / systemd unit. Data dir = SQLite file + blobs folder (backup = copy folder).

## 8. Agent Resource Budget

| Metric | Target |
|---|---|
| Idle CPU | ≈ 0% (timer-wakeups only, no busy polling) |
| RSS | ≤ 30 MB typical, ≤ 60 MB during screenshot/upload |
| Disk | binary ≤ 15 MB; queue + logs bounded (default 200 MB cap) |
| Network | heartbeat < 1 KB; ≤ ~15 MB/month baseline at 5-min interval, far less at 1 h |
| Scheduling | runs at below-normal priority; screenshot/zip work is throttled; never pegs a core |
| Startup | doesn't delay the Unity app launch |

Implementation notes: no polling loops where an event exists; coalesce timers; gzip/zstd only above a size threshold; avoid in-memory buffering of big blobs (stream); cap goroutines; a self-watchdog restarts the agent if wedged (OS service recovery policy).

## 8a. Installation & Provisioning

Every machine is a **fresh, standalone install**: nothing may be assumed pre-installed (no Go, .NET, VC++ runtimes, Python, PowerShell modules).
- The agent is a **single static binary** with the local dashboard assets embedded; no runtime dependencies.
- **Installer**: one signed package per OS (Windows: MSI or a small installer exe; macOS: pkg) that supports silent install with parameters, e.g. `installer /S SERVER=https://… TOKEN=… APP_PATH="C:\Kiosk\app.exe"`. It installs the binary, registers the logon auto-start/Task Scheduler entry (§6.7), sets recovery options, opens the local dashboard for first-run setup if no parameters were given, and enrolls with the server.
- **Zero-touch option**: a pre-baked config file (server URL, enrollment token, app definition) beside the installer, so imaging/cloning a machine requires no typing.
- **Uninstall/upgrade** are clean and keep the device identity unless told to reset.

## 9. Security

Threat model note: the system is private and the **data flowing back to the server isn't sensitive**, and agent reports can't change server-side config. So v1 aims for sensible, not paranoid:
- Secrets are limited to connection details (server URL, enrollment token, device/API key) and IDs. Those are stored with normal OS file permissions, not heavy encryption. The "secret" config field type only masks values in the UI/logs.
- The controls that matter are the ones protecting *what the server sends down* (signed config/scripts/releases, allowlisted scripts, authenticated operators), since that's what could harm a machine.

- **Enrollment**: one-time token → agent generates a keypair → server issues per-device credential (mTLS client cert or signed device token). Revocable per device.
- **Transport**: TLS only (except explicit LAN mode), cert pinning to server CA optional.
- **Signed content**: config bundles and scripts are signed by the server key; the agent verifies before applying, so a compromised CDN/proxy can't push code.
- **No inbound ports** on clients. Local SDK/agent API bound to 127.0.0.1 with a per-install token.
- **Least privilege**: agent runs as a service with only the permissions it needs; scripts run from an allowlist, never arbitrary strings from the network; sensitive values (API keys in configs) support server-side encryption at rest and a "secret" field type that is masked in the UI.
- **Audit log** for every operator action; rate limits and lockout on login.
- Physical-access threat model: installation PCs are in public places → disable remote-visible secrets on disk where possible, assume local tampering is possible but remotely-triggered damage is contained by signing + allowlists.

## 10. Failure Modes to Handle

| Scenario | Behaviour |
|---|---|
| Device offline for days | Runs on cached config; watchdog still works; queue buffers events; on reconnect, sends summary + drains queue by priority. |
| Server down | Agents back off with jitter; no effect on running installs. |
| Bad config pushed | Schema validation (server) + post-apply health check + auto-rollback (agent) + staged rollout limits blast radius. |
| Power loss mid-write | Atomic file writes; transaction-safe local state (SQLite/bolt) on agent. |
| Stale command on reconnect | TTL expiry; operator sees "expired". |
| Clock wrong on device | Server-corrected timestamps; signature checks don't depend on wall-clock. |
| Data cap hit | Hard budget stops screenshots/logs; config + alerts still allowed (tiny). |
| Agent crash/hang | OS service auto-restart; self-watchdog; app is unaffected (separate process). |

## 11. Phased Roadmap

**Phase 0 — Spike (1–2 wks)** *(define the OpenAPI contract first)*: Go agent + server skeleton; enrollment; check-in; serve a JSON config to a Windows test machine; Unity sample reading it.

**Phase 1 — MVP**: device registry & groups, layered config + schema validation, atomic apply + rollback, heartbeat + process watchdog, offline queue, basic web dashboard (fleet, device detail, config editor), Windows installer/service, Unity SDK v0.

**Phase 2 — Operations**: on-demand + scheduled screenshots (with budgets), logs fetch, built-in commands, script library, alerts/webhooks, audit log, bandwidth profiles & usage reporting, staged rollouts.

**Phase 3 — Platforms & polish**: macOS (and Linux) agent adapters, localhost status UI polish, OIDC, Postgres option, dashboards for trends/uptime reports.

**Phase 4 — OTA (bonus, designed-for but not required)**: see §6.8. App build / asset distribution, agent self-update, USB/LAN offline update path.

**Later**: remote live view on good links.

## 12. Open Questions (please weigh in)

**Answered**
1. ~~Session model~~ — machines are always logged in, screen on, app running/should be running → agent runs in the user session (§6.7).
2. ~~Who launches the app~~ — an existing script watches and restarts the app; the agent should replace it (§6.7), with a monitor-only migration mode.
3. ~~Connectivity~~ — 4G prepaid, ~20 GB/month cap, often poor reception (§6.6).
4. ~~App/asset updates~~ — config + monitoring is the requirement; OTA is a bonus (§6.8, Phase 4).

**Still open**
5. ~~Operators~~ — two audiences: on-site/remoted-in person uses the local dashboard; app admins use the remote dashboard (§7).
6. ~~Hosting~~ — some servers local, some cloud; same binary, per-agent server URL with fallbacks (§6.9).
7. ~~Other apps~~ — must be generic; apps talk directly to the server or are relayed through the agent (§6.9).
8. ~~Licensing~~ — private for now, possibly open-sourced or sold later. Design implication: keep dependencies permissively licensed, keep Project scoping and auth clean from the start, and don't hardcode anything personal. No decision needed yet.
9. ~~Existing restart script~~ — only checks the process and restarts it if dead. The agent's supervisor (§6.7) is a strict superset, so parity is easy.

**Still open**
10. ~~Unity version~~ — Unity 6 baseline, other versions best-effort; the project stays app-agnostic via the plain REST contract (§6.9).
11. **Product name** — placeholder `RemoteConfig` until decided.

**Resolved in later discussion**: single app per machine (v1); reload modes none/watch/trigger/restart (§6.2); app assumed always running with optional scheduled app/PC restarts (§6.7); all displays captured by default; third-party remote access (TeamViewer etc.) is out of scope; fresh standalone installs with no prerequisites (§8a); light secret handling (§9); two-layer heartbeat (§6.10).

**Product name** for the project (affects module path, binary names, installer).

## 13. Decisions Log

| Decision | Choice | Date |
|---|---|---|
| Fleet size | Dozens (<50) → SQLite, single-node server | 2026-10-26 |
| Hosting | Agnostic (cloud or local) → single binary + Docker, pluggable blob store | 2026-10-26 |
| Languages | Go agent + Go server + web SPA UI | 2026-10-26 (proposed; open to veto) |
| Client OS | Windows first; macOS/Linux via portable core + OS adapters | 2026-10-26 |
| Agent session | Runs in the always-logged-in user session; owns/supervises the app, replacing the existing restart script | 2026-10-26 |
| Connectivity | 4G prepaid, ~20 GB cap, poor reception → resumable chunked transfers, ~3 GB/month default agent budget | 2026-10-26 |
| Openness | Public versioned OpenAPI backend; apps connect directly or relayed via agent; Project is the top-level scope | 2026-10-26 |
| Dashboards | Local agent-served dashboard (setup/troubleshooting, offline) + remote admin dashboard (per-Project roles) | 2026-10-26 |
| App integration | Plain REST/JSON, same app-facing contract on local agent (127.0.0.1) and remote server; no SDK required; Unity 6 baseline SDK | 2026-10-26 |
| Licensing | Undecided (private now, maybe OSS/commercial) → keep deps permissive, defer choice | 2026-10-26 |
| Scope | Config + monitoring core; OTA updates as bonus Phase 4 using content-addressed chunks | 2026-10-26 |
