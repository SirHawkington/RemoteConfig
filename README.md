# RemoteConfig (placeholder name)

Remote config + monitoring for apps on unattended machines, built for flaky/metered links.
See [DESIGN.md](DESIGN.md) for the design and [api/openapi.yaml](api/openapi.yaml) for the REST contract.

**Status: Phase 1.** Working and tested:

- Enrollment, check-in, layered config (global -> tag -> device), ETag/long-poll delivery, atomic apply with last-known-good.
- **Process supervision** in the agent: launches the app, restarts on exit, relaunches on missed heartbeats (hang detection), crash-loop protection with backoff, daily scheduled restart, `restart_app` command, `monitor` mode for running beside an old watch script, and config `reload_mode` `restart` / `trigger`.
- **Graceful quit**: whenever the agent stops the app (restart, scheduled restart, config change, hang) it asks first: a lifecycle message the Unity SDK long-polls for, plus WM_CLOSE to the app's windows (so apps without the SDK close politely too). The app gets `quit_timeout_s` (default 10) to save and exit; only then is it killed. A hung app gets at most 3 s, since it cannot answer.
- **The app outlives the agent**: stopping, crashing or upgrading the agent does not touch the app. The agent records which process it started, and the next agent adopts that very process (identified by PID *and* start time *and* program path, so a recycled PID is never mistaken for it) instead of launching a duplicate. Set `stop_app_on_agent_exit` if you want the opposite.
- **SQLite storage** (pure Go, no cgo) with events and metrics retention.
- **Web dashboard** embedded in the server: fleet overview, device detail, config layer editor, enrollment tokens, remote restart, and (for admins) creating and renaming projects, members and accounts.
- Local agent REST API relaying the same contract on `127.0.0.1`, plus a read-only status page.

- **Screenshots**: all displays, downscaled by GDI itself (a 4K screen never sits in memory at full size), JPEG, scheduled and/or when the app hangs or crashes, plus "Capture now". Near-identical frames are skipped. Pictures queue on disk and upload in 64 KB resumable chunks that survive dropped connections, byte-for-byte verified (SHA-256). Gallery with lightbox in the dashboard; the newest 200 per device or 14 days are kept.
- **Data budget**: each agent counts the bytes it actually moves, measured at the socket (TLS and headers included), persisted across restarts, per carrier billing cycle (`reset_day`). At the soft threshold it warns; when used up, screenshots and metrics pause while check-ins, config and commands keep working. Shown per device in the dashboard.
- **Unity 6 package** ([unity/com.remoteconfig.client](unity/com.remoteconfig.client/README.md)): heartbeat, live config with hot reload, quit hook, metrics/events, error forwarding, and a test scene. Starts itself when the agent launches the app, so a built player needs no scene changes. Tested in Unity 6000.3 and 6000.6 (39 tests), and end to end as built Windows players under the real agent and server. Standalone players need **Run In Background** enabled, or they pause when unfocused and the agent restarts them as hung (the client warns if it is off).
- **Accounts and roles**: every dashboard user has their own login, and per-project roles decide what they can do. See [Accounts and roles](#accounts-and-roles).
- **Windows auto-start**: `agent install` / `uninstall` / `status` via a Task Scheduler task, with single-instance lock and a rotating log file.

Not yet: signed config, an MSI package, screenshots on macOS/Linux, capture of exclusive-fullscreen apps (see below), log fetching, resumable artifact upload,
disk-backed offline event queue, OIDC/SSO sign-in, two-factor authentication, OTA updates, macOS/Linux adapters.

## Layout

| Path | What |
|---|---|
| `api/openapi.yaml` | REST contract (device-facing + admin) |
| `internal/proto` | Wire types shared by agent and server |
| `internal/server` | Server, SQLite store, embedded dashboard (`web/`) |
| `internal/agent` | Agent: enroll, check-in, config apply, supervisor, screenshots, outbox/uploader, data budget, local API |
| `internal/capture` | Screen capture (Windows GDI), downscale, JPEG, change detection |
| `cmd/server`, `cmd/agent` | Entry points |
| `cmd/testapp` | Stand-in app for tests (heartbeats, can crash or hang on demand) |
| `unity/com.remoteconfig.client` | Unity 6 package (UPM): heartbeat, live config, quit hook, metrics/events, test scene. See its [README](unity/com.remoteconfig.client/README.md) |
| `internal/e2e_test.go` | Server + agent end-to-end test |

## Accounts and roles

The dashboard and admin API need a login; there is no shared password. On first run the server creates
an `admin` account and prints its password once. Sign in, change it from the account menu, then create
the people who need access (**Users** tab) and give them a role per project (**Members** tab).

| Role (per project) | Can |
|---|---|
| **viewer** | see devices, config, screenshots, events. Secret values in a supervisor's environment are hidden |
| **operator** | + restart apps, take screenshots, check in, rename and tag devices, edit config **except the `supervisor` section**, delete screenshots |
| **admin** | + the `supervisor` section, enrol and remove devices, manage members, read the audit log, send commands beyond restart/screenshot |
| **server admin** (a flag on the account) | admin in every project, plus create accounts and projects |

Why operators cannot touch `supervisor`: it chooses the program the agent runs on the machine, so editing
it is closer to deploying software than changing a setting. A project you have no role in answers `404`, as if it did not exist.

- **Passwords** are hashed (PBKDF2-SHA256, 600 000 rounds), at least 10 characters. Five wrong attempts lock that
  account/address for 15 minutes, and a wrong user and a wrong password look identical. Changing a password signs the other
  sessions out; disabling an account cuts off its sessions and tokens immediately.
- **Scripts** use personal access tokens (account menu), which act as you, are stored hashed, shown once, expire (default 90 days) and can be revoked.
  The old `-admin-token` flag still works: that token becomes a personal access token of `admin`. An existing database's plain-text admin token is
  converted to a hashed one on first start and erased from the file.
- **Audit log** (Audit tab): sign-ins, config edits, commands, member changes, and *refused* attempts. It records which parts of a config changed, never the values.
- **Offline administration**, no login needed, straight on the database file: `server user list|add|passwd|admin|disable|enable|delete|grant|revoke` (see `server user -h`).
  Changes apply immediately to a running server.
- **Use HTTPS** anywhere beyond localhost: `-tls-cert`/`-tls-key`, or a reverse proxy. The server warns if you listen publicly without TLS.
  The dashboard is served with a strict Content-Security-Policy (no inline script), no framing and no referrer.

## Signed config and commands

The server signs every effective config and every command with an Ed25519 key (`signing.json`, beside the
database; keep it private and back it up). Agents verify before applying anything and refuse what does not
check out: edited content, a config for another device, an older config replayed (rollback), a command that
was edited, forged or already run.

- **Pin the key at install.** "Add device" puts `-server-key <public key>` in the install command (also
  `server keys show`). An agent with a pin is strict from its first byte: it refuses to enrol with a server
  that presents another key, and never accepts unsigned config.
- **No pin:** the agent learns the key at enrolment only over https or to a loopback address. Over plain HTTP to
  another machine it stays in *legacy* mode (unsigned accepted) unless you pass `-insecure-tofu`, which trusts
  whoever answers first. Once an agent trusts a key it never goes back to unsigned.
- **Rotation:** `server keys rotate` or Users > Signing key > Rotate. The old key signs the new one, so pinned
  agents follow by themselves, including ones that were offline for a while.
- **Visibility:** each device shows `strict`, `legacy` or `rejecting` (refused something in the last 24 h and has not accepted a good config since; a
  `signature.rejected` event lists what). A cached signed config is re-verified at every agent start.
- **Protect the key file.** Give the server a passphrase (12+ characters) in `RC_SIGNING_PASSPHRASE`, or in a file
  with `-signing-passphrase-file`, and it encrypts the private key inside `signing.json` (PBKDF2-SHA256 and AES-256-GCM).
  A plain key file is encrypted the first time the server starts with a passphrase. Without the passphrase the server
  refuses to start, so a copied file, backup or disk image cannot be used to sign commands. `server keys protect` changes
  the passphrase, `server keys unprotect` removes it. Old copies of an unencrypted `signing.json`, backups included,
  still hold the key: destroy them. The server logs a warning at start while the key is unencrypted.
  This does not help against someone who can run code on the server while it runs (the key is in memory then),
  or against a passphrase stored next to the file it protects.
- **What it does not cover:** someone who controls the server or its `signing.json` can sign anything.
  Signatures protect the path between server and agent (proxies, hijacked DNS, a stolen database copy
  of configs), not the server itself. Scripts and OTA releases do not exist yet; when they do, they use the same
  envelope with their own payload type, so a signed config can never be passed off as a script.

## Scripts and releases (Library tab)

Both run code on your devices, so both are project-admin only, both need an agent that verifies signatures
(an agent that does not refuses), and both are referred to by hash: the signed command carries the SHA-256 of
what an administrator uploaded, and the agent checks the bytes it receives against it before running or
unpacking anything. Nothing in a command can name different content.

- **Scripts**: PowerShell, cmd, bash, sh or python, versioned and immutable. A device runs one at a time, at low
  priority, with a time limit, arguments passed as an argument list (never through a shell string), and sends back the
  exit code and the start and end of the output (32 KB). Send from the Library tab or
  `POST .../devices/{id}/commands {"type":"run_script","params":{"script":"clear-cache","args":["x"]}}`.
  A script that is still running when the agent restarts is reported as failed, not re-run.
- **App releases**: upload a zip of the build folder. The device downloads it (resumes after a dropped link,
  counts against the data budget and stops when the budget is used up), unpacks it beside earlier builds
  (paths that leave the folder, links and zip bombs are refused), restarts the app on it and waits `health_s`
  (default 45 s) for it to stay up. If it crashes or does not start, the previous build is put back and
  the failure is reported. To use it, write the program path in the supervisor config with the placeholder:
  `"exe": "${release}\\kiosk.exe"`.
- **Agent releases**: upload the agent executable with the version `agent version` prints
  (`go build -ldflags "-X main.version=1.2.0"` sets it) and its architecture. The device runs the new
  binary with `version` first; if that fails nothing changes. Otherwise it swaps the binary, reports, and
  exits with code 75 so the scheduled task starts the new one. The app keeps running. A new binary that restarts
  three times without managing to check in is replaced by the previous one.
- **Staged rollouts.** The Install and Run dialogs send in stages by default: the canary device(s) get it first;
  the rest only after the canary reports success and then stays healthy for the wait you set (default 2 minutes for a
  release: no error-level event such as a crash loop or a rolled-back build, signatures still accepted, and back online,
  which matters when the agent restarts itself). A failure or an unhealthy canary halts the rollout and nothing more is
  sent; you can also halt it by hand. Devices already told still run the command. Pick the canary as a device you can
  get to, ideally one with a screen you can look at, and use waves (`batch`) for a large fleet.
  API: `POST .../rollouts`. Sending straight to chosen devices is still possible by unticking "Send in stages".
- **Not covered:** a new agent binary that cannot start at all (missing runtime, blocked by antivirus) never
  reaches the code that notices; the smoke test catches most of this but not everything, and recovery then needs
  someone on site or a remote session. There are no delta downloads: a build is sent whole.

### Command line: `rcctl`

For build scripts and quick use without the dashboard. Make an API token in the dashboard's account menu,
then (the token comes from the environment so it never shows in a process list):

```bash
export RCCTL_SERVER=https://rc.example.com RCCTL_TOKEN=...        # or RCCTL_TOKEN_FILE; RCCTL_PROJECT if you have several
rcctl devices
rcctl script add clear-cache clear.ps1                            # a new version of "clear-cache"
rcctl script run clear-cache -devices lobby-1 -arg C:\cache       # staged: lobby-1 first
rcctl release upload kiosk-1.4.2.zip -name kiosk -version 1.4.2
rcctl release send kiosk@1.4.2 -devices lobby-1,lobby-2,hall-1 -soak 300 -wait
rcctl release upload agent.exe -version 1.2.0 -arch amd64         # an agent build
rcctl rollout list | show <id> | halt <id> | watch <id>
```

Choose devices with `-devices` (names or ids; the first are the canary), `-tag` or `-all`; `-now` skips the staging.
`-wait` follows the rollout and exits 1 if it halts, so a script can stop. Exit codes: 0 ok, 1 failed or halted,
2 wrong usage or missing settings, 3 not allowed (bad token or role).

## Screenshots and the data budget

Turn them on in any config layer (they merge field by field, so a device layer can change just the interval):

```json
{ "data": {},
  "screenshots": { "enabled": true, "interval_s": 300, "max_width": 1280, "quality": 60, "on_event": true },
  "budget": { "monthly_mb": 3000, "reset_day": 1, "soft_pct": 80 } }
```

Typos and out-of-range values are rejected when you save. Roughly 60-130 KB per display per picture
at the defaults; with unchanged-frame skipping, a mostly static kiosk uses far less than
`24 h / interval x displays x size` suggests. Set `monthly_mb` below the SIM's real cap to leave headroom.

**Limitation:** capture uses GDI. It sees borderless/windowed Unity (`FullScreenMode.FullScreenWindow`) and
normal desktops. A locked or asleep screen, or an app in *exclusive* fullscreen, can produce a black image;
the agent flags that (`screenshot.black` event, "black" in the gallery). If you hit it, use
Fullscreen Window in the Unity player settings. DXGI desktop duplication would be the next step.

## Linux and macOS agents (written, not yet run on real machines)

The agent builds for `linux` and `darwin` (amd64 and arm64): `GOOS=linux GOARCH=amd64 go build ./cmd/agent`.
Everything that does not touch the operating system is the same code as on Windows and is tested; **the parts below
that do touch it were written against the platform documentation and have only been compiled, never run on a real
Linux or macOS machine.** Try one device before a fleet.

| | Windows | Linux | macOS |
|---|---|---|---|
| Start at logon, restart | scheduled task | systemd **user** unit | LaunchAgent |
| App outlives an agent restart or update | yes | yes (`KillMode=process`) | yes (`AbandonProcessGroup`) |
| Adopt a running app after an agent restart | yes | yes (`/proc`) | yes (`ps`) |
| Only one agent per state folder | named mutex | `flock` | `flock` |
| Screenshots | built in (GDI) | needs one of `grim`, `scrot`, `maim`, `import`, `gnome-screenshot`, `spectacle` | built-in `screencapture`; needs Screen Recording permission |
| Graceful quit of the app | window close, then kill | SIGTERM, then kill | SIGTERM, then kill |
| Scripts | powershell, cmd | bash, sh, python, pwsh | bash, sh, python, pwsh |

Install exactly like on Windows, as the user who runs the kiosk (`agent install -server ... -enroll-token ... -server-key ...`);
`agent status` and `agent uninstall [-purge]` work too. Notes:
- Linux: the service starts when that user logs in; for a machine that boots without a login, run `loginctl enable-linger <user>` once as root. Screenshots assume `DISPLAY=:0` if the service has none. On an X11 desktop with several monitors you get one wide picture, not one per monitor. Wayland compositors such as GNOME may refuse screenshots from background programs.
- macOS: grant the agent binary Screen Recording in System Settings, or the pictures show only the wallpaper (the agent flags an all-black picture, but not a wallpaper-only one).
- A release zip made on Windows has no execute permission; the agent marks the supervisor's program executable after unpacking. Build app releases for the target platform.
- An agent update exits with code 75 and relies on `Restart=always` / `KeepAlive` to start the new binary.

## Deploying an agent (Windows)

On the target machine, from the kiosk's auto-login account (use "Add device" in the dashboard to get a token):

```powershell
agent.exe install -server https://rc.example.com -enroll-token <TOKEN>
```

This copies the agent to `C:\ProgramData\RemoteConfig`, writes `agent.json`, registers a scheduled task
(starts at logon, restarts if it crashes, plus a one-minute watchdog that relaunches it if it was killed),
and starts it. Nothing else needs to be installed.

- **Zero-touch:** put an `agent.json` (`{"server": "...", "enroll_token": "..."}`) next to `agent.exe` and run `agent.exe install`.
- **Upgrade:** run `install` again with the new binary; the device keeps its identity. `-reset` forces re-enrollment.
- **Check on it:** `agent.exe status` (task state, identity, health, last log lines). Logs are in `<dir>\agent.log` (rotated, 2 x 2 MB).
- **Remove:** `agent.exe uninstall` (add `-purge` to delete files and identity).
- Other flags: `-dir`, `-user DOMAIN\name` (account whose logon starts it), `-elevated` (to supervise an elevated app), `-no-start`, `-task-name`.
- **Upgrading does not interrupt the app.** `install` stops the old agent and starts the new one; the app keeps running and the new agent adopts it (verified on the real Task Scheduler: same process, same start time, launched once). The same happens if the agent crashes or is killed and the one-minute watchdog relaunches it (about 35 s in testing).
- `uninstall` removes the auto-start and leaves a running app alone (taking management away is not the same as closing the display).

## Desktop window (Windows)

`agent-ui.exe` is a small native window for the person on site: live status (connection, app, supervision, data use),
the agent log, and first-run setup / settings (server URL, enrollment token, server key, interval, local address).
It also has **Check in now**, **Capture screenshot**, **Restart app** and **Start agent** buttons.

- It is a separate program that talks to the agent's local API, so it costs nothing while closed and the agent never depends on it.
  The log is read straight from disk, so it still works when the agent is not running.
- Ship it beside `agent.exe`: `agent install` copies it into the install folder and adds a Start menu shortcut
  ("RemoteConfig Agent"). **Save and apply** runs `agent install` with the form's values, so it behaves exactly like the command line.
- Build: `go build -ldflags "-H=windowsgui" -o bin/agent-ui.exe ./cmd/agentui` (without the flag a console window flashes up).
  The manifest resource is checked in as `cmd/agentui/rsrc_windows_amd64.syso`; regenerate it with
  `go run ./tools/mksyso -manifest cmd/agentui/agentui.manifest -o cmd/agentui/rsrc_windows_amd64.syso`.

### Server window, for a local run

`server-ui.exe` runs the server without a command line: put it beside `server.exe` and double-click it. It starts the
server and shows everything you need to set up a first device, each with a **Copy** button: the server address for agents,
the first-run `admin` password, the signing key to pin, a single-use **enrollment token** (72 hours; **New** makes another, and
creates a project called "Main" if the server has none) and the ready-made `agent.exe install ...` command. It also has a live
log, **Stop**, **Restart**, **Open dashboard**, **Reset** admin password (`server user passwd`) and **Open** data folder.
To ask the server for tokens, the window starts it with a one-off admin token (in the server's environment, never on a command
line) and revokes it again when the server is stopped.

- Settings (port, data folder, check-in interval, demo project, start on open) are saved in `server-ui.json` beside the program
  and turned into the server's normal flags on each start. By default the server listens on this PC only; tick
  "Let other PCs on the network connect" for agents on other machines (plain HTTP: see the TLS notes above).
- The server is a child of the window and stops when it closes (also if the window is killed), so it is for local and
  trial use. For a server that must keep running unattended, run `server.exe` as a service or from a scheduled task instead.
- Build: `go build -ldflags "-H=windowsgui" -o bin/server-ui.exe ./cmd/serverui`; its manifest resource is a copy of the agent window's.
- Against an agent started by hand: `agent-ui.exe -state-dir .gent-state -log-file .gent.log -listen 127.0.0.1:7878`.

## Try it from source (Windows, Go 1.26+)

```powershell
go test ./... -race
go build -o bin ./cmd/...

# terminal 1: server with a demo project; prints the first-run admin password and an enrollment token
.\bin\server.exe -dev-seed -checkin-interval 15s

# terminal 2: agent (use the enrollment token printed above)
.\bin\agent.exe -server http://localhost:8080 -enroll-token <TOKEN> -state-dir .\agent-state
```

Open http://localhost:8080/ and sign in as `admin` with the password the server printed on first run. To have the agent run and watch an app,
add a `supervisor` block to the global layer in the Config tab:

```json
{ "data": { "volume": 0.8 },
  "reload_mode": "watch",
  "supervisor": { "exe": "C:\\Kiosk\\app.exe", "heartbeat_timeout_s": 30, "scheduled_restart": "04:00" } }
```

The app should `PUT /v1/status` to the local API every few seconds, and (optionally, the Unity SDK does) long-poll `GET /v1/lifecycle`
to learn it should save and quit. The agent passes it
`REMOTECONFIG_URL`, `REMOTECONFIG_TOKEN` and `REMOTECONFIG_CONFIG_FILE` in its environment.
`bin\testapp.exe` is a ready-made stand-in (`-crash-after 5s`, `-hang-after 5s`).

Local agent status page: http://127.0.0.1:7878/ . The effective config is written to
`<state-dir>/effective-config.json` (or `-out-dir`).
