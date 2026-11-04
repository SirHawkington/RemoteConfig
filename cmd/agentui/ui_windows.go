//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/tailscale/walk"
	. "github.com/tailscale/walk/declarative"
	"github.com/tailscale/win"
	"golang.org/x/sys/windows"

	"remoteconfig/internal/proto"
)

const (
	windowTitle     = "RemoteConfig Agent"
	defaultTaskName = "RemoteConfigAgent"
	pollEvery       = 2 * time.Second
	logTailBytes    = 96 << 10
)

func main() {
	runtime.LockOSThread() // walk runs the whole UI on this thread

	dir := flag.String("dir", defaultDir(), "agent install directory (agent.exe, agent.json, state, log)")
	stateDir := flag.String("state-dir", "", "agent state directory, if not the install's (for an agent started by hand)")
	logFile := flag.String("log-file", "", "agent log file, if not the install's")
	listen := flag.String("listen", "", "agent local API address, if not the install's")
	tab := flag.Int("tab", -1, "tab to open first: 0 status, 1 log, 2 settings")
	task := flag.String("task-name", defaultTaskName, "scheduled task that runs the agent")
	flag.Parse()

	if _, err := walk.InitApp(); err != nil {
		fmt.Fprintln(os.Stderr, "cannot start the UI:", err)
		os.Exit(1)
	}

	// Double-clicked from Explorer this process owns a console that would flash up; drop it.
	windows.NewLazySystemDLL("kernel32.dll").NewProc("FreeConsole").Call()

	// One window per machine: a second launch just brings the first to the front.
	if _, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(`Local\RemoteConfigAgentUI`)); err == windows.ERROR_ALREADY_EXISTS {
		if h := win.FindWindow(nil, windows.StringToUTF16Ptr(windowTitle)); h != 0 {
			win.ShowWindow(h, win.SW_RESTORE)
			win.SetForegroundWindow(h)
		}
		return
	}

	in, s, err := resolveInstall(*dir, overrides{StateDir: *stateDir, LogFile: *logFile, Listen: *listen})
	if err != nil {
		fatal(err.Error())
	}
	u := &ui{in: in, cfg: s, task: *task, client: newClient(in), done: make(chan struct{}), kick: make(chan struct{}, 1)}
	if err := u.build(*tab); err != nil {
		fatal(err.Error())
	}
	go u.poll()
	u.mw.Show()
	walk.App().Run()
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	walk.MsgBox(nil, windowTitle, msg, walk.MsgBoxOK|walk.MsgBoxIconError)
	os.Exit(1)
}

// defaultDir is the directory holding agent.json: beside this program when it is installed
// there (agent install copies it next to agent.exe), otherwise the standard location.
func defaultDir() string {
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(d, "agent.json")); err == nil {
			return d
		}
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "RemoteConfig")
	}
	return `C:\ProgramData\RemoteConfig`
}

type ui struct {
	in     install
	cfg    settings
	task   string
	client *apiClient
	done   chan struct{}
	kick   chan struct{} // poll again now

	mw       *walk.MainWindow
	tabs     *walk.TabWidget
	headline *walk.Label
	detail   *walk.TextLabel
	vals     [rowCount]*walk.TextLabel
	logView  *walk.TextEdit
	follow   *walk.CheckBox
	notice   *walk.Label

	checkinBtn, captureBtn, restartBtn, startBtn, dashBtn, saveBtn, logFolderBtn, copyLogBtn *walk.PushButton
	fServer, fToken, fKey, fInterval, fListen                                                *walk.LineEdit
	reset                                                                                    *walk.CheckBox

	lastLog string
	server  string // for "Open dashboard"
}

const (
	rowDevice = iota
	rowProject
	rowServer
	rowVersion
	rowCheckin
	rowConfig
	rowApp
	rowSupervisor
	rowData
	rowQueue
	rowCount
)

var rowNames = [rowCount]string{
	"Device", "Project", "Server", "Agent version", "Last check-in", "Config revision",
	"App", "App supervision", "Data this cycle", "Waiting to send",
}

func (u *ui) build(tab int) error {
	var rows []Widget
	for i := range u.vals {
		rows = append(rows, Label{Text: rowNames[i] + ":", TextAlignment: AlignFar}, TextLabel{AssignTo: &u.vals[i], MinSize: Size{Width: 300}})
	}
	err := MainWindow{
		AssignTo: &u.mw, Title: windowTitle, MinSize: Size{Width: 560, Height: 560}, Size: Size{Width: 620, Height: 620},
		Layout: VBox{MarginsZero: false},
		Children: []Widget{
			Label{AssignTo: &u.headline, Font: Font{PointSize: 16, Bold: true}, Text: "Connecting to the agent…"},
			TextLabel{AssignTo: &u.detail, Text: " "},
			TabWidget{AssignTo: &u.tabs, Pages: []TabPage{
				{Title: "Status", Layout: Grid{Columns: 2, Spacing: 8}, Children: append(rows, VSpacer{ColumnSpan: 2})},
				{Title: "Log", Layout: VBox{}, Children: []Widget{
					TextEdit{AssignTo: &u.logView, ReadOnly: true, VScroll: true, HScroll: true, Font: Font{Family: "Consolas", PointSize: 9}},
					Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
						CheckBox{AssignTo: &u.follow, Text: "Follow newest", Checked: true},
						HSpacer{},
					}},
				}},
				{Title: "Settings", Layout: VBox{}, Children: u.settingsPage()},
			}},
			Label{AssignTo: &u.notice, Text: ""},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				PushButton{AssignTo: &u.checkinBtn, Text: "Check in now", OnClicked: func() {
					u.act("Check-in requested", func() (string, error) { return "", u.client.checkinNow() })
				}},
				PushButton{AssignTo: &u.captureBtn, Text: "Capture screenshot", OnClicked: func() {
					u.act("", u.client.captureNow)
				}},
				PushButton{AssignTo: &u.restartBtn, Text: "Restart app", OnClicked: u.confirmRestart},
				PushButton{AssignTo: &u.saveBtn, Text: "Save and apply", Visible: false, OnClicked: u.save},
				PushButton{AssignTo: &u.logFolderBtn, Text: "Open log folder", Visible: false, OnClicked: u.openLogFolder},
				PushButton{AssignTo: &u.copyLogBtn, Text: "Copy log", Visible: false, OnClicked: func() { walk.Clipboard().SetText(u.logView.Text()) }},
				HSpacer{},
				PushButton{AssignTo: &u.startBtn, Text: "Start agent", Visible: false, OnClicked: u.startAgent},
				PushButton{AssignTo: &u.dashBtn, Text: "Open server dashboard", Enabled: false, OnClicked: u.openDashboard},
			}},
		},
	}.Create()
	if err != nil {
		return err
	}
	if tb := u.mw.ToolBar(); tb != nil {
		tb.SetVisible(false) // an empty toolbar would otherwise sit on top of the first row
	}
	u.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) { close(u.done) })
	u.setActions(false, false)
	// Buttons placed inside a tab page never receive clicks in this walk fork, so the
	// per-tab actions live in the bottom row and follow the selected tab.
	u.tabs.CurrentIndexChanged().Attach(u.syncTabButtons)

	f := formFrom(u.cfg)
	u.fServer.SetText(f.Server)
	u.fKey.SetText(f.ServerKey)
	u.fInterval.SetText(f.Interval)
	u.fListen.SetText(f.Listen)
	if _, err := os.Stat(filepath.Join(u.in.StateDir, "identity.json")); f.Server == "" && err != nil {
		u.tabs.SetCurrentIndex(2) // nothing configured and never enrolled: this is the first run
	}
	if tab >= 0 && tab < 3 {
		u.tabs.SetCurrentIndex(tab)
	}
	u.syncTabButtons()
	return nil
}

func (u *ui) syncTabButtons() {
	i := u.tabs.CurrentIndex()
	u.logFolderBtn.SetVisible(i == 1)
	u.copyLogBtn.SetVisible(i == 1)
	u.saveBtn.SetVisible(i == 2)
}

func (u *ui) settingsPage() []Widget {
	field := func(label, cue string, to **walk.LineEdit, password bool) []Widget {
		return []Widget{Label{Text: label, TextAlignment: AlignFar}, LineEdit{AssignTo: to, CueBanner: cue, PasswordMode: password}}
	}
	var grid []Widget
	grid = append(grid, field("Server URL:", "https://rc.example.com", &u.fServer, false)...)
	grid = append(grid, field("Enrollment token:", "single use; leave empty to keep the saved one", &u.fToken, true)...)
	grid = append(grid, field("Server key:", "from \"Add device\" in the dashboard (recommended)", &u.fKey, false)...)
	grid = append(grid, field("Check-in interval:", "empty = follow the server, or e.g. 5m", &u.fInterval, false)...)
	grid = append(grid, field("Local API address:", defaultListen, &u.fListen, false)...)
	return []Widget{
		Composite{Layout: Grid{Columns: 2, MarginsZero: true, Spacing: 8}, Children: grid},
		CheckBox{AssignTo: &u.reset, Text: "Enroll as a new device (needs a fresh enrollment token)"},
		Label{Text: "Saving writes agent.json in " + u.in.Dir + ", registers the logon task and restarts the agent."},
		VSpacer{},
	}
}

// ---------------------------------------------------------------- polling and rendering

func (u *ui) poll() {
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		o, err := u.client.overview()
		logText, _ := tailFile(u.in.LogFile, logTailBytes)
		select {
		case <-u.done:
			return
		default:
		}
		u.mw.Synchronize(func() { u.render(o, err, logText) })
		select {
		case <-u.done:
			return
		case <-t.C:
		case <-u.kick:
		}
	}
}

func (u *ui) render(o *proto.Overview, err error, logText string) {
	now := time.Now()
	set := func(row int, s string) { u.vals[row].SetText(s) }
	head := func(text, detail string) {
		u.headline.SetText(text)
		u.detail.SetText(detail)
	}
	if logText != u.lastLog {
		u.lastLog = logText
		u.logView.SetText(strings.ReplaceAll(logText, "\n", "\r\n"))
		if u.follow.Checked() {
			u.logView.SetTextSelection(len(u.logView.Text()), len(u.logView.Text()))
			u.logView.ScrollToCaret()
		}
	}

	if err != nil {
		for i := range u.vals {
			set(i, "—")
		}
		head("Agent is not running", err.Error())
		u.startBtn.SetVisible(true)
		u.setActions(false, false)
		u.dashBtn.SetEnabled(u.server != "")
		return
	}
	u.startBtn.SetVisible(false)
	u.server = o.Server

	switch {
	case !o.Enrolled:
		head("Waiting to enroll", "Not enrolled with a server yet. Check the Settings tab and the log.")
	case o.Connected:
		head("Connected", "Checked in "+ago(o.LastCheckinAt, now)+"; config revision "+fmt.Sprint(o.ConfigRevision)+".")
	default:
		head("Offline", "Cannot reach the server. The app keeps running on its last config; the agent retries on its own.")
	}

	set(rowDevice, orDash(o.DeviceID))
	set(rowProject, orDash(o.Project))
	set(rowServer, orDash(o.Server))
	set(rowVersion, orDash(o.Version)+" (running "+dur(now.Sub(o.StartedAt))+")")
	set(rowCheckin, ago(o.LastCheckinAt, now))
	cfg := "none yet"
	if o.ConfigRevision > 0 {
		cfg = fmt.Sprint(o.ConfigRevision)
		if o.ConfigAcked > 0 {
			cfg += fmt.Sprintf(" (app confirmed %d)", o.ConfigAcked)
		}
	}
	set(rowConfig, cfg)

	app := "no heartbeat yet"
	if o.App != nil {
		app = o.App.State
		if o.App.UptimeS > 0 {
			app += ", up " + dur(time.Duration(o.App.UptimeS)*time.Second)
		}
		if o.App.Build != "" {
			app += ", build " + o.App.Build
		}
		if o.App.FPS > 0 {
			app += fmt.Sprintf(", %.0f fps", o.App.FPS)
		}
		app += fmt.Sprintf(" (heartbeat %ds ago)", o.HeartbeatAge)
		if o.App.Message != "" {
			app += " — " + o.App.Message
		}
	}
	set(rowApp, app)

	sv := o.Supervisor
	switch {
	case sv.CrashLoop:
		set(rowSupervisor, "crash loop: gave up after repeated crashes (restart it to try again)")
	case !sv.Managing:
		set(rowSupervisor, "not supervising an app on this machine")
	case sv.Running:
		set(rowSupervisor, fmt.Sprintf("running, pid %d, up %s, %d restart(s)", sv.PID, dur(time.Duration(sv.UptimeS)*time.Second), sv.Restarts))
	default:
		s := fmt.Sprintf("%s, %d restart(s)", sv.State, sv.Restarts)
		if sv.LastExit != "" {
			s += "; last exit " + sv.LastExit
		}
		set(rowSupervisor, s)
	}

	data := megabytes(o.Data.OutBytes) + " out / " + megabytes(o.Data.InBytes) + " in"
	if o.Data.LimitMB > 0 {
		data += fmt.Sprintf(" (%d%% of %d MB, %s)", o.Data.UsedPct, o.Data.LimitMB, o.Data.State)
	}
	set(rowData, data)
	set(rowQueue, fmt.Sprintf("%d event(s), %d screenshot(s)", o.PendingEvents, o.QueuedScreenshots))

	u.setActions(o.Enrolled, sv.Managing)
	u.dashBtn.SetEnabled(o.Server != "")
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func (u *ui) setActions(enrolled, managing bool) {
	u.checkinBtn.SetEnabled(enrolled)
	u.captureBtn.SetEnabled(enrolled)
	u.restartBtn.SetEnabled(managing)
}

// ---------------------------------------------------------------- actions

// act runs a call to the agent off the UI thread and reports its outcome in the notice line.
func (u *ui) act(okMsg string, call func() (string, error)) {
	u.notice.SetText("Working…")
	go func() {
		msg, err := call()
		u.mw.Synchronize(func() {
			switch {
			case err != nil:
				u.notice.SetText("Failed: " + err.Error())
			case msg != "":
				u.notice.SetText(msg)
			default:
				u.notice.SetText(okMsg)
			}
		})
		select {
		case u.kick <- struct{}{}:
		default:
		}
	}()
}

func (u *ui) confirmRestart() {
	if walk.MsgBox(u.mw, windowTitle, "Restart the app now? It is asked to save and quit first.", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != win.IDYES {
		return
	}
	u.act("", u.client.restartApp)
}

func (u *ui) startAgent() {
	u.notice.SetText("Starting the agent…")
	go func() {
		out, err := runHidden("schtasks.exe", "/Run", "/TN", u.task)
		u.mw.Synchronize(func() {
			if err != nil {
				msg := firstLine(out, err)
				if strings.Contains(strings.ToLower(out+msg), "cannot find") {
					msg = fmt.Sprintf("there is no scheduled task named %q. Use Save and apply on the Settings tab to install the agent, or pass -task-name if it was installed under another name", u.task)
				}
				u.notice.SetText("Could not start the agent: " + msg)
				return
			}
			u.notice.SetText("Agent starting…")
		})
		time.Sleep(2 * time.Second)
		select {
		case u.kick <- struct{}{}:
		default:
		}
	}()
}

func (u *ui) openLogFolder() {
	if _, err := os.Stat(u.in.LogFile); err != nil {
		walk.MsgBox(u.mw, windowTitle, "There is no log file yet at "+u.in.LogFile, walk.MsgBoxOK|walk.MsgBoxIconInformation)
		return
	}
	exec.Command("explorer.exe", "/select,"+u.in.LogFile).Start()
}

func (u *ui) openDashboard() {
	s := strings.TrimSpace(u.server)
	if s == "" {
		s = strings.TrimSpace(u.fServer.Text())
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return
	}
	exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", s).Start()
}

// save writes the form into agent.json by running `agent install`, the one code path that
// also registers the logon task and restarts the agent, so the UI and the command line
// can never disagree about what an install is.
func (u *ui) save() {
	f := form{
		Server: u.fServer.Text(), Token: u.fToken.Text(), ServerKey: u.fKey.Text(),
		Interval: u.fInterval.Text(), Listen: u.fListen.Text(),
	}
	if msg := f.validate(); msg != "" {
		walk.MsgBox(u.mw, windowTitle, msg, walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	exe := u.agentExe()
	if exe == "" {
		walk.MsgBox(u.mw, windowTitle, "agent.exe was not found in "+u.in.Dir+" or beside this program.", walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	cfg := f.apply(u.cfg)
	reset := u.reset.Checked()
	u.saveBtn.SetEnabled(false)
	u.notice.SetText("Installing…")
	go func() {
		out, err := installAgent(exe, u.in.Dir, u.task, cfg, reset)
		u.mw.Synchronize(func() {
			u.saveBtn.SetEnabled(true)
			if err != nil {
				u.notice.SetText("Install failed")
				walk.MsgBox(u.mw, windowTitle, "Could not apply the settings:\n\n"+firstLines(out, err), walk.MsgBoxOK|walk.MsgBoxIconError)
				return
			}
			u.cfg = cfg
			u.fToken.SetText("")
			u.reset.SetChecked(false)
			u.notice.SetText("Settings saved; the agent was restarted.")
			u.tabs.SetCurrentIndex(0)
		})
		select {
		case u.kick <- struct{}{}:
		default:
		}
	}()
}

func (u *ui) agentExe() string {
	cands := []string{filepath.Join(u.in.Dir, "agent.exe")}
	if self, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(self), "agent.exe"))
	}
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// installAgent hands the settings to `agent install` through a private temp file, so the
// enrollment token never appears on a command line other users could list.
func installAgent(exe, dir, task string, cfg settings, reset bool) (string, error) {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp("", "remoteconfig-ui-*.json") // created 0600
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()
	args := []string{"install", "-dir", dir, "-task-name", task, "-config", tmp.Name()}
	if reset {
		args = append(args, "-reset")
	}
	return runHidden(exe, args...)
}

func runHidden(name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	var buf bytes.Buffer
	c.Stdout, c.Stderr = &buf, &buf
	err := c.Run()
	return strings.TrimSpace(buf.String()), err
}

func firstLine(out string, err error) string {
	if out == "" {
		return err.Error()
	}
	return strings.SplitN(out, "\n", 2)[0]
}

func firstLines(out string, err error) string {
	if out == "" {
		return err.Error()
	}
	return out
}
