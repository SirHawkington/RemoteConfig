//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/walk"
	. "github.com/tailscale/walk/declarative"
	"github.com/tailscale/win"
	"golang.org/x/sys/windows"
)

const (
	windowTitle     = "RemoteConfig Server"
	pollEvery       = time.Second
	enrollTTLHours  = 72
	defaultProjName = "Main"
)

func main() {
	runtime.LockOSThread() // walk runs the whole UI on this thread

	dir := flag.String("dir", "", "folder for settings and data (default: beside this program)")
	serverExe := flag.String("server", "", "path of server.exe (default: beside this program)")
	flag.Parse()

	if _, err := walk.InitApp(); err != nil {
		fmt.Fprintln(os.Stderr, "cannot start the UI:", err)
		os.Exit(1)
	}
	windows.NewLazySystemDLL("kernel32.dll").NewProc("FreeConsole").Call()

	if _, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(`Local\RemoteConfigServerUI`)); err == windows.ERROR_ALREADY_EXISTS {
		if h := win.FindWindow(nil, windows.StringToUTF16Ptr(windowTitle)); h != 0 {
			win.ShowWindow(h, win.SW_RESTORE)
			win.SetForegroundWindow(h)
		}
		return
	}

	base := *dir
	if base == "" {
		base = defaultBase()
	}
	cfgPath := filepath.Join(base, configName)
	cfg, err := loadConfig(cfgPath, base)
	if err != nil {
		fatal(err.Error())
	}
	u := &ui{cfg: cfg, cfgPath: cfgPath, run: &runner{exe: findServer(*serverExe)}, done: make(chan struct{})}
	if err := u.build(); err != nil {
		fatal(err.Error())
	}
	go u.poll()
	if cfg.AutoStart {
		u.startServer()
	}
	u.mw.Show()
	walk.App().Run()
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	walk.MsgBox(nil, windowTitle, msg, walk.MsgBoxOK|walk.MsgBoxIconError)
	os.Exit(1)
}

// defaultBase is where settings and data live: beside this program when that folder can be
// written (a portable setup), otherwise the user's local application data.
func defaultBase() string {
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		if f, err := os.CreateTemp(d, ".rc-write-test-*"); err == nil {
			f.Close()
			os.Remove(f.Name())
			return d
		}
	}
	if la := os.Getenv("LocalAppData"); la != "" {
		return filepath.Join(la, "RemoteConfigServer")
	}
	return `C:\ProgramData\RemoteConfigServer`
}

func findServer(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if self, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(self), "server.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

type ui struct {
	cfg     config
	cfgPath string
	run     *runner
	done    chan struct{}

	mw       *walk.MainWindow
	tabs     *walk.TabWidget
	headline *walk.Label
	detail   *walk.TextLabel
	logView  *walk.TextEdit
	follow   *walk.CheckBox
	notice   *walk.Label

	state, dashboard, data                       *walk.TextLabel
	agentAddr, adminPW, signKey, token, installC *walk.LineEdit
	projects                                     *walk.ComboBox

	startBtn, stopBtn, restartBtn, dashBtn, saveBtn, copyLogBtn, folderBtn, resetBtn *walk.PushButton
	copyAddr, copyPW, copyKey, copyToken, newToken, copyInstall                      *walk.PushButton
	fPort, fData, fInterval                                                          *walk.LineEdit
	fNetwork, fSeed, fAuto                                                           *walk.CheckBox

	lastGen   int
	snap      snapshot
	api       *apiClient // for the current run
	apiToken  string
	loadedFor time.Time // run whose projects have been loaded
	projIDs   []string
	enrollTok string
	enrollKey string
}

func (u *ui) build() error {
	row := func(label string, value Widget, buttons ...Widget) []Widget {
		return []Widget{
			Label{Text: label, TextAlignment: AlignFar}, value,
			Composite{Layout: HBox{MarginsZero: true, Spacing: 4}, Children: buttons},
		}
	}
	ro := func(to **walk.LineEdit) Widget {
		return LineEdit{AssignTo: to, ReadOnly: true, MinSize: Size{Width: 380}}
	}
	btn := func(to **walk.PushButton, text string, f func()) Widget {
		return PushButton{AssignTo: to, Text: text, OnClicked: f}
	}
	var grid []Widget
	grid = append(grid, row("State:", TextLabel{AssignTo: &u.state}, btn(&u.dashBtn, "Open dashboard", u.openDashboard))...)
	grid = append(grid, row("Dashboard:", TextLabel{AssignTo: &u.dashboard})...)
	grid = append(grid, row("Server address for agents:", ro(&u.agentAddr), btn(&u.copyAddr, "Copy", func() { u.copy(u.agentAddr.Text(), "Server address") }))...)
	grid = append(grid, row("Admin password:", ro(&u.adminPW), btn(&u.copyPW, "Copy", func() { u.copy(u.adminPW.Text(), "Admin password") }),
		btn(&u.resetBtn, "Reset", u.resetAdmin))...)
	grid = append(grid, row("Signing key:", ro(&u.signKey), btn(&u.copyKey, "Copy", func() { u.copy(u.signKey.Text(), "Signing key") }))...)
	grid = append(grid, row("Project:", ComboBox{AssignTo: &u.projects, MinSize: Size{Width: 380}})...)
	grid = append(grid, row("Enrollment token:", ro(&u.token), btn(&u.copyToken, "Copy", func() { u.copy(u.token.Text(), "Enrollment token") }),
		btn(&u.newToken, "New", u.createEnrollment))...)
	grid = append(grid, row("Install command:", ro(&u.installC), btn(&u.copyInstall, "Copy", func() { u.copy(u.installC.Text(), "Install command") }))...)
	grid = append(grid, row("Data folder:", TextLabel{AssignTo: &u.data}, btn(&u.folderBtn, "Open", u.openDataFolder))...)

	err := MainWindow{
		AssignTo: &u.mw, Title: windowTitle, MinSize: Size{Width: 720, Height: 640}, Size: Size{Width: 780, Height: 700},
		Layout: VBox{},
		Children: []Widget{
			Label{AssignTo: &u.headline, Font: Font{PointSize: 16, Bold: true}, Text: "Starting…"},
			TextLabel{AssignTo: &u.detail, Text: " "},
			Composite{Layout: Grid{Columns: 3, MarginsZero: true, Spacing: 6}, Children: grid},
			TabWidget{AssignTo: &u.tabs, Pages: []TabPage{
				{Title: "Log", Layout: VBox{}, Children: []Widget{
					TextEdit{AssignTo: &u.logView, ReadOnly: true, VScroll: true, HScroll: true, Font: Font{Family: "Consolas", PointSize: 9}},
					CheckBox{AssignTo: &u.follow, Text: "Follow newest", Checked: true},
				}},
				{Title: "Settings", Layout: VBox{}, Children: u.settingsPage()},
			}},
			Label{AssignTo: &u.notice, Text: ""},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				btn(&u.startBtn, "Start", u.startServer),
				btn(&u.stopBtn, "Stop", u.stopServer),
				btn(&u.restartBtn, "Restart", u.restartServer),
				HSpacer{},
				PushButton{AssignTo: &u.saveBtn, Text: "Save settings", Visible: false, OnClicked: u.save},
				PushButton{AssignTo: &u.copyLogBtn, Text: "Copy log", OnClicked: func() { walk.Clipboard().SetText(u.logView.Text()) }},
			}},
		},
	}.Create()
	if err != nil {
		return err
	}
	if tb := u.mw.ToolBar(); tb != nil {
		tb.SetVisible(false) // an empty toolbar would otherwise sit on top of the first row
	}
	u.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if u.run.snapshot().Running {
			if walk.MsgBox(u.mw, windowTitle, "Closing this window stops the server. Close it?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != win.IDYES {
				*canceled = true
				return
			}
			u.shutdown()
		}
		close(u.done)
	})
	u.tabs.CurrentIndexChanged().Attach(u.syncTabButtons)
	u.fillForm()
	u.syncTabButtons()
	u.render(u.run.snapshot())
	return nil
}

func (u *ui) fillForm() {
	u.fPort.SetText(strconv.Itoa(u.cfg.Port))
	u.fData.SetText(u.cfg.DataDir)
	u.fInterval.SetText(u.cfg.Interval)
	u.fNetwork.SetChecked(u.cfg.Network)
	u.fSeed.SetChecked(u.cfg.DevSeed)
	u.fAuto.SetChecked(u.cfg.AutoStart)
}

func (u *ui) settingsPage() []Widget {
	field := func(label, cue string, to **walk.LineEdit) []Widget {
		return []Widget{Label{Text: label, TextAlignment: AlignFar}, LineEdit{AssignTo: to, CueBanner: cue}}
	}
	var grid []Widget
	grid = append(grid, field("Port:", "8080", &u.fPort)...)
	grid = append(grid, field("Data folder:", "database, signing key and uploads live here", &u.fData)...)
	grid = append(grid, field("Check-in interval:", "how often agents check in, e.g. 5m", &u.fInterval)...)
	return []Widget{
		Composite{Layout: Grid{Columns: 2, MarginsZero: true, Spacing: 8}, Children: grid},
		CheckBox{AssignTo: &u.fNetwork, Text: "Let other PCs on the network connect (needed for agents on other machines)"},
		CheckBox{AssignTo: &u.fSeed, Text: "Create a demo project with a sample config on each start"},
		CheckBox{AssignTo: &u.fAuto, Text: "Start the server when this window opens"},
		Label{Text: "Other PCs connect over plain HTTP unless you set up TLS; keep this off on an untrusted network."},
		Label{Text: "A signing-key passphrase is taken from the RC_SIGNING_PASSPHRASE environment variable if it is set."},
		VSpacer{},
	}
}

func (u *ui) syncTabButtons() {
	u.saveBtn.SetVisible(u.tabs.CurrentIndex() == 1)
	u.copyLogBtn.SetVisible(u.tabs.CurrentIndex() == 0)
}

func (u *ui) copy(text, what string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	walk.Clipboard().SetText(text)
	u.notice.SetText(what + " copied to the clipboard.")
}

// ---------------------------------------------------------------- polling and rendering

func (u *ui) poll() {
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		select {
		case <-u.done:
			return
		case <-t.C:
		}
		s := u.run.snapshot()
		var text string
		if s.Gen != u.lastGen {
			text = u.run.text()
		}
		select {
		case <-u.done:
			return
		default:
		}
		u.mw.Synchronize(func() {
			if s.Gen != u.lastGen {
				u.lastGen = s.Gen
				u.logView.SetText(text)
				if u.follow.Checked() {
					n := len(u.logView.Text())
					u.logView.SetTextSelection(n, n)
					u.logView.ScrollToCaret()
				}
			}
			u.render(s)
			if s.Running && s.Scan.Listening && u.loadedFor != s.StartedAt {
				u.loadedFor = s.StartedAt
				u.loadProjects(true)
			}
		})
	}
}

func (u *ui) render(s snapshot) {
	u.snap = s
	switch {
	case s.Running && s.Scan.Listening:
		u.headline.SetText("Server is running")
		u.detail.SetText("Up " + dur(time.Since(s.StartedAt)) + ".")
		u.state.SetText("running for " + dur(time.Since(s.StartedAt)))
	case s.Running:
		u.headline.SetText("Starting…")
		u.detail.SetText(" ")
		u.state.SetText("starting")
	case s.ExitMsg != "":
		u.headline.SetText("Server is stopped")
		u.detail.SetText(s.ExitMsg)
		u.state.SetText(s.ExitMsg)
	default:
		u.headline.SetText("Server is stopped")
		u.detail.SetText("Press Start to run it.")
		u.state.SetText("stopped")
	}
	dash := u.cfg.dashboardURL()
	if !u.cfg.Network {
		dash += "   (this PC only; allow network access in Settings for other PCs)"
	}
	u.dashboard.SetText(dash)
	u.data.SetText(u.cfg.DataDir)

	addr := u.cfg.agentURL() // copied as is, so no commentary in it
	if u.agentAddr.Text() != addr {
		u.agentAddr.SetText(addr)
	}
	pw := s.Scan.AdminPassword
	if pw == "" {
		pw = "set earlier: use Reset to make a new one"
	}
	if u.adminPW.Text() != pw {
		u.adminPW.SetText(pw)
	}
	key := orDash(s.Scan.ServerKey)
	if u.signKey.Text() != key {
		u.signKey.SetText(key)
	}
	token := orDash(u.enrollTok)
	if u.token.Text() != token {
		u.token.SetText(token)
	}
	cmd := installCommand(u.cfg.agentURL(), u.enrollTok, firstNonEmpty(s.Scan.ServerKey, u.enrollKey))
	if u.installC.Text() != cmd {
		u.installC.SetText(cmd)
	}

	ready := s.Running && s.Scan.Listening
	u.startBtn.SetEnabled(!s.Running)
	u.stopBtn.SetEnabled(s.Running)
	u.restartBtn.SetEnabled(s.Running)
	u.dashBtn.SetEnabled(ready)
	u.copyAddr.SetEnabled(true)
	u.copyPW.SetEnabled(s.Scan.AdminPassword != "")
	u.resetBtn.SetEnabled(u.run.exe != "")
	u.copyKey.SetEnabled(s.Scan.ServerKey != "")
	u.copyToken.SetEnabled(u.enrollTok != "")
	u.copyInstall.SetEnabled(u.enrollTok != "")
	u.newToken.SetEnabled(ready && u.api != nil)
	u.projects.SetEnabled(ready)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---------------------------------------------------------------- server control

func (u *ui) startServer() {
	if u.run.exe == "" {
		u.notice.SetText("server.exe was not found beside this program.")
		return
	}
	if msg := u.cfg.validate(); msg != "" {
		u.notice.SetText(msg)
		return
	}
	if err := os.MkdirAll(u.cfg.DataDir, 0o755); err != nil {
		u.notice.SetText("Cannot create the data folder: " + err.Error())
		return
	}
	// A one-off admin token lets this window ask the server for enrollment tokens. It only
	// ever lives in this process and the server's environment.
	u.apiToken = newAPIToken()
	u.api = newAPI(u.cfg, u.apiToken)
	u.loadedFor = time.Time{}
	if err := u.run.start(u.cfg.args(), []string{"RC_ADMIN_TOKEN=" + u.apiToken}); err != nil {
		u.api = nil
		u.notice.SetText("Could not start the server: " + err.Error())
		return
	}
	u.notice.SetText("")
	u.render(u.run.snapshot())
}

// shutdown stops the server, first revoking the window's own admin token. It blocks.
func (u *ui) shutdown() {
	if u.api != nil && u.run.snapshot().Scan.Listening {
		u.api.dropBootstrapTokens()
	}
	u.run.stop()
	u.api = nil
}

func (u *ui) stopServer() {
	u.notice.SetText("Stopping…")
	go func() {
		u.shutdown()
		u.mw.Synchronize(func() {
			u.notice.SetText("")
			u.render(u.run.snapshot())
		})
	}()
}

func (u *ui) restartServer() {
	u.notice.SetText("Restarting…")
	go func() {
		u.shutdown()
		u.mw.Synchronize(func() { u.startServer() })
	}()
}

func (u *ui) save() {
	port, err := parsePort(u.fPort.Text())
	c := config{
		Port: port, Network: u.fNetwork.Checked(), DataDir: strings.TrimSpace(u.fData.Text()),
		Interval: strings.TrimSpace(u.fInterval.Text()), DevSeed: u.fSeed.Checked(), AutoStart: u.fAuto.Checked(),
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	} else {
		msg = c.validate()
	}
	if msg != "" {
		walk.MsgBox(u.mw, windowTitle, msg, walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	if err := saveConfig(u.cfgPath, c); err != nil {
		walk.MsgBox(u.mw, windowTitle, "Could not save the settings:\n\n"+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	changed := c != u.cfg
	u.cfg = c
	u.render(u.run.snapshot())
	if changed && u.run.snapshot().Running {
		if walk.MsgBox(u.mw, windowTitle, "Settings saved. Restart the server now to use them?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == win.IDYES {
			u.restartServer()
			return
		}
		u.notice.SetText("Settings saved; they apply the next time the server starts.")
		return
	}
	u.notice.SetText("Settings saved.")
}

func (u *ui) openDashboard() {
	exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", u.cfg.dashboardURL()).Start()
}

func (u *ui) openDataFolder() {
	if err := os.MkdirAll(u.cfg.DataDir, 0o755); err != nil {
		u.notice.SetText("Cannot open the data folder: " + err.Error())
		return
	}
	exec.Command("explorer.exe", u.cfg.DataDir).Start()
}

// ---------------------------------------------------------------- projects and enrollment

// loadProjects fills the project list from the running server. With auto set it also makes a
// first enrollment token, so a fresh setup already has one to copy.
func (u *ui) loadProjects(auto bool) {
	api := u.api
	if api == nil {
		return
	}
	go func() {
		list, err := api.projects()
		u.mw.Synchronize(func() {
			if err != nil {
				u.notice.SetText("Could not read the projects: " + err.Error())
				return
			}
			prev := u.selectedProject()
			u.projIDs = u.projIDs[:0]
			var names []string
			for _, p := range list {
				u.projIDs = append(u.projIDs, p.ID)
				names = append(names, p.Name)
			}
			u.projects.SetModel(names)
			for i, id := range u.projIDs {
				if id == prev {
					u.projects.SetCurrentIndex(i)
				}
			}
			if u.projects.CurrentIndex() < 0 && len(names) > 0 {
				u.projects.SetCurrentIndex(0)
			}
			if auto && u.enrollTok == "" && len(list) > 0 {
				u.createEnrollment()
			}
		})
	}()
}

func (u *ui) selectedProject() string {
	i := u.projects.CurrentIndex()
	if i < 0 || i >= len(u.projIDs) {
		return ""
	}
	return u.projIDs[i]
}

// createEnrollment makes a single-use enrollment token for the chosen project, creating a
// project first when the server has none yet.
func (u *ui) createEnrollment() {
	api, project := u.api, u.selectedProject()
	if api == nil {
		return
	}
	u.notice.SetText("Creating an enrollment token…")
	go func() {
		created := ""
		if project == "" {
			p, err := api.createProject(defaultProjName)
			if err != nil {
				u.mw.Synchronize(func() { u.notice.SetText("Could not create a project: " + err.Error()) })
				return
			}
			project, created = p.ID, p.Name
		}
		e, err := api.newEnrollment(project, enrollTTLHours)
		u.mw.Synchronize(func() {
			if err != nil {
				u.notice.SetText("Could not create the token: " + err.Error())
				return
			}
			u.enrollTok, u.enrollKey = e.Token, e.ServerKey
			msg := fmt.Sprintf("New enrollment token for %q: single use, valid %d hours.", project, enrollTTLHours)
			if created != "" {
				msg = fmt.Sprintf("Created the project %q. ", created) + msg
			}
			u.notice.SetText(msg)
			u.render(u.run.snapshot())
			if created != "" {
				u.loadProjects(false)
			}
		})
	}()
}

// resetAdmin sets a new generated password for "admin" through `server user passwd`, which
// works straight on the database file and takes effect on a running server too.
func (u *ui) resetAdmin() {
	if u.run.exe == "" {
		u.notice.SetText("server.exe was not found beside this program.")
		return
	}
	if walk.MsgBox(u.mw, windowTitle, "Set a new password for the \"admin\" account? Anyone signed in as admin is signed out.", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != win.IDYES {
		return
	}
	u.notice.SetText("Resetting…")
	go func() {
		out, err := runHidden(u.run.exe, "user", "passwd", "-data", u.cfg.dbPath(), "-username", "admin")
		u.mw.Synchronize(func() {
			if err != nil {
				u.notice.SetText("Could not reset the password")
				walk.MsgBox(u.mw, windowTitle, "Could not reset the password:\n\n"+firstLines(out, err), walk.MsgBoxOK|walk.MsgBoxIconError)
				return
			}
			pw := passwordFrom(out)
			if pw == "" {
				u.notice.SetText("Password reset, but its value could not be read from the output.")
				return
			}
			u.run.mu.Lock()
			u.run.scan.AdminPassword = pw
			u.run.mu.Unlock()
			walk.Clipboard().SetText(pw)
			u.notice.SetText("New admin password is shown above and copied to the clipboard.")
			u.render(u.run.snapshot())
		})
	}()
}
