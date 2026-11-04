//go:build windows

package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	defaultTaskName = "RemoteConfigAgent"
	uiExeName       = "agent-ui.exe"
	uiShortcutName  = "RemoteConfig Agent"
)

// uiShortcutPath is the current user's Start Menu entry for the desktop UI.
func uiShortcutPath() string {
	return filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", uiShortcutName+".lnk")
}

// createUIShortcut makes (or refreshes) the Start Menu shortcut. Best effort: the shortcut is a
// convenience, so a failure is reported but never fails the install.
func createUIShortcut(target, workDir string) error {
	if os.Getenv("APPDATA") == "" {
		return fmt.Errorf("no APPDATA")
	}
	ps := `$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:RC_LNK);$s.TargetPath=$env:RC_TARGET;$s.WorkingDirectory=$env:RC_DIR;$s.Description='RemoteConfig agent status and settings';$s.Save()`
	c := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	c.Env = append(os.Environ(), "RC_LNK="+uiShortcutPath(), "RC_TARGET="+target, "RC_DIR="+workDir)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func defaultInstallDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "RemoteConfig")
	}
	return `C:\ProgramData\RemoteConfig`
}

func schtasks(args ...string) (string, error) {
	out, err := exec.Command("schtasks.exe", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func taskExists(name string) bool {
	_, err := schtasks("/Query", "/TN", name)
	return err == nil
}

type commonFlags struct {
	dir, task *string
}

func addCommon(fs *flag.FlagSet) commonFlags {
	return commonFlags{
		dir:  fs.String("dir", defaultInstallDir(), "install directory (binary, agent.json, state, logs)"),
		task: fs.String("task-name", defaultTaskName, "scheduled task name"),
	}
}

func installCmd(args []string) int {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	common := addCommon(fs)
	server := fs.String("server", "", "server base URL, e.g. https://rc.example.com")
	token := fs.String("enroll-token", "", "one-time enrollment token")
	cfgFile := fs.String("config", "", "agent.json to install (default: agent.json beside this binary, if present)")
	userName := fs.String("user", "", `account whose logon starts the agent, as DOMAIN\user (default: current user)`)
	elevated := fs.Bool("elevated", false, "run the agent with the account's highest privileges (to supervise an elevated app)")
	noStart := fs.Bool("no-start", false, "register the task but do not start it now")
	reset := fs.Bool("reset", false, "forget this device's identity so it enrolls again (needs a new -enroll-token)")
	listen := fs.String("listen", "", "local API address (default 127.0.0.1:7878)")
	serverKey := fs.String("server-key", "", "the server's public signing key (from the dashboard's \"Add device\"): the agent will only act on config and commands signed by it")
	fs.Parse(args)

	// 1. settings: flags > -config file > agent.json beside the installer (zero-touch).
	var fc fileConfig
	src := *cfgFile
	if src == "" && exeDir() != "" && fileExists(filepath.Join(exeDir(), "agent.json")) {
		src = filepath.Join(exeDir(), "agent.json")
	}
	if src != "" {
		var err error
		if fc, err = loadFileConfig(src); err != nil {
			return fail("reading %s: %v", src, err)
		}
		fmt.Printf("using settings from %s\n", src)
	}
	if *server != "" {
		fc.Server = *server
	}
	if *token != "" {
		fc.EnrollToken = *token
	}
	if *listen != "" {
		fc.Listen = *listen
	}
	if *serverKey != "" {
		fc.ServerKey = *serverKey
	}

	dir, err := filepath.Abs(*common.dir)
	if err != nil {
		return fail("%v", err)
	}
	stateDir := filepath.Join(dir, "state")
	fc.StateDir, fc.LogFile = stateDir, filepath.Join(dir, "agent.log")
	if fc.OutDir == "" {
		fc.OutDir = stateDir
	}

	identity := filepath.Join(stateDir, "identity.json")
	if *reset {
		os.Remove(identity)
	}
	if fc.Server == "" {
		return fail("no server given: use -server (and -enroll-token), or place an agent.json beside this binary")
	}
	if fc.ServerKey == "" && !strings.HasPrefix(strings.ToLower(fc.Server), "https://") {
		fmt.Println("note: no -server-key given and the server is not https, so the agent cannot safely learn the signing key over the network;")
		fmt.Println("      it will accept unsigned config until you reinstall with -server-key (shown by the dashboard's \"Add device\").")
	}
	if fc.EnrollToken == "" && !fileExists(identity) {
		return fail("this device is not enrolled yet: pass -enroll-token (create one in the dashboard with \"Add device\")")
	}

	u := *userName
	if u == "" {
		cu, err := user.Current()
		if err != nil {
			return fail("cannot determine current user: %v", err)
		}
		u = cu.Username
	}

	// 2. directories, with the kiosk account allowed to write state and logs.
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return fail("creating %s: %v", stateDir, err)
	}
	if out, err := exec.Command("icacls.exe", dir, "/grant", u+":(OI)(CI)M").CombinedOutput(); err != nil {
		fmt.Printf("warning: could not grant %s write access to %s: %v\n%s\n", u, dir, err, strings.TrimSpace(string(out)))
	}

	// 3. stop a running copy (upgrade), then install the binary.
	if taskExists(*common.task) {
		schtasks("/End", "/TN", *common.task)
	}
	self, err := os.Executable()
	if err != nil {
		return fail("%v", err)
	}
	dest := filepath.Join(dir, "agent.exe")
	if !samePath(self, dest) {
		if err := copyFileRetry(self, dest); err != nil {
			return fail("installing %s: %v (is the agent still running? try `agent uninstall` first)", dest, err)
		}
	}
	// The desktop UI, when it was shipped beside the agent, goes in next to it.
	uiDest := ""
	if ui := filepath.Join(filepath.Dir(self), uiExeName); fileExists(ui) {
		uiDest = filepath.Join(dir, uiExeName)
		if !samePath(ui, uiDest) {
			if err := copyFileRetry(ui, uiDest); err != nil {
				fmt.Printf("warning: could not install %s: %v\n", uiExeName, err)
				uiDest = ""
			}
		}
	}
	cfgPath := filepath.Join(dir, "agent.json")
	if err := saveFileConfig(cfgPath, fc); err != nil {
		return fail("writing %s: %v", cfgPath, err)
	}

	// 4. the scheduled task.
	xmlPath := filepath.Join(os.TempDir(), "remoteconfig-task.xml")
	xml := buildTaskXML(taskParams{
		User: u, Exe: dest, Args: `run -config "` + cfgPath + `"`, WorkDir: dir, Elevated: *elevated,
	})
	if err := os.WriteFile(xmlPath, utf16LE(xml), 0o600); err != nil {
		return fail("%v", err)
	}
	defer os.Remove(xmlPath)
	if out, err := schtasks("/Create", "/TN", *common.task, "/XML", xmlPath, "/F"); err != nil {
		return fail("registering the scheduled task failed: %v\n%s\n(registering a task for another user needs an Administrator prompt)", err, out)
	}

	fmt.Printf("installed:\n  binary   %s\n  settings %s\n  state    %s\n  log      %s\n  task     %s (runs at logon of %s, restarts on failure)\n",
		dest, cfgPath, stateDir, fc.LogFile, *common.task, u)
	if uiDest != "" {
		if err := createUIShortcut(uiDest, dir); err != nil {
			fmt.Printf("  window   %s (could not create a Start menu shortcut: %v)\n", uiDest, err)
		} else {
			fmt.Printf("  window   %s (Start menu: %s)\n", uiDest, uiShortcutName)
		}
	}

	if *noStart {
		fmt.Println("not started (-no-start); it will start at the next logon of that user")
		return 0
	}
	if out, err := schtasks("/Run", "/TN", *common.task); err != nil {
		fmt.Printf("warning: could not start the task now: %v\n%s\n", err, out)
		fmt.Println("it will start at the next logon of that user")
		return 0
	}
	fmt.Println("started; check progress with: agent status")
	return 0
}

func uninstallCmd(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	common := addCommon(fs)
	purge := fs.Bool("purge", false, "also delete the install directory, including identity, state and logs")
	fs.Parse(args)

	dir, _ := filepath.Abs(*common.dir)
	if taskExists(*common.task) {
		schtasks("/End", "/TN", *common.task)
		if out, err := schtasks("/Delete", "/TN", *common.task, "/F"); err != nil {
			return fail("deleting task: %v\n%s", err, out)
		}
		fmt.Printf("removed scheduled task %s\n", *common.task)
	} else {
		fmt.Printf("no scheduled task named %s\n", *common.task)
	}
	os.Remove(uiShortcutPath())
	if !*purge {
		fmt.Printf("files left in %s (use -purge to delete them; the device keeps its identity)\n", dir)
		return 0
	}
	if self, err := os.Executable(); err == nil && within(self, dir) {
		// A running exe can't delete itself: let a detached shell finish the job once we
		// have exited. The raw command line avoids Go's argument re-quoting (which breaks
		// `&` and nested quotes), and /s makes cmd strip only the outer pair of quotes.
		c := exec.Command("cmd.exe")
		c.Dir = os.TempDir() // never inherit a working directory inside the folder being deleted
		c.SysProcAttr = &syscall.SysProcAttr{
			CmdLine:       fmt.Sprintf(`cmd.exe /d /s /c "ping -n 4 127.0.0.1 >nul & rmdir /s /q "%s""`, dir),
			HideWindow:    true,
			CreationFlags: 0x00000008 | 0x08000000, // DETACHED_PROCESS | CREATE_NO_WINDOW
		}
		if err := c.Start(); err != nil {
			return fail("could not schedule deletion of %s: %v", dir, err)
		}
		fmt.Printf("deleting %s in a few seconds\n", dir)
		return 0
	}
	if err := removeAllRetry(dir); err != nil {
		return fail("deleting %s: %v", dir, err)
	}
	fmt.Printf("deleted %s\n", dir)
	return 0
}

func statusCmd(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	common := addCommon(fs)
	fs.Parse(args)
	dir, _ := filepath.Abs(*common.dir)

	if out, err := schtasks("/Query", "/TN", *common.task, "/V", "/FO", "LIST"); err != nil {
		fmt.Printf("task:      %s is NOT installed\n", *common.task)
	} else {
		fmt.Printf("task:      %s\n", *common.task)
		for _, l := range strings.Split(out, "\n") {
			l = strings.TrimSpace(l)
			for _, k := range []string{"Status:", "Last Run Time:", "Last Result:", "Run As User:", "Next Run Time:"} {
				if strings.HasPrefix(l, k) {
					fmt.Printf("  %s\n", l)
				}
			}
		}
	}

	fc, err := loadFileConfig(filepath.Join(dir, "agent.json"))
	if err != nil {
		fmt.Printf("settings:  none found in %s\n", dir)
		return 1
	}
	fmt.Printf("settings:  %s (server %s)\n", filepath.Join(dir, "agent.json"), fc.Server)
	if fileExists(filepath.Join(fc.StateDir, "identity.json")) {
		fmt.Println("identity:  enrolled")
	} else {
		fmt.Println("identity:  not enrolled yet")
	}
	addr := fc.Listen
	if addr == "" {
		addr = "127.0.0.1:7878"
	}
	c := http.Client{Timeout: 2 * time.Second}
	if resp, err := c.Get("http://" + addr + "/healthz"); err == nil {
		resp.Body.Close()
		fmt.Printf("agent:     running (status page http://%s/)\n", addr)
	} else {
		fmt.Println("agent:     not responding")
	}
	if fc.LogFile != "" {
		fmt.Printf("log:       %s\n", fc.LogFile)
		if tail := lastLines(fc.LogFile, 3); tail != "" {
			fmt.Println(indent(tail))
		}
	}
	return 0
}

// ---------------------------------------------------------------- helpers

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	return 1
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func within(path, dir string) bool {
	rel, err := filepath.Rel(strings.ToLower(dir), strings.ToLower(path))
	return err == nil && !strings.HasPrefix(rel, "..")
}

// copyFileRetry copies src to dst, retrying briefly while a just-stopped agent
// releases its executable.
func copyFileRetry(src, dst string) (err error) {
	for i := 0; i < 20; i++ {
		if err = copyFile(src, dst); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	os.Remove(dst)
	return os.Rename(tmp, dst)
}

func removeAllRetry(dir string) (err error) {
	for i := 0; i < 10; i++ {
		if err = os.RemoveAll(dir); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
}

func lastLines(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\r\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func indent(s string) string { return "  " + strings.ReplaceAll(s, "\n", "\n  ") }
