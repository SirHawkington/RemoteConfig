//go:build linux || darwin

package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	defaultUnit  = "remoteconfig-agent"
	defaultLabel = "com.remoteconfig.agent"
)

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	return 1
}

func defaultInstallDir() string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "RemoteConfig")
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "remoteconfig")
	}
	return filepath.Join(home, ".local", "share", "remoteconfig")
}

// servicePath is where the unit or plist lives.
func servicePath(name string) string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "LaunchAgents", name+".plist")
	}
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = filepath.Join(home, ".config")
	}
	return filepath.Join(cfg, "systemd", "user", name+".service")
}

func serviceName() string {
	if runtime.GOOS == "darwin" {
		return defaultLabel
	}
	return defaultUnit
}

func ctl(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func guiDomain() string { return "gui/" + strconv.Itoa(os.Getuid()) }

type commonFlags struct{ dir, name *string }

func addCommon(fs *flag.FlagSet) commonFlags {
	what := "systemd user unit name"
	if runtime.GOOS == "darwin" {
		what = "LaunchAgent label"
	}
	return commonFlags{
		dir:  fs.String("dir", defaultInstallDir(), "install directory (binary, agent.json, state, logs)"),
		name: fs.String("service-name", serviceName(), what),
	}
}

func installCmd(args []string) int {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	common := addCommon(fs)
	server := fs.String("server", "", "server base URL, e.g. https://rc.example.com")
	token := fs.String("enroll-token", "", "one-time enrollment token")
	cfgFile := fs.String("config", "", "agent.json to install (default: agent.json beside this binary, if present)")
	noStart := fs.Bool("no-start", false, "write the service but do not start it now")
	reset := fs.Bool("reset", false, "forget this device's identity so it enrolls again (needs a new -enroll-token)")
	listen := fs.String("listen", "", "local API address (default 127.0.0.1:7878)")
	serverKey := fs.String("server-key", "", "the server's public signing key (from the dashboard's \"Add device\"): the agent will only act on config and commands signed by it")
	fs.Parse(args)

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
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fail("creating %s: %v", stateDir, err)
	}

	self, err := os.Executable()
	if err != nil {
		return fail("%v", err)
	}
	dest := filepath.Join(dir, "agent")
	svc := servicePath(*common.name)
	stopService(*common.name, svc) // an upgrade: let go of the old binary first
	if self != dest {
		// write beside it and rename, so a running copy is never overwritten in place
		if err := copyExecutable(self, dest); err != nil {
			return fail("installing %s: %v", dest, err)
		}
	}
	cfgPath := filepath.Join(dir, "agent.json")
	if err := saveFileConfig(cfgPath, fc); err != nil {
		return fail("writing %s: %v", cfgPath, err)
	}

	var body string
	if runtime.GOOS == "darwin" {
		body = launchdPlist(*common.name, dest, cfgPath, dir, fc.LogFile)
	} else {
		body = systemdUnit(dest, cfgPath, dir)
	}
	if err := os.MkdirAll(filepath.Dir(svc), 0o755); err != nil {
		return fail("%v", err)
	}
	if err := os.WriteFile(svc, []byte(body), 0o644); err != nil {
		return fail("writing %s: %v", svc, err)
	}
	fmt.Printf("installed:\n  binary   %s\n  settings %s\n  state    %s\n  log      %s\n  service  %s\n", dest, cfgPath, stateDir, fc.LogFile, svc)

	if runtime.GOOS == "linux" {
		if out, err := ctl("systemctl", "--user", "daemon-reload"); err != nil {
			return fail("systemctl --user daemon-reload: %v\n%s\n(is a systemd user session running? run this as the kiosk user, in its session)", err, out)
		}
		if out, err := ctl("systemctl", "--user", "enable", *common.name); err != nil {
			return fail("enabling the service: %v\n%s", err, out)
		}
		fmt.Println("note: it starts when that user logs in. For a machine that boots without anyone logging in, run once as root: loginctl enable-linger <user>")
		fmt.Println("note: screenshots need a display (the agent assumes DISPLAY=:0 if the service has none) and one of grim, scrot, maim, import (ImageMagick), gnome-screenshot or spectacle")
	} else {
		fmt.Println("note: screenshots need the Screen Recording permission: System Settings > Privacy & Security > Screen Recording, for the agent binary")
	}
	if *noStart {
		fmt.Println("not started (-no-start); it will start at the next login of that user")
		return 0
	}
	if runtime.GOOS == "linux" {
		if out, err := ctl("systemctl", "--user", "restart", *common.name); err != nil {
			fmt.Printf("warning: could not start the service now: %v\n%s\n", err, out)
			return 0
		}
	} else if out, err := ctl("launchctl", "bootstrap", guiDomain(), svc); err != nil {
		fmt.Printf("warning: could not start the LaunchAgent now: %v\n%s\nit will start at the next login of that user\n", err, out)
		return 0
	}
	fmt.Println("started; check progress with: agent status")
	return 0
}

// stopService stops a running copy; failures are fine (it may not be installed yet).
func stopService(name, svc string) {
	if runtime.GOOS == "darwin" {
		ctl("launchctl", "bootout", guiDomain()+"/"+name)
		return
	}
	if fileExists(svc) {
		ctl("systemctl", "--user", "stop", name)
	}
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func uninstallCmd(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	common := addCommon(fs)
	purge := fs.Bool("purge", false, "also delete the install directory, including identity, state and logs")
	fs.Parse(args)

	dir, _ := filepath.Abs(*common.dir)
	svc := servicePath(*common.name)
	if fileExists(svc) {
		if runtime.GOOS == "darwin" {
			ctl("launchctl", "bootout", guiDomain()+"/"+*common.name)
		} else {
			ctl("systemctl", "--user", "disable", "--now", *common.name)
		}
		if err := os.Remove(svc); err != nil {
			return fail("removing %s: %v", svc, err)
		}
		if runtime.GOOS == "linux" {
			ctl("systemctl", "--user", "daemon-reload")
		}
		fmt.Printf("removed %s\n", svc)
	} else {
		fmt.Printf("no service file at %s\n", svc)
	}
	if !*purge {
		fmt.Printf("files left in %s (use -purge to delete them; the device keeps its identity)\n", dir)
		return 0
	}
	if err := os.RemoveAll(dir); err != nil {
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
	svc := servicePath(*common.name)

	switch {
	case !fileExists(svc):
		fmt.Printf("service:   %s is NOT installed\n", *common.name)
	case runtime.GOOS == "linux":
		active, _ := ctl("systemctl", "--user", "is-active", *common.name)
		enabled, _ := ctl("systemctl", "--user", "is-enabled", *common.name)
		fmt.Printf("service:   %s (%s, %s)\n", *common.name, active, enabled)
	default:
		out, err := ctl("launchctl", "print", guiDomain()+"/"+*common.name)
		state := "not loaded"
		if err == nil {
			state = "loaded"
			for _, l := range strings.Split(out, "\n") {
				if l = strings.TrimSpace(l); strings.HasPrefix(l, "state =") || strings.HasPrefix(l, "last exit code") {
					state += ", " + l
				}
			}
		}
		fmt.Printf("service:   %s (%s)\n", *common.name, state)
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
		fmt.Printf("agent:     answering on %s\n", addr)
		return 0
	}
	fmt.Printf("agent:     not answering on %s\n", addr)
	return 1
}
