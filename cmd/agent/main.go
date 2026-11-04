// Command agent is the RemoteConfig client agent (placeholder name).
//
//	agent run        run the agent (default; also what the scheduled task executes)
//	agent install    copy to a permanent location and register auto-start (Windows)
//	agent uninstall  remove the auto-start task (and, with -purge, all files)
//	agent status     show the task, identity and whether the agent is answering
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"remoteconfig/internal/agent"
)

// version is what `agent version` prints and what an agent release must be uploaded as.
// Release builds can set it: go build -ldflags "-X main.version=1.2.0".
var version = "0.1.0-phase1"

func main() {
	cmd, args := "run", os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run":
		runAgent(args)
	case "install":
		os.Exit(installCmd(args))
	case "uninstall":
		os.Exit(uninstallCmd(args))
	case "status":
		os.Exit(statusCmd(args))
	case "version":
		fmt.Println(version)
	case "help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: agent <command> [flags]

  run         run the agent (default)
  install     install and register auto-start at logon (Windows)
  uninstall   remove auto-start; -purge also deletes files and identity
  status      show task state, identity and agent health
  version     print the version

Run "agent <command> -h" for flags.
`)
}

// configPathFromArgs finds -config / --config before full flag parsing, so the file's
// values can be used as flag defaults (flags still win).
func configPathFromArgs(args []string) string {
	for i, a := range args {
		a = strings.TrimLeft(a, "-")
		if a == "config" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "config=") {
			return strings.TrimPrefix(a, "config=")
		}
	}
	if p := os.Getenv("RC_CONFIG"); p != "" {
		return p
	}
	if d := exeDir(); d != "" {
		if p := filepath.Join(d, "agent.json"); fileExists(p) {
			return p
		}
	}
	return ""
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func runAgent(args []string) {
	var fc fileConfig
	cfgPath := configPathFromArgs(args)
	if cfgPath != "" {
		var err error
		if fc, err = loadFileConfig(cfgPath); err != nil {
			log.Fatalf("reading config %s: %v", cfgPath, err)
		}
	}
	or := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	userCfg, _ := os.UserConfigDir()

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fs.String("config", cfgPath, "path of agent.json (default: agent.json beside the binary)")
	server := fs.String("server", or(fc.Server, os.Getenv("RC_SERVER")), "server base URL, e.g. http://localhost:8080")
	token := fs.String("enroll-token", or(fc.EnrollToken, os.Getenv("RC_ENROLL_TOKEN")), "one-time enrollment token (first run only)")
	state := fs.String("state-dir", or(fc.StateDir, filepath.Join(userCfg, "RemoteConfig")), "directory for identity and caches")
	out := fs.String("out-dir", fc.OutDir, "directory where effective-config.json is written for the app (default: state-dir)")
	listen := fs.String("listen", or(fc.Listen, "127.0.0.1:7878"), "local API address (empty to disable)")
	interval := fs.Duration("interval", fc.interval(), "override check-in interval (0 = follow server)")
	logFile := fs.String("log-file", fc.LogFile, "append logs here (rotated) instead of stderr")
	serverKey := fs.String("server-key", fc.ServerKey, "the server's public signing key (base64), shown by the dashboard's \"Add device\" and `server keys show`: pins trust so unsigned config is refused from the start")
	requireSigs := fs.Bool("require-signatures", fc.RequireSignatures, "refuse unsigned config and commands even before a server key is known")
	insecureTOFU := fs.Bool("insecure-tofu", fc.InsecureTOFU, "trust a key learned over plain HTTP from another machine (unsafe; prefer -server-key)")
	fs.Parse(args)

	var logw io.Writer = os.Stderr
	if *logFile != "" {
		rf, err := agent.NewRotatingFile(*logFile, 2<<20)
		if err != nil {
			log.Fatalf("opening log file: %v", err)
		}
		defer rf.Close()
		logw = rf
	}
	logger := log.New(logw, "agent ", log.LstdFlags)

	// A binary installed by an agent update gets a few starts to prove itself; if it keeps dying
	// before it can check in, the previous one is restored and started in its place.
	if agent.CheckPendingUpdate(*state, logger.Printf) {
		os.Exit(75)
	}

	// One agent per state dir. A second copy (say a manual run while the scheduled task
	// is active) would fight the first over the app. Exit 0 so Task Scheduler does not
	// treat "already running" as a failure and keep retrying.
	if ok, err := agent.AcquireSingleInstance(*state); err != nil {
		logger.Printf("single-instance check failed (continuing): %v", err)
	} else if !ok {
		logger.Printf("another agent already runs for %s; exiting", *state)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	logger.Printf("agent %s starting (state %s)", version, *state)
	a := agent.New(agent.Options{
		Server: *server, EnrollToken: *token, StateDir: *state, OutDir: *out,
		Listen: *listen, Interval: *interval, Version: version, Log: logger,
		ServerKey: *serverKey, RequireSignatures: *requireSigs, InsecureTOFU: *insecureTOFU,
	})
	if err := a.Run(ctx); err != nil {
		logger.Printf("agent stopped: %v", err)
		os.Exit(1) // non-zero: Task Scheduler restarts us
	}
}
