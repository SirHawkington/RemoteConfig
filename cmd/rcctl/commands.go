package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"remoteconfig/internal/proto"
)

// parse reads flags that may come before, between or after the positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// targetFlags are shared by everything that sends something to devices.
type targetFlags struct {
	devices, tag        *string
	all, now, wait      *bool
	canary, soak, batch *int
}

func addTargetFlags(fs *flag.FlagSet, soak int) *targetFlags {
	return &targetFlags{
		devices: fs.String("devices", "", "device names or ids, comma separated; the first ones are the canary"),
		tag:     fs.String("tag", "", "every device with this tag"),
		all:     fs.Bool("all", false, "every device in the project"),
		now:     fs.Bool("now", false, "send to all chosen devices at once, with no canary and no waiting"),
		wait:    fs.Bool("wait", false, "follow the rollout until it finishes; exit 1 if it halts"),
		canary:  fs.Int("canary", 1, "devices that go first"),
		soak:    fs.Int("soak", soak, "seconds the canary must stay healthy before the rest are sent"),
		batch:   fs.Int("batch", 0, "devices per wave after the canary (0 = all the rest)"),
	}
}

// send starts a staged rollout (or, with -now, queues the command on each device).
func (c *client) send(project string, t *targetFlags, typ string, params map[string]any) int {
	ids, err := c.pick(project, *t.devices, *t.tag, *t.all)
	if err != nil {
		return c.fail(err)
	}
	if *t.now {
		bad := 0
		for _, id := range ids {
			var cmd proto.Command
			if err := c.postJSON("/projects/"+project+"/devices/"+id+"/commands", proto.CommandRequest{Type: typ, Params: params}, &cmd); err != nil {
				fmt.Fprintf(c.out, "%s: %v\n", id, err)
				bad++
				continue
			}
			fmt.Fprintf(c.out, "%s: queued %s\n", id, cmd.ID)
		}
		if bad > 0 {
			return 1
		}
		return 0
	}
	soak := *t.soak
	var ro proto.Rollout
	if err := c.postJSON("/projects/"+project+"/rollouts", proto.RolloutRequest{Type: typ, Params: params, Devices: ids, Canary: *t.canary, SoakS: &soak, Batch: *t.batch}, &ro); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.out, "rollout %s started: %d devices, %d canary, wait %ds. The canary has its command.\n", ro.ID, len(ids), ro.Canary, ro.SoakS)
	if *t.wait {
		return c.watch(project, ro.ID)
	}
	fmt.Fprintf(c.out, "follow it with: rcctl rollout watch %s\n", ro.ID)
	return 0
}

// ---------------------------------------------------------------- scripts

var interpreterByExt = map[string]string{".ps1": "powershell", ".cmd": "cmd", ".bat": "cmd", ".sh": "bash", ".py": "python"}

func (c *client) script(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.err, usage)
		return 2
	}
	project, err := c.proj()
	if err != nil {
		return c.fail(err)
	}
	fs := flag.NewFlagSet("script "+args[0], flag.ContinueOnError)
	fs.SetOutput(c.err)
	switch args[0] {
	case "list":
		var list []proto.ScriptInfo
		if err := c.getJSON("/projects/"+project+"/scripts", &list); err != nil {
			return c.fail(err)
		}
		fmt.Fprintf(c.out, "%-22s %-4s %-11s %-12s %s\n", "NAME", "VER", "RUNS WITH", "HASH", "ADDED")
		for _, s := range list {
			fmt.Fprintf(c.out, "%-22s v%-3d %-11s %-12s %s\n", s.Name, s.Version, s.Interpreter, s.SHA256[:12], ago(s.CreatedAt))
		}
		return 0

	case "add":
		interp := fs.String("interpreter", "", "powershell, cmd, bash, sh or python (default: from the file extension)")
		timeout := fs.Int("timeout", 120, "time limit in seconds")
		desc := fs.String("desc", "", "what it does")
		pos, err := parse(fs, args[1:])
		if err != nil {
			return 2
		}
		if len(pos) != 2 {
			fmt.Fprintln(c.err, "usage: rcctl script add <name> <file> [-interpreter x] [-timeout s] [-desc text]")
			return 2
		}
		body, err := os.ReadFile(pos[1])
		if err != nil {
			return c.fail(err)
		}
		if *interp == "" {
			*interp = interpreterByExt[strings.ToLower(filepath.Ext(pos[1]))]
		}
		if *interp == "" {
			return c.fail(errors.New("cannot tell the interpreter from the file name: pass -interpreter"))
		}
		var s proto.ScriptInfo
		if err := c.postJSON("/projects/"+project+"/scripts", proto.ScriptCreate{Name: pos[0], Interpreter: *interp, Content: string(body), Description: *desc, TimeoutS: *timeout}, &s); err != nil {
			return c.fail(err)
		}
		fmt.Fprintf(c.out, "%s v%d stored (%s, hash %s)\n", s.Name, s.Version, s.Interpreter, s.SHA256[:12])
		return 0

	case "run":
		var sargs multi
		fs.Var(&sargs, "arg", "an argument for the script (repeat for more)")
		version := fs.Int("version", 0, "script version (default: the newest)")
		t := addTargetFlags(fs, 30)
		pos, err := parse(fs, args[1:])
		if err != nil {
			return 2
		}
		if len(pos) < 1 || len(pos) > 2 {
			fmt.Fprintln(c.err, "usage: rcctl script run <name> [-devices a,b | -tag x | -all] [-arg x ...] [-now] [-wait]")
			return 2
		}
		if len(pos) == 2 && *t.devices == "" { // rcctl script run name kiosk-1,kiosk-2
			*t.devices = pos[1]
		}
		params := map[string]any{"script": pos[0], "args": []string(sargs)}
		if *version > 0 {
			params["version"] = float64(*version)
		}
		return c.send(project, t, "run_script", params)
	}
	fmt.Fprintf(c.err, "unknown script command %q\n", args[0])
	return 2
}

// ---------------------------------------------------------------- releases

func (c *client) release(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.err, usage)
		return 2
	}
	project, err := c.proj()
	if err != nil {
		return c.fail(err)
	}
	fs := flag.NewFlagSet("release "+args[0], flag.ContinueOnError)
	fs.SetOutput(c.err)
	switch args[0] {
	case "list":
		list, err := c.releases(project)
		if err != nil {
			return c.fail(err)
		}
		fmt.Fprintf(c.out, "%-18s %-6s %-14s %-10s %-14s %-9s %-12s %s\n", "ID", "KIND", "NAME", "VERSION", "PLATFORM", "SIZE", "HASH", "ADDED")
		for _, r := range list {
			fmt.Fprintf(c.out, "%-18s %-6s %-14s %-10s %-14s %-9s %-12s %s\n", r.ID, r.Kind, r.Name, r.Version, r.OS+"/"+r.Arch, size(r.Size), r.SHA256[:12], ago(r.CreatedAt))
		}
		return 0

	case "upload":
		kind := fs.String("kind", "", "app (a .zip of the build folder) or agent (the executable); default from the file")
		name := fs.String("name", "", "release name, e.g. kiosk (default: agent for agent builds)")
		version := fs.String("version", "", "version, e.g. 1.4.2 (agent builds: the version `agent version` prints)")
		osName := fs.String("os", "windows", "windows, linux or darwin")
		arch := fs.String("arch", "", "amd64 or arm64 (required for agent builds)")
		notes := fs.String("notes", "", "release notes")
		pos, err := parse(fs, args[1:])
		if err != nil || len(pos) != 1 {
			fmt.Fprintln(c.err, "usage: rcctl release upload <file> -version v [-kind app|agent] [-name n] [-os o] [-arch a] [-notes text]")
			return 2
		}
		if *kind == "" {
			*kind = "agent"
			if strings.EqualFold(filepath.Ext(pos[0]), ".zip") {
				*kind = "app"
			}
		}
		if *name == "" && *kind == "agent" {
			*name = "agent"
		}
		f, err := os.Open(pos[0])
		if err != nil {
			return c.fail(err)
		}
		defer f.Close()
		st, _ := f.Stat()
		q := url.Values{"kind": {*kind}, "name": {*name}, "version": {*version}, "os": {*osName}, "arch": {*arch}, "notes": {*notes}}
		fmt.Fprintf(c.out, "uploading %s (%s)...\n", pos[0], size(st.Size()))
		var r proto.ReleaseInfo
		if err := c.do("POST", "/projects/"+project+"/releases?"+q.Encode(), f, "application/octet-stream", &r); err != nil {
			return c.fail(err)
		}
		fmt.Fprintf(c.out, "%s: %s %s for %s/%s, hash %s\nsend it with: rcctl release send %s@%s -devices <names>\n", r.ID, r.Name, r.Version, r.OS, r.Arch, r.SHA256[:12], r.Name, r.Version)
		return 0

	case "send":
		osName := fs.String("os", "", "pick the build for this OS when name@version exists for several")
		health := fs.Int("health", 0, "seconds an app release must stay up before it counts as healthy (default 45)")
		t := addTargetFlags(fs, 120)
		pos, err := parse(fs, args[1:])
		if err != nil || len(pos) < 1 || len(pos) > 2 {
			fmt.Fprintln(c.err, "usage: rcctl release send <name@version|id> [-devices a,b | -tag x | -all] [-canary n] [-soak s] [-batch n] [-now] [-wait]")
			return 2
		}
		if len(pos) == 2 && *t.devices == "" {
			*t.devices = pos[1]
		}
		rel, err := c.findRelease(project, pos[0], *osName)
		if err != nil {
			return c.fail(err)
		}
		fmt.Fprintf(c.out, "sending %s %s (%s %s/%s, %s)\n", rel.Name, rel.Version, rel.Kind, rel.OS, rel.Arch, size(rel.Size))
		params := map[string]any{"release_id": rel.ID}
		if *health > 0 {
			params["health_s"] = float64(*health)
		}
		return c.send(project, t, "apply_release", params)
	}
	fmt.Fprintf(c.err, "unknown release command %q\n", args[0])
	return 2
}

func (c *client) releases(project string) ([]proto.ReleaseInfo, error) {
	var list []proto.ReleaseInfo
	err := c.getJSON("/projects/"+project+"/releases", &list)
	return list, err
}

func (c *client) findRelease(project, ref, osName string) (proto.ReleaseInfo, error) {
	list, err := c.releases(project)
	if err != nil {
		return proto.ReleaseInfo{}, err
	}
	name, version, byName := strings.Cut(ref, "@")
	var hits []proto.ReleaseInfo
	for _, r := range list {
		if r.ID == ref || (byName && r.Name == name && r.Version == version && (osName == "" || r.OS == osName)) {
			hits = append(hits, r)
		}
	}
	switch len(hits) {
	case 0:
		return proto.ReleaseInfo{}, fmt.Errorf("no release %q (see: rcctl release list)", ref)
	case 1:
		return hits[0], nil
	}
	return proto.ReleaseInfo{}, fmt.Errorf("%q is several builds (different platforms): add -os or use the id", ref)
}

func size(n int64) string {
	switch {
	case n < 1<<10:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	case n < 1<<30:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
}

// ---------------------------------------------------------------- rollouts

func (c *client) rollout(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.err, usage)
		return 2
	}
	project, err := c.proj()
	if err != nil {
		return c.fail(err)
	}
	switch args[0] {
	case "list":
		list, err := c.rollouts(project)
		if err != nil {
			return c.fail(err)
		}
		fmt.Fprintf(c.out, "%-14s %-14s %-9s %-8s %s\n", "ID", "TYPE", "STATE", "DEVICES", "STARTED")
		for _, r := range list {
			fmt.Fprintf(c.out, "%-14s %-14s %-9s %-8d %s\n", r.ID, r.Type, r.State, len(r.Targets), ago(r.CreatedAt))
		}
		return 0
	case "show", "halt", "watch":
		if len(args) != 2 {
			fmt.Fprintf(c.err, "usage: rcctl rollout %s <id>\n", args[0])
			return 2
		}
		switch args[0] {
		case "show":
			r, err := c.rolloutByID(project, args[1])
			if err != nil {
				return c.fail(err)
			}
			c.printRollout(r)
			return 0
		case "halt":
			var r proto.Rollout
			if err := c.postJSON("/projects/"+project+"/rollouts/"+args[1]+"/halt", nil, &r); err != nil {
				return c.fail(err)
			}
			fmt.Fprintln(c.out, "halted. Devices already told still run it; nothing more will be sent.")
			return 0
		}
		return c.watch(project, args[1])
	}
	fmt.Fprintf(c.err, "unknown rollout command %q\n", args[0])
	return 2
}

func (c *client) rollouts(project string) ([]proto.Rollout, error) {
	var list []proto.Rollout
	err := c.getJSON("/projects/"+project+"/rollouts", &list)
	return list, err
}

func (c *client) rolloutByID(project, id string) (proto.Rollout, error) {
	list, err := c.rollouts(project)
	if err != nil {
		return proto.Rollout{}, err
	}
	for _, r := range list {
		if r.ID == id {
			return r, nil
		}
	}
	return proto.Rollout{}, fmt.Errorf("no rollout %q", id)
}

func (c *client) printRollout(r proto.Rollout) {
	fmt.Fprintf(c.out, "rollout %s: %s, %s\n", r.ID, r.Type, r.State)
	if r.Reason != "" {
		fmt.Fprintf(c.out, "  reason: %s\n", r.Reason)
	}
	for _, d := range r.Devices {
		line := fmt.Sprintf("  %-7s %-20s %s", d.Stage, d.Name, d.Status)
		if d.Result != "" {
			line += ": " + strings.SplitN(d.Result, "\n", 2)[0]
		}
		fmt.Fprintln(c.out, line)
	}
}

// watchEvery is how often watch asks the server (tests shorten it).
var watchEvery = 2 * time.Second

// watch prints the rollout whenever it changes until it is done or halted.
func (c *client) watch(project, id string) int {
	last := ""
	for {
		r, err := c.rolloutByID(project, id)
		if err != nil {
			return c.fail(err)
		}
		var b strings.Builder
		prev := c.out
		c.out = &b
		c.printRollout(r)
		c.out = prev
		if b.String() != last {
			fmt.Fprintf(c.out, "%s\n", strings.TrimRight(b.String(), "\n"))
			last = b.String()
		}
		switch r.State {
		case "done":
			return 0
		case "halted":
			return 1
		}
		time.Sleep(watchEvery)
	}
}
