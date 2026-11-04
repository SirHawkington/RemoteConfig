package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

type taskDoc struct {
	XMLName  xml.Name `xml:"Task"`
	Triggers struct {
		Logon struct {
			UserID string `xml:"UserId"`
			Delay  string `xml:"Delay"`
		} `xml:"LogonTrigger"`
		Watchdog struct {
			Interval string `xml:"Repetition>Interval"`
			Stop     string `xml:"Repetition>StopAtDurationEnd"`
		} `xml:"TimeTrigger"`
	} `xml:"Triggers"`
	Principal struct {
		UserID    string `xml:"UserId"`
		LogonType string `xml:"LogonType"`
		RunLevel  string `xml:"RunLevel"`
	} `xml:"Principals>Principal"`
	Settings struct {
		Multiple string `xml:"MultipleInstancesPolicy"`
		Limit    string `xml:"ExecutionTimeLimit"`
		Priority string `xml:"Priority"`
		Battery  string `xml:"DisallowStartIfOnBatteries"`
		Restart  struct {
			Interval string `xml:"Interval"`
			Count    int    `xml:"Count"`
		} `xml:"RestartOnFailure"`
	} `xml:"Settings"`
	Exec struct {
		Command string `xml:"Command"`
		Args    string `xml:"Arguments"`
		WorkDir string `xml:"WorkingDirectory"`
	} `xml:"Actions>Exec"`
}

func parseTask(t *testing.T, s string) taskDoc {
	t.Helper()
	// encoding/xml refuses a UTF-16 declaration on an already-decoded string.
	s = strings.Replace(s, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)
	var d taskDoc
	if err := xml.Unmarshal([]byte(s), &d); err != nil {
		t.Fatalf("task XML is not well formed: %v\n%s", err, s)
	}
	return d
}

func TestTaskXMLHasTheSettingsTheDesignRequires(t *testing.T) {
	d := parseTask(t, buildTaskXML(taskParams{
		User: `KIOSK\visitor`, Exe: `C:\ProgramData\RemoteConfig\agent.exe`,
		Args: `run -config "C:\ProgramData\RemoteConfig\agent.json"`, WorkDir: `C:\ProgramData\RemoteConfig`,
	}))
	if d.Triggers.Logon.UserID != `KIOSK\visitor` || d.Principal.UserID != `KIOSK\visitor` {
		t.Fatalf("trigger/principal user wrong: %+v %+v", d.Triggers, d.Principal)
	}
	if d.Principal.LogonType != "InteractiveToken" {
		t.Fatalf("must run in the interactive desktop session, got %q", d.Principal.LogonType)
	}
	if d.Principal.RunLevel != "LeastPrivilege" {
		t.Fatalf("default must not elevate, got %q", d.Principal.RunLevel)
	}
	if d.Settings.Restart.Count < 100 || d.Settings.Restart.Interval != "PT1M" {
		t.Fatalf("restart on failure not configured: %+v", d.Settings.Restart)
	}
	if w := d.Triggers.Watchdog; w.Interval != "PT1M" || w.Stop != "false" {
		t.Fatalf("per-minute watchdog trigger missing (restart-on-failure alone does not cover a killed agent): %+v", w)
	}
	if d.Settings.Multiple != "IgnoreNew" || d.Settings.Limit != "PT0S" {
		t.Fatalf("must be a single, unlimited instance: %+v", d.Settings)
	}
	if d.Settings.Battery != "false" {
		t.Fatal("must start on battery (UPS) too")
	}
	if d.Settings.Priority != "5" {
		t.Fatalf("priority %s: the default 7 would make the launched Unity app run below normal", d.Settings.Priority)
	}
	if d.Exec.Command != `C:\ProgramData\RemoteConfig\agent.exe` || !strings.Contains(d.Exec.Args, `-config "C:\ProgramData\RemoteConfig\agent.json"`) {
		t.Fatalf("action wrong: %+v", d.Exec)
	}
}

func TestTaskXMLElevatedAndEscaping(t *testing.T) {
	d := parseTask(t, buildTaskXML(taskParams{
		User: `DOM\o'brien & <co>`, Exe: `C:\Program Files\R&D\agent.exe`, Args: `run`, WorkDir: `C:\x`, Elevated: true,
	}))
	if d.Principal.RunLevel != "HighestAvailable" {
		t.Fatalf("elevated flag ignored: %q", d.Principal.RunLevel)
	}
	if d.Principal.UserID != `DOM\o'brien & <co>` || d.Exec.Command != `C:\Program Files\R&D\agent.exe` {
		t.Fatalf("special characters were not escaped round-trip: %q / %q", d.Principal.UserID, d.Exec.Command)
	}
}

func TestUTF16LEHasBOMAndRoundTrips(t *testing.T) {
	in := "<a>héllo ✓</a>"
	b := utf16LE(in)
	if b[0] != 0xFF || b[1] != 0xFE {
		t.Fatal("missing UTF-16LE byte order mark")
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 2; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	if got := string(utf16.Decode(u)); got != in {
		t.Fatalf("round trip: %q", got)
	}
}

func TestFileConfigResolvesRelativePathsAgainstTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	os.WriteFile(path, []byte(`{"server":"https://x","state_dir":"state","log_file":"logs/a.log","out_dir":"`+strings.ReplaceAll(dir, `\`, `\\`)+`","interval":"90s"}`), 0o600)
	c, err := loadFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir != filepath.Join(dir, "state") || c.LogFile != filepath.Join(dir, "logs", "a.log") {
		t.Fatalf("relative paths not resolved: %+v", c)
	}
	if c.OutDir != dir {
		t.Fatalf("absolute path changed: %q", c.OutDir)
	}
	if c.interval().Seconds() != 90 {
		t.Fatalf("interval: %v", c.interval())
	}
}

func TestConfigPathPrefersExplicitArg(t *testing.T) {
	if got := configPathFromArgs([]string{"-server", "x", "-config", `C:\a\b.json`}); got != `C:\a\b.json` {
		t.Fatalf("got %q", got)
	}
	if got := configPathFromArgs([]string{"--config=D:\\c.json"}); got != `D:\c.json` {
		t.Fatalf("got %q", got)
	}
}
