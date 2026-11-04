package main

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestSystemdUnitKeepsTheAppAliveAndQuotesPaths(t *testing.T) {
	u := systemdUnit(`/home/kiosk user/100% "agent"/agent`, "/home/kiosk user/agent.json", "/home/kiosk user")
	for _, want := range []string{
		"KillMode=process", // the supervised app must survive an agent restart or update
		"Restart=always",   // including the exit code an agent update uses
		"WantedBy=default.target",
		`ExecStart="/home/kiosk user/100%% \"agent\"/agent" run -config "/home/kiosk user/agent.json"`,
		`WorkingDirectory="/home/kiosk user"`,
	} {
		if !strings.Contains(u, want) {
			t.Errorf("missing %q in:\n%s", want, u)
		}
	}
	if strings.Contains(u, "%\"") || strings.Contains(strings.ReplaceAll(u, "%%", ""), "%") {
		t.Errorf("an unescaped %% would be read by systemd as a specifier:\n%s", u)
	}
}

func TestLaunchdPlistIsValidXMLThatSurvivesStrangePaths(t *testing.T) {
	p := launchdPlist("com.remoteconfig.agent", `/Users/a&b/<x>/agent`, "/Users/a&b/agent.json", "/Users/a&b", "/Users/a&b/agent.log")
	d := xml.NewDecoder(strings.NewReader(p))
	d.Strict = false
	d.Entity = xml.HTMLEntity
	var strs []string
	var keys []string
	var last string
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("not well-formed XML: %v\n%s", err, p)
		}
		switch v := tok.(type) {
		case xml.StartElement:
			last = v.Name.Local
		case xml.CharData:
			s := strings.TrimSpace(string(v))
			if s == "" {
				continue
			}
			if last == "key" {
				keys = append(keys, s)
			} else if last == "string" {
				strs = append(strs, s)
			}
		}
	}
	joined := strings.Join(keys, ",")
	for _, k := range []string{"Label", "ProgramArguments", "KeepAlive", "RunAtLoad", "AbandonProcessGroup", "ThrottleInterval"} {
		if !strings.Contains(joined, k) {
			t.Errorf("no %s key", k)
		}
	}
	found := false
	for _, s := range strs {
		found = found || s == `/Users/a&b/<x>/agent` // decoded back to exactly what was given
	}
	if !found {
		t.Errorf("the executable path did not round-trip through the escaping: %q", strs)
	}
}
