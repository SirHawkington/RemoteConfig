package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// The files that make the agent start at logon and come back after it exits: a systemd user
// unit on Linux, a LaunchAgent on macOS. They are plain text so they can be checked on any
// platform; install_unix.go writes and loads them.

// systemdQuote quotes one word of an ExecStart= line: double quotes, with backslash, quote and
// the % specifier character escaped.
func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`)
	return `"` + r.Replace(s) + `"`
}

// systemdUnit is the user unit. KillMode=process matters: the app the agent supervises is meant
// to outlive the agent (an agent update, or a restart, must not blank the display), and the
// default would have systemd kill every process in the unit's cgroup when the agent stops.
// Restart=always also covers the exit code an agent update uses to ask for a restart.
func systemdUnit(exe, cfg, workDir string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=RemoteConfig agent\nAfter=network-online.target\nWants=network-online.target\n\n")
	fmt.Fprintf(&b, "[Service]\nType=simple\nExecStart=%s run -config %s\n", systemdQuote(exe), systemdQuote(cfg))
	fmt.Fprintf(&b, "WorkingDirectory=%s\nRestart=always\nRestartSec=10\nKillMode=process\n\n", systemdQuote(workDir))
	fmt.Fprintf(&b, "[Install]\nWantedBy=default.target\n")
	return b.String()
}

func plistString(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return "<string>" + b.String() + "</string>"
}

// launchdPlist is the LaunchAgent. AbandonProcessGroup keeps launchd from killing the app when
// the agent exits, for the same reason as KillMode=process above; KeepAlive restarts the agent
// whatever its exit code.
func launchdPlist(label, exe, cfg, workDir, logFile string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	fmt.Fprintf(&b, "\t<key>Label</key>\n\t%s\n", plistString(label))
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, a := range []string{exe, "run", "-config", cfg} {
		fmt.Fprintf(&b, "\t\t%s\n", plistString(a))
	}
	b.WriteString("\t</array>\n")
	fmt.Fprintf(&b, "\t<key>WorkingDirectory</key>\n\t%s\n", plistString(workDir))
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>KeepAlive</key>\n\t<true/>\n")
	b.WriteString("\t<key>ThrottleInterval</key>\n\t<integer>10</integer>\n")
	b.WriteString("\t<key>AbandonProcessGroup</key>\n\t<true/>\n")
	fmt.Fprintf(&b, "\t<key>StandardErrorPath</key>\n\t%s\n\t<key>StandardOutPath</key>\n\t%s\n", plistString(logFile), plistString(logFile))
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}
