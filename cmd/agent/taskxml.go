package main

import (
	"bytes"
	"encoding/xml"
	"unicode/utf16"
)

// taskParams describes the Windows scheduled task that keeps the agent running.
type taskParams struct {
	User      string // DOMAIN\user whose logon starts the agent (the kiosk's auto-login account)
	Exe       string // full path of agent.exe
	Args      string // e.g. `run -config "C:\...\agent.json"`
	WorkDir   string
	Elevated  bool   // run with the user's highest privileges (needed to supervise an elevated app)
	LogonWait string // ISO 8601 delay after logon, e.g. PT15S
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// buildTaskXML renders the task definition imported with `schtasks /Create /XML`.
//
// Why these settings:
//   - LogonTrigger: the agent must live in the logged-in desktop session (screenshots,
//     launching the app on the visible desktop). Kiosks auto-login, so this starts it
//     on every boot.
//   - RestartOnFailure: if the agent exits non-zero by itself (a crash), Task Scheduler
//     starts it again after a minute, up to 999 times.
//   - TimeTrigger every minute: the watchdog for every other way the agent can vanish
//     (killed from outside, session quirks). See the comment on the trigger below.
//   - MultipleInstancesPolicy IgnoreNew + no time limit: exactly one long-running copy.
//   - Priority 5 (normal): the app we launch inherits the agent's priority class, and
//     the Task Scheduler default (below normal) would slow the Unity app down.
//   - Runs on battery, without network: kiosks are often on UPS/cellular.
func buildTaskXML(p taskParams) string {
	run := "LeastPrivilege"
	if p.Elevated {
		run = "HighestAvailable"
	}
	wait := p.LogonWait
	if wait == "" {
		wait = "PT15S"
	}
	var b bytes.Buffer
	w := func(s string) { b.WriteString(s) }
	w(`<?xml version="1.0" encoding="UTF-16"?>` + "\n")
	w(`<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` + "\n")
	w(`  <RegistrationInfo><Description>RemoteConfig agent: keeps the managed app configured, running and monitored.</Description></RegistrationInfo>` + "\n")
	w(`  <Triggers>` + "\n")
	w(`    <LogonTrigger><Enabled>true</Enabled><UserId>` + xmlEscape(p.User) + `</UserId><Delay>` + xmlEscape(wait) + `</Delay></LogonTrigger>` + "\n")
	// Watchdog: relaunch every minute. IgnoreNew makes this a no-op while the agent is up,
	// and it starts a dead agent within a minute. RestartOnFailure alone is not enough: it
	// does not fire when the process is killed from outside (verified on Windows 11).
	w(`    <TimeTrigger><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2020-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>` + "\n")
	w(`  </Triggers>` + "\n")
	w(`  <Principals><Principal id="Author"><UserId>` + xmlEscape(p.User) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>` + run + `</RunLevel></Principal></Principals>` + "\n")
	w(`  <Settings>` + "\n")
	w(`    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>` + "\n")
	w(`    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>` + "\n")
	w(`    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>` + "\n")
	w(`    <AllowHardTerminate>true</AllowHardTerminate>` + "\n")
	w(`    <StartWhenAvailable>true</StartWhenAvailable>` + "\n")
	w(`    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>` + "\n")
	w(`    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>` + "\n")
	w(`    <AllowStartOnDemand>true</AllowStartOnDemand>` + "\n")
	w(`    <Enabled>true</Enabled>` + "\n")
	w(`    <Hidden>false</Hidden>` + "\n")
	w(`    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>` + "\n")
	w(`    <Priority>5</Priority>` + "\n")
	w(`    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>` + "\n")
	w(`  </Settings>` + "\n")
	w(`  <Actions Context="Author"><Exec><Command>` + xmlEscape(p.Exe) + `</Command><Arguments>` + xmlEscape(p.Args) + `</Arguments><WorkingDirectory>` + xmlEscape(p.WorkDir) + `</WorkingDirectory></Exec></Actions>` + "\n")
	w(`</Task>` + "\n")
	return b.String()
}

// utf16LE encodes s as UTF-16 little endian with a byte order mark, which is what
// schtasks expects for files that declare encoding="UTF-16".
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2+len(u)*2)
	out = append(out, 0xFF, 0xFE)
	for _, c := range u {
		out = append(out, byte(c), byte(c>>8))
	}
	return out
}
