//go:build windows

package main

import (
	"bytes"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

var generatedPwRe = regexp.MustCompile(`(?m)^password:\s+(\S+)`)

// passwordFrom reads the generated password out of `server user passwd` output.
func passwordFrom(out string) string {
	if m := generatedPwRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

func runHidden(name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	var buf bytes.Buffer
	c.Stdout, c.Stderr = &buf, &buf
	err := c.Run()
	return strings.TrimSpace(buf.String()), err
}

func firstLines(out string, err error) string {
	if out == "" {
		return err.Error()
	}
	return out
}
