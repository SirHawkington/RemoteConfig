//go:build !windows && !linux && !darwin

package main

import (
	"fmt"
	"os"
)

// Auto-start registration is Windows-only for now. TODO(macOS): LaunchAgent plist;
// TODO(Linux): systemd user unit.
func unsupported() int {
	fmt.Fprintln(os.Stderr, "install/uninstall/status are only implemented for Windows so far; run `agent run` under your own supervisor")
	return 1
}

func installCmd([]string) int   { return unsupported() }
func uninstallCmd([]string) int { return unsupported() }
func statusCmd([]string) int    { return unsupported() }
