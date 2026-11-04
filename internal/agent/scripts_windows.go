//go:build windows

package agent

import (
	"os/exec"
	"strconv"
	"syscall"
)

const (
	createNoWindow           = 0x08000000
	belowNormalPriorityClass = 0x00004000
)

// prepareScript: no console window over the installation's display, and a low priority so a
// maintenance script never competes with the app for the CPU.
func prepareScript(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow | belowNormalPriorityClass}
}

// killTree ends the process and everything it started (a script's children).
func killTree(pid int) {
	exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)).Run()
}
