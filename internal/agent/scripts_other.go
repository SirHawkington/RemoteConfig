//go:build !windows

package agent

import (
	"os/exec"
	"syscall"
)

// prepareScript puts the script in its own process group, so a timeout can end its children too.
func prepareScript(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killTree(pid int) { syscall.Kill(-pid, syscall.SIGKILL) }
