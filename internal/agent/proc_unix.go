//go:build !windows

package agent

import (
	"syscall"
	"time"
)

func waitProcess(pid int) int {
	for syscall.Kill(pid, 0) == nil {
		time.Sleep(500 * time.Millisecond)
	}
	return 0
}

func killProcess(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }
func quitProcess(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }
