//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"syscall"
)

var instanceLock *os.File // held for the life of the process; the OS drops it however we exit

// AcquireSingleInstance takes an exclusive lock on a file in the state directory (key). It
// returns ok=false if another agent already holds it.
func AcquireSingleInstance(key string) (bool, error) {
	if err := os.MkdirAll(key, 0o755); err != nil {
		return false, err
	}
	f, err := os.OpenFile(filepath.Join(key, "agent.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return false, nil
		}
		return false, err
	}
	instanceLock = f
	return true, nil
}
