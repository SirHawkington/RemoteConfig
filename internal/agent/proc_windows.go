//go:build windows

package agent

import (
	"errors"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The supervisor works with processes by PID so it can manage an app it did not launch
// itself: one started by a previous agent, which this agent then adopts.

var (
	user32                       = windows.NewLazySystemDLL("user32.dll")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procPostMessageW             = user32.NewProc("PostMessageW")
)

const (
	wmClose     = 0x0010
	stillActive = 259
)

// identityOf describes a running process; it fails if there is no such running process.
func identityOf(pid int) (procIdentity, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return procIdentity{}, err
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return procIdentity{}, err
	}
	if code != stillActive {
		return procIdentity{}, errors.New("process has exited")
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return procIdentity{}, err
	}
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return procIdentity{}, err
	}
	return procIdentity{
		PID:     pid,
		Created: uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime),
		Image:   windows.UTF16ToString(buf[:n]),
	}, nil
}

// waitProcess blocks until the process exits and returns its exit code.
func waitProcess(pid int) int {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return -1 // already gone
	}
	defer windows.CloseHandle(h)
	windows.WaitForSingleObject(h, windows.INFINITE)
	var code uint32
	windows.GetExitCodeProcess(h, &code)
	return int(int32(code)) // 0xFFFFFFFF (killed) reads as -1
}

func killProcess(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

// quitProcess asks the process to close the way a user would: WM_CLOSE to each of its
// visible top-level windows. A Unity player treats that like Alt+F4: it runs its quit
// handlers (Application.wantsToQuit, OnApplicationQuit) and exits. It does not wait.
//
// EnumWindows needs a callback, and Go can only ever create a limited number of them
// (they are never freed), so there is exactly one, parameterised through package state.
var (
	enumMu   sync.Mutex
	enumPID  uint32
	enumHits int
	enumCb   = syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		var pid uint32
		procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid == enumPID {
			if vis, _, _ := procIsWindowVisible.Call(hwnd); vis != 0 {
				procPostMessageW.Call(hwnd, wmClose, 0, 0)
				enumHits++
			}
		}
		return 1 // keep enumerating
	})
)

func quitProcess(pid int) error {
	enumMu.Lock()
	defer enumMu.Unlock()
	enumPID, enumHits = uint32(pid), 0
	procEnumWindows.Call(enumCb, 0)
	if enumHits == 0 {
		return errNoWindow
	}
	return nil
}
