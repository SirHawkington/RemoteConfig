//go:build windows

package main

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	pRegisterClassEx = user32.NewProc("RegisterClassExW")
	pCreateWindowEx  = user32.NewProc("CreateWindowExW")
	pShowWindow      = user32.NewProc("ShowWindow")
	pGetMessage      = user32.NewProc("GetMessageW")
	pTranslate       = user32.NewProc("TranslateMessage")
	pDispatch        = user32.NewProc("DispatchMessageW")
	pDefWindowProc   = user32.NewProc("DefWindowProcW")
	pPostQuit        = user32.NewProc("PostQuitMessage")
	pDestroyWindow   = user32.NewProc("DestroyWindow")
)

type wndClassEx struct {
	size, style                        uint32
	wndProc                            uintptr
	clsExtra, wndExtra                 int32
	instance, icon, cursor, background uintptr
	menuName, className                *uint16
	iconSm                             uintptr
}

type point struct{ x, y int32 }
type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

const (
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	swShowMinNoActive = 7 // visible to EnumWindows, but does not pop up on the user's screen
)

// A window procedure like a real app's: WM_CLOSE runs the app's quit path.
var wndProc = syscall.NewCallback(func(hwnd, m, w, l uintptr) uintptr {
	switch m {
	case wmClose:
		logf("window: WM_CLOSE received")
		pDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		pPostQuit.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, m, w, l)
	return r
})

func runWindow() {
	runtime.LockOSThread() // a window must be pumped by the thread that created it
	class, _ := windows.UTF16PtrFromString("RemoteConfigTestApp")
	title, _ := windows.UTF16PtrFromString("RemoteConfig test app")
	wc := wndClassEx{wndProc: wndProc, className: class}
	wc.size = uint32(unsafe.Sizeof(wc))
	pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
	hwnd, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)),
		0x00CF0000, 100, 100, 320, 200, 0, 0, 0, 0) // WS_OVERLAPPEDWINDOW
	if hwnd == 0 {
		logf("window: could not create")
		return
	}
	pShowWindow.Call(hwnd, swShowMinNoActive)
	logf("window: created")
	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslate.Call(uintptr(unsafe.Pointer(&m)))
		pDispatch.Call(uintptr(unsafe.Pointer(&m)))
	}
	logf("window: closed, exiting")
	os.Exit(0)
}
