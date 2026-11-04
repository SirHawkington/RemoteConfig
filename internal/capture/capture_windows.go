//go:build windows

package capture

import (
	"fmt"
	"image"
	"sort"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")

	procEnumDisplayMonitors = user32.NewProc("EnumDisplayMonitors")
	procGetDC               = user32.NewProc("GetDC")
	procReleaseDC           = user32.NewProc("ReleaseDC")
	procSetDpiAwarenessCtx  = user32.NewProc("SetProcessDpiAwarenessContext")
	procCreateCompatibleDC  = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection    = gdi32.NewProc("CreateDIBSection")
	procSelectObject        = gdi32.NewProc("SelectObject")
	procSetStretchBltMode   = gdi32.NewProc("SetStretchBltMode")
	procSetBrushOrgEx       = gdi32.NewProc("SetBrushOrgEx")
	procStretchBlt          = gdi32.NewProc("StretchBlt")
	procDeleteObject        = gdi32.NewProc("DeleteObject")
	procDeleteDC            = gdi32.NewProc("DeleteDC")
	dpiOnce                 sync.Once
)

const (
	srccopy    = 0x00CC0020
	captureblt = 0x40000000 // include layered / transparent windows
	halftone   = 4          // good-quality downscale inside StretchBlt
)

type rect struct{ left, top, right, bottom int32 }

type bitmapInfoHeader struct {
	size          uint32
	width, height int32
	planes, bpp   uint16
	compression   uint32
	sizeImage     uint32
	xppm, yppm    int32
	clrUsed, clrI uint32
}

type gdiCapturer struct{ mu sync.Mutex }

// New returns the GDI based capturer.
func New() Capturer { return &gdiCapturer{} }

func (g *gdiCapturer) Capture(maxWidth, quality int) ([]Shot, error) {
	g.mu.Lock() // one capture at a time: they briefly allocate a bitmap per display
	defer g.mu.Unlock()
	dpiOnce.Do(func() {
		// Without this, Windows hands a DPI-unaware process virtualised (scaled) coordinates
		// and we would capture only part of a high-DPI display. -4 = per-monitor v2.
		procSetDpiAwarenessCtx.Call(^uintptr(3))
	})

	mons, err := monitors()
	if err != nil {
		return nil, err
	}
	if len(mons) == 0 {
		return nil, fmt.Errorf("no displays found (is a user logged in and the screen on?)")
	}
	screen, _, _ := procGetDC.Call(0)
	if screen == 0 {
		return nil, fmt.Errorf("cannot access the desktop (not an interactive session?)")
	}
	defer procReleaseDC.Call(0, screen)

	shots := make([]Shot, 0, len(mons))
	for i, m := range mons {
		w, h := int(m.right-m.left), int(m.bottom-m.top)
		img, err := grab(screen, m, w, h, maxWidth)
		if err != nil {
			return nil, fmt.Errorf("display %d: %w", i, err)
		}
		s, err := Finish(i, img, w, h, quality)
		if err != nil {
			return nil, err
		}
		shots = append(shots, s)
	}
	return shots, nil
}

// grab copies one monitor's rectangle from the desktop DC into a freshly allocated
// DIB section at the target size; GDI does the downscale, so even a 4K display never
// materialises at full size in our memory.
func grab(screen uintptr, m rect, w, h, maxWidth int) (*image.RGBA, error) {
	tw, th := ScaledSize(w, h, maxWidth)

	mem, _, _ := procCreateCompatibleDC.Call(screen)
	if mem == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(mem)

	bmi := bitmapInfoHeader{size: uint32(unsafe.Sizeof(bitmapInfoHeader{})), width: int32(tw), height: -int32(th), planes: 1, bpp: 32}
	var bits unsafe.Pointer
	bmp, _, _ := procCreateDIBSection.Call(mem, uintptr(unsafe.Pointer(&bmi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == nil {
		return nil, fmt.Errorf("CreateDIBSection failed")
	}
	defer procDeleteObject.Call(bmp)

	old, _, _ := procSelectObject.Call(mem, bmp)
	defer procSelectObject.Call(mem, old)

	procSetStretchBltMode.Call(mem, halftone)
	procSetBrushOrgEx.Call(mem, 0, 0, 0) // required after HALFTONE
	ok, _, _ := procStretchBlt.Call(mem, 0, 0, uintptr(tw), uintptr(th),
		screen, uintptr(m.left), uintptr(m.top), uintptr(w), uintptr(h), srccopy|captureblt)
	if ok == 0 {
		return nil, fmt.Errorf("StretchBlt failed (screen locked or no access to the desktop)")
	}

	// BGRA -> RGBA, copying out before the DIB section is freed.
	src := unsafe.Slice((*byte)(bits), tw*th*4)
	img := image.NewRGBA(image.Rect(0, 0, tw, th))
	for i := 0; i < len(src); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = src[i+2], src[i+1], src[i], 255
	}
	return img, nil
}

// monitors lists display rectangles in virtual-screen coordinates, left to right then
// top to bottom, so "display 0" is stable and predictable.
//
// EnumDisplayMonitors needs a callback, and Go can only ever create about 2000 of them
// (they are never freed). Making one per capture would crash a long-running agent after
// a week of 5-minute screenshots, so there is exactly one, filling package state under a lock.
var (
	monMu  sync.Mutex
	monOut []rect
	monCb  = syscall.NewCallback(func(hMon, hdc uintptr, r *rect, lparam uintptr) uintptr {
		monOut = append(monOut, *r)
		return 1
	})
)

func monitors() ([]rect, error) {
	monMu.Lock()
	defer monMu.Unlock()
	monOut = nil
	ok, _, err := procEnumDisplayMonitors.Call(0, 0, monCb, 0)
	if ok == 0 {
		return nil, fmt.Errorf("EnumDisplayMonitors: %v", err)
	}
	out := append([]rect(nil), monOut...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].left != out[j].left {
			return out[i].left < out[j].left
		}
		return out[i].top < out[j].top
	})
	return out, nil
}
