// Package capture grabs screenshots of every display, downscaled and JPEG encoded,
// cheaply enough to run on low-end kiosk PCs next to a Unity app.
package capture

import (
	"bytes"
	"errors"
	"image"
	"image/jpeg"
)

// Shot is one display's capture.
type Shot struct {
	Display int // 0-based index in left-to-right, top-to-bottom order
	Width   int // pixels after downscaling
	Height  int
	OrigW   int // the display's native size
	OrigH   int
	JPEG    []byte
	// Grid is a tiny brightness map of the picture (see Similar), used to avoid
	// re-uploading a screen that has not meaningfully changed.
	Grid []byte
	// Black is true when every pixel is black. On Windows that usually means the screen is
	// locked/asleep, or an exclusive-fullscreen game that GDI cannot see.
	Black bool
}

// Capturer takes screenshots. It is an interface so tests can substitute a fake.
type Capturer interface {
	// Capture grabs all displays, each scaled to at most maxWidth pixels wide (never
	// enlarged), JPEG quality 1-100.
	Capture(maxWidth, quality int) ([]Shot, error)
}

var ErrUnsupported = errors.New("screen capture is not implemented on this platform yet")

// ScaledSize returns the size w x h shrunk to at most maxWidth wide, keeping aspect ratio.
func ScaledSize(w, h, maxWidth int) (int, int) {
	if maxWidth <= 0 || w <= maxWidth || w <= 0 {
		return w, h
	}
	nh := int(float64(h)*float64(maxWidth)/float64(w) + 0.5)
	if nh < 1 {
		nh = 1
	}
	return maxWidth, nh
}

// Finish encodes an RGBA picture into a Shot: brightness grid, black detection, JPEG.
func Finish(display int, img *image.RGBA, origW, origH, quality int) (Shot, error) {
	if quality < 1 || quality > 100 {
		quality = 60
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		return Shot{}, err
	}
	grid, black := BrightnessGrid(img)
	b := img.Bounds()
	return Shot{
		Display: display, Width: b.Dx(), Height: b.Dy(), OrigW: origW, OrigH: origH,
		JPEG: buf.Bytes(), Grid: grid, Black: black,
	}, nil
}

const (
	gridX, gridY = 32, 18
	// A cell counts as changed when its average brightness moves by more than this (0-255)...
	cellDelta = 12
	// ...and two pictures are "similar" if no more than this many of the 576 cells changed
	// (about 2%): enough room for a clock, a cursor or a small animation, not for a new screen.
	maxChangedCells = 12
)

// BrightnessGrid averages the picture into a 32x18 grid of 0-255 luminance values.
func BrightnessGrid(img *image.RGBA) (grid []byte, allBlack bool) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	grid = make([]byte, gridX*gridY)
	if w == 0 || h == 0 {
		return grid, true
	}
	var sum, cnt [gridX * gridY]uint64
	allBlack = true
	for y := 0; y < h; y++ {
		row := img.Pix[y*img.Stride : y*img.Stride+w*4]
		cy := y * gridY / h
		for x := 0; x < w; x++ {
			r, g, bl := uint64(row[x*4]), uint64(row[x*4+1]), uint64(row[x*4+2])
			if r|g|bl != 0 {
				allBlack = false
			}
			i := cy*gridX + x*gridX/w
			sum[i] += (r*299 + g*587 + bl*114) / 1000
			cnt[i]++
		}
	}
	for i := range grid {
		if cnt[i] > 0 {
			grid[i] = byte(sum[i] / cnt[i])
		}
	}
	return grid, allBlack
}

// Similar reports whether two brightness grids describe essentially the same screen.
func Similar(a, b []byte) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	changed := 0
	for i := range a {
		d := int(a[i]) - int(b[i])
		if d < 0 {
			d = -d
		}
		if d > cellDelta {
			changed++
		}
	}
	return changed <= maxChangedCells
}
