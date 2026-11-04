package capture

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"runtime"
	"testing"
)

func solid(w, h int, c color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.R, c.G, c.B, 255
	}
	return img
}

func TestScaledSize(t *testing.T) {
	cases := []struct{ w, h, max, ew, eh int }{
		{3840, 2160, 1280, 1280, 720},
		{1920, 1080, 1280, 1280, 720},
		{1024, 768, 1280, 1024, 768}, // never enlarged
		{1920, 1080, 0, 1920, 1080},  // 0 = native
		{1080, 1920, 540, 540, 960},  // portrait kiosk
		{4000, 1, 100, 100, 1},       // never collapses to zero height
	}
	for _, c := range cases {
		if w, h := ScaledSize(c.w, c.h, c.max); w != c.ew || h != c.eh {
			t.Errorf("ScaledSize(%d,%d,%d) = %dx%d, want %dx%d", c.w, c.h, c.max, w, h, c.ew, c.eh)
		}
	}
}

func TestFinishProducesDecodableJPEGAndDetectsBlack(t *testing.T) {
	s, err := Finish(2, solid(320, 180, color.RGBA{200, 30, 30, 255}), 1920, 1080, 60)
	if err != nil {
		t.Fatal(err)
	}
	if s.Display != 2 || s.Width != 320 || s.Height != 180 || s.OrigW != 1920 || s.Black {
		t.Fatalf("unexpected shot: %+v", s)
	}
	img, err := jpeg.Decode(bytes.NewReader(s.JPEG))
	if err != nil || img.Bounds().Dx() != 320 {
		t.Fatalf("not a valid 320px JPEG: %v", err)
	}
	if b, _ := Finish(0, solid(64, 36, color.RGBA{}), 64, 36, 60); !b.Black {
		t.Fatal("all-black frame not flagged")
	}
}

func TestSimilarToleratesSmallChangesButNotNewScreens(t *testing.T) {
	base := solid(640, 360, color.RGBA{40, 90, 160, 255})
	a, _ := BrightnessGrid(base)

	// a "clock": a small bright patch in one corner
	clock := solid(640, 360, color.RGBA{40, 90, 160, 255})
	for y := 5; y < 20; y++ {
		for x := 560; x < 630; x++ {
			clock.SetRGBA(x, y, color.RGBA{255, 255, 255, 255})
		}
	}
	if b, _ := BrightnessGrid(clock); !Similar(a, b) {
		t.Error("a small ticking element made the screen look different; unchanged-frame skipping would never trigger")
	}

	// a different scene: left half dark, right half bright
	other := solid(640, 360, color.RGBA{10, 10, 10, 255})
	for y := 0; y < 360; y++ {
		for x := 320; x < 640; x++ {
			other.SetRGBA(x, y, color.RGBA{230, 230, 60, 255})
		}
	}
	if c, _ := BrightnessGrid(other); Similar(a, c) {
		t.Error("a completely different screen was judged similar")
	}
	if !Similar(a, a) || Similar(a, nil) {
		t.Error("identity / length mismatch handling wrong")
	}
}

// Runs the real GDI path when a desktop is available (skipped on other platforms and in
// non-interactive sessions).
func TestCaptureRealScreen(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	shots, err := New().Capture(640, 50)
	if err != nil {
		t.Skipf("no interactive desktop here: %v", err)
	}
	if len(shots) == 0 {
		t.Fatal("no displays captured")
	}
	for _, s := range shots {
		if s.Width > 640 || s.Width < 1 || len(s.JPEG) < 200 {
			t.Fatalf("implausible shot: %dx%d, %d bytes", s.Width, s.Height, len(s.JPEG))
		}
		if _, err := jpeg.Decode(bytes.NewReader(s.JPEG)); err != nil {
			t.Fatalf("display %d is not a valid JPEG: %v", s.Display, err)
		}
		t.Logf("display %d: native %dx%d -> %dx%d, %d KB, black=%v", s.Display, s.OrigW, s.OrigH, s.Width, s.Height, len(s.JPEG)/1024, s.Black)
	}
}
