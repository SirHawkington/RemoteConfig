package capture

import (
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func writePNG(t *testing.T, dir, name string, img image.Image) string {
	t.Helper()
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDownscaleAveragesInsteadOfSkipping(t *testing.T) {
	// a 1-pixel black and white checkerboard must average to grey, not to whichever pixel a
	// nearest-neighbour pick lands on
	src := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			v := uint8(0)
			if (x+y)%2 == 0 {
				v = 255
			}
			src.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}
	d := Downscale(src, 2, 2)
	for y := 0; y < 2; y++ {
		for x := 0; x < 2; x++ {
			if c := d.RGBAAt(x, y); c.R < 120 || c.R > 135 || c.A != 255 {
				t.Fatalf("pixel %d,%d = %v", x, y, c)
			}
		}
	}
	if got := Downscale(src, 8, 8); got.RGBAAt(0, 0).R != 255 || got.RGBAAt(1, 0).R != 0 {
		t.Fatal("the same size must be a copy")
	}
	if got := Downscale(image.NewRGBA(image.Rect(0, 0, 0, 0)), 4, 4); got.Bounds().Dx() != 4 {
		t.Fatal("an empty source must not panic")
	}
}

func TestShotsFromFilesDecodesScalesAndSkipsMissingDisplays(t *testing.T) {
	dir := t.TempDir()
	red := solid(400, 200, color.RGBA{200, 30, 30, 255})
	files := []string{
		writePNG(t, dir, "d0.png", red),
		filepath.Join(dir, "d1.png"), // the tool wrote only as many files as there are displays
		writePNG(t, dir, "d2.png", solid(100, 100, color.RGBA{0, 0, 0, 255})),
	}
	shots, err := ShotsFromFiles(files, 200, 60)
	if err != nil || len(shots) != 2 {
		t.Fatalf("%v %d", err, len(shots))
	}
	if shots[0].Width != 200 || shots[0].Height != 100 || shots[0].OrigW != 400 || shots[0].Black {
		t.Fatalf("first: %+v", shots[0])
	}
	if !shots[1].Black || shots[1].Width != 100 {
		t.Fatalf("a black screen (no permission, or locked) must be flagged, and never enlarged: %+v", shots[1])
	}
	if shots[0].Display != 0 || shots[1].Display != 1 {
		t.Fatalf("displays are numbered by the pictures that exist: %d %d", shots[0].Display, shots[1].Display)
	}
}

func TestShotsFromFilesExplainsFailures(t *testing.T) {
	dir := t.TempDir()
	if _, err := ShotsFromFiles([]string{filepath.Join(dir, "none.png")}, 100, 60); err == nil {
		t.Fatal("no files, no error")
	}
	bad := filepath.Join(dir, "bad.png")
	os.WriteFile(bad, []byte("this is not a picture"), 0o600)
	if _, err := ShotsFromFiles([]string{bad}, 100, 60); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestChooseToolTakesTheFirstInstalledOne(t *testing.T) {
	have := map[string]bool{"scrot": true, "import": true}
	look := func(n string) (string, error) {
		if have[n] {
			return "/usr/bin/" + n, nil
		}
		return "", errors.New("not found")
	}
	tool, path, err := ChooseTool(linuxTools, look)
	if err != nil || tool.Name != "scrot" || path != "/usr/bin/scrot" {
		t.Fatalf("%v %v %v", tool.Name, path, err)
	}
	if args := tool.Args([]string{"/tmp/x.png"}); len(args) == 0 || args[len(args)-1] != "/tmp/x.png" {
		t.Fatalf("the tool is not told where to write: %v", args)
	}
	have = map[string]bool{"grim": true, "scrot": true}
	if tool, _, _ := ChooseTool(linuxTools, look); tool.Name != "grim" {
		t.Fatalf("Wayland's tool should come first: %s", tool.Name)
	}
	have = map[string]bool{}
	if _, _, err := ChooseTool(linuxTools, look); err == nil {
		t.Fatal("no tool, no error")
	}
	for _, tl := range linuxTools { // every entry must produce a usable command line
		if a := tl.Args([]string{"/tmp/o.png"}); len(a) == 0 {
			t.Errorf("%s builds no arguments", tl.Name)
		}
	}
}
