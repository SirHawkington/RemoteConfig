package capture

import (
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // decoders for what the screenshot tools write
	_ "image/png"
	"os"
	"sort"
)

// Downscale shrinks src to w x h by averaging the source pixels each destination pixel covers,
// which keeps text legible where picking every n-th pixel would not.
func Downscale(src image.Image, w, h int) *image.RGBA {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	if sw == 0 || sh == 0 || w == 0 || h == 0 {
		return dst
	}
	for y := 0; y < h; y++ {
		y0, y1 := y*sh/h, (y+1)*sh/h
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < w; x++ {
			x0, x1 := x*sw/w, (x+1)*sw/w
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, bl, n uint64
			for yy := y0; yy < y1 && yy < sh; yy++ {
				for xx := x0; xx < x1 && xx < sw; xx++ {
					cr, cg, cb, _ := src.At(b.Min.X+xx, b.Min.Y+yy).RGBA()
					r, g, bl, n = r+uint64(cr>>8), g+uint64(cg>>8), bl+uint64(cb>>8), n+1
				}
			}
			if n == 0 {
				continue
			}
			i := dst.PixOffset(x, y)
			dst.Pix[i], dst.Pix[i+1], dst.Pix[i+2], dst.Pix[i+3] = uint8(r/n), uint8(g/n), uint8(bl/n), 255
		}
	}
	return dst
}

// ShotsFromFiles turns the picture files a screenshot tool wrote (one per display, in display
// order) into Shots. Files that are missing or empty are skipped: some tools are told to write
// up to N displays and write only as many as exist.
func ShotsFromFiles(files []string, maxWidth, quality int) ([]Shot, error) {
	var shots []Shot
	var lastErr error
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil || st.Size() == 0 {
			continue
		}
		fh, err := os.Open(f)
		if err != nil {
			lastErr = err
			continue
		}
		img, _, err := image.Decode(fh)
		fh.Close()
		if err != nil {
			lastErr = fmt.Errorf("the screenshot tool wrote something that is not a picture: %w", err)
			continue
		}
		ow, oh := img.Bounds().Dx(), img.Bounds().Dy()
		w, h := ScaledSize(ow, oh, maxWidth)
		s, err := Finish(len(shots), Downscale(img, w, h), ow, oh, quality)
		if err != nil {
			lastErr = err
			continue
		}
		shots = append(shots, s)
	}
	if len(shots) == 0 {
		if lastErr == nil {
			lastErr = errors.New("the screenshot tool produced no picture (no display, or the screen-capture permission is missing)")
		}
		return nil, lastErr
	}
	sort.SliceStable(shots, func(i, j int) bool { return shots[i].Display < shots[j].Display })
	return shots, nil
}

// Tool is a command-line screenshot program. Args builds its arguments for the output files.
type Tool struct {
	Name string
	Args func(outs []string) []string
}

// linuxTools in order of preference: Wayland first (grim), then the common X11 tools. All but the
// last write a single picture of the whole desktop, so a multi-monitor X11 desktop is one wide shot.
var linuxTools = []Tool{
	{"grim", func(o []string) []string { return []string{o[0]} }},
	{"scrot", func(o []string) []string { return []string{"-z", "-o", o[0]} }},
	{"maim", func(o []string) []string { return []string{o[0]} }},
	{"import", func(o []string) []string { return []string{"-window", "root", o[0]} }},
	{"gnome-screenshot", func(o []string) []string { return []string{"-f", o[0]} }},
	{"spectacle", func(o []string) []string { return []string{"-b", "-n", "-o", o[0]} }},
}

// ChooseTool picks the first of tools that look can find.
func ChooseTool(tools []Tool, look func(string) (string, error)) (Tool, string, error) {
	for _, t := range tools {
		if p, err := look(t.Name); err == nil {
			return t, p, nil
		}
	}
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}
	return Tool{}, "", fmt.Errorf("no screenshot tool is installed: install one of %v", names)
}
