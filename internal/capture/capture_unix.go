//go:build linux || darwin

package capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// There is no pure-Go way to read another program's pixels on these systems without cgo and
// per-desktop APIs, so the agent runs the platform's own screenshot tool. That keeps the agent a
// single static binary. It costs a process start per capture, which is fine at one picture every
// few minutes.
//
//	macOS  screencapture, one file per display. The agent (or the terminal that started it) needs the
//	       Screen Recording permission in System Settings, or the picture is only the wallpaper.
//	Linux  grim (Wayland) or scrot/maim/import/gnome-screenshot/spectacle (X11).

const maxDisplays = 8

type toolCapturer struct{}

func New() Capturer { return toolCapturer{} }

func (toolCapturer) Capture(maxWidth, quality int) ([]Shot, error) {
	dir, err := os.MkdirTemp("", "rc-shot-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	var cmd *exec.Cmd
	var outs []string
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if runtime.GOOS == "darwin" {
		args := []string{"-x", "-t", "png"} // -x: no shutter sound
		for i := 0; i < maxDisplays; i++ {
			f := filepath.Join(dir, fmt.Sprintf("d%d.png", i))
			outs = append(outs, f)
			args = append(args, f)
		}
		cmd = exec.CommandContext(ctx, "screencapture", args...)
	} else {
		tool, path, err := ChooseTool(linuxTools, exec.LookPath)
		if err != nil {
			return nil, err
		}
		outs = []string{filepath.Join(dir, "screen.png")}
		cmd = exec.CommandContext(ctx, path, tool.Args(outs)...)
		cmd.Env = os.Environ()
		// An agent started by systemd has no idea which display it belongs to; a kiosk's is :0.
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			cmd.Env = append(cmd.Env, "DISPLAY=:0")
		}
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		if shots, ferr := ShotsFromFiles(outs, maxWidth, quality); ferr == nil {
			return shots, nil // wrote the pictures but exited non-zero
		}
		return nil, fmt.Errorf("%s failed: %v: %s", filepath.Base(cmd.Path), err, firstLine(string(out)))
	}
	return ShotsFromFiles(outs, maxWidth, quality)
}

func firstLine(s string) string {
	for i, r := range s {
		if r == '\n' {
			return s[:i]
		}
	}
	return s
}
