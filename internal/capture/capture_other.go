//go:build !windows && !linux && !darwin

package capture

type unsupported struct{}

// New returns a capturer that always fails. TODO(macOS): CGDisplayCreateImage (needs the
// Screen Recording permission); TODO(Linux): X11/Wayland portal.
func New() Capturer { return unsupported{} }

func (unsupported) Capture(int, int) ([]Shot, error) { return nil, ErrUnsupported }
