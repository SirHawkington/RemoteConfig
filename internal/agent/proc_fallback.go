//go:build !windows && !linux && !darwin

package agent

import "errors"

// No way to tell processes apart on this platform: adoption is refused and a restarted agent
// launches its own copy of the app.
func identityOf(pid int) (procIdentity, error) {
	return procIdentity{}, errors.New("process identity is not implemented on this platform")
}
