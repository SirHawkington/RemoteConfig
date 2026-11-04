//go:build darwin

package agent

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func psField(pid int, field string) (string, error) {
	cmd := exec.Command("ps", "-o", field+"=", "-p", strconv.Itoa(pid))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "", errors.New("no such process")
	}
	return s, nil
}

// identityOf uses ps: macOS has no /proc, and the sysctl route needs cgo.
func identityOf(pid int) (procIdentity, error) {
	start, err := psField(pid, "lstart")
	if err != nil {
		return procIdentity{}, err
	}
	created, err := parsePsStart(start)
	if err != nil {
		return procIdentity{}, err
	}
	image, err := psField(pid, "comm") // the full path of the executable on macOS
	if err != nil {
		return procIdentity{}, err
	}
	return procIdentity{PID: pid, Created: created, Image: image}, nil
}
