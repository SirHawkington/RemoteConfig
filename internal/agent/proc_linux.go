//go:build linux

package agent

import (
	"fmt"
	"os"
	"strings"
)

func identityOf(pid int) (procIdentity, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procIdentity{}, err
	}
	started, err := parseProcStat(string(b))
	if err != nil {
		return procIdentity{}, err
	}
	image, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return procIdentity{}, err
	}
	return procIdentity{PID: pid, Created: started, Image: strings.TrimSuffix(image, " (deleted)")}, nil
}
