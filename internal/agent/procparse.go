package agent

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// procIdentity pins down one process: a pid alone can be reused, a pid with its start time and
// executable cannot. The supervisor records it so a restarted agent adopts the app a previous
// agent started, and never touches an unrelated process that inherited the pid.
type procIdentity struct {
	PID     int    `json:"pid"`
	Created uint64 `json:"created"`
	Image   string `json:"image"`
}

// parseProcStat extracts the start time (clock ticks since boot, field 22) from the text of
// /proc/<pid>/stat. The command name in field 2 may contain spaces and parentheses, so the
// fields are counted from the last closing parenthesis.
func parseProcStat(stat string) (uint64, error) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, fmt.Errorf("unexpected /proc stat format")
	}
	f := strings.Fields(stat[i+1:]) // f[0] is field 3 (state)
	if len(f) < 20 {
		return 0, fmt.Errorf("short /proc stat line")
	}
	return strconv.ParseUint(f[19], 10, 64)
}

// parsePsStart reads the output of `ps -o lstart= -p <pid>` (for example "Mon Oct 27 14:07:20 2026",
// with the locale forced to C) as local time.
func parsePsStart(s string) (uint64, error) {
	s = strings.Join(strings.Fields(s), " ") // ps pads single-digit days
	t, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", s, time.Local)
	if err != nil {
		return 0, err
	}
	return uint64(t.Unix()), nil
}
