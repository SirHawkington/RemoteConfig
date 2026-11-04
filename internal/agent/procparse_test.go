package agent

import (
	"testing"
	"time"
)

func TestProcStatStartTimeIsFound(t *testing.T) {
	// field 22 is 123456 in each of these
	lines := map[string]string{
		"plain":       "4242 (app) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 123456 1000000 500 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0",
		"spaces":      "4242 (Unity Player) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 123456 1000000 500 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0",
		"parens":      "4242 (a) S (b) c) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 123456 1000000 500 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0",
		"newline too": "4242 (app) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 123456 1000000 500 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n",
	}
	for name, l := range lines {
		got, err := parseProcStat(l)
		if err != nil || got != 123456 {
			t.Errorf("%s: %d %v", name, got, err)
		}
	}
	for name, l := range map[string]string{"empty": "", "no paren": "4242 app S 1", "short": "4242 (app) S 1 2 3"} {
		if _, err := parseProcStat(l); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPsStartTimeHandlesPaddedDays(t *testing.T) {
	a, err := parsePsStart("Mon Oct 27 14:07:20 2026")
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(time.Date(2026, 10, 27, 14, 7, 20, 0, time.Local).Unix()); a != want {
		t.Fatalf("%d != %d", a, want)
	}
	b, err := parsePsStart("Sun Nov  1 09:00:01 2026") // ps pads a one-digit day with a space
	if err != nil || b == 0 {
		t.Fatalf("%v", err)
	}
	if _, err := parsePsStart("garbage"); err == nil {
		t.Fatal("accepted garbage")
	}
}
