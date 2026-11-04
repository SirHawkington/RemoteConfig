package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"remoteconfig/internal/proto"
)

// usageTracker counts the bytes this agent moves over the network in the current
// data-budget cycle and survives restarts. It counts at the socket, below TLS, so the
// figure includes headers and encryption overhead: the number a carrier would bill, minus
// only TCP/IP framing (a few percent).
type usageTracker struct {
	mu   sync.Mutex
	path string
	now  func() time.Time

	cycle        string // start date of the current cycle, e.g. "2026-10-01"
	in, out      int64
	softNotified bool
	hardNotified bool
	resetDay     int
}

type usageFile struct {
	Cycle        string `json:"cycle"`
	In           int64  `json:"in"`
	Out          int64  `json:"out"`
	SoftNotified bool   `json:"soft_notified,omitempty"`
	HardNotified bool   `json:"hard_notified,omitempty"`
}

func newUsageTracker(path string) *usageTracker {
	return &usageTracker{path: path, now: time.Now}
}

// cycleKey returns the start date of the billing cycle containing now. resetDay is the
// day of month the carrier restarts the allowance (1-28, anything else means 1).
func cycleKey(now time.Time, resetDay int) string {
	if resetDay < 1 || resetDay > 28 {
		resetDay = 1
	}
	y, m, d := now.Date()
	if d < resetDay {
		m--
		if m < time.January {
			m, y = time.December, y-1
		}
	}
	return fmt.Sprintf("%04d-%02d-%02d", y, int(m), resetDay)
}

func (u *usageTracker) load() {
	b, err := os.ReadFile(u.path)
	if err != nil {
		return
	}
	var f usageFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	u.mu.Lock()
	u.cycle, u.in, u.out, u.softNotified, u.hardNotified = f.Cycle, f.In, f.Out, f.SoftNotified, f.HardNotified
	u.mu.Unlock()
}

func (u *usageTracker) save() {
	u.mu.Lock()
	b, _ := json.Marshal(usageFile{u.cycle, u.in, u.out, u.softNotified, u.hardNotified})
	u.mu.Unlock()
	writeFileAtomic(u.path, b)
}

// roll starts a new cycle if the date has moved past the current one. Caller holds u.mu.
func (u *usageTracker) roll() {
	key := cycleKey(u.now(), u.resetDay)
	if key != u.cycle {
		u.cycle, u.in, u.out = key, 0, 0
		u.softNotified, u.hardNotified = false, false
	}
}

func (u *usageTracker) add(in, out int) {
	u.mu.Lock()
	u.roll()
	u.in += int64(in)
	u.out += int64(out)
	u.mu.Unlock()
}

// Budget evaluation results.
const (
	budgetNone      = "none"
	budgetOK        = "ok"
	budgetSoft      = "soft"
	budgetExhausted = "exhausted"
)

type usageView struct {
	In, Out  int64
	LimitMB  int
	State    string
	NewSoft  bool // the soft threshold was crossed since we last said so
	NewHard  bool
	UsedPct  int
	CycleKey string
}

// view evaluates usage against the policy without side effects (NewSoft/NewHard say a
// threshold has not been announced yet). Use claim to announce.
func (u *usageTracker) view(p *proto.BudgetPolicy) usageView { return u.evaluate(p, false) }

// claim is view plus: thresholds reported as new are marked announced, so each is
// reported exactly once per cycle. Only the caller that emits the event should use it;
// pure checks like "may I upload?" must use view, or they would swallow the announcement.
func (u *usageTracker) claim(p *proto.BudgetPolicy) usageView { return u.evaluate(p, true) }

func (u *usageTracker) evaluate(p *proto.BudgetPolicy, mark bool) usageView {
	u.mu.Lock()
	defer u.mu.Unlock()
	if p != nil {
		u.resetDay = p.ResetDay
	}
	u.roll()
	v := usageView{In: u.in, Out: u.out, State: budgetNone, CycleKey: u.cycle}
	if p == nil || p.MonthlyMB <= 0 {
		return v
	}
	v.LimitMB = p.MonthlyMB
	limit := int64(p.MonthlyMB) << 20
	softPct := p.SoftPct
	if softPct <= 0 || softPct >= 100 {
		softPct = 80
	}
	total := u.in + u.out
	v.UsedPct = int(total * 100 / limit)
	switch {
	case total >= limit:
		v.State = budgetExhausted
	case total*100 >= limit*int64(softPct):
		v.State = budgetSoft
	default:
		v.State = budgetOK
	}
	if v.State == budgetExhausted && !u.hardNotified {
		v.NewHard = true
		u.hardNotified = u.hardNotified || mark
	}
	if (v.State == budgetSoft || v.State == budgetExhausted) && !u.softNotified {
		v.NewSoft = true
		u.softNotified = u.softNotified || mark
	}
	return v
}

// countingConn counts every byte that crosses the socket.
type countingConn struct {
	net.Conn
	u *usageTracker
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.u.add(n, 0)
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.u.add(0, n)
	}
	return n, err
}
