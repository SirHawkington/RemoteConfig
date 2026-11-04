package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"

	"remoteconfig/internal/capture"
	"remoteconfig/internal/proto"
)

type lastShot struct {
	grid []byte
	at   time.Time
}

type screenState struct {
	mu        sync.Mutex
	last      map[int]lastShot // per display: the last picture we queued
	wasBlack  map[int]bool
	lastError string
}

func randomID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func clamp(v, lo, hi int) int { return max(lo, min(v, hi)) }

func (a *Agent) screenshotPolicy() *proto.ScreenshotPolicy {
	if c := a.currentConfig(); c != nil {
		return c.Screenshots
	}
	return nil
}

func (a *Agent) budgetPolicy() *proto.BudgetPolicy {
	if c := a.currentConfig(); c != nil {
		return c.Budget
	}
	return nil
}

// allowBulk says whether non-essential traffic (screenshots, artifacts, metrics) may be
// sent. Check-ins, config, acks and command results are never gated: they are tiny and
// they are how the operator finds out a device is in trouble.
func (a *Agent) allowBulk() bool {
	return a.usage.view(a.budgetPolicy()).State != budgetExhausted
}

// reportBudget emits one event per cycle when a threshold is first crossed.
func (a *Agent) reportBudget() usageView {
	v := a.usage.claim(a.budgetPolicy())
	if v.NewSoft && v.State != budgetExhausted {
		a.QueueEvent(proto.Event{Type: "budget.soft", Level: "warn",
			Message: fmt.Sprintf("%d%% of the %d MB data budget used this cycle", v.UsedPct, v.LimitMB)})
	}
	if v.NewHard {
		a.QueueEvent(proto.Event{Type: "budget.exhausted", Level: "error",
			Message: fmt.Sprintf("data budget of %d MB used up: screenshots and metrics are paused until the cycle resets", v.LimitMB)})
	}
	return v
}

// screenshotLoop takes scheduled captures per the policy. It runs from the cached
// config, so scheduled captures continue (and queue on disk) while offline.
func (a *Agent) screenshotLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	var last time.Time
	started := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		p := a.screenshotPolicy()
		if p == nil || !p.Enabled {
			continue
		}
		interval := time.Duration(clamp(p.IntervalS, 0, 7*86400)) * time.Second
		if interval == 0 {
			interval = 5 * time.Minute
		}
		interval = max(interval, 10*time.Second)
		if last.IsZero() { // first capture shortly after start, not instantly: the app is still loading
			last = started.Add(min(interval, 45*time.Second) - interval)
		}
		if time.Since(last) < interval || !a.allowBulk() {
			continue
		}
		last = time.Now()
		if _, _, err := a.captureAndQueue("schedule", false); err != nil {
			a.noteCaptureError(err)
			continue
		}
		if a.isConnected() {
			go a.drainOutbox(ctx)
		}
	}
}

func (a *Agent) isConnected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connected
}

// noteCaptureError logs a failure once per distinct message, so a locked screen does
// not fill the log every interval.
func (a *Agent) noteCaptureError(err error) {
	a.shots.mu.Lock()
	same := a.shots.lastError == err.Error()
	a.shots.lastError = err.Error()
	a.shots.mu.Unlock()
	if !same {
		a.logf("screenshot failed: %v", err)
		a.QueueEvent(proto.Event{Type: "screenshot.failed", Level: "warn", Message: err.Error()})
	}
}

// captureAndQueue grabs every display and queues the pictures for upload. force
// bypasses unchanged-frame suppression (operator asked, or something just broke).
func (a *Agent) captureAndQueue(reason string, force bool) (queued, skipped int, err error) {
	p := a.screenshotPolicy()
	maxW, quality := 1280, 60
	unchangedEvery := time.Hour
	uploadUnchanged := false
	if p != nil {
		if p.MaxWidth > 0 {
			maxW = clamp(p.MaxWidth, 64, 7680)
		}
		if p.Quality > 0 {
			quality = clamp(p.Quality, 1, 100)
		}
		if p.UnchangedEveryS > 0 {
			unchangedEvery = time.Duration(p.UnchangedEveryS) * time.Second
		}
		uploadUnchanged = p.UploadUnchanged
	}

	shots, err := a.capturer.Capture(maxW, quality)
	if err != nil {
		return 0, 0, err
	}
	a.shots.mu.Lock()
	a.shots.lastError = ""
	now := time.Now().UTC()
	group := strconv.FormatInt(now.UnixMilli(), 10) // ties the displays of one capture together
	for _, s := range shots {
		if s.Black && !a.shots.wasBlack[s.Display] {
			a.QueueEvent(proto.Event{Type: "screenshot.black", Level: "warn",
				Message: fmt.Sprintf("display %d is black: locked or asleep, or an exclusive-fullscreen app that cannot be captured", s.Display)})
		}
		a.shots.wasBlack[s.Display] = s.Black

		prev, seen := a.shots.last[s.Display]
		if !force && !uploadUnchanged && seen && capture.Similar(prev.grid, s.Grid) && now.Sub(prev.at) < unchangedEvery {
			skipped++
			continue
		}
		sum := sha256.Sum256(s.JPEG)
		it := outboxItem{
			ClientID: randomID(), Kind: "screenshot", ContentType: "image/jpeg",
			Size: int64(len(s.JPEG)), SHA256: hex.EncodeToString(sum[:]), CapturedAt: now,
			Meta: map[string]any{
				"display": s.Display, "width": s.Width, "height": s.Height,
				"orig_width": s.OrigW, "orig_height": s.OrigH,
				"reason": reason, "group": group, "black": s.Black,
			},
		}
		if err := a.outbox.add(it, s.JPEG); err != nil {
			a.shots.mu.Unlock()
			return queued, skipped, err
		}
		a.shots.last[s.Display] = lastShot{grid: s.Grid, at: now}
		queued++
	}
	a.shots.mu.Unlock()

	if dropped := a.outbox.enforceCaps(); dropped > 0 {
		a.QueueEvent(proto.Event{Type: "outbox.dropped", Level: "warn",
			Message: fmt.Sprintf("offline queue full: discarded the %d oldest item(s)", dropped)})
	}
	return queued, skipped, nil
}

// maybeCaptureOnEvent grabs a screenshot when the app misbehaves, so the operator can
// see what the screen looked like. Throttled to one per minute.
func (a *Agent) maybeCaptureOnEvent(e proto.Event) {
	switch e.Type {
	case "app.hung", "app.crash", "app.crashloop":
	default:
		return
	}
	p := a.screenshotPolicy()
	if p == nil || !p.OnEvent {
		return
	}
	now := time.Now().UnixNano()
	prev := a.lastEventShot.Load()
	if now-prev < int64(time.Minute) || !a.lastEventShot.CompareAndSwap(prev, now) {
		return
	}
	go func() {
		if _, _, err := a.captureAndQueue("event:"+e.Type, true); err != nil {
			a.noteCaptureError(err)
			return
		}
		if a.isConnected() && a.runCtx != nil {
			a.drainOutbox(a.runCtx)
		}
	}()
}
