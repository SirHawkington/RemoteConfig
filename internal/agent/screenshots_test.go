package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"remoteconfig/internal/capture"
	"remoteconfig/internal/proto"
	"remoteconfig/internal/server"
)

// ---------------------------------------------------------------- fakes and helpers

// fakeCapturer returns canned pictures so tests do not depend on a real display.
type fakeCapturer struct {
	mu    sync.Mutex
	shots []capture.Shot
	err   error
	calls int
}

func (f *fakeCapturer) Capture(int, int) ([]capture.Shot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.shots, f.err
}

func (f *fakeCapturer) set(shots ...capture.Shot) { f.mu.Lock(); f.shots = shots; f.mu.Unlock() }

func (f *fakeCapturer) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

// noiseShot is a picture of random pixels: it barely compresses, so its size is
// predictable and it spans many 64 KB upload chunks.
func noiseShot(display, w, h int, seed int64) capture.Shot {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	rand.New(rand.NewSource(seed)).Read(img.Pix)
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	s, err := capture.Finish(display, img, w, h, 95)
	if err != nil {
		panic(err)
	}
	return s
}

type env struct {
	t         *testing.T
	st        *server.Store
	srv       *httptest.Server
	agent     *Agent
	cap       *fakeCapturer
	deviceID  string
	stateDir  string
	enroll    string
	stop      func() // stops the agent AND the server
	stopAgent func() // stops only the agent (the server keeps running)
}

func (e *env) admin(method, path string, body, out any) int {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/v1/admin/projects/demo"+path, rd)
	req.Header.Set("Authorization", "Bearer adm")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode/100 == 2 && resp.StatusCode != 204 {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func (e *env) artifacts() []proto.ArtifactInfo {
	var l []proto.ArtifactInfo
	e.admin("GET", "/devices/"+e.deviceID+"/artifacts?limit=500", nil, &l)
	return l
}

func (e *env) detail() proto.DeviceDetail {
	var d proto.DeviceDetail
	e.admin("GET", "/devices/"+e.deviceID+"/detail", nil, &d)
	return d
}

func (e *env) command(typ string) {
	e.t.Helper()
	e.admin("POST", "/devices/"+e.deviceID+"/commands", proto.CommandRequest{Type: typ}, nil)
}

func wait(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// newEnv starts a real server (optionally behind a link wrapper) and a real agent.
func newEnv(t *testing.T, global proto.ConfigDocument, link func(http.Handler) http.Handler, tweak ...func(*Options)) *env {
	t.Helper()
	st, err := server.OpenStore("", "adm")
	if err != nil {
		t.Fatal(err)
	}
	st.Seed("demo", "Demo", &global)
	tok := st.NewEnrollToken("demo", nil, time.Hour)
	var h http.Handler = server.New(st, server.Options{CheckinInterval: time.Second}).Handler()
	if link != nil {
		h = link(h)
	}
	srv := httptest.NewServer(h)

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	cap := &fakeCapturer{}
	opts := Options{Server: srv.URL, EnrollToken: tok, StateDir: t.TempDir(), Listen: addr,
		Interval: 150 * time.Millisecond, Version: "test", Capturer: cap}
	for _, f := range tweak {
		f(&opts)
	}
	a := New(opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()

	e := &env{t: t, st: st, srv: srv, agent: a, cap: cap, stateDir: opts.StateDir, enroll: tok}
	e.stopAgent = func() { cancel(); <-done }
	e.stop = func() { e.stopAgent(); srv.Close(); st.Close() }
	t.Cleanup(e.stop)
	wait(t, "enrollment", 10*time.Second, func() bool { e.deviceID = a.DeviceID(); return e.deviceID != "" })
	return e
}

// ---------------------------------------------------------------- tests

// The headline property: an upload survives a link that keeps dying mid-transfer, ends up
// byte-identical on the server, and is stored exactly once.
func TestScreenshotUploadSurvivesAnUnreliableLink(t *testing.T) {
	var patches atomic.Int32
	link := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPatch {
				switch n := patches.Add(1); n % 3 {
				case 1: // connection dies before the chunk reaches the server
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				case 2: // the server stores the chunk, but the response never makes it back
					next.ServeHTTP(httptest.NewRecorder(), r)
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, link)
	shot := noiseShot(0, 800, 500, 1)
	if len(shot.JPEG) < 6*chunkSize {
		t.Fatalf("test picture too small to exercise chunking: %d bytes", len(shot.JPEG))
	}
	e.cap.set(shot)

	e.command("capture_screenshot")
	wait(t, "screenshot to arrive despite the dropped connections", 30*time.Second, func() bool { return len(e.artifacts()) == 1 })

	arts := e.artifacts()
	if arts[0].Size != int64(len(shot.JPEG)) || arts[0].Meta["reason"] != "command" || arts[0].Meta["display"] != 0.0 {
		t.Fatalf("metadata wrong: %+v", arts[0])
	}
	var got bytes.Buffer
	req, _ := http.NewRequest("GET", e.srv.URL+"/v1/admin/projects/demo/artifacts/"+arts[0].ID, nil)
	req.Header.Set("Authorization", "Bearer adm")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got.ReadFrom(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got.Bytes(), shot.JPEG) {
		t.Fatal("stored picture differs from the captured one")
	}
	if n := patches.Load(); n < 6 {
		t.Fatalf("only %d PATCH requests: the link never actually failed", n)
	}
	wait(t, "local copy removed after upload", 5*time.Second, func() bool { return len(e.agent.outbox.list()) == 0 })
	time.Sleep(500 * time.Millisecond) // and it must not be uploaded a second time
	if n := len(e.artifacts()); n != 1 {
		t.Fatalf("%d copies stored, want exactly 1", n)
	}
}

func TestMultipleDisplaysShareAGroup(t *testing.T) {
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, nil)
	e.cap.set(noiseShot(0, 160, 90, 1), noiseShot(1, 160, 90, 2))
	e.command("capture_screenshot")
	wait(t, "both displays", 15*time.Second, func() bool { return len(e.artifacts()) == 2 })
	a := e.artifacts()
	if a[0].Meta["group"] == "" || a[0].Meta["group"] != a[1].Meta["group"] {
		t.Fatalf("displays of one capture must share a group: %v vs %v", a[0].Meta["group"], a[1].Meta["group"])
	}
	if a[0].Meta["display"] == a[1].Meta["display"] {
		t.Fatalf("both artifacts claim the same display: %+v", a)
	}
	r := e.detail().Commands[0]
	if r.Status != "succeeded" {
		t.Fatalf("command not reported succeeded: %+v", r)
	}
}

func TestDataBudgetPausesBulkTrafficButNotCheckins(t *testing.T) {
	e := newEnv(t, proto.ConfigDocument{
		Data:   map[string]any{},
		Budget: map[string]any{"monthly_mb": 1},
	}, nil)
	wait(t, "budget policy to reach the agent", 10*time.Second, func() bool { return e.agent.budgetPolicy() != nil })
	if size := len(noiseShot(0, 400, 300, 3).JPEG); size < 100_000 { // roughly 200-300 KB each
		t.Fatalf("test picture unexpectedly small: %d", size)
	}

	const queued = 8
	for i := 0; i < queued; i++ {
		e.cap.set(noiseShot(0, 400, 300, int64(10+i))) // distinct pictures
		e.command("capture_screenshot")
		wait(t, "capture to be queued", 10*time.Second, func() bool { return e.cap.count() > i })
	}

	wait(t, "budget to be exhausted", 30*time.Second, func() bool { return e.detail().BudgetState == "exhausted" })
	d := e.detail()
	if d.BudgetMB != 1 {
		t.Fatalf("budget not reported: %+v", d.DeviceSummary)
	}
	if used := d.BytesIn + d.BytesOut; used < 1<<20 {
		t.Fatalf("exhausted but only %d bytes counted", used)
	}

	// Uploads stop: some screenshots arrived, the rest stay safely queued on disk...
	time.Sleep(700 * time.Millisecond)
	stored, waiting := len(e.artifacts()), len(e.agent.outbox.list())
	if stored == 0 || stored >= queued || waiting == 0 {
		t.Fatalf("expected a partial upload: stored=%d waiting=%d of %d", stored, waiting, queued)
	}
	time.Sleep(700 * time.Millisecond)
	if again := len(e.artifacts()); again != stored {
		t.Fatalf("uploads continued past the budget: %d -> %d", stored, again)
	}
	// ...while the control channel stays alive, so the operator still sees the device.
	seen := e.detail().LastSeenAt
	time.Sleep(600 * time.Millisecond)
	if !e.detail().LastSeenAt.After(seen) {
		t.Fatal("check-ins stopped when the budget ran out")
	}
	var warned bool
	for _, ev := range e.detail().Events {
		warned = warned || ev.Type == "budget.exhausted"
	}
	if !warned {
		t.Fatal("no budget.exhausted event reported to the server")
	}

	// A new billing cycle starts: the queue drains.
	e.agent.usage.mu.Lock()
	e.agent.usage.now = func() time.Time { return time.Now().AddDate(0, 0, 40) }
	e.agent.usage.mu.Unlock()
	wait(t, "queue to drain in the new cycle", 30*time.Second, func() bool { return len(e.artifacts()) == queued })
	wait(t, "state back to ok", 10*time.Second, func() bool { return e.detail().BudgetState != "exhausted" })
}

func TestScheduledCaptureSkipsUnchangedScreens(t *testing.T) {
	a := New(Options{StateDir: t.TempDir(), Capturer: &fakeCapturer{}})
	cap := a.capturer.(*fakeCapturer)
	a.cfg = &proto.EffectiveConfig{Revision: 1, Etag: "e", Data: map[string]any{},
		Screenshots: &proto.ScreenshotPolicy{Enabled: true, IntervalS: 60}}

	same := noiseShot(0, 160, 90, 5)
	cap.set(same)
	if q, s, err := a.captureAndQueue("schedule", false); err != nil || q != 1 || s != 0 {
		t.Fatalf("first capture: queued=%d skipped=%d err=%v", q, s, err)
	}
	if q, s, _ := a.captureAndQueue("schedule", false); q != 0 || s != 1 {
		t.Fatalf("an identical screen must be skipped: queued=%d skipped=%d", q, s)
	}
	if q, _, _ := a.captureAndQueue("command", true); q != 1 {
		t.Fatalf("force must bypass the skip: %d", q)
	}
	cap.set(noiseShot(0, 160, 90, 99)) // a different picture
	if q, _, _ := a.captureAndQueue("schedule", false); q != 1 {
		t.Fatalf("a changed screen must be queued: %d", q)
	}
	// operator wants every frame
	a.cfg.Screenshots.UploadUnchanged = true
	if q, _, _ := a.captureAndQueue("schedule", false); q != 1 {
		t.Fatalf("upload_unchanged must disable skipping: %d", q)
	}
	// each display tracked separately
	a.cfg.Screenshots.UploadUnchanged = false
	cap.set(noiseShot(0, 160, 90, 99), noiseShot(1, 160, 90, 7))
	if q, s, _ := a.captureAndQueue("schedule", false); q != 1 || s != 1 {
		t.Fatalf("display 0 unchanged, display 1 new: queued=%d skipped=%d", q, s)
	}
}

func TestBlackScreenAndCaptureFailuresAreReportedOnce(t *testing.T) {
	a := New(Options{StateDir: t.TempDir(), Capturer: &fakeCapturer{}})
	cap := a.capturer.(*fakeCapturer)
	black, _ := capture.Finish(0, image.NewRGBA(image.Rect(0, 0, 64, 36)), 64, 36, 60)
	cap.set(black)
	for i := 0; i < 3; i++ {
		a.captureAndQueue("schedule", true)
	}
	count := func(typ string) (n int) {
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, e := range a.events {
			if e.Type == typ {
				n++
			}
		}
		return
	}
	if n := count("screenshot.black"); n != 1 {
		t.Fatalf("%d black-screen events for 3 black captures, want 1", n)
	}

	cap.mu.Lock()
	cap.err = errors.New("screen locked")
	cap.mu.Unlock()
	for i := 0; i < 4; i++ {
		_, _, err := a.captureAndQueue("schedule", false)
		a.noteCaptureError(err)
	}
	if n := count("screenshot.failed"); n != 1 {
		t.Fatalf("%d failure events for 4 identical failures, want 1", n)
	}
}

func TestOutboxCapDropsOldestAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	a := New(Options{StateDir: dir, Capturer: &fakeCapturer{}})
	for i := 0; i < outboxMaxItems+5; i++ {
		a.outbox.add(outboxItem{ClientID: randomID(), Kind: "screenshot", Size: 3,
			CapturedAt: time.Unix(1_700_000_000+int64(i), 0)}, []byte{1, 2, 3})
	}
	if dropped := a.outbox.enforceCaps(); dropped != 5 {
		t.Fatalf("dropped %d, want 5", dropped)
	}
	items := a.outbox.list()
	if len(items) != outboxMaxItems || !items[0].CapturedAt.After(items[len(items)-1].CapturedAt) {
		t.Fatalf("queue should hold the newest %d, newest first: got %d", outboxMaxItems, len(items))
	}
	// a fresh agent process sees the same queue
	if b := New(Options{StateDir: dir, Capturer: &fakeCapturer{}}); len(b.outbox.list()) != outboxMaxItems {
		t.Fatal("outbox did not survive a restart")
	}
}

func TestCycleKeyFollowsTheCarrierResetDay(t *testing.T) {
	at := func(m time.Month, d int) time.Time { return time.Date(2026, m, d, 12, 0, 0, 0, time.UTC) }
	cases := []struct {
		now  time.Time
		day  int
		want string
	}{
		{at(10, 26), 1, "2026-10-01"},
		{at(10, 26), 15, "2026-10-15"},
		{at(10, 10), 15, "2026-09-15"}, // before this month's reset: still last month's cycle
		{at(1, 5), 20, "2025-12-20"},   // wraps the year
		{at(3, 31), 0, "2026-03-01"},   // 0 means the 1st
		{at(3, 31), 31, "2026-03-01"},  // out of range falls back to the 1st
	}
	for _, c := range cases {
		if got := cycleKey(c.now, c.day); got != c.want {
			t.Errorf("cycleKey(%s, %d) = %s, want %s", c.now.Format("2006-01-02"), c.day, got, c.want)
		}
	}
}

func TestUsageThresholdsNotifyOnceAndPersist(t *testing.T) {
	path := t.TempDir() + "/usage.json"
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	u := newUsageTracker(path)
	u.now = func() time.Time { return now }
	pol := &proto.BudgetPolicy{MonthlyMB: 10, SoftPct: 50}

	if v := u.view(nil); v.State != budgetNone {
		t.Fatalf("no policy: %s", v.State)
	}
	u.add(1<<20, 1<<20) // 2 of 10 MB
	if v := u.view(pol); v.State != budgetOK || v.NewSoft {
		t.Fatalf("20%%: %+v", v)
	}
	u.add(3<<20, 1<<20) // 6 of 10 MB: past the 50% soft line
	// Plain checks (e.g. "may I upload?") must not use up the announcement...
	for i := 0; i < 3; i++ {
		if v := u.view(pol); v.State != budgetSoft || !v.NewSoft {
			t.Fatalf("60%% (check %d): %+v", i, v)
		}
	}
	// ...only the caller that emits the event claims it, and only once.
	if v := u.claim(pol); !v.NewSoft {
		t.Fatalf("claim did not see the new threshold: %+v", v)
	}
	if v := u.claim(pol); v.NewSoft {
		t.Fatal("the soft threshold was announced twice")
	}
	u.add(5<<20, 0) // 11 of 10 MB
	if v := u.claim(pol); v.State != budgetExhausted || !v.NewHard || v.UsedPct != 110 {
		t.Fatalf("110%%: %+v", v)
	}
	u.save()

	// restart: counters and "already announced" flags come back
	u2 := newUsageTracker(path)
	u2.now = u.now
	u2.load()
	if v := u2.claim(pol); v.State != budgetExhausted || v.NewHard || v.In+v.Out != 11<<20 {
		t.Fatalf("after restart: %+v", v)
	}
	// next cycle resets everything
	now = now.AddDate(0, 1, 0)
	if v := u2.view(pol); v.State != budgetOK || v.In+v.Out != 0 {
		t.Fatalf("new cycle: %+v", v)
	}
}

func TestCountingConnCountsBothDirections(t *testing.T) {
	u := newUsageTracker("")
	c1, c2 := net.Pipe()
	cc := &countingConn{Conn: c1, u: u}
	go func() { c2.Write([]byte("hello")); buf := make([]byte, 3); c2.Read(buf); c2.Close() }()
	buf := make([]byte, 5)
	cc.Read(buf)
	cc.Write([]byte("abc"))
	if v := u.view(nil); v.In != 5 || v.Out != 3 {
		t.Fatalf("in=%d out=%d, want 5/3", v.In, v.Out)
	}
}
