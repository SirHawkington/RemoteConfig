package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"remoteconfig/internal/proto"
)

type rolloutFixture struct {
	t    *testing.T
	st   *Store
	srv  *Server
	devs []proto.EnrollResponse
	rel  proto.ReleaseInfo
}

func newRolloutFixture(t *testing.T, devices int, tick time.Duration) *rolloutFixture {
	t.Helper()
	st, err := OpenStore("", "adm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	st.Seed("demo", "Demo", &proto.ConfigDocument{Data: map[string]any{}})
	st.Seed("other", "Other", &proto.ConfigDocument{Data: map[string]any{}})
	if tick == 0 {
		tick = time.Hour // tests step the engine by hand
	}
	srv := New(st, Options{CheckinInterval: time.Minute, RolloutTick: tick})
	f := &rolloutFixture{t: t, st: st, srv: srv}
	for i := 0; i < devices; i++ {
		f.devs = append(f.devs, enrollDevice(t, st, srv.Handler()))
		f.checkIn(i)
	}
	_, f.rel = f.upload("kind=app&name=kiosk&version=1.0&os=windows", []byte("build"))
	return f
}

func (f *rolloutFixture) req(method, path string, body []byte, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = "192.0.2.10:5555"
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, r)
	return rec
}

func (f *rolloutFixture) upload(query string, body []byte) (int, proto.ReleaseInfo) {
	rec := f.req("POST", A+"/releases?"+query, body, "adm")
	var x proto.ReleaseInfo
	json.Unmarshal(rec.Body.Bytes(), &x)
	return rec.Code, x
}

func (f *rolloutFixture) ids(idx ...int) []string {
	var out []string
	for _, i := range idx {
		out = append(out, f.devs[i].DeviceID)
	}
	return out
}

func (f *rolloutFixture) create(in proto.RolloutRequest) (int, proto.Rollout) {
	b, _ := json.Marshal(in)
	rec := f.req("POST", A+"/rollouts", b, "adm")
	var ro proto.Rollout
	json.Unmarshal(rec.Body.Bytes(), &ro)
	return rec.Code, ro
}

func (f *rolloutFixture) get(id string) proto.Rollout {
	f.t.Helper()
	var list []proto.Rollout
	json.Unmarshal(f.req("GET", A+"/rollouts", nil, "adm").Body.Bytes(), &list)
	for _, r := range list {
		if r.ID == id {
			return r
		}
	}
	f.t.Fatalf("rollout %s not listed", id)
	return proto.Rollout{}
}

func (f *rolloutFixture) pass(now time.Time) {
	f.st.mu.Lock()
	f.srv.rolloutPass(now)
	f.st.mu.Unlock()
}

func (f *rolloutFixture) checkIn(i int) {
	f.st.mu.Lock()
	f.st.D.Devices[f.devs[i].DeviceID].LastSeen = time.Now().UTC()
	f.st.mu.Unlock()
}

func (f *rolloutFixture) commands(i int) []proto.Command {
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	return append([]proto.Command(nil), f.st.D.Devices[f.devs[i].DeviceID].Commands...)
}

// report plays the device: the newest command ends with this status.
func (f *rolloutFixture) report(i int, status, result string) {
	f.t.Helper()
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	d := f.st.D.Devices[f.devs[i].DeviceID]
	if len(d.Commands) == 0 {
		f.t.Fatalf("device %d has no command to report on", i)
	}
	c := &d.Commands[len(d.Commands)-1]
	c.Status = status
	if c.Params == nil {
		c.Params = map[string]any{}
	}
	c.Params["result"] = result
	d.LastSeen = time.Now().UTC()
}

func (f *rolloutFixture) event(i int, level, typ string) {
	f.st.mu.Lock()
	f.st.appendEvents(f.devs[i].DeviceID, []proto.Event{{Type: typ, Level: level, Message: "boom", TS: time.Now().UTC()}})
	f.st.mu.Unlock()
}

func (f *rolloutFixture) sentTo() (n int) {
	for i := range f.devs {
		n += len(f.commands(i))
	}
	return
}

func soak(n int) *int { return &n }

func (f *rolloutFixture) request(devs []string, canary, soakS, batch int) proto.RolloutRequest {
	return proto.RolloutRequest{Type: "apply_release", Params: map[string]any{"release_id": f.rel.ID},
		Devices: devs, Canary: canary, SoakS: soak(soakS), Batch: batch}
}

// ---------------------------------------------------------------- the staging itself

func TestOnlyTheCanaryGetsTheReleaseUntilItHasSucceededAndSoaked(t *testing.T) {
	f := newRolloutFixture(t, 4, 0)
	code, ro := f.create(f.request(f.ids(0, 1, 2, 3), 1, 60, 0))
	if code != 201 || ro.State != "canary" {
		t.Fatalf("create: %d %+v", code, ro)
	}
	if len(f.commands(0)) != 1 || f.sentTo() != 1 {
		t.Fatalf("the canary should be the only device told: %d commands in total", f.sentTo())
	}
	if c := f.commands(0)[0]; c.Type != "apply_release" || c.Params["sha256"] != f.rel.SHA256 {
		t.Fatalf("not resolved from the library: %+v", c)
	}

	now := time.Now().UTC()
	f.pass(now) // the canary is still working on it
	if f.sentTo() != 1 {
		t.Fatal("others were told before the canary reported")
	}
	f.report(0, "succeeded", "installed")
	f.pass(now)
	if got := f.get(ro.ID); got.State != "soaking" || f.sentTo() != 1 {
		t.Fatalf("success alone is not enough: %s, %d sent", got.State, f.sentTo())
	}
	f.pass(now.Add(30 * time.Second))
	if f.sentTo() != 1 {
		t.Fatal("sent before the soak was over")
	}
	f.pass(now.Add(61 * time.Second))
	if got := f.get(ro.ID); got.State != "rolling" || f.sentTo() != 4 {
		t.Fatalf("after the soak the rest should be sent: %s, %d sent", got.State, f.sentTo())
	}
	for i := 1; i < 4; i++ {
		f.report(i, "succeeded", "installed")
	}
	f.pass(now.Add(70 * time.Second))
	if got := f.get(ro.ID); got.State != "done" {
		t.Fatalf("state %s", got.State)
	}
}

func TestACanaryFailureStopsEverythingAndSaysWhy(t *testing.T) {
	f := newRolloutFixture(t, 3, 0)
	_, ro := f.create(f.request(f.ids(0, 1, 2), 1, 0, 0))
	f.report(0, "failed", "app release 1.0 did not stay up; rolled back to 0.9")
	f.pass(time.Now().UTC())
	got := f.get(ro.ID)
	if got.State != "halted" || !strings.Contains(got.Reason, "did not stay up") {
		t.Fatalf("%s: %q", got.State, got.Reason)
	}
	f.pass(time.Now().UTC().Add(time.Hour))
	if f.sentTo() != 1 {
		t.Fatalf("a halted rollout kept sending: %d commands", f.sentTo())
	}
}

func TestACanaryThatTurnsUnhealthyDuringTheSoakStopsTheRollout(t *testing.T) {
	f := newRolloutFixture(t, 3, 0)
	_, ro := f.create(f.request(f.ids(0, 1, 2), 1, 60, 0))
	now := time.Now().UTC()
	f.report(0, "succeeded", "installed")
	f.pass(now)
	time.Sleep(5 * time.Millisecond)
	f.event(0, "error", "app.crashloop") // reported after the command succeeded
	f.pass(now.Add(10 * time.Second))
	got := f.get(ro.ID)
	if got.State != "halted" || !strings.Contains(got.Reason, "app.crashloop") {
		t.Fatalf("%s: %q", got.State, got.Reason)
	}
	f.pass(now.Add(time.Hour))
	if f.sentTo() != 1 {
		t.Fatal("sent to the rest of the fleet after the canary went bad")
	}
}

func TestAnErrorBeforeTheCanarySucceededDoesNotCountAgainstTheSoak(t *testing.T) {
	f := newRolloutFixture(t, 2, 0)
	_, ro := f.create(f.request(f.ids(0, 1), 1, 0, 0))
	f.event(0, "error", "app.start_failed") // the old build's trouble that the release is meant to fix
	time.Sleep(5 * time.Millisecond)
	f.report(0, "succeeded", "installed")
	now := time.Now().UTC().Add(time.Second)
	f.pass(now)
	f.pass(now.Add(time.Second))
	if got := f.get(ro.ID); got.State != "rolling" {
		t.Fatalf("%s: %q", got.State, got.Reason)
	}
}

func TestWavesGoOneAtATimeAndAFailureInALaterWaveStopsTheRest(t *testing.T) {
	f := newRolloutFixture(t, 6, 0)
	_, ro := f.create(f.request(f.ids(0, 1, 2, 3, 4, 5), 1, 0, 2))
	now := time.Now().UTC().Add(time.Second)
	f.report(0, "succeeded", "ok")
	f.pass(now)
	f.pass(now) // soak 0: straight on
	if f.sentTo() != 3 {
		t.Fatalf("first wave should be the canary plus 2: %d", f.sentTo())
	}
	f.pass(now)
	if f.sentTo() != 3 {
		t.Fatal("the next wave went before the first finished")
	}
	f.report(1, "succeeded", "ok")
	f.report(2, "failed", "download: the data budget is used up")
	f.pass(now)
	got := f.get(ro.ID)
	if got.State != "halted" || !strings.Contains(got.Reason, "data budget") {
		t.Fatalf("%s: %q", got.State, got.Reason)
	}
	if f.sentTo() != 3 {
		t.Fatalf("devices 4-6 were sent to after a failure: %d commands", f.sentTo())
	}
}

func TestAWholeCanaryGroupMustSucceed(t *testing.T) {
	f := newRolloutFixture(t, 4, 0)
	_, ro := f.create(f.request(f.ids(0, 1, 2, 3), 2, 0, 0))
	if f.sentTo() != 2 {
		t.Fatalf("two canaries: %d", f.sentTo())
	}
	f.report(0, "succeeded", "ok")
	f.pass(time.Now().UTC())
	if got := f.get(ro.ID); got.State != "canary" {
		t.Fatalf("one of two canaries done: %s", got.State)
	}
	f.report(1, "succeeded", "ok")
	f.pass(time.Now().UTC())
	f.pass(time.Now().UTC())
	if got := f.get(ro.ID); got.State != "rolling" || f.sentTo() != 4 {
		t.Fatalf("%s %d", got.State, f.sentTo())
	}
}

func TestACanaryThatNeverComesBackOnlineHaltsTheRollout(t *testing.T) {
	f := newRolloutFixture(t, 2, 0)
	_, ro := f.create(f.request(f.ids(0, 1), 1, 5, 0))
	now := time.Now().UTC()
	f.report(0, "succeeded", "agent updated; restarting")
	f.pass(now)
	f.st.mu.Lock()
	f.st.D.Devices[f.devs[0].DeviceID].LastSeen = now.Add(-time.Hour) // gone dark: the new agent never checked in
	f.st.mu.Unlock()
	f.pass(now.Add(10 * time.Second))
	if got := f.get(ro.ID); got.State != "soaking" || f.sentTo() != 1 {
		t.Fatalf("it may still be restarting: %s", got.State)
	}
	f.pass(now.Add(20 * time.Minute))
	if got := f.get(ro.ID); got.State != "halted" || !strings.Contains(got.Reason, "did not come back") || f.sentTo() != 1 {
		t.Fatalf("%s %q %d", got.State, got.Reason, f.sentTo())
	}
}

func TestAnOperatorCanHaltARolloutThatIsInProgress(t *testing.T) {
	f := newRolloutFixture(t, 3, 0)
	_, ro := f.create(f.request(f.ids(0, 1, 2), 1, 60, 0))
	rec := f.req("POST", A+"/rollouts/"+ro.ID+"/halt", nil, "adm")
	if rec.Code != 200 || f.get(ro.ID).State != "halted" {
		t.Fatalf("halt: %d", rec.Code)
	}
	f.report(0, "succeeded", "ok")
	f.pass(time.Now().UTC().Add(time.Hour))
	if f.sentTo() != 1 {
		t.Fatal("a halted rollout carried on")
	}
	if rec := f.req("POST", A+"/rollouts/"+ro.ID+"/halt", nil, "adm"); rec.Code != 409 {
		t.Fatalf("halting twice: %d", rec.Code)
	}
	if rec := f.req("POST", A+"/rollouts/ro_nope/halt", nil, "adm"); rec.Code != 404 {
		t.Fatalf("unknown rollout: %d", rec.Code)
	}
}

// ---------------------------------------------------------------- refusing bad requests

func TestABadRolloutRequestSendsNothingToAnyone(t *testing.T) {
	f := newRolloutFixture(t, 2, 0)
	other := f.st.NewEnrollToken("other", nil, time.Hour)
	var er proto.EnrollResponse
	b, _ := json.Marshal(proto.EnrollRequest{Token: other, Hostname: "x", OS: "windows"})
	json.Unmarshal(f.req("POST", "/v1/enroll", b, "").Body.Bytes(), &er)

	linux := proto.ReleaseInfo{}
	_, linux = f.upload("kind=app&name=kiosk&version=1.0&os=linux", []byte("x"))

	good := map[string]any{"release_id": f.rel.ID}
	for name, in := range map[string]proto.RolloutRequest{
		"unknown type":                  {Type: "reboot", Devices: f.ids(0)},
		"no devices":                    {Type: "apply_release", Params: good},
		"unknown device":                {Type: "apply_release", Params: good, Devices: []string{"dev_nope"}},
		"a device of another project":   {Type: "apply_release", Params: good, Devices: []string{f.devs[0].DeviceID, er.DeviceID}},
		"a device listed twice":         {Type: "apply_release", Params: good, Devices: []string{f.devs[0].DeviceID, f.devs[0].DeviceID}},
		"unknown release":               {Type: "apply_release", Params: map[string]any{"release_id": "rel_nope"}, Devices: f.ids(0, 1)},
		"wrong platform for one device": {Type: "apply_release", Params: map[string]any{"release_id": linux.ID}, Devices: f.ids(0, 1)},
		"negative soak":                 {Type: "apply_release", Params: good, Devices: f.ids(0), SoakS: soak(-1)},
	} {
		b, _ := json.Marshal(in)
		if rec := f.req("POST", A+"/rollouts", b, "adm"); rec.Code != 400 {
			t.Errorf("%s: want 400, got %d", name, rec.Code)
		}
	}
	if f.sentTo() != 0 {
		t.Fatalf("a rejected rollout still queued %d commands", f.sentTo())
	}
}

func TestOnlyProjectAdminsStartRollouts(t *testing.T) {
	f := newAuthFixture(t)
	op := f.user("op", false, map[string]Role{"demo": RoleOperator})
	viewer := f.user("vw", false, map[string]Role{"demo": RoleViewer})
	body := proto.RolloutRequest{Type: "run_script", Devices: []string{f.dev.DeviceID}}
	if code, _, _ := f.call("POST", A+"/rollouts", op, body); code != 403 {
		t.Errorf("operator started a rollout: %d", code)
	}
	if code, _, _ := f.call("POST", A+"/rollouts/ro_x/halt", op, nil); code != 403 {
		t.Errorf("operator halted one: %d", code)
	}
	if rec := f.raw("GET", A+"/rollouts", viewer, nil, nil); rec.Code != 200 {
		t.Errorf("a viewer cannot see rollouts: %d", rec.Code)
	}
	if code, _, _ := f.call("GET", A+"/rollouts", "", nil); code != 401 {
		t.Errorf("anonymous: %d", code)
	}
}

// ---------------------------------------------------------------- the background loop

func TestTheLoopAdvancesRolloutsByItselfAndStopsWhenTheStoreCloses(t *testing.T) {
	f := newRolloutFixture(t, 3, 20*time.Millisecond)
	_, ro := f.create(f.request(f.ids(0, 1, 2), 1, 0, 0))
	f.report(0, "succeeded", "ok")
	deadline := time.Now().Add(5 * time.Second)
	for f.sentTo() != 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if f.sentTo() != 3 {
		t.Fatalf("the loop never sent to the rest (state %s)", f.get(ro.ID).State)
	}
	f.st.Close() // must not leave a goroutine poking a closed database (run with -race)
	time.Sleep(100 * time.Millisecond)
}
