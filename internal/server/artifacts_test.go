package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"remoteconfig/internal/proto"
)

type fixture struct {
	t   *testing.T
	st  *Store
	h   http.Handler
	dev proto.EnrollResponse
}

func newFixture(t *testing.T) *fixture {
	st, err := OpenStore("", "adm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	st.Seed("demo", "Demo", &proto.ConfigDocument{Data: map[string]any{}})
	h := New(st, Options{CheckinInterval: time.Minute}).Handler()
	return &fixture{t: t, st: st, h: h, dev: enrollDevice(t, st, h)}
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func (f *fixture) raw(method, path, token string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) create(token string, in proto.ArtifactInit) (proto.ArtifactSession, int) {
	var s proto.ArtifactSession
	code := do(f.t, f.h, "POST", "/v1/artifacts", token, in, &s)
	return s, code
}

func (f *fixture) patch(token, id string, offset int, chunk []byte) *httptest.ResponseRecorder {
	return f.raw("PATCH", "/v1/artifacts/"+id, token, chunk, map[string]string{"Upload-Offset": strconv.Itoa(offset)})
}

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func (f *fixture) uploadAll(clientID string, data []byte, captured time.Time) string {
	f.t.Helper()
	s, code := f.create(f.dev.DeviceToken, proto.ArtifactInit{ClientID: clientID, Kind: "screenshot", Size: int64(len(data)),
		ContentType: "image/jpeg", SHA256: sha(data), CapturedAt: captured, Meta: map[string]any{"display": 0.0}})
	if code != 201 && code != 200 {
		f.t.Fatalf("create: %d", code)
	}
	for off := int(s.Offset); off < len(data); {
		end := min(off+64<<10, len(data))
		if rec := f.patch(f.dev.DeviceToken, s.ID, off, data[off:end]); rec.Code != 204 {
			f.t.Fatalf("patch at %d: %d %s", off, rec.Code, rec.Body.String())
		}
		off = end
	}
	return s.ID
}

func TestChunkedUploadStoresVerifiedFileAndServesIt(t *testing.T) {
	f := newFixture(t)
	data := payload(150_000) // three chunks of 64 KB
	id := f.uploadAll("c1", data, time.Now())

	var list []proto.ArtifactInfo
	do(t, f.h, "GET", "/v1/admin/projects/demo/devices/"+f.dev.DeviceID+"/artifacts?kind=screenshot", "adm", nil, &list)
	if len(list) != 1 || list[0].ID != id || list[0].Size != int64(len(data)) || list[0].Meta["display"] != 0.0 {
		t.Fatalf("listing wrong: %+v", list)
	}
	rec := f.raw("GET", "/v1/admin/projects/demo/artifacts/"+id, "adm", nil, nil)
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), data) || rec.Header().Get("Content-Type") != "image/jpeg" {
		t.Fatalf("download wrong: %d type=%q equal=%v", rec.Code, rec.Header().Get("Content-Type"), bytes.Equal(rec.Body.Bytes(), data))
	}
	if rec.Header().Get("Cache-Control") == "" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing cache / nosniff headers")
	}
	if f.raw("GET", "/v1/admin/projects/demo/artifacts/"+id, "", nil, nil).Code != 401 {
		t.Fatal("artifact served without admin token")
	}
}

func TestCreateIsIdempotentAndUploadResumes(t *testing.T) {
	f := newFixture(t)
	data := payload(200_000)
	init := proto.ArtifactInit{ClientID: "resume-me", Kind: "screenshot", Size: int64(len(data)), SHA256: sha(data)}

	s1, code := f.create(f.dev.DeviceToken, init)
	if code != 201 || s1.Offset != 0 {
		t.Fatalf("first create: %d %+v", code, s1)
	}
	f.patch(f.dev.DeviceToken, s1.ID, 0, data[:64<<10]) // one chunk makes it, then the link drops

	// The agent does not know whether that chunk landed. It re-creates (same client_id):
	s2, code := f.create(f.dev.DeviceToken, init)
	if code != 200 || s2.ID != s1.ID || s2.Offset != 64<<10 {
		t.Fatalf("resume must return the same session at the server's offset: %d %+v", code, s2)
	}
	// HEAD reports the same offset
	rec := f.raw("HEAD", "/v1/artifacts/"+s1.ID, f.dev.DeviceToken, nil, nil)
	if rec.Header().Get("Upload-Offset") != strconv.Itoa(64<<10) || rec.Header().Get("Upload-Complete") != "false" {
		t.Fatalf("HEAD: %v", rec.Header())
	}

	for off := int(s2.Offset); off < len(data); off += 64 << 10 {
		end := min(off+64<<10, len(data))
		rec := f.patch(f.dev.DeviceToken, s1.ID, off, data[off:end])
		if rec.Code != 204 {
			t.Fatalf("resumed patch: %d", rec.Code)
		}
		if end == len(data) && rec.Header().Get("Upload-Complete") != "true" {
			t.Fatal("final chunk must report completion")
		}
	}
	// Retrying the final chunk after a lost response is harmless and still says complete.
	last := (len(data) - 1) / (64 << 10) * (64 << 10)
	if rec := f.patch(f.dev.DeviceToken, s1.ID, last, data[last:]); rec.Code != 204 || rec.Header().Get("Upload-Complete") != "true" {
		t.Fatalf("replayed final chunk: %d %v", rec.Code, rec.Header())
	}
	// And creating it again reports complete, so the agent can delete its local copy.
	if s3, _ := f.create(f.dev.DeviceToken, init); !s3.Complete {
		t.Fatalf("recreate after completion: %+v", s3)
	}
}

func TestOffsetMismatchTellsClientWhereToResume(t *testing.T) {
	f := newFixture(t)
	data := payload(100_000)
	s, _ := f.create(f.dev.DeviceToken, proto.ArtifactInit{ClientID: "x", Kind: "other", Size: int64(len(data)), SHA256: sha(data)})
	f.patch(f.dev.DeviceToken, s.ID, 0, data[:40_000])

	rec := f.patch(f.dev.DeviceToken, s.ID, 0, data[:40_000]) // a duplicate of an already-applied chunk
	if rec.Code != 409 || rec.Header().Get("Upload-Offset") != "40000" {
		t.Fatalf("duplicate chunk: %d offset=%q", rec.Code, rec.Header().Get("Upload-Offset"))
	}
	rec = f.patch(f.dev.DeviceToken, s.ID, 90_000, data[90_000:]) // a gap
	if rec.Code != 409 || rec.Header().Get("Upload-Offset") != "40000" {
		t.Fatalf("gap: %d offset=%q", rec.Code, rec.Header().Get("Upload-Offset"))
	}
	if rec := f.patch(f.dev.DeviceToken, s.ID, 40_000, append(data[40_000:], 1)); rec.Code != 413 {
		t.Fatalf("data past the declared size must be refused, got %d", rec.Code)
	}
}

func TestChecksumMismatchIsRejectedAndNothingIsKept(t *testing.T) {
	f := newFixture(t)
	good := payload(70_000)
	bad := append([]byte(nil), good...)
	bad[1234] ^= 0xFF
	s, _ := f.create(f.dev.DeviceToken, proto.ArtifactInit{ClientID: "corrupt", Kind: "screenshot", Size: int64(len(good)), SHA256: sha(good)})
	f.patch(f.dev.DeviceToken, s.ID, 0, bad[:64<<10])
	rec := f.patch(f.dev.DeviceToken, s.ID, 64<<10, bad[64<<10:])
	if rec.Code != 422 {
		t.Fatalf("corrupt upload accepted: %d", rec.Code)
	}
	var list []proto.ArtifactInfo
	do(t, f.h, "GET", "/v1/admin/projects/demo/devices/"+f.dev.DeviceID+"/artifacts", "adm", nil, &list)
	if len(list) != 0 {
		t.Fatalf("corrupt artifact is listed: %+v", list)
	}
	entries, _ := os.ReadDir(f.st.artifactDir)
	if len(entries) != 0 {
		t.Fatalf("files left behind: %v", entries)
	}
	// the same client_id can start over cleanly
	if s2, code := f.create(f.dev.DeviceToken, proto.ArtifactInit{ClientID: "corrupt", Kind: "screenshot", Size: int64(len(good)), SHA256: sha(good)}); code != 201 || s2.Offset != 0 {
		t.Fatalf("restart after corruption: %d %+v", code, s2)
	}
}

func TestUploadValidationAndOwnership(t *testing.T) {
	f := newFixture(t)
	other := enrollDevice(t, f.st, f.h)
	data := payload(100)
	ok := proto.ArtifactInit{ClientID: "a", Kind: "screenshot", Size: 100, SHA256: sha(data)}

	for name, mut := range map[string]func(*proto.ArtifactInit){
		"no client id": func(i *proto.ArtifactInit) { i.ClientID = "" },
		"bad kind":     func(i *proto.ArtifactInit) { i.Kind = "exe" },
		"zero size":    func(i *proto.ArtifactInit) { i.Size = 0 },
		"no checksum":  func(i *proto.ArtifactInit) { i.SHA256 = "" },
		"non-hex sum":  func(i *proto.ArtifactInit) { i.SHA256 = fmt.Sprintf("%064s", "zz") },
	} {
		in := ok
		mut(&in)
		if _, code := f.create(f.dev.DeviceToken, in); code != 400 {
			t.Errorf("%s: want 400 got %d", name, code)
		}
	}
	big := ok
	big.Size = maxArtifactBytes + 1
	if _, code := f.create(f.dev.DeviceToken, big); code != 413 {
		t.Errorf("oversize: want 413 got %d", code)
	}
	if _, code := f.create("", ok); code != 401 {
		t.Errorf("no token: want 401 got %d", code)
	}

	s, _ := f.create(f.dev.DeviceToken, ok)
	if rec := f.patch(other.DeviceToken, s.ID, 0, data); rec.Code != 404 {
		t.Fatalf("another device could write into this upload: %d", rec.Code)
	}
	if rec := f.raw("HEAD", "/v1/artifacts/"+s.ID, other.DeviceToken, nil, nil); rec.Code != 404 {
		t.Fatalf("another device could probe this upload: %d", rec.Code)
	}
	if rec := f.patch(f.dev.DeviceToken, s.ID, 0, nil); rec.Code != 204 && rec.Code != 400 {
		t.Logf("empty chunk -> %d", rec.Code)
	}

	// a project admin cannot reach artifacts of another project
	f.patch(f.dev.DeviceToken, s.ID, 0, data)
	if rec := f.raw("GET", "/v1/admin/projects/other-project/artifacts/"+s.ID, "adm", nil, nil); rec.Code != 404 {
		t.Fatalf("artifact reachable through the wrong project: %d", rec.Code)
	}
}

func TestRetentionKeepsNewestScreenshotsOnly(t *testing.T) {
	f := newFixture(t)
	base := time.Now().Add(-time.Hour)
	var oldest string
	for i := 0; i < maxScreenshotsPerDev+5; i++ {
		id := f.uploadAll(fmt.Sprintf("s%03d", i), []byte{byte(i), 1, 2}, base.Add(time.Duration(i)*time.Second))
		if i == 0 {
			oldest = id
		}
	}
	var list []proto.ArtifactInfo
	do(t, f.h, "GET", "/v1/admin/projects/demo/devices/"+f.dev.DeviceID+"/artifacts?limit=500", "adm", nil, &list)
	if len(list) != maxScreenshotsPerDev {
		t.Fatalf("kept %d, want %d", len(list), maxScreenshotsPerDev)
	}
	if list[0].CapturedAt.Before(list[len(list)-1].CapturedAt) {
		t.Fatal("listing is not newest first")
	}
	if f.raw("GET", "/v1/admin/projects/demo/artifacts/"+oldest, "adm", nil, nil).Code != 404 {
		t.Fatal("the oldest screenshot should have been pruned")
	}
	if _, err := os.Stat(f.st.binPath(oldest)); !os.IsNotExist(err) {
		t.Fatal("pruned artifact's file still on disk")
	}
}

func TestStaleAndOldDataIsPruned(t *testing.T) {
	f := newFixture(t)
	// an upload that was started two days ago and never finished
	s, _ := f.create(f.dev.DeviceToken, proto.ArtifactInit{ClientID: "stuck", Kind: "screenshot", Size: 10, SHA256: sha(payload(10))})
	f.st.mu.Lock()
	f.st.exec(`UPDATE artifacts SET created_at=? WHERE id=?`, time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339Nano), s.ID)
	f.st.mu.Unlock()
	// a complete screenshot captured three weeks ago
	old := f.uploadAll("ancient", []byte{9, 9, 9}, time.Now().Add(-21*24*time.Hour))

	f.st.Prune()
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	if f.st.getArtifact(s.ID) != nil || f.st.getArtifact(old) != nil {
		t.Fatal("stale upload / expired screenshot survived pruning")
	}
}

func TestRemovingDeviceDeletesItsArtifacts(t *testing.T) {
	f := newFixture(t)
	id := f.uploadAll("gone", payload(500), time.Now())
	if do(t, f.h, "DELETE", "/v1/admin/projects/demo/devices/"+f.dev.DeviceID, "adm", nil, nil) != 204 {
		t.Fatal("delete device")
	}
	if _, err := os.Stat(f.st.binPath(id)); !os.IsNotExist(err) {
		t.Fatal("artifact file survived device removal")
	}
}

func TestPolicyValidationAndFieldLevelMerge(t *testing.T) {
	f := newFixture(t)
	put := func(scope string, doc proto.ConfigDocument) int {
		return do(t, f.h, "PUT", "/v1/admin/projects/demo/config/"+scope, "adm", doc, nil)
	}
	bad := []proto.ConfigDocument{
		{Data: map[string]any{}, Screenshots: map[string]any{"interval": 60}},   // typo: unknown field
		{Data: map[string]any{}, Screenshots: map[string]any{"interval_s": 3}},  // below the floor
		{Data: map[string]any{}, Screenshots: map[string]any{"quality": 101}},   //
		{Data: map[string]any{}, Screenshots: map[string]any{"max_width": 10}},  //
		{Data: map[string]any{}, Budget: map[string]any{"monthly_mb": -5}},      //
		{Data: map[string]any{}, Budget: map[string]any{"reset_day": 31}},       //
		{Data: map[string]any{}, Budget: map[string]any{"soft_pct": 100}},       //
		{Data: map[string]any{}, Budget: map[string]any{"monthly": 100}},        // unknown field
		{Data: map[string]any{}, Screenshots: map[string]any{"enabled": "yes"}}, // wrong type
	}
	for i, d := range bad {
		if code := put("global", d); code != 400 {
			t.Errorf("bad policy #%d accepted (%d): %+v %+v", i, code, d.Screenshots, d.Budget)
		}
	}

	if put("global", proto.ConfigDocument{Data: map[string]any{},
		Screenshots: map[string]any{"enabled": true, "interval_s": 300, "quality": 70},
		Budget:      map[string]any{"monthly_mb": 3000, "reset_day": 15}}) != 200 {
		t.Fatal("valid global policy rejected")
	}
	// A device layer that only changes the interval must not switch screenshots off
	// just because it did not mention "enabled".
	put("device:"+f.dev.DeviceID, proto.ConfigDocument{Data: map[string]any{}, Screenshots: map[string]any{"interval_s": 60}})

	var d proto.DeviceDetail
	do(t, f.h, "GET", "/v1/admin/projects/demo/devices/"+f.dev.DeviceID+"/detail", "adm", nil, &d)
	s, b := d.Effective.Screenshots, d.Effective.Budget
	if s == nil || !s.Enabled || s.IntervalS != 60 || s.Quality != 70 {
		t.Fatalf("screenshots did not merge field by field: %+v", s)
	}
	if b == nil || b.MonthlyMB != 3000 || b.ResetDay != 15 {
		t.Fatalf("budget wrong: %+v", b)
	}
}

func TestCheckinRecordsBudgetState(t *testing.T) {
	f := newFixture(t)
	do(t, f.h, "POST", "/v1/checkin", f.dev.DeviceToken, proto.CheckinRequest{Session: "s", Seq: 1,
		BytesIn: 1_000_000, BytesOut: 2_000_000, BudgetMB: 10, BudgetState: "soft"}, nil)
	var d proto.DeviceDetail
	do(t, f.h, "GET", "/v1/admin/projects/demo/devices/"+f.dev.DeviceID+"/detail", "adm", nil, &d)
	if d.BudgetMB != 10 || d.BudgetState != "soft" || d.BytesIn != 1_000_000 || d.BytesOut != 2_000_000 {
		t.Fatalf("budget not recorded: %+v", d.DeviceSummary)
	}
}
