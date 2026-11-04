package internal_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"remoteconfig/internal/agent"
	"remoteconfig/internal/proto"
	"remoteconfig/internal/server"
)

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func call(t *testing.T, method, url, token string, body any, out any, hdr map[string]string) int {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, url, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode/100 == 2 && resp.StatusCode != 204 && resp.StatusCode != 304 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func readCfg(path string) *proto.EffectiveConfig {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var c proto.EffectiveConfig
	if json.Unmarshal(b, &c) != nil {
		return nil
	}
	return &c
}

func TestEndToEnd(t *testing.T) {
	st, err := server.OpenStore("", "admin-secret")
	if err != nil {
		t.Fatal(err)
	}
	st.Seed("demo", "Demo", &proto.ConfigDocument{Data: map[string]any{"volume": 0.8, "ui": map[string]any{"lang": "en", "debug": false}}})
	enroll := st.NewEnrollToken("demo", []string{"lobby"}, time.Hour)
	ts := httptest.NewServer(server.New(st, server.Options{CheckinInterval: 200 * time.Millisecond}).Handler())
	defer ts.Close()
	admin := ts.URL + "/v1/admin/projects/demo"

	stateDir, outDir, listen := t.TempDir(), t.TempDir(), freeAddr(t)
	a := agent.New(agent.Options{Server: ts.URL, EnrollToken: enroll, StateDir: stateDir, OutDir: outDir, Listen: listen, Interval: 200 * time.Millisecond, Version: "test"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	cfgFile := filepath.Join(outDir, "effective-config.json")

	// 1. enrolls and receives the global config; file written for the app.
	waitFor(t, "initial config file", func() bool { return readCfg(cfgFile) != nil })
	c1 := readCfg(cfgFile)
	if c1.Data["volume"] != 0.8 || c1.Revision != 1 {
		t.Fatalf("unexpected initial config: %+v", c1)
	}

	// 2. a token can't be reused.
	if code := call(t, "POST", ts.URL+"/v1/enroll", "", proto.EnrollRequest{Token: enroll, Hostname: "x"}, nil, nil); code != 401 {
		t.Fatalf("reused enrollment token: want 401 got %d", code)
	}

	// 3. layered config: tag overrides global, deep merge keeps sibling keys.
	call(t, "PUT", admin+"/config/tag:lobby", "admin-secret",
		proto.ConfigDocument{Data: map[string]any{"ui": map[string]any{"lang": "fr"}}}, nil, nil)
	waitFor(t, "revision 2", func() bool { c := readCfg(cfgFile); return c != nil && c.Revision == 2 })
	c2 := readCfg(cfgFile)
	ui := c2.Data["ui"].(map[string]any)
	if ui["lang"] != "fr" || ui["debug"] != false || c2.Data["volume"] != 0.8 {
		t.Fatalf("bad merge: %+v", c2.Data)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "last-known-good.json")); err != nil {
		t.Fatalf("last-known-good not kept: %v", err)
	}

	// 4. local API: token required, ETag/304, status relay.
	local := "http://" + listen
	waitFor(t, "local api", func() bool {
		r, err := http.Get(local + "/healthz")
		if err == nil {
			r.Body.Close()
		}
		return err == nil
	})
	if code := call(t, "GET", local+"/v1/config", "", nil, nil, nil); code != 401 {
		t.Fatalf("local api without token: want 401 got %d", code)
	}
	tok, _ := os.ReadFile(filepath.Join(stateDir, "local-token"))
	var lc proto.EffectiveConfig
	if code := call(t, "GET", local+"/v1/config", string(tok), nil, &lc, nil); code != 200 || lc.Revision != 2 {
		t.Fatalf("local config: code=%d %+v", code, lc)
	}
	if code := call(t, "GET", local+"/v1/config", string(tok), nil, nil, map[string]string{"If-None-Match": `"` + lc.Etag + `"`}); code != 304 {
		t.Fatalf("want 304 got %d", code)
	}
	if code := call(t, "PUT", local+"/v1/status", string(tok), proto.AppStatus{State: "running", Build: "1.0"}, nil, nil); code != 204 {
		t.Fatalf("put status: %d", code)
	}

	// 5. long-poll wakes on change.
	got := make(chan int, 1)
	go func() {
		var c proto.EffectiveConfig
		call(t, "GET", local+"/v1/config?wait=10", string(tok), nil, &c, map[string]string{"If-None-Match": `"` + lc.Etag + `"`})
		got <- c.Revision
	}()
	time.Sleep(100 * time.Millisecond)
	call(t, "PUT", admin+"/config/device:"+a.DeviceID(), "admin-secret",
		proto.ConfigDocument{Data: map[string]any{"volume": 0.3}}, nil, nil)
	select {
	case rev := <-got:
		if rev != 3 {
			t.Fatalf("long-poll revision: %d", rev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll never returned")
	}

	// 6. server sees app heartbeat + in-sync device.
	waitFor(t, "device summary", func() bool {
		var devs []proto.DeviceSummary
		call(t, "GET", admin+"/devices", "admin-secret", nil, &devs, nil)
		return len(devs) == 1 && devs[0].AppState == "running" && devs[0].InSync && devs[0].Reachability == "online"
	})

	// 7. commands: queued, delivered via check-in, result reported.
	var cmd proto.Command
	call(t, "POST", admin+"/devices/"+a.DeviceID()+"/commands", "admin-secret", proto.CommandRequest{Type: "checkin_now"}, &cmd, nil)
	waitFor(t, "command result", func() bool {
		st.Lock()
		defer st.Unlock()
		for _, c := range st.D.Devices[a.DeviceID()].Commands {
			if c.ID == cmd.ID {
				return c.Status == "succeeded"
			}
		}
		return false
	})

	// 8. server outage: agent keeps serving cached config locally.
	ts.Close()
	time.Sleep(600 * time.Millisecond)
	if code := call(t, "GET", local+"/v1/config", string(tok), nil, &lc, nil); code != 200 || lc.Revision != 3 {
		t.Fatalf("offline local config: code=%d rev=%d", code, lc.Revision)
	}
	fmt.Println("e2e ok")
}
