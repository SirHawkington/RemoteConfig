// Command testapp is a stand-in for a supervised app, used by the supervisor tests and
// for manual experiments. It heartbeats to the local agent API like the Unity SDK does.
//
//	testapp -crash-after 2s     exit(3) after 2s
//	testapp -hang-after 2s      go completely silent after 2s but keep running (a frozen app)
//	testapp -log run.log        append a line per start, so tests can count launches
//	testapp -ignore-quit        keep running when asked to quit (a misbehaving app)
//	testapp -lifecycle=false    do not poll for quit requests (an app without the SDK)
//	testapp -window             also open a (minimised) window that exits on WM_CLOSE (Windows)
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	frozen  atomic.Bool
	logPath string
	logMu   sync.Mutex
)

func logf(format string, a ...any) {
	if logPath == "" {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, format+"\n", a...)
		f.Close()
	}
}

func main() {
	crashAfter := flag.Duration("crash-after", 0, "exit with code 3 after this long")
	hangAfter := flag.Duration("hang-after", 0, "stop responding after this long")
	every := flag.Duration("every", 200*time.Millisecond, "heartbeat interval")
	ignoreQuit := flag.Bool("ignore-quit", false, "ignore quit requests")
	lifecycle := flag.Bool("lifecycle", true, "poll the agent for quit requests, like the SDK does")
	window := flag.Bool("window", false, "open a window that closes on WM_CLOSE")
	flag.StringVar(&logPath, "log", "", "append a line on start")
	flag.Parse()

	logf("start pid=%d", os.Getpid())
	base, token := os.Getenv("REMOTECONFIG_URL"), os.Getenv("REMOTECONFIG_TOKEN")

	if *window {
		go runWindow()
	}
	if *lifecycle && base != "" {
		go pollLifecycle(base, token, *ignoreQuit)
	}

	start := time.Now()
	for {
		el := time.Since(start)
		if *crashAfter > 0 && el > *crashAfter {
			os.Exit(3)
		}
		if *hangAfter > 0 && el > *hangAfter {
			frozen.Store(true) // a frozen process answers nothing, quit requests included
			select {}
		}
		body := fmt.Sprintf(`{"state":"running","uptime_s":%d,"build":"testapp"}`, int(el.Seconds()))
		req, _ := http.NewRequest(http.MethodPut, base+"/status", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
		time.Sleep(*every)
	}
}

// pollLifecycle is what the Unity SDK does: long-poll the agent; when it says quit, save
// state and exit.
func pollLifecycle(base, token string, ignore bool) {
	client := &http.Client{Timeout: 40 * time.Second}
	for !frozen.Load() {
		req, _ := http.NewRequest(http.MethodGet, base+"/lifecycle?wait=20", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		var msg struct {
			Action string `json:"action"`
			Reason string `json:"reason"`
		}
		if resp.StatusCode == http.StatusOK {
			json.NewDecoder(resp.Body).Decode(&msg)
		}
		resp.Body.Close()
		if msg.Action == "quit" && !frozen.Load() {
			logf("quit requested: %s", msg.Reason)
			if !ignore {
				os.Exit(0)
			}
			logf("ignoring the quit request")
			time.Sleep(300 * time.Millisecond)
		}
	}
}
