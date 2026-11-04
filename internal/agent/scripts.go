package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"remoteconfig/internal/proto"
)

// Scripts: the server's library, run on this machine. What runs is exactly the bytes whose
// SHA-256 is in the signed command; the fetch itself needs no trust, because a wrong byte
// fails the hash. A script is never run by an agent that does not verify signatures.

const (
	maxScriptOutput = 32 << 10
	maxScriptBytes  = 256 << 10
)

var scriptMu sync.Mutex // one script at a time: they are maintenance jobs, not a workload

// asyncCommands are the long-running ones. runCommand starts them and returns at once, so a
// 10-minute script or a 500 MB download never stalls check-ins or the supervisor; the result
// is reported when they finish.
func (a *Agent) startAsync(ctx context.Context, c proto.Command, fn func(context.Context, proto.Command) proto.CommandResult) {
	a.mu.Lock()
	if a.running == nil {
		a.running = map[string]bool{}
	}
	a.running[c.ID] = true
	a.mu.Unlock()
	go func() {
		res := fn(a.runCtx, c)
		a.mu.Lock()
		delete(a.running, c.ID)
		a.mu.Unlock()
		a.logf("command %s (%s): ok=%v", c.ID, c.Type, res.OK)
		// The check-in context may be long gone; the result matters more than prompt delivery.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(a.runCtx), 2*time.Minute)
		defer cancel()
		for i := 0; i < 5; i++ {
			if st, err := a.server(rctx, http.MethodPost, "/v1/commands/"+c.ID+"/result", res, nil, nil); err == nil && st/100 == 2 {
				a.exitIfUpdating()
				return
			}
			select {
			case <-rctx.Done():
				return
			case <-time.After(time.Duration(i+1) * 5 * time.Second):
			}
		}
	}()
}

func (a *Agent) isRunning(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running[id]
}

// getBytes fetches a small file from the server (scripts).
func (a *Agent) getBytes(ctx context.Context, path string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.id.Server, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.id.DeviceToken)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server answered HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("larger than allowed")
	}
	return b, nil
}

func str(p map[string]any, k string) string { s, _ := p[k].(string); return s }
func num(p map[string]any, k string) int    { f, _ := p[k].(float64); return int(f) }

// cappedBuffer keeps the start and the end of a long output, which is where the interesting
// lines usually are, and counts what it dropped.
type cappedBuffer struct {
	mu      sync.Mutex
	head    bytes.Buffer
	tail    []byte
	dropped int64
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	half := maxScriptOutput / 2
	if room := half - b.head.Len(); room > 0 {
		k := min(room, len(p))
		b.head.Write(p[:k])
		p = p[k:]
	}
	if len(p) > 0 {
		b.tail = append(b.tail, p...)
		if over := len(b.tail) - half; over > 0 {
			b.dropped += int64(over)
			b.tail = b.tail[over:]
		}
	}
	return n, nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := strings.ToValidUTF8(b.head.String(), "?")
	if b.dropped > 0 {
		s += fmt.Sprintf("\n... %d bytes omitted ...\n", b.dropped)
	}
	return s + strings.ToValidUTF8(string(b.tail), "?")
}
