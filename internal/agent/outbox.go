package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// outbox is the on-disk queue of artifacts waiting to be uploaded. It survives agent
// restarts and long offline stretches. Each item is <client_id>.dat (the bytes) plus
// <client_id>.json (metadata); the .json is written last, so an item only exists once
// both are complete.
type outbox struct {
	dir string
	mu  sync.Mutex
}

type outboxItem struct {
	ClientID    string         `json:"client_id"`
	Kind        string         `json:"kind"`
	ContentType string         `json:"content_type"`
	Size        int64          `json:"size"`
	SHA256      string         `json:"sha256"`
	CapturedAt  time.Time      `json:"captured_at"`
	Meta        map[string]any `json:"meta,omitempty"`
}

const (
	outboxMaxItems = 40
	outboxMaxBytes = 40 << 20
)

func newOutbox(dir string) *outbox { return &outbox{dir: dir} }

func (o *outbox) dataPath(id string) string { return filepath.Join(o.dir, id+".dat") }
func (o *outbox) metaPath(id string) string { return filepath.Join(o.dir, id+".json") }

func (o *outbox) add(it outboxItem, data []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := os.MkdirAll(o.dir, 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(o.dataPath(it.ClientID), data); err != nil {
		return err
	}
	meta, _ := json.Marshal(it)
	return writeFileAtomic(o.metaPath(it.ClientID), meta)
}

// list returns queued items, newest capture first: after an outage the freshest
// screenshot matters most, so it goes out before older ones.
func (o *outbox) list() []outboxItem {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.listLocked()
}

func (o *outbox) listLocked() []outboxItem {
	entries, _ := os.ReadDir(o.dir)
	var items []outboxItem
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(o.dir, e.Name()))
		if err != nil {
			continue
		}
		var it outboxItem
		if json.Unmarshal(b, &it) != nil || it.ClientID == "" {
			continue
		}
		if _, err := os.Stat(o.dataPath(it.ClientID)); err != nil {
			os.Remove(o.metaPath(it.ClientID)) // orphaned metadata
			continue
		}
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CapturedAt.After(items[j].CapturedAt) })
	return items
}

func (o *outbox) remove(id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	os.Remove(o.metaPath(id))
	os.Remove(o.dataPath(id))
}

// enforceCaps drops the oldest items until the queue fits, and returns how many went.
func (o *outbox) enforceCaps() (dropped int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	items := o.listLocked() // newest first
	var total int64
	for i, it := range items {
		total += it.Size
		if i >= outboxMaxItems || total > outboxMaxBytes {
			os.Remove(o.metaPath(it.ClientID))
			os.Remove(o.dataPath(it.ClientID))
			dropped++
		}
	}
	return dropped
}

func (o *outbox) read(id string) ([]byte, error) { return os.ReadFile(o.dataPath(id)) }
