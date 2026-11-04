package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver: no cgo, single static binary

	"remoteconfig/internal/proto"
)

type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type EnrollToken struct {
	Token     string    `json:"token"`
	Project   string    `json:"project"`
	Tags      []string  `json:"tags,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

type Device struct {
	ID           string   `json:"id"`
	Project      string   `json:"project"`
	Name         string   `json:"name"`
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	AgentVersion string   `json:"agent_version"`
	Tags         []string `json:"tags,omitempty"`
	Token        string   `json:"token"`

	EnrolledAt time.Time `json:"enrolled_at"`
	LastSeen   time.Time `json:"last_seen"`
	Session    string    `json:"session"`  // agent run id; seq restarts when it changes
	LastSeq    int64     `json:"last_seq"` // newest check-in seq seen in this session

	ReportedRevision int    `json:"reported_revision"`
	EffRevision      int    `json:"eff_revision"`
	EffEtag          string `json:"eff_etag"`

	App      *proto.AppStatus   `json:"app,omitempty"`
	System   *proto.SystemStats `json:"system,omitempty"`
	Commands []proto.Command    `json:"commands,omitempty"`
	Restarts int                `json:"restarts"` // app restarts reported by the agent, cumulative
	BytesIn  int64              `json:"bytes_in"` // current data-budget cycle, as reported by the agent
	BytesOut int64              `json:"bytes_out"`

	BudgetMB    int    `json:"budget_mb,omitempty"`
	BudgetState string `json:"budget_state,omitempty"`

	Trust *proto.TrustReport `json:"trust,omitempty"` // the agent's own account of its signature checking
}

// Data is the in-memory working set. For a fleet of dozens this is tiny, so reads never
// touch the database; every mutation is written through to SQLite by the save* methods.
// Events and metrics are append-only tables that are only queried from SQL.
//
// Accounts, memberships, sessions and the audit log are deliberately NOT cached: they
// are read from SQLite on every request, so `server user ...` run against the same
// database file takes effect immediately, and a revoked token stops working at once.
type Data struct {
	Projects map[string]*Project
	Tokens   map[string]*EnrollToken
	Devices  map[string]*Device
	Configs  map[string]*proto.ConfigDocument // key: project|scope
}

const (
	maxEventsPerDevice = 1000
	metricsRetention   = 30 * 24 * time.Hour
)

const schema = `
CREATE TABLE IF NOT EXISTS meta     (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens   (token TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices  (id TEXT PRIMARY KEY, project TEXT NOT NULL, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS configs  (key TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	device_id TEXT NOT NULL, ts TEXT NOT NULL, type TEXT NOT NULL,
	level TEXT NOT NULL DEFAULT 'info', message TEXT NOT NULL DEFAULT '', data TEXT
);
CREATE INDEX IF NOT EXISTS events_device ON events(device_id, id DESC);
CREATE TABLE IF NOT EXISTS metrics (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	device_id TEXT NOT NULL, ts TEXT NOT NULL, name TEXT NOT NULL, value REAL NOT NULL, tags TEXT
);
CREATE INDEX IF NOT EXISTS metrics_device_name ON metrics(device_id, name, id DESC);
`

type Store struct {
	mu sync.Mutex // guards D and serialises writes
	db *sql.DB
	D  Data

	closing   chan struct{} // closed by Close
	closeOnce sync.Once

	artifactDir string // where uploaded files live
	tempDir     bool   // artifactDir is a throw-away directory (in-memory store): remove on Close

	dbPath    string // "" for an in-memory store
	signer    *Signer
	signerErr error

	signingPass string

	// changed is closed (and replaced) whenever any config document changes so
	// long-polling GET /config calls wake up.
	changed chan struct{}
}

// OpenStore opens (creating if needed) the SQLite database at path. An empty path
// gives a throw-away in-memory database, handy for tests.
func OpenStore(path, adminToken string) (*Store, error) {
	dsn := "file::memory:"
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		dsn = "file:" + filepath.ToSlash(path) + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(1)" // secure_delete: a deleted secret is overwritten, not left in free pages
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; also keeps ":memory:" a single database
	if _, err := db.Exec(schema + artifactSchema + authSchema + librarySchema + rolloutSchema); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, changed: make(chan struct{}), dbPath: path, closing: make(chan struct{})}
	if path == "" {
		dir, err := os.MkdirTemp("", "rc-artifacts-")
		if err != nil {
			db.Close()
			return nil, err
		}
		s.artifactDir, s.tempDir = dir, true
	} else if err := s.SetArtifactDir(filepath.Join(filepath.Dir(path), "artifacts")); err != nil {
		db.Close()
		return nil, err
	}
	s.D = Data{
		Projects: map[string]*Project{}, Tokens: map[string]*EnrollToken{},
		Devices: map[string]*Device{}, Configs: map[string]*proto.ConfigDocument{},
	}
	if err := s.load(); err != nil {
		db.Close()
		return nil, err
	}
	// A database from before accounts existed kept the one shared admin token in plain text.
	// It becomes an ordinary (hashed) personal access token of a server admin, so scripts
	// that use it keep working, and the plain-text copy is deleted.
	var legacy string
	if err := db.QueryRow(`SELECT v FROM meta WHERE k='admin_token'`).Scan(&legacy); err == nil {
		if legacy != "" {
			if err := s.EnsureLegacyAdminToken(legacy); err != nil {
				db.Close()
				return nil, err
			}
		}
		db.Exec(`DELETE FROM meta WHERE k='admin_token'`)
		db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`) // push the erase into the main file and empty the log
	}
	if adminToken != "" {
		if err := s.EnsureLegacyAdminToken(adminToken); err != nil {
			db.Close()
			return nil, err
		}
	}
	s.Prune()
	return s, nil
}

// Signer returns the server's signing keys, opening (or creating) the key file next to the
// database on first use: <database dir>/signing.json. An in-memory store gets a throw-away key.
func (s *Store) Signer() (*Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signer == nil && s.signerErr == nil {
		path := ""
		if s.dbPath != "" {
			path = filepath.Join(filepath.Dir(s.dbPath), "signing.json")
		}
		s.signer, s.signerErr = OpenSignerWith(path, s.signingPass)
	}
	return s.signer, s.signerErr
}

// SetSigningPassphrase gives the passphrase that seals the signing key on disk. Call it before
// the key is first used (before Signer or SetSigningKeyPath).
func (s *Store) SetSigningPassphrase(pass string) {
	s.mu.Lock()
	s.signingPass = pass
	s.mu.Unlock()
}

// SetSigningKeyPath chooses where the signing key file lives (default: signing.json beside
// the database). Call it before the server starts.
func (s *Store) SetSigningKeyPath(path string) error {
	s.mu.Lock()
	pass := s.signingPass
	s.mu.Unlock()
	sg, err := OpenSignerWith(path, pass)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.signer, s.signerErr = sg, nil
	s.mu.Unlock()
	return nil
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() { close(s.closing) }) // stops background loops before the database goes away
	s.mu.Lock()                                 // and waits for one that is mid-pass
	s.mu.Unlock()
	if s.signer != nil {
		s.signer.Close()
	}
	err := s.db.Close()
	if s.tempDir {
		os.RemoveAll(s.artifactDir)
	}
	return err
}

// SetArtifactDir chooses where uploaded files are stored (default: "artifacts" next to
// the database).
func (s *Store) SetArtifactDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	s.artifactDir, s.tempDir = dir, false
	return nil
}

func (s *Store) load() error {
	rows, err := s.db.Query(`SELECT id, name FROM projects`)
	if err != nil {
		return err
	}
	for rows.Next() {
		p := &Project{}
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			rows.Close()
			return err
		}
		s.D.Projects[p.ID] = p
	}
	rows.Close()

	loadJSON := func(query string, each func(key, js string) error) error {
		rows, err := s.db.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k, js string
			if err := rows.Scan(&k, &js); err != nil {
				return err
			}
			if err := each(k, js); err != nil {
				return err
			}
		}
		return rows.Err()
	}
	if err := loadJSON(`SELECT token, json FROM tokens`, func(k, js string) error {
		t := &EnrollToken{}
		s.D.Tokens[k] = t
		return json.Unmarshal([]byte(js), t)
	}); err != nil {
		return err
	}
	if err := loadJSON(`SELECT id, json FROM devices`, func(k, js string) error {
		d := &Device{}
		s.D.Devices[k] = d
		return json.Unmarshal([]byte(js), d)
	}); err != nil {
		return err
	}
	return loadJSON(`SELECT key, json FROM configs`, func(k, js string) error {
		c := &proto.ConfigDocument{}
		s.D.Configs[k] = c
		return json.Unmarshal([]byte(js), c)
	})
}

// ---------------------------------------------------------------- write-through
// All save* methods expect the caller to hold s.mu. Failures are logged, not returned:
// the in-memory state stays authoritative for the running process.

func (s *Store) exec(q string, args ...any) {
	if _, err := s.db.Exec(q, args...); err != nil {
		log.Printf("store: %v", err)
	}
}

func (s *Store) setMeta(k, v string) {
	s.exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
}

func (s *Store) saveProject(p *Project) {
	s.exec(`INSERT INTO projects(id,name) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name`, p.ID, p.Name)
}

func (s *Store) saveToken(t *EnrollToken) {
	b, _ := json.Marshal(t)
	s.exec(`INSERT INTO tokens(token,json) VALUES(?,?) ON CONFLICT(token) DO UPDATE SET json=excluded.json`, t.Token, string(b))
}

func (s *Store) saveDevice(d *Device) {
	b, _ := json.Marshal(d)
	s.exec(`INSERT INTO devices(id,project,json) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET json=excluded.json`, d.ID, d.Project, string(b))
}

func (s *Store) deleteDevice(id string) {
	rows, err := s.db.Query(`SELECT id FROM artifacts WHERE device_id=?`, id)
	if err == nil {
		var ids []string
		for rows.Next() {
			var aid string
			if rows.Scan(&aid) == nil {
				ids = append(ids, aid)
			}
		}
		rows.Close()
		for _, aid := range ids {
			os.Remove(s.partPath(aid))
			os.Remove(s.binPath(aid))
		}
		s.exec(`DELETE FROM artifacts WHERE device_id=?`, id)
	}
	delete(s.D.Devices, id)
	s.exec(`DELETE FROM devices WHERE id=?`, id)
	s.exec(`DELETE FROM events WHERE device_id=?`, id)
	s.exec(`DELETE FROM metrics WHERE device_id=?`, id)
}

func (s *Store) saveConfig(key string, c *proto.ConfigDocument) {
	b, _ := json.Marshal(c)
	s.exec(`INSERT INTO configs(key,json) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET json=excluded.json`, key, string(b))
}

func (s *Store) deleteConfig(key string) {
	delete(s.D.Configs, key)
	s.exec(`DELETE FROM configs WHERE key=?`, key)
}

func (s *Store) appendEvents(deviceID string, evs []proto.Event) {
	if len(evs) == 0 {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("store: %v", err)
		return
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for _, e := range evs {
		if e.TS.IsZero() {
			e.TS = now
		}
		if e.Level == "" {
			e.Level = "info"
		}
		var data any
		if len(e.Data) > 0 {
			b, _ := json.Marshal(e.Data)
			data = string(b)
		}
		if _, err := tx.Exec(`INSERT INTO events(device_id,ts,type,level,message,data) VALUES(?,?,?,?,?,?)`,
			deviceID, e.TS.UTC().Format(time.RFC3339Nano), e.Type, e.Level, e.Message, data); err != nil {
			log.Printf("store: %v", err)
			return
		}
	}
	// keep only the newest maxEventsPerDevice rows per device
	tx.Exec(`DELETE FROM events WHERE device_id=? AND id <= COALESCE((SELECT id FROM events WHERE device_id=? ORDER BY id DESC LIMIT 1 OFFSET ?), 0)`,
		deviceID, deviceID, maxEventsPerDevice)
	if err := tx.Commit(); err != nil {
		log.Printf("store: %v", err)
	}
}

// ListEvents returns a device's newest events first.
func (s *Store) listEvents(deviceID string, limit int) []proto.Event {
	rows, err := s.db.Query(`SELECT ts,type,level,message,data FROM events WHERE device_id=? ORDER BY id DESC LIMIT ?`, deviceID, limit)
	if err != nil {
		log.Printf("store: %v", err)
		return nil
	}
	defer rows.Close()
	out := []proto.Event{}
	for rows.Next() {
		var ts, typ, lvl, msg string
		var data sql.NullString
		if rows.Scan(&ts, &typ, &lvl, &msg, &data) != nil {
			continue
		}
		e := proto.Event{Type: typ, Level: lvl, Message: msg}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		if data.Valid {
			json.Unmarshal([]byte(data.String), &e.Data)
		}
		out = append(out, e)
	}
	return out
}

func (s *Store) appendMetrics(deviceID string, ms []proto.Metric) {
	if len(ms) == 0 {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("store: %v", err)
		return
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for _, m := range ms {
		if m.TS.IsZero() {
			m.TS = now
		}
		var tags any
		if len(m.Tags) > 0 {
			b, _ := json.Marshal(m.Tags)
			tags = string(b)
		}
		if _, err := tx.Exec(`INSERT INTO metrics(device_id,ts,name,value,tags) VALUES(?,?,?,?,?)`,
			deviceID, m.TS.UTC().Format(time.RFC3339Nano), m.Name, m.Value, tags); err != nil {
			log.Printf("store: %v", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("store: %v", err)
	}
}

// latestMetrics returns the newest value of each metric name for a device.
func (s *Store) latestMetrics(deviceID string) map[string]float64 {
	out := map[string]float64{}
	rows, err := s.db.Query(`SELECT name, value FROM metrics WHERE id IN (SELECT MAX(id) FROM metrics WHERE device_id=? GROUP BY name)`, deviceID)
	if err != nil {
		log.Printf("store: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		var v float64
		if rows.Scan(&n, &v) == nil {
			out[n] = v
		}
	}
	return out
}

// metricSeries returns up to limit points of one metric, oldest first.
func (s *Store) metricSeries(deviceID, name string, limit int) []proto.Metric {
	rows, err := s.db.Query(`SELECT ts, value FROM (SELECT id,ts,value FROM metrics WHERE device_id=? AND name=? ORDER BY id DESC LIMIT ?) ORDER BY id`, deviceID, name, limit)
	if err != nil {
		log.Printf("store: %v", err)
		return nil
	}
	defer rows.Close()
	out := []proto.Metric{}
	for rows.Next() {
		var ts string
		m := proto.Metric{Name: name}
		if rows.Scan(&ts, &m.Value) == nil {
			m.TS, _ = time.Parse(time.RFC3339Nano, ts)
			out = append(out, m)
		}
	}
	return out
}

// Prune drops expired data. Call at startup and periodically.
func (s *Store) Prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().Add(-metricsRetention).UTC().Format(time.RFC3339Nano)
	s.exec(`DELETE FROM metrics WHERE ts < ?`, cut)
	s.pruneArtifacts("")
	s.pruneAuth()
	s.exec(`DELETE FROM tokens WHERE json_extract(json,'$.used') = 1 OR json_extract(json,'$.expires_at') < ?`, time.Now().UTC().Format(time.RFC3339Nano))
	// Mirror the token deletion in memory.
	for k, t := range s.D.Tokens {
		if t.Used || time.Now().After(t.ExpiresAt) {
			delete(s.D.Tokens, k)
		}
	}
}

// Lock/Unlock expose the store mutex for tests and tooling that read D directly.
func (s *Store) Lock()   { s.mu.Lock() }
func (s *Store) Unlock() { s.mu.Unlock() }

// Seed ensures a project and its global config exist (used by -dev-seed).
func (s *Store) Seed(id, name string, global *proto.ConfigDocument) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.D.Projects[id]; !ok {
		p := &Project{ID: id, Name: name}
		s.D.Projects[id] = p
		s.saveProject(p)
	}
	if _, ok := s.D.Configs[id+"|global"]; !ok {
		s.D.Configs[id+"|global"] = global
		s.saveConfig(id+"|global", global)
	}
}

func (s *Store) NewEnrollToken(project string, tags []string, ttl time.Duration) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &EnrollToken{Token: NewToken(12), Project: project, Tags: tags, ExpiresAt: time.Now().Add(ttl).UTC()}
	s.D.Tokens[t.Token] = t
	s.saveToken(t)
	return t.Token
}

func (s *Store) notifyChanged() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func NewToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
