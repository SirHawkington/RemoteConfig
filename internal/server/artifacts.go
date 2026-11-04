package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"remoteconfig/internal/proto"
)

const (
	maxArtifactBytes       = 25 << 20 // per artifact
	maxChunkBytes          = 1 << 20  // per PATCH
	maxOpenUploadsPerDev   = 50
	maxScreenshotsPerDev   = 200
	screenshotRetention    = 14 * 24 * time.Hour
	incompleteUploadMaxAge = 24 * time.Hour
)

const artifactSchema = `
CREATE TABLE IF NOT EXISTS artifacts (
	id TEXT PRIMARY KEY,
	device_id TEXT NOT NULL,
	client_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	content_type TEXT NOT NULL,
	size INTEGER NOT NULL,
	received INTEGER NOT NULL DEFAULT 0,
	sha256 TEXT NOT NULL,
	captured_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	complete INTEGER NOT NULL DEFAULT 0,
	meta TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS artifacts_client ON artifacts(device_id, client_id);
CREATE INDEX IF NOT EXISTS artifacts_device ON artifacts(device_id, complete, captured_at DESC);
`

// Artifact bytes live as files under the store's artifact directory: <id>.part while an
// upload is in progress, <id>.bin once complete and checksum-verified. (A pluggable blob
// store, e.g. S3, would replace these file operations; nothing else depends on them.)

type artifactRow struct {
	ID, DeviceID, ClientID, Kind, ContentType, SHA256 string
	Size, Received                                    int64
	CapturedAt, CreatedAt                             time.Time
	Complete                                          bool
	Meta                                              map[string]any
}

func (s *Store) partPath(id string) string { return filepath.Join(s.artifactDir, id+".part") }
func (s *Store) binPath(id string) string  { return filepath.Join(s.artifactDir, id+".bin") }

const artifactCols = `id,device_id,client_id,kind,content_type,size,received,sha256,captured_at,created_at,complete,meta`

func scanArtifact(sc interface{ Scan(...any) error }) (*artifactRow, error) {
	var a artifactRow
	var cap, created string
	var complete int
	var meta sql.NullString
	if err := sc.Scan(&a.ID, &a.DeviceID, &a.ClientID, &a.Kind, &a.ContentType, &a.Size, &a.Received, &a.SHA256, &cap, &created, &complete, &meta); err != nil {
		return nil, err
	}
	a.CapturedAt, _ = time.Parse(time.RFC3339Nano, cap)
	a.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	a.Complete = complete == 1
	if meta.Valid {
		json.Unmarshal([]byte(meta.String), &a.Meta)
	}
	return &a, nil
}

// getArtifact returns nil if there is no such artifact. Caller holds s.mu.
func (s *Store) getArtifact(id string) *artifactRow {
	a, err := scanArtifact(s.db.QueryRow(`SELECT `+artifactCols+` FROM artifacts WHERE id=?`, id))
	if err != nil {
		return nil
	}
	return a
}

func (s *Store) artifactByClient(deviceID, clientID string) *artifactRow {
	a, err := scanArtifact(s.db.QueryRow(`SELECT `+artifactCols+` FROM artifacts WHERE device_id=? AND client_id=?`, deviceID, clientID))
	if err != nil {
		return nil
	}
	return a
}

func (s *Store) removeArtifact(a *artifactRow) {
	os.Remove(s.partPath(a.ID))
	os.Remove(s.binPath(a.ID))
	s.exec(`DELETE FROM artifacts WHERE id=?`, a.ID)
}

// listArtifacts returns a device's complete artifacts of a kind, newest capture first.
func (s *Store) listArtifacts(deviceID, kind string, limit int) []proto.ArtifactInfo {
	q := `SELECT ` + artifactCols + ` FROM artifacts WHERE device_id=? AND complete=1`
	args := []any{deviceID}
	if kind != "" {
		q += ` AND kind=?`
		args = append(args, kind)
	}
	q += ` ORDER BY captured_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		log.Printf("store: %v", err)
		return nil
	}
	defer rows.Close()
	out := []proto.ArtifactInfo{}
	for rows.Next() {
		if a, err := scanArtifact(rows); err == nil {
			out = append(out, proto.ArtifactInfo{ID: a.ID, Kind: a.Kind, Size: a.Size, ContentType: a.ContentType,
				CapturedAt: a.CapturedAt, CreatedAt: a.CreatedAt, Meta: a.Meta})
		}
	}
	return out
}

// pruneArtifacts enforces retention for one device (or all devices when deviceID is "").
// Caller holds s.mu.
func (s *Store) pruneArtifacts(deviceID string) {
	now := time.Now().UTC()
	where, args := ``, []any{}
	if deviceID != "" {
		where, args = ` AND device_id=?`, []any{deviceID}
	}
	collect := func(q string, a ...any) []*artifactRow {
		rows, err := s.db.Query(q, a...)
		if err != nil {
			return nil
		}
		defer rows.Close()
		var out []*artifactRow
		for rows.Next() {
			if r, err := scanArtifact(rows); err == nil {
				out = append(out, r)
			}
		}
		return out
	}
	// uploads that never finished
	for _, a := range collect(`SELECT `+artifactCols+` FROM artifacts WHERE complete=0 AND created_at < ?`+where,
		append([]any{now.Add(-incompleteUploadMaxAge).Format(time.RFC3339Nano)}, args...)...) {
		s.removeArtifact(a)
	}
	// old screenshots
	for _, a := range collect(`SELECT `+artifactCols+` FROM artifacts WHERE complete=1 AND kind='screenshot' AND captured_at < ?`+where,
		append([]any{now.Add(-screenshotRetention).Format(time.RFC3339Nano)}, args...)...) {
		s.removeArtifact(a)
	}
	// more than the per-device cap: keep the newest
	devs := []string{deviceID}
	if deviceID == "" {
		devs = devs[:0]
		for id := range s.D.Devices {
			devs = append(devs, id)
		}
	}
	for _, d := range devs {
		for _, a := range collect(`SELECT `+artifactCols+` FROM artifacts WHERE device_id=? AND complete=1 AND kind='screenshot' ORDER BY captured_at DESC, id DESC LIMIT -1 OFFSET ?`, d, maxScreenshotsPerDev) {
			s.removeArtifact(a)
		}
	}
}

// ---------------------------------------------------------------- device API

func (s *Server) createArtifact(w http.ResponseWriter, r *http.Request, dev *Device) {
	var in proto.ArtifactInit
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	switch {
	case in.ClientID == "" || len(in.ClientID) > 64:
		writeErr(w, http.StatusBadRequest, "client_id required (max 64 chars)")
		return
	case in.Kind != "screenshot" && in.Kind != "log" && in.Kind != "other":
		writeErr(w, http.StatusBadRequest, "kind must be screenshot, log or other")
		return
	case in.Size <= 0:
		writeErr(w, http.StatusBadRequest, "size required")
		return
	case in.Size > maxArtifactBytes:
		writeErr(w, http.StatusRequestEntityTooLarge, "artifact too large")
		return
	case len(in.SHA256) != 64:
		writeErr(w, http.StatusBadRequest, "sha256 (64 hex chars) required")
		return
	}
	if _, err := hex.DecodeString(in.SHA256); err != nil {
		writeErr(w, http.StatusBadRequest, "sha256 must be hex")
		return
	}
	if in.ContentType == "" {
		in.ContentType = "application/octet-stream"
	}
	if in.CapturedAt.IsZero() {
		in.CapturedAt = time.Now()
	}

	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	// Idempotent: a retry after a lost response gets the same session and offset back.
	if a := s.st.artifactByClient(dev.ID, in.ClientID); a != nil {
		writeJSON(w, http.StatusOK, proto.ArtifactSession{ID: a.ID, Offset: a.Received, Complete: a.Complete})
		return
	}
	var open int
	s.st.db.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE device_id=? AND complete=0`, dev.ID).Scan(&open)
	if open >= maxOpenUploadsPerDev {
		writeErr(w, http.StatusTooManyRequests, "too many unfinished uploads")
		return
	}
	id := "art_" + NewToken(8)
	if err := os.WriteFile(s.st.partPath(id), nil, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, "storage unavailable")
		return
	}
	meta, _ := json.Marshal(in.Meta)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.st.db.Exec(`INSERT INTO artifacts(`+artifactCols+`) VALUES(?,?,?,?,?,?,0,?,?,?,0,?)`,
		id, dev.ID, in.ClientID, in.Kind, in.ContentType, in.Size, strings.ToLower(in.SHA256),
		in.CapturedAt.UTC().Format(time.RFC3339Nano), now, string(meta)); err != nil {
		os.Remove(s.st.partPath(id))
		writeErr(w, http.StatusInternalServerError, "could not record upload")
		return
	}
	writeJSON(w, http.StatusCreated, proto.ArtifactSession{ID: id, Offset: 0})
}

// ownedArtifact loads an artifact that belongs to dev. Caller holds s.st.mu.
func (s *Server) ownedArtifact(w http.ResponseWriter, r *http.Request, dev *Device) *artifactRow {
	a := s.st.getArtifact(r.PathValue("id"))
	if a == nil || a.DeviceID != dev.ID {
		writeErr(w, http.StatusNotFound, "no such upload")
		return nil
	}
	return a
}

func (s *Server) headArtifact(w http.ResponseWriter, r *http.Request, dev *Device) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	a := s.ownedArtifact(w, r, dev)
	if a == nil {
		return
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(a.Received, 10))
	w.Header().Set("Upload-Complete", strconv.FormatBool(a.Complete))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) patchArtifact(w http.ResponseWriter, r *http.Request, dev *Device) {
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || offset < 0 {
		writeErr(w, http.StatusBadRequest, "Upload-Offset header required")
		return
	}
	// Read the body before taking the store lock: a slow link must not block the server.
	chunk, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxChunkBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "chunk too large")
		} else {
			writeErr(w, http.StatusBadRequest, "body not received: "+err.Error())
		}
		return
	}

	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	a := s.ownedArtifact(w, r, dev)
	if a == nil {
		return
	}
	setOffset := func(v int64) { w.Header().Set("Upload-Offset", strconv.FormatInt(v, 10)) }

	if a.Complete { // a retry of the final chunk after its response was lost
		setOffset(a.Size)
		w.Header().Set("Upload-Complete", "true")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if offset != a.Received { // the client is out of step: tell it where we are
		setOffset(a.Received)
		writeErr(w, http.StatusConflict, "offset mismatch")
		return
	}
	if a.Received+int64(len(chunk)) > a.Size {
		writeErr(w, http.StatusRequestEntityTooLarge, "chunk runs past the declared size")
		return
	}

	f, err := os.OpenFile(s.st.partPath(a.ID), os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "storage unavailable")
		return
	}
	// Truncate to the recorded offset first: a previous write may have landed on disk
	// without its database update (crash in between), and we must not append after junk.
	if err := f.Truncate(a.Received); err == nil {
		_, err = f.WriteAt(chunk, a.Received)
	}
	f.Close()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "storage write failed")
		return
	}
	a.Received += int64(len(chunk))
	s.st.exec(`UPDATE artifacts SET received=? WHERE id=?`, a.Received, a.ID)
	setOffset(a.Received)

	if a.Received < a.Size {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Last byte in: verify the whole file before accepting it.
	sum, err := fileSHA256(s.st.partPath(a.ID))
	if err != nil || sum != a.SHA256 {
		s.st.removeArtifact(a)
		writeErr(w, http.StatusUnprocessableEntity, "checksum mismatch")
		return
	}
	if err := os.Rename(s.st.partPath(a.ID), s.st.binPath(a.ID)); err != nil {
		writeErr(w, http.StatusInternalServerError, "storage rename failed")
		return
	}
	s.st.exec(`UPDATE artifacts SET complete=1 WHERE id=?`, a.ID)
	s.st.pruneArtifacts(dev.ID)
	w.Header().Set("Upload-Complete", "true")
	w.WriteHeader(http.StatusNoContent)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---------------------------------------------------------------- admin API

func (s *Server) listDeviceArtifacts(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 60
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	writeJSON(w, http.StatusOK, s.st.listArtifacts(d.ID, r.URL.Query().Get("kind"), limit))
}

// adminArtifact loads an artifact that belongs to the URL's project. Caller holds s.st.mu.
func (s *Server) adminArtifact(w http.ResponseWriter, r *http.Request) *artifactRow {
	a := s.st.getArtifact(r.PathValue("id"))
	if a != nil {
		if d, ok := s.st.D.Devices[a.DeviceID]; ok && d.Project == r.PathValue("project") && a.Complete {
			return a
		}
	}
	writeErr(w, http.StatusNotFound, "no such artifact")
	return nil
}

func (s *Server) getArtifactFile(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	a := s.adminArtifact(w, r)
	var path string
	if a != nil {
		path = s.st.binPath(a.ID)
	}
	s.st.mu.Unlock()
	if a == nil {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "file missing")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Artifacts are immutable, so the browser may keep them; "private" keeps proxies out.
	w.Header().Set("Cache-Control", "private, max-age=86400, immutable")
	http.ServeContent(w, r, "", a.CapturedAt, f)
}

func (s *Server) deleteArtifact(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	a := s.adminArtifact(w, r)
	if a == nil {
		return
	}
	s.st.removeArtifact(a)
	s.audit(r, "artifact.deleted", r.PathValue("project"), a.ID, a.Kind)
	w.WriteHeader(http.StatusNoContent)
}
