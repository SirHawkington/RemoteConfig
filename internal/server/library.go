package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"remoteconfig/internal/proto"
)

// The script library and the release store. Both are immutable once uploaded and are
// referred to by content hash: the signed command that tells a device to run a script or apply
// a release carries the hash, so the server cannot be tricked (and the network cannot trick the
// agent) into running anything other than what an administrator uploaded.

const (
	maxScriptBytes  = 256 << 10
	maxReleaseBytes = 2 << 30
	maxScriptArgs   = 16
	maxScriptArgLen = 1024
)

const librarySchema = `
CREATE TABLE IF NOT EXISTS scripts (
	id TEXT PRIMARY KEY,
	project TEXT NOT NULL,
	name TEXT NOT NULL,
	version INTEGER NOT NULL,
	interpreter TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	timeout_s INTEGER NOT NULL,
	sha256 TEXT NOT NULL,
	content BLOB NOT NULL,
	created_at TEXT NOT NULL,
	created_by TEXT NOT NULL DEFAULT '',
	UNIQUE(project, name, version)
);
CREATE TABLE IF NOT EXISTS releases (
	id TEXT PRIMARY KEY,
	project TEXT NOT NULL,
	kind TEXT NOT NULL,
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	os TEXT NOT NULL,
	arch TEXT NOT NULL,
	size INTEGER NOT NULL,
	sha256 TEXT NOT NULL,
	notes TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	created_by TEXT NOT NULL DEFAULT '',
	UNIQUE(project, kind, name, version, os, arch)
);
`

var (
	nameRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$`)
)

// interpreters an agent is willing to run; anything else is refused at upload, not at run time.
var scriptInterpreters = map[string]bool{"powershell": true, "cmd": true, "bash": true, "sh": true, "python": true}

func (s *Store) releasePath(id string) string { return filepath.Join(s.artifactDir, id+".rel") }

func userName(r *http.Request) string {
	if p := principalOf(r); p != nil && p.User != nil {
		return p.User.Username
	}
	return ""
}

// ---------------------------------------------------------------- scripts

const scriptCols = `id,project,name,version,interpreter,description,timeout_s,sha256,length(content),created_at,created_by`

func scanScript(sc interface{ Scan(...any) error }) (proto.ScriptInfo, error) {
	var x proto.ScriptInfo
	var created string
	err := sc.Scan(&x.ID, &x.Project, &x.Name, &x.Version, &x.Interpreter, &x.Description, &x.TimeoutS, &x.SHA256, &x.Size, &created, &x.CreatedBy)
	x.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return x, err
}

// scriptsFor lists a project's scripts, newest version of each name first. Caller holds s.mu.
func (s *Store) scriptsFor(project string) []proto.ScriptInfo {
	rows, err := s.db.Query(`SELECT `+scriptCols+` FROM scripts WHERE project=? ORDER BY name, version DESC`, project)
	out := []proto.ScriptInfo{}
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		if x, err := scanScript(rows); err == nil {
			out = append(out, x)
		}
	}
	return out
}

func (s *Server) listScripts(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	writeJSON(w, http.StatusOK, s.st.scriptsFor(r.PathValue("project")))
}

func (s *Server) createScript(w http.ResponseWriter, r *http.Request) {
	var in proto.ScriptCreate
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	switch {
	case !nameRE.MatchString(in.Name):
		writeErr(w, http.StatusBadRequest, "name: letters, digits, . _ - (max 64)")
		return
	case !scriptInterpreters[in.Interpreter]:
		writeErr(w, http.StatusBadRequest, "interpreter must be one of powershell, cmd, bash, sh, python")
		return
	case strings.TrimSpace(in.Content) == "":
		writeErr(w, http.StatusBadRequest, "content required")
		return
	case len(in.Content) > maxScriptBytes:
		writeErr(w, http.StatusRequestEntityTooLarge, "script too large (256 KB max)")
		return
	}
	if in.TimeoutS <= 0 {
		in.TimeoutS = 120
	}
	if in.TimeoutS > 3600 {
		writeErr(w, http.StatusBadRequest, "timeout_s: 3600 at most")
		return
	}
	sum := sha256.Sum256([]byte(in.Content))
	project := r.PathValue("project")

	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	var latest sql.NullInt64
	s.st.db.QueryRow(`SELECT MAX(version) FROM scripts WHERE project=? AND name=?`, project, in.Name).Scan(&latest)
	id := "scr_" + NewToken(6)
	ver := int(latest.Int64) + 1
	if _, err := s.st.db.Exec(`INSERT INTO scripts(id,project,name,version,interpreter,description,timeout_s,sha256,content,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		id, project, in.Name, ver, in.Interpreter, in.Description, in.TimeoutS, hex.EncodeToString(sum[:]), []byte(in.Content),
		time.Now().UTC().Format(time.RFC3339Nano), userName(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store the script")
		return
	}
	s.audit(r, "script.created", project, in.Name, fmt.Sprintf("v%d %s", ver, in.Interpreter))
	x, _ := scanScript(s.st.db.QueryRow(`SELECT `+scriptCols+` FROM scripts WHERE id=?`, id))
	writeJSON(w, http.StatusCreated, x)
}

func (s *Server) getScriptContent(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	var body []byte
	err := s.st.db.QueryRow(`SELECT content FROM scripts WHERE id=? AND project=?`, r.PathValue("id"), r.PathValue("project")).Scan(&body)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such script")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(body)
}

func (s *Server) deleteScript(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	res, err := s.st.db.Exec(`DELETE FROM scripts WHERE id=? AND project=?`, r.PathValue("id"), r.PathValue("project"))
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		writeErr(w, http.StatusNotFound, "no such script")
		return
	}
	s.audit(r, "script.deleted", r.PathValue("project"), r.PathValue("id"), "")
	w.WriteHeader(http.StatusNoContent)
}

// deviceScript is what an agent fetches to run a script: the bytes only, from its own project.
// The agent compares their hash with the one in its signed command.
func (s *Server) deviceScript(w http.ResponseWriter, r *http.Request, dev *Device) {
	s.st.mu.Lock()
	var body []byte
	err := s.st.db.QueryRow(`SELECT content FROM scripts WHERE id=? AND project=?`, r.PathValue("id"), dev.Project).Scan(&body)
	s.st.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such script")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(body)
}

// resolveRunScript turns an operator's request ({script: name or id, version?, args?}) into the
// parameters that get signed. The hash comes from the library, never from the request.
// Caller holds s.st.mu.
func (s *Server) resolveRunScript(project string, in map[string]any) (map[string]any, error) {
	ref, _ := in["script"].(string)
	if ref == "" {
		return nil, fmt.Errorf("script required (a library name or id)")
	}
	q := `SELECT ` + scriptCols + ` FROM scripts WHERE project=? AND (id=? OR name=?) ORDER BY version DESC`
	args := []any{project, ref, ref}
	if v, ok := in["version"].(float64); ok && v >= 1 {
		q = `SELECT ` + scriptCols + ` FROM scripts WHERE project=? AND (id=? OR name=?) AND version=?`
		args = append(args, int(v))
	}
	x, err := scanScript(s.st.db.QueryRow(q+` LIMIT 1`, args...))
	if err != nil {
		return nil, fmt.Errorf("no such script %q in this project", ref)
	}
	var argv []string
	if raw, ok := in["args"].([]any); ok {
		if len(raw) > maxScriptArgs {
			return nil, fmt.Errorf("at most %d arguments", maxScriptArgs)
		}
		for _, a := range raw {
			str, ok := a.(string)
			if !ok || len(str) > maxScriptArgLen || strings.ContainsRune(str, 0) {
				return nil, fmt.Errorf("arguments must be text of at most %d bytes", maxScriptArgLen)
			}
			argv = append(argv, str)
		}
	}
	return map[string]any{
		"script_id": x.ID, "name": x.Name, "version": x.Version, "interpreter": x.Interpreter,
		"sha256": x.SHA256, "size": x.Size, "timeout_s": x.TimeoutS, "args": argv,
	}, nil
}

// ---------------------------------------------------------------- releases

const releaseCols = `id,project,kind,name,version,os,arch,size,sha256,notes,created_at,created_by`

func scanRelease(sc interface{ Scan(...any) error }) (proto.ReleaseInfo, error) {
	var x proto.ReleaseInfo
	var created string
	err := sc.Scan(&x.ID, &x.Project, &x.Kind, &x.Name, &x.Version, &x.OS, &x.Arch, &x.Size, &x.SHA256, &x.Notes, &created, &x.CreatedBy)
	x.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return x, err
}

func (s *Store) releaseByID(project, id string) (proto.ReleaseInfo, bool) {
	x, err := scanRelease(s.db.QueryRow(`SELECT `+releaseCols+` FROM releases WHERE id=? AND project=?`, id, project))
	return x, err == nil
}

func (s *Server) listReleases(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	out := []proto.ReleaseInfo{}
	rows, err := s.st.db.Query(`SELECT `+releaseCols+` FROM releases WHERE project=? ORDER BY created_at DESC`, r.PathValue("project"))
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			if x, err := scanRelease(rows); err == nil {
				out = append(out, x)
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// createRelease takes the file as the request body and the description as query parameters, so
// a build of a gigabyte streams to disk instead of being held in memory. The server computes
// the hash itself.
func (s *Server) createRelease(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	x := proto.ReleaseInfo{
		ID: "rel_" + NewToken(6), Project: r.PathValue("project"), Kind: q.Get("kind"), Name: q.Get("name"),
		Version: q.Get("version"), OS: q.Get("os"), Arch: q.Get("arch"), Notes: q.Get("notes"), CreatedBy: userName(r),
	}
	if x.Arch == "" {
		x.Arch = "any"
	}
	switch {
	case x.Kind != "app" && x.Kind != "agent":
		writeErr(w, http.StatusBadRequest, "kind must be app or agent")
		return
	case !nameRE.MatchString(x.Name):
		writeErr(w, http.StatusBadRequest, "name: letters, digits, . _ - (max 64)")
		return
	case !versionRE.MatchString(x.Version):
		writeErr(w, http.StatusBadRequest, "version: letters, digits, . _ + - (max 32)")
		return
	case x.OS == "" || len(x.OS) > 16:
		writeErr(w, http.StatusBadRequest, "os required (windows, linux, darwin)")
		return
	case x.Kind == "agent" && x.Arch == "any":
		writeErr(w, http.StatusBadRequest, "an agent build is for one architecture: set arch (amd64, arm64)")
		return
	case len(x.Notes) > 500:
		writeErr(w, http.StatusBadRequest, "notes: 500 characters at most")
		return
	}

	s.st.mu.Lock()
	var dup int
	s.st.db.QueryRow(`SELECT COUNT(*) FROM releases WHERE project=? AND kind=? AND name=? AND version=? AND os=? AND arch=?`,
		x.Project, x.Kind, x.Name, x.Version, x.OS, x.Arch).Scan(&dup)
	dir := s.st.artifactDir
	s.st.mu.Unlock()
	if dup > 0 {
		writeErr(w, http.StatusConflict, "that version already exists: releases are immutable, upload a new version")
		return
	}

	part := filepath.Join(dir, x.ID+".part")
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "storage unavailable")
		return
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), http.MaxBytesReader(w, r.Body, maxReleaseBytes))
	f.Close()
	if err != nil || n == 0 {
		os.Remove(part)
		writeErr(w, http.StatusBadRequest, "the file did not arrive completely (or is empty)")
		return
	}
	x.Size, x.SHA256, x.CreatedAt = n, hex.EncodeToString(h.Sum(nil)), time.Now().UTC()

	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if err := os.Rename(part, s.st.releasePath(x.ID)); err != nil {
		os.Remove(part)
		writeErr(w, http.StatusInternalServerError, "storage rename failed")
		return
	}
	if _, err := s.st.db.Exec(`INSERT INTO releases(`+releaseCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		x.ID, x.Project, x.Kind, x.Name, x.Version, x.OS, x.Arch, x.Size, x.SHA256, x.Notes, x.CreatedAt.Format(time.RFC3339Nano), x.CreatedBy); err != nil {
		os.Remove(s.st.releasePath(x.ID))
		writeErr(w, http.StatusConflict, "that version already exists")
		return
	}
	s.audit(r, "release.created", x.Project, x.Name, fmt.Sprintf("%s %s %s/%s %s", x.Kind, x.Version, x.OS, x.Arch, x.SHA256[:12]))
	writeJSON(w, http.StatusCreated, x)
}

func (s *Server) deleteRelease(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	x, ok := s.st.releaseByID(r.PathValue("project"), r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such release")
		return
	}
	s.st.exec(`DELETE FROM releases WHERE id=?`, x.ID)
	os.Remove(s.st.releasePath(x.ID))
	s.audit(r, "release.deleted", x.Project, x.Name, x.Version)
	w.WriteHeader(http.StatusNoContent)
}

// deviceRelease serves a release file to a device of the same project. Range requests work, so
// an interrupted download resumes where it stopped.
func (s *Server) deviceRelease(w http.ResponseWriter, r *http.Request, dev *Device) {
	s.st.mu.Lock()
	x, ok := s.st.releaseByID(dev.Project, r.PathValue("id"))
	path := s.st.releasePath(x.ID)
	s.st.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "no such release")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "file missing")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", `"`+x.SHA256+`"`)
	http.ServeContent(w, r, "", x.CreatedAt, f)
}

// resolveApplyRelease checks that a release fits the device and produces the signed parameters.
// Caller holds s.st.mu.
func (s *Server) resolveApplyRelease(d *Device, in map[string]any) (map[string]any, error) {
	id, _ := in["release_id"].(string)
	x, ok := s.st.releaseByID(d.Project, id)
	if !ok {
		return nil, fmt.Errorf("no such release %q in this project", id)
	}
	if x.OS != d.OS {
		return nil, fmt.Errorf("this release is for %s, the device runs %s", x.OS, d.OS)
	}
	if x.Arch != "any" && x.Arch != d.Arch {
		return nil, fmt.Errorf("this release is for %s, the device is %s", x.Arch, d.Arch)
	}
	out := map[string]any{
		"release_id": x.ID, "kind": x.Kind, "name": x.Name, "version": x.Version,
		"sha256": x.SHA256, "size": x.Size,
	}
	if v, ok := in["health_s"].(float64); ok && v >= 5 && v <= 3600 {
		out["health_s"] = int(v)
	}
	return out, nil
}
