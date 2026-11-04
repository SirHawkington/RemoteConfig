package agent

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"remoteconfig/internal/proto"
)

// Releases: a build the server stores and an administrator sends to chosen devices.
//
// The signed command carries the release's SHA-256 and size. The bytes come over an
// unauthenticated-in-content download (HTTP range requests, resumable, counted against the data
// budget) and are checked against that hash before anything is unpacked or executed.
//
// App releases are unpacked beside each other and the supervisor's ${release} placeholder is
// pointed at the new folder; if the app does not stay up, the previous folder is put back. Agent
// releases replace the agent's own executable after a smoke test, and are rolled back if the new
// binary does not get as far as checking in.

const (
	maxReleaseBytes    = 4 << 30
	maxUnpackedBytes   = 8 << 30
	maxUnpackedFiles   = 20000
	downloadStall      = 90 * time.Second
	maxDownloadTries   = 8
	defaultHealth      = 45 * time.Second
	maxTrialBoots      = 3
	exitForUpdate      = 75
	releasePlaceholder = "${release}"
)

var releaseMu sync.Mutex // one release operation at a time

type releaseState struct {
	Dir         string `json:"dir"` // folder the app runs from (${release})
	Version     string `json:"version"`
	ReleaseID   string `json:"release_id"`
	PrevDir     string `json:"prev_dir,omitempty"`
	PrevVersion string `json:"prev_version,omitempty"`
}

func (a *Agent) releaseRoot() string { return filepath.Join(a.o.StateDir, "releases") }

func (a *Agent) loadReleaseState() {
	b, err := os.ReadFile(filepath.Join(a.releaseRoot(), "current.json"))
	if err != nil {
		return
	}
	var st releaseState
	if json.Unmarshal(b, &st) == nil && st.Dir != "" {
		a.mu.Lock()
		a.rel = st
		a.mu.Unlock()
	}
}

func (a *Agent) saveReleaseState(st releaseState) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	if err := writeFileAtomic(filepath.Join(a.releaseRoot(), "current.json"), b); err != nil {
		return err
	}
	a.mu.Lock()
	a.rel = st
	a.mu.Unlock()
	return nil
}

func (a *Agent) releaseSnapshot() releaseState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rel
}

// expandRelease fills in the supervisor's ${release} placeholder with the folder of the app
// release in force. With none installed it is left alone (and the start fails visibly).
func (a *Agent) expandRelease(c proto.SupervisorConfig) proto.SupervisorConfig {
	dir := a.releaseSnapshot().Dir
	if dir == "" {
		return c
	}
	ex := func(s string) string { return strings.ReplaceAll(s, releasePlaceholder, dir) }
	c.Exe, c.Workdir = ex(c.Exe), ex(c.Workdir)
	c.Args = append([]string(nil), c.Args...)
	for i := range c.Args {
		c.Args[i] = ex(c.Args[i])
	}
	if len(c.Env) > 0 {
		env := make(map[string]string, len(c.Env))
		for k, v := range c.Env {
			env[k] = ex(v)
		}
		c.Env = env
	}
	return c
}

// ---------------------------------------------------------------- entry point

func (a *Agent) applyRelease(ctx context.Context, c proto.Command) proto.CommandResult {
	fail := func(format string, args ...any) proto.CommandResult {
		return proto.CommandResult{OK: false, Output: fmt.Sprintf(format, args...)}
	}
	if !a.trust.strict() {
		return fail("refused: this agent does not verify signatures, so it will not install software from the server (pin the server key with -server-key)")
	}
	id, kind, version := str(c.Params, "release_id"), str(c.Params, "kind"), str(c.Params, "version")
	want, size := strings.ToLower(str(c.Params, "sha256")), int64(num(c.Params, "size"))
	if id == "" || version == "" || len(want) != 64 || size <= 0 || size > maxReleaseBytes || (kind != "app" && kind != "agent") {
		return fail("malformed apply_release command")
	}
	if !releaseMu.TryLock() {
		return fail("another release is being installed on this device")
	}
	defer releaseMu.Unlock()

	if kind == "agent" && version == a.o.Version {
		return proto.CommandResult{OK: true, Output: "already running agent " + version}
	}
	if kind == "app" && a.releaseSnapshot().ReleaseID == id {
		return proto.CommandResult{OK: true, Output: "app release " + version + " is already in place"}
	}

	if err := os.MkdirAll(filepath.Join(a.releaseRoot(), "incoming"), 0o755); err != nil {
		return fail("no space to work in: %v", err)
	}
	file := filepath.Join(a.releaseRoot(), "incoming", want[:16]+".bin")
	if _, err := os.Stat(file); err != nil { // not downloaded yet (a finished download is kept until installed)
		t0 := time.Now()
		if err := a.download(ctx, id, want, size, file); err != nil {
			return fail("download: %v", err)
		}
		a.QueueEvent(proto.Event{Type: "release.downloaded", Level: "info",
			Message: fmt.Sprintf("%s %s: %d MB in %s", kind, version, size>>20, time.Since(t0).Round(time.Second))})
	}
	defer os.Remove(file)

	if kind == "app" {
		return a.installApp(ctx, c, file, id, version, want)
	}
	return a.installAgent(c, file, id, version)
}

// ---------------------------------------------------------------- download

// download fetches release id into dest, resuming a partial file, and verifies size and hash.
// It stops (keeping what it has) if the data budget runs out, so a later attempt continues.
func (a *Agent) download(ctx context.Context, id, wantSHA string, size int64, dest string) error {
	part := dest + ".part"
	dl := &http.Client{Transport: a.client.Transport} // no overall timeout: a big file on a slow link takes a while
	var lastErr error
	for try := 1; try <= maxDownloadTries; try++ {
		if !a.allowBulk() {
			return errors.New("the data budget is used up; the partial download is kept and will resume next cycle")
		}
		off := int64(0)
		if st, err := os.Stat(part); err == nil {
			off = st.Size()
		}
		if off > size {
			os.Remove(part)
			off = 0
		}
		if off < size {
			var retry bool
			retry, lastErr = a.fetchRange(ctx, dl, id, part, off, size)
			if lastErr != nil && !retry {
				return lastErr
			}
			if lastErr != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Duration(try) * 3 * time.Second):
				}
				continue
			}
		}
		if st, err := os.Stat(part); err != nil || st.Size() != size {
			continue
		}
		sum, err := fileSHA256(part)
		if err != nil {
			return err
		}
		if sum != wantSHA {
			os.Remove(part)
			a.trust.reject("release", "the downloaded file does not match the hash the server signed")
			return errors.New("the downloaded file does not match the signed hash; it was discarded")
		}
		return os.Rename(part, dest)
	}
	if lastErr == nil {
		lastErr = errors.New("incomplete")
	}
	return fmt.Errorf("gave up after %d attempts: %w", maxDownloadTries, lastErr)
}

// fetchRange appends bytes from off to part. retry says whether the failure may be transient.
func (a *Agent) fetchRange(ctx context.Context, dl *http.Client, id, part string, off, size int64) (retry bool, err error) {
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodGet, strings.TrimRight(a.id.Server, "/")+"/v1/releases/"+id+"/file", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+a.id.DeviceToken)
	if off > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
	}
	resp, err := dl.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		os.Remove(part)
		return true, errors.New("server rejected the resume point; starting over")
	case resp.StatusCode == http.StatusOK:
		off = 0 // the server ignored Range and sent everything
	case resp.StatusCode == http.StatusPartialContent:
	case resp.StatusCode >= 500:
		return true, fmt.Errorf("server answered HTTP %d", resp.StatusCode)
	default:
		return false, fmt.Errorf("server answered HTTP %d", resp.StatusCode)
	}
	flags := os.O_WRONLY | os.O_CREATE
	if off == 0 {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(part, flags, 0o600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return false, err
		}
	}

	var got atomic.Int64
	go func() { // give up on a connection that has gone silent
		t := time.NewTicker(downloadStall / 3)
		defer t.Stop()
		last, lastAt := int64(-1), time.Now()
		for {
			select {
			case <-actx.Done():
				return
			case <-t.C:
				if g := got.Load(); g != last {
					last, lastAt = g, time.Now()
				} else if time.Since(lastAt) > downloadStall {
					cancel()
					return
				}
			}
		}
	}()
	buf := make([]byte, 64<<10)
	var sinceCheck int64
	for off+got.Load() < size {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if int64(n) > size-off-got.Load() {
				return false, errors.New("the server sent more than the signed size")
			}
			if _, werr := f.Write(buf[:n]); werr != nil {
				return false, werr
			}
			got.Add(int64(n))
			if sinceCheck += int64(n); sinceCheck > 8<<20 {
				sinceCheck = 0
				if !a.allowBulk() {
					return false, errors.New("the data budget ran out during the download; the partial file is kept and will resume next cycle")
				}
			}
		}
		if rerr != nil {
			if rerr == io.EOF && off+got.Load() >= size {
				break
			}
			return true, rerr
		}
	}
	return false, f.Sync()
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

// ---------------------------------------------------------------- app releases

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func (a *Agent) installApp(ctx context.Context, c proto.Command, file, id, version, sha string) proto.CommandResult {
	fail := func(format string, args ...any) proto.CommandResult {
		return proto.CommandResult{OK: false, Output: fmt.Sprintf(format, args...)}
	}
	name := fmt.Sprintf("%s-%s-%s", safeName(str(c.Params, "name")), safeName(version), sha[:8])
	final := filepath.Join(a.releaseRoot(), "app", name)
	if _, err := os.Stat(final); err != nil {
		tmp := final + ".tmp"
		os.RemoveAll(tmp)
		if err := os.MkdirAll(tmp, 0o755); err != nil {
			return fail("cannot create %s: %v", tmp, err)
		}
		if err := extractZip(file, tmp); err != nil {
			os.RemoveAll(tmp)
			return fail("unpacking: %v", err)
		}
		if err := os.Rename(tmp, final); err != nil {
			os.RemoveAll(tmp)
			return fail("unpacking: %v", err)
		}
	}
	root := final
	if ents, err := os.ReadDir(final); err == nil && len(ents) == 1 && ents[0].IsDir() { // a zip of "the folder", not of its contents
		root = filepath.Join(final, ents[0].Name())
	}

	a.markExecutable(root)

	prev := a.releaseSnapshot()
	next := releaseState{Dir: root, Version: version, ReleaseID: id, PrevDir: prev.Dir, PrevVersion: prev.Version}
	if err := a.saveReleaseState(next); err != nil {
		return fail("could not record the release: %v", err)
	}
	if !a.sup.Managing() {
		return proto.CommandResult{OK: true, Output: fmt.Sprintf("app release %s unpacked and selected; the app is not supervised here, so it was not restarted", version)}
	}

	health := defaultHealth
	if n := num(c.Params, "health_s"); n >= 5 {
		health = time.Duration(n) * time.Second
	}
	before := a.sup.Snapshot().Attempts
	a.sup.RequestRestart("app release " + version)
	if why := a.watchHealth(ctx, before, health); why != "" {
		if prev.Dir == "" {
			return fail("app release %s is not healthy (%s) and there is no earlier release to go back to", version, why)
		}
		a.saveReleaseState(releaseState{Dir: prev.Dir, Version: prev.Version, ReleaseID: prev.ReleaseID, PrevDir: root, PrevVersion: version})
		a.sup.RequestRestart("rolling back app release " + version)
		a.QueueEvent(proto.Event{Type: "release.rolled_back", Level: "error",
			Message: fmt.Sprintf("app release %s did not stay up (%s); went back to %s", version, why, orNone(prev.Version))})
		return fail("app release %s did not stay up (%s); rolled back to %s", version, why, orNone(prev.Version))
	}
	a.pruneReleases(root, prev.Dir)
	a.QueueEvent(proto.Event{Type: "release.applied", Level: "info", Message: "app release " + version + " is running"})
	return proto.CommandResult{OK: true, Output: fmt.Sprintf("app release %s is running and stayed up for %s", version, health)}
}

// markExecutable makes the program the supervisor will start executable. A zip made on Windows
// carries no permission bits, so on Linux and macOS the unpacked app would otherwise not run.
func (a *Agent) markExecutable(root string) {
	if runtime.GOOS == "windows" {
		return
	}
	c := a.currentConfig()
	if c == nil || c.Supervisor == nil || c.Supervisor.Exe == "" {
		return
	}
	exe := filepath.Clean(strings.ReplaceAll(c.Supervisor.Exe, releasePlaceholder, root))
	if rel, err := filepath.Rel(root, exe); err != nil || strings.HasPrefix(rel, "..") {
		return // not inside the release: not ours to change
	}
	if st, err := os.Stat(exe); err == nil && st.Mode().IsRegular() {
		os.Chmod(exe, st.Mode()|0o111)
	}
}

func orNone(s string) string {
	if s == "" {
		return "the previous state"
	}
	return s
}

// watchHealth waits for the supervisor to launch the new build and keep it running for `health`.
// It returns why it gave up, or "" when the app is healthy. Nothing counts until the supervisor
// has made a new launch attempt, so the state left by the old build is not mistaken for the new.
func (a *Agent) watchHealth(ctx context.Context, attemptsBefore int, health time.Duration) string {
	deadline := time.Now().Add(health + 3*time.Minute)
	pid := 0
	for time.Now().Before(deadline) {
		snap := a.sup.Snapshot()
		if snap.Attempts > attemptsBefore {
			switch {
			case snap.CrashLoop || (!snap.Running && snap.State == "backoff"):
				return "it would not start or kept crashing"
			case pid == 0 && snap.Running:
				pid = snap.PID
			case pid != 0 && (!snap.Running || snap.PID != pid):
				return "it exited " + snap.LastExit
			case pid != 0 && snap.UptimeS >= int64(health.Seconds()):
				return ""
			}
		}
		select {
		case <-ctx.Done():
			return "the agent was stopping"
		case <-time.After(500 * time.Millisecond):
		}
	}
	if pid == 0 {
		return "it was not restarted in time"
	}
	return "it did not run long enough to be judged"
}

// pruneReleases keeps the release in force and the one before it.
func (a *Agent) pruneReleases(keep ...string) {
	ents, err := os.ReadDir(filepath.Join(a.releaseRoot(), "app"))
	if err != nil {
		return
	}
	for _, e := range ents {
		p := filepath.Join(a.releaseRoot(), "app", e.Name())
		kept := false
		for _, k := range keep {
			if k != "" && (k == p || strings.HasPrefix(k, p+string(filepath.Separator))) {
				kept = true
			}
		}
		if !kept {
			os.RemoveAll(p)
		}
	}
}

// extractZip unpacks a release archive into dest. Names that leave dest, absolute names, links
// and archives that expand absurdly are refused: the archive is trusted (its hash was signed)
// but a mistake in one should not be able to overwrite the agent or fill the disk.
func extractZip(zipPath, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > maxUnpackedFiles {
		return fmt.Errorf("more than %d files", maxUnpackedFiles)
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	var total int64
	for _, f := range zr.File {
		name := f.Name
		if name == "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) || strings.Contains(name, ":") {
			return fmt.Errorf("unsafe name %q", name)
		}
		for _, seg := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
			if seg == ".." {
				return fmt.Errorf("unsafe name %q", name)
			}
		}
		target := filepath.Join(absDest, filepath.FromSlash(name))
		if rel, err := filepath.Rel(absDest, target); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe name %q", name)
		}
		mode := f.Mode()
		switch {
		case mode&os.ModeSymlink != 0 || !(mode.IsRegular() || mode.IsDir()):
			return fmt.Errorf("%q is a link or special file", name)
		case mode.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if total += int64(f.UncompressedSize64); total > maxUnpackedBytes {
			return errors.New("expands to more than 8 GB")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		perm := os.FileMode(0o644)
		if mode&0o100 != 0 {
			perm = 0o755
		}
		if err := writeZipFile(f, target, perm); err != nil {
			return err
		}
	}
	return nil
}

func writeZipFile(f *zip.File, target string, perm os.FileMode) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(rc, int64(f.UncompressedSize64)+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n != int64(f.UncompressedSize64) {
		err = fmt.Errorf("%q is not the size its header claims", f.Name)
	}
	return err
}

// ---------------------------------------------------------------- agent releases
