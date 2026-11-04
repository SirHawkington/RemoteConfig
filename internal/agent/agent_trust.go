package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"remoteconfig/internal/proto"
	"remoteconfig/internal/signing"
)

// Glue between the agent and its trust store: where signed copies live, how keys are learned
// at enrollment and afterwards, and the persisted record of commands already executed.

func (a *Agent) signedCachePath() string { return filepath.Join(a.o.StateDir, "signed-config.json") }

func (a *Agent) serverURL() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.id.Server != "" {
		return a.id.Server
	}
	return a.o.Server
}

func (a *Agent) identitySnapshot() identity {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.id
}

// needSignedCopy: the agent trusts a key but has no signed config on disk (it used to run
// unsigned, then learned the key). It must fetch one now, while online: after a reboot with no
// signal it would otherwise have no config it is willing to start the app from.
func (a *Agent) needSignedCopy() bool {
	if !a.trust.strict() {
		return false
	}
	_, err := os.Stat(a.signedCachePath())
	return err != nil
}

// persistSigned saves the signed config that is now in force and raises the anti-rollback floor.
func (a *Agent) persistSigned(env *signing.Envelope, issued time.Time) {
	if b, err := json.Marshal(env); err == nil {
		if err := writeFileAtomic(a.signedCachePath(), b); err != nil {
			a.logf("could not save the signed config: %v", err)
		}
	}
	a.trust.setApplied(issued)
}

func (t *trustStore) setApplied(issued time.Time) {
	t.mu.Lock()
	if issued.After(t.lastIssued) {
		t.lastIssued = issued
	}
	t.mu.Unlock()
}

// learnEnrollmentKey takes the key the server presented at enrollment. A pinned key must match
// (or be vouched for); otherwise this is some other server than the one the operator pinned.
func (a *Agent) learnEnrollmentKey(k *proto.KeyInfo) error {
	if k == nil {
		if a.trust.strict() {
			return errors.New("this agent requires signed config but the server offers no signing key (is it an older version?)")
		}
		return nil // legacy: carry on unsigned, as before
	}
	err := a.trust.consider(proto.KeySet{Current: k.KeyID, Keys: []proto.KeyInfo{*k}}, "enrollment")
	if err != nil && a.trust.strict() {
		return fmt.Errorf("refusing to enrol: %w", err)
	}
	if err != nil {
		a.logf("not trusting the server's signing key yet (%v); config will be accepted unsigned until it can be", err)
	}
	return nil
}

// bootstrapTrust: an agent that is not strict yet (it enrolled before signing existed, or over
// a channel that could not vouch for a key) tries to learn the server's key whenever it checks
// in. It only succeeds where first-use trust is allowed.
func (a *Agent) bootstrapTrust(ctx context.Context) {
	if a.trust.strict() && len(a.trust.pubkeys()) > 0 {
		return
	}
	if err := a.trust.fetchKeys(ctx, false); err != nil && err.Error() != "key list fetched recently" {
		a.trust.sayOnce("keys", "could not learn the server's signing key: "+err.Error())
	}
}

func (t *trustStore) sayOnce(key, msg string) {
	t.mu.Lock()
	first := t.said[key+msg].IsZero()
	t.said[key+msg] = time.Now()
	t.mu.Unlock()
	if first {
		t.a.logf("%s", msg)
	}
}

// serverGet is GET with the device credential that returns the body and headers (a.server
// decodes JSON, which a signed envelope must not be).
func (a *Agent) serverGet(ctx context.Context, path string, hdr map[string]string) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.serverURL()+path, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.identitySnapshot().DeviceToken)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, b, resp.Header, err
}

// ---------------------------------------------------------------- commands already executed

const handledKeep = 500

func (a *Agent) handledPath() string { return filepath.Join(a.o.StateDir, "handled-commands.json") }

// loadHandledCommands restores the ids of commands this device already ran, so a captured
// signed command replayed after an agent restart is recognised as old instead of run again.
func (a *Agent) loadHandledCommands() {
	b, err := os.ReadFile(a.handledPath())
	if err != nil {
		return
	}
	var ids []string
	if json.Unmarshal(b, &ids) != nil {
		return
	}
	a.mu.Lock()
	for _, id := range ids {
		a.handled[id] = true
	}
	a.handledList = ids
	a.mu.Unlock()
}

func (a *Agent) rememberCommand(id string) {
	a.mu.Lock()
	a.handledList = append(a.handledList, id)
	if n := len(a.handledList); n > handledKeep {
		for _, old := range a.handledList[:n-handledKeep] {
			delete(a.handled, old)
		}
		a.handledList = a.handledList[n-handledKeep:]
	}
	b, _ := json.Marshal(a.handledList)
	a.mu.Unlock()
	writeFileAtomic(a.handledPath(), b)
}
