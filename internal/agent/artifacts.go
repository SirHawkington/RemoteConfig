package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"remoteconfig/internal/proto"
)

// chunkSize is small on purpose: on a flaky 4G link a dropped connection should cost
// one 64 KB chunk, not a whole screenshot, and each chunk is independently resumable.
const chunkSize = 64 << 10

type uploadResult int

const (
	uploadDone       uploadResult = iota // stored on the server; delete the local copy
	uploadRetryLater                     // network/server trouble; keep it, try next cycle
	uploadDrop                           // the server will never accept it; delete the local copy
)

// serverRaw is like server() but for a raw byte body, returning the response headers.
func (a *Agent) serverRaw(ctx context.Context, method, path string, body []byte, hdr map[string]string) (int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.id.Server+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.id.DeviceToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, nil
}

// drainOutbox uploads queued artifacts, newest first, while the data budget allows.
// It is safe to call from several places; only one drain runs at a time.
func (a *Agent) drainOutbox(ctx context.Context) {
	if !a.drainMu.TryLock() {
		return
	}
	defer a.drainMu.Unlock()
	defer a.usage.save()

	deadline := time.Now().Add(90 * time.Second)
	sent := 0
	for _, it := range a.outbox.list() {
		if ctx.Err() != nil || time.Now().After(deadline) || sent >= 12 {
			return
		}
		if !a.allowBulk() {
			return
		}
		switch a.uploadOne(ctx, it) {
		case uploadDone:
			a.outbox.remove(it.ClientID)
			sent++
		case uploadDrop:
			a.outbox.remove(it.ClientID)
			a.QueueEvent(proto.Event{Type: "artifact.dropped", Level: "warn",
				Message: fmt.Sprintf("the server refused %s %s", it.Kind, it.ClientID)})
		case uploadRetryLater:
			return
		}
	}
}

// uploadOne runs the resumable protocol for a single item:
//
//	POST /v1/artifacts            (idempotent by client_id) -> id + how many bytes the server has
//	PATCH /v1/artifacts/{id}      one chunk at Upload-Offset; 409 tells us where to resume
//
// Re-running after any failure is safe: the POST returns the same session with the
// server's current offset, so no byte is sent twice.
func (a *Agent) uploadOne(ctx context.Context, it outboxItem) uploadResult {
	data, err := a.outbox.read(it.ClientID)
	if err != nil || int64(len(data)) != it.Size {
		return uploadDrop // local file damaged; nothing to send
	}
	var sess proto.ArtifactSession
	status, err := a.server(ctx, http.MethodPost, "/v1/artifacts", proto.ArtifactInit{
		ClientID: it.ClientID, Kind: it.Kind, Size: it.Size, ContentType: it.ContentType,
		SHA256: it.SHA256, CapturedAt: it.CapturedAt, Meta: it.Meta,
	}, &sess, nil)
	if err != nil {
		return uploadRetryLater
	}
	switch {
	case status == http.StatusOK || status == http.StatusCreated:
	case status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge || status == http.StatusUnprocessableEntity:
		return uploadDrop
	default:
		return uploadRetryLater // 401, 429, 5xx ...
	}
	if sess.Complete {
		return uploadDone
	}

	offset := sess.Offset
	for guard := int(it.Size/chunkSize) + 20; offset < it.Size && guard > 0; guard-- {
		if !a.allowBulk() || ctx.Err() != nil {
			return uploadRetryLater // budget ran out mid-upload; resume next cycle/period
		}
		end := min(offset+chunkSize, it.Size)
		status, hdr, err := a.serverRaw(ctx, http.MethodPatch, "/v1/artifacts/"+sess.ID, data[offset:end],
			map[string]string{"Upload-Offset": strconv.FormatInt(offset, 10)})
		if err != nil {
			return uploadRetryLater
		}
		switch status {
		case http.StatusNoContent:
			next, perr := strconv.ParseInt(hdr.Get("Upload-Offset"), 10, 64)
			if perr != nil {
				next = end
			}
			offset = next
			if hdr.Get("Upload-Complete") == "true" {
				return uploadDone
			}
		case http.StatusConflict: // we and the server disagree about the offset: take theirs
			next, perr := strconv.ParseInt(hdr.Get("Upload-Offset"), 10, 64)
			if perr != nil || next < 0 || next > it.Size {
				return uploadRetryLater
			}
			offset = next
		case http.StatusUnprocessableEntity, http.StatusRequestEntityTooLarge, http.StatusBadRequest:
			return uploadDrop // e.g. checksum mismatch: resending the same bytes cannot help
		default:
			return uploadRetryLater
		}
	}
	if offset >= it.Size {
		return uploadDone
	}
	return uploadRetryLater
}
