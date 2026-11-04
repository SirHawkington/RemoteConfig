package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"remoteconfig/internal/proto"
)

// deepMerge returns base overlaid with over. Maps merge recursively; everything
// else (scalars, arrays) is replaced.
func deepMerge(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if om, ok := v.(map[string]any); ok {
			if bm, ok := out[k].(map[string]any); ok {
				out[k] = deepMerge(bm, om)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// effective merges global -> tag:* (in tag order) -> device:<id> for a device.
// Revision is left as the device's currently stored revision; callers use
// bumpIfChanged to advance it. Caller must hold the store lock.
func (s *Store) effective(dev *Device) proto.EffectiveConfig {
	scopes := []string{"global"}
	for _, t := range dev.Tags {
		scopes = append(scopes, "tag:"+t)
	}
	scopes = append(scopes, "device:"+dev.ID)

	data := map[string]any{}
	var reload string
	var sup *proto.SupervisorConfig
	shots, budget := map[string]any{}, map[string]any{}
	for _, sc := range scopes {
		doc, ok := s.D.Configs[dev.Project+"|"+sc]
		if !ok {
			continue
		}
		data = deepMerge(data, doc.Data)
		shots = deepMerge(shots, doc.Screenshots)
		budget = deepMerge(budget, doc.Budget)
		if doc.ReloadMode != "" {
			reload = doc.ReloadMode
		}
		if doc.Supervisor != nil {
			sup = doc.Supervisor
		}
	}
	if reload == "" {
		reload = "watch"
	}
	cfg := proto.EffectiveConfig{
		Revision:   dev.EffRevision,
		ReloadMode: reload,
		Data:       data,
		Supervisor: sup,
	}
	if len(shots) > 0 { // layers were validated on save, so decoding cannot fail
		cfg.Screenshots = &proto.ScreenshotPolicy{}
		remarshal(shots, cfg.Screenshots)
	}
	if len(budget) > 0 {
		cfg.Budget = &proto.BudgetPolicy{}
		remarshal(budget, cfg.Budget)
	}
	cfg.Etag = etagOf(cfg)
	return cfg
}

// remarshal converts a generic map into a typed struct.
func remarshal(from map[string]any, to any) {
	b, _ := json.Marshal(from)
	json.Unmarshal(b, to)
}

// decodeStrict converts a map into a typed struct, rejecting unknown fields so typos
// ("interval" for "interval_s") are caught when the layer is saved, not silently ignored.
func decodeStrict(from map[string]any, to any) error {
	b, _ := json.Marshal(from)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(to)
}

// etagOf hashes everything except revision/etag. encoding/json sorts map keys,
// so the hash is stable.
func etagOf(c proto.EffectiveConfig) string {
	c.Revision = 0
	c.Etag = ""
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// current returns the device's effective config, advancing the device's revision
// if the content changed since last computed. Caller must hold the store lock.
func (s *Store) current(dev *Device) proto.EffectiveConfig {
	cfg := s.effective(dev)
	if cfg.Etag != dev.EffEtag {
		dev.EffRevision++
		dev.EffEtag = cfg.Etag
		cfg.Revision = dev.EffRevision
	}
	return cfg
}
