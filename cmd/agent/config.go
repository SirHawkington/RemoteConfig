package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// fileConfig is agent.json: the settings an installer bakes in so the scheduled task
// only needs `agent run -config <file>`. Command-line flags override it.
type fileConfig struct {
	Server      string `json:"server,omitempty"`
	EnrollToken string `json:"enroll_token,omitempty"` // single use; ignored once the device has an identity
	StateDir    string `json:"state_dir,omitempty"`
	OutDir      string `json:"out_dir,omitempty"`
	Listen      string `json:"listen,omitempty"`
	Interval    string `json:"interval,omitempty"` // Go duration, e.g. "5m"
	LogFile     string `json:"log_file,omitempty"`
	// ServerKey pins the server's public signing key. With it the agent refuses unsigned or
	// wrongly signed config and commands from the first moment, with no trust-on-first-use.
	ServerKey         string `json:"server_key,omitempty"`
	RequireSignatures bool   `json:"require_signatures,omitempty"`
	InsecureTOFU      bool   `json:"insecure_tofu,omitempty"`
}

func loadFileConfig(path string) (fileConfig, error) {
	var c fileConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	// Relative paths in the file are relative to the file itself.
	base := filepath.Dir(path)
	for _, p := range []*string{&c.StateDir, &c.OutDir, &c.LogFile} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	return c, nil
}

func saveFileConfig(path string, c fileConfig) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func (c fileConfig) interval() time.Duration {
	d, _ := time.ParseDuration(c.Interval)
	return d
}

// exeDir is the directory containing the running binary ("" if unknown).
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}
