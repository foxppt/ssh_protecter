package firewall

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"ssh-protecter/internal/config"
)

// Bootstrap is emitted by the future successful TOTP initialization/config
// coordinator, never by merely parsing an unverified configuration file.
type Bootstrap struct {
	Version      int            `json:"version"`
	Initialized  bool           `json:"initialized"`
	Policy       Policy         `json:"policy"`
	UserID       string         `json:"user_id,omitempty"`
	Secret       string         `json:"secret,omitempty"`
	StoragePath  string         `json:"storage_path,omitempty"`
	ActiveConfig *config.Config `json:"active_config,omitempty"`
}

func LoadIdentity(path string) (Bootstrap, error) {
	f, e := os.Open(path)
	if e != nil {
		return Bootstrap{}, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return Bootstrap{}, e
	}
	if st.Size() > 1<<20 {
		return Bootstrap{}, fmt.Errorf("identity file too large")
	}
	if runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0 {
		return Bootstrap{}, fmt.Errorf("identity file must be private (0600)")
	}
	var b Bootstrap
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if e = d.Decode(&b); e != nil {
		return b, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return b, fmt.Errorf("invalid trailing identity data")
	}
	if b.Version != 1 || !b.Initialized || b.UserID == "" || b.Secret == "" {
		return b, fmt.Errorf("identity is not initialized")
	}
	if b.ActiveConfig != nil {
		if e = b.ActiveConfig.Validate(); e != nil {
			return Bootstrap{}, fmt.Errorf("invalid active configuration: %w", e)
		}
		p := Policy{Ports: b.ActiveConfig.SSH.Ports, IPv4: b.ActiveConfig.SSH.ProtectIPv4, IPv6: b.ActiveConfig.SSH.ProtectIPv6, PermanentIPs: b.ActiveConfig.SSH.PermanentAllowIPs}
		if !EqualPolicy(p, b.Policy) || b.ActiveConfig.Storage.Path != b.StoragePath {
			return Bootstrap{}, fmt.Errorf("active configuration conflicts with identity baseline")
		}
	}
	return b, b.Policy.Validate()
}

// SaveIdentity atomically replaces a private identity + last-good baseline file.
func SaveIdentity(path string, b Bootstrap) error {
	if b.Version != 1 || !b.Initialized || b.UserID == "" || b.Secret == "" {
		return fmt.Errorf("incomplete identity")
	}
	if e := b.Policy.Validate(); e != nil {
		return e
	}
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".identity-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if e = json.NewEncoder(f).Encode(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	if runtime.GOOS == "linux" {
		d, e := os.Open(dir)
		if e != nil {
			return e
		}
		defer d.Close()
		return d.Sync()
	}
	return nil
}

func LoadBootstrap(path string) (Policy, error) {
	f, e := os.Open(path)
	if e != nil {
		return Policy{}, e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	var b Bootstrap
	if e = d.Decode(&b); e != nil {
		return Policy{}, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return Policy{}, fmt.Errorf("bootstrap must contain one JSON object")
	}
	if b.Version != 1 || !b.Initialized {
		return Policy{}, fmt.Errorf("bootstrap is not a confirmed initialized version 1 snapshot")
	}
	if e = b.Policy.Validate(); e != nil {
		return Policy{}, e
	}
	return b.Policy, nil
}
