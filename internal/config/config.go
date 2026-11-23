package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Tag != "!!str" {
		return fmt.Errorf("duration must be a string such as 5m")
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}
func (d Duration) Value() time.Duration { return time.Duration(d) }

type Config struct {
	SSH struct {
		Ports             []uint16 `yaml:"ports"`
		ProtectIPv4       bool     `yaml:"protect_ipv4"`
		ProtectIPv6       bool     `yaml:"protect_ipv6"`
		PermanentAllowIPs []string `yaml:"permanent_allow_ips"`
	} `yaml:"ssh"`
	Authorization struct {
		Duration Duration `yaml:"duration"`
	} `yaml:"authorization"`
	Verification struct {
		FailureWindow Duration `yaml:"failure_window"`
		MaxFailures   int      `yaml:"max_failures"`
		BanDuration   Duration `yaml:"ban_duration"`
	} `yaml:"verification"`
	HTTP struct {
		Mode           string   `yaml:"mode"`
		Listen         string   `yaml:"listen"`
		TLSCertFile    string   `yaml:"tls_cert_file"`
		TLSKeyFile     string   `yaml:"tls_key_file"`
		TrustedProxies []string `yaml:"trusted_proxies"`
	} `yaml:"http"`
	Storage struct {
		Path string `yaml:"path"`
	} `yaml:"storage"`
	Clock struct {
		RequireSync bool     `yaml:"require_sync"`
		MaxSkew     Duration `yaml:"max_skew"`
	} `yaml:"clock"`
}

// Populate newly introduced settings when loading an older committed snapshot.
func (c *Config) UnmarshalJSON(data []byte) error {
	type plain Config
	v := plain(Defaults())
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil {
		return e
	}
	*c = Config(v)
	return nil
}

// Clone detaches slices before publishing configuration to another goroutine.
func (c Config) Clone() Config {
	c.SSH.Ports = append([]uint16(nil), c.SSH.Ports...)
	c.SSH.PermanentAllowIPs = append([]string(nil), c.SSH.PermanentAllowIPs...)
	c.HTTP.TrustedProxies = append([]string(nil), c.HTTP.TrustedProxies...)
	return c
}

func Defaults() Config {
	var c Config
	c.SSH.Ports = []uint16{22}
	c.SSH.ProtectIPv4 = true
	c.SSH.ProtectIPv6 = true
	c.Authorization.Duration = Duration(5 * time.Minute)
	c.Verification.FailureWindow = Duration(time.Hour)
	c.Verification.MaxFailures = 5
	c.Verification.BanDuration = Duration(24 * time.Hour)
	c.HTTP.Mode = "direct_tls"
	c.HTTP.Listen = ":443"
	c.HTTP.TLSCertFile = "/etc/ssh-protecter/tls/fullchain.pem"
	c.HTTP.TLSKeyFile = "/etc/ssh-protecter/tls/privkey.pem"
	c.Storage.Path = "/var/lib/ssh-protecter/state.db"
	c.Clock.RequireSync = true
	c.Clock.MaxSkew = Duration(2 * time.Second)
	return c
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	return Decode(f)
}
func Decode(r io.Reader) (Config, error) {
	c := Defaults()
	d := yaml.NewDecoder(r)
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return Config{}, fmt.Errorf("config must contain exactly one YAML document")
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}
func (c Config) Validate() error {
	if len(c.SSH.Ports) == 0 {
		return fmt.Errorf("ssh.ports must not be empty")
	}
	seen := map[uint16]bool{}
	for _, p := range c.SSH.Ports {
		if p == 0 || seen[p] {
			return fmt.Errorf("invalid or duplicate SSH port: %d", p)
		}
		seen[p] = true
	}
	ips := map[netip.Addr]bool{}
	for _, s := range c.SSH.PermanentAllowIPs {
		a, err := ParseIP(s)
		if err != nil {
			return fmt.Errorf("permanent_allow_ips: %w", err)
		}
		if ips[a] {
			return fmt.Errorf("duplicate permanent IP: %s", a)
		}
		ips[a] = true
	}
	for name, v := range map[string]Duration{"authorization.duration": c.Authorization.Duration, "verification.failure_window": c.Verification.FailureWindow, "verification.ban_duration": c.Verification.BanDuration, "clock.max_skew": c.Clock.MaxSkew} {
		if v.Value() < time.Second || v.Value()%time.Second != 0 {
			return fmt.Errorf("%s must be a positive whole number of seconds", name)
		}
	}
	if c.Verification.MaxFailures < 1 {
		return fmt.Errorf("verification.max_failures must be positive")
	}
	host, port, err := net.SplitHostPort(c.HTTP.Listen)
	if err != nil {
		return fmt.Errorf("http.listen: %w", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("http.listen requires a port from 1 to 65535")
	}
	if c.HTTP.Mode != "direct_tls" && c.HTTP.Mode != "reverse_proxy" {
		return fmt.Errorf("http.mode must be direct_tls or reverse_proxy")
	}
	if c.HTTP.Mode == "direct_tls" && (c.HTTP.TLSCertFile == "" || c.HTTP.TLSKeyFile == "") {
		return fmt.Errorf("direct_tls requires certificate and key paths")
	}
	if c.HTTP.Mode == "reverse_proxy" {
		a, e := netip.ParseAddr(host)
		if e != nil || !a.IsLoopback() {
			return fmt.Errorf("reverse_proxy must listen on an explicit loopback IP")
		}
		if len(c.HTTP.TrustedProxies) == 0 {
			return fmt.Errorf("reverse_proxy requires trusted_proxies")
		}
		if c.HTTP.TLSCertFile != "" || c.HTTP.TLSKeyFile != "" {
			return fmt.Errorf("reverse_proxy requires empty TLS certificate and key paths")
		}
	}
	for _, s := range c.HTTP.TrustedProxies {
		if _, e := netip.ParsePrefix(s); e != nil {
			return fmt.Errorf("trusted_proxies must contain CIDR prefixes: %q", s)
		}
	}
	if c.Storage.Path == "" {
		return fmt.Errorf("storage.path is required")
	}
	return nil
}

func ParseIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid IP address: %q", s)
	}
	return a.Unmap(), nil
}
