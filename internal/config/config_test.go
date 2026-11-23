package config

import (
	"strings"
	"testing"
	"time"
)

func TestDecodeDefaultsAndExplicitDisable(t *testing.T) {
	c, err := Decode(strings.NewReader("ssh:\n  protect_ipv6: false\nauthorization:\n  duration: 7m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.SSH.ProtectIPv6 || !c.SSH.ProtectIPv4 || c.Authorization.Duration.Value() != 7*time.Minute {
		t.Fatalf("unexpected config: %+v", c)
	}
}
func TestRejectUnsafeConfiguration(t *testing.T) {
	for name, input := range map[string]string{
		"unknown":            "ssh:\n  port: 22\n",
		"duplicate":          "ssh:\n  ports: [22]\n  ports: [2222]\n",
		"empty ports":        "ssh:\n  ports: []\n",
		"zero port":          "ssh:\n  ports: [0]\n",
		"duplicate ports":    "ssh:\n  ports: [22, 22]\n",
		"bad IP":             "ssh:\n  permanent_allow_ips: [example.org]\n",
		"scoped IP":          "ssh:\n  permanent_allow_ips: ['fe80::1%eth0']\n",
		"mapped duplicate":   "ssh:\n  permanent_allow_ips: ['192.0.2.1', '::ffff:192.0.2.1']\n",
		"negative duration":  "verification:\n  ban_duration: -1h\n",
		"subsecond duration": "authorization:\n  duration: 500ms\n",
		"number duration":    "authorization:\n  duration: 300\n",
		"bad attempts":       "verification:\n  max_failures: 0\n",
		"bad listen":         "http:\n  listen: ':0'\n",
		"public proxy":       "http:\n  mode: reverse_proxy\n  listen: '0.0.0.0:8080'\n",
		"multiple documents": "{}\n---\n{}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}
func TestReverseProxy(t *testing.T) {
	_, err := Decode(strings.NewReader("http:\n  mode: reverse_proxy\n  listen: '[::1]:8080'\n  tls_cert_file: ''\n  tls_key_file: ''\n  trusted_proxies: ['::1/128']\n"))
	if err != nil {
		t.Fatal(err)
	}
}
