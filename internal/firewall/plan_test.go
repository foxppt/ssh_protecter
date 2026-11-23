package firewall

import (
	"context"
	"errors"
	"ssh-protecter/internal/state"
	"strings"
	"testing"
	"time"
)

func TestPlanScopeAndDeadlines(t *testing.T) {
	now := time.Unix(1800000000, 0)
	p := Policy{Ports: []uint16{2222, 22}, IPv4: true, IPv6: true, PermanentIPs: []string{"::ffff:192.0.2.1", "2001:db8::1"}}
	script, e := Render(p, []state.Grant{{IP: "192.0.2.2", ExpiresAt: now.Add(60 * time.Second).Unix()}, {IP: "2001:db8::2", ExpiresAt: now.Unix()}}, now, ApplyBudget)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"destroy table inet ssh_protecter", "elements = { 22, 2222 }", "192.0.2.2 timeout 58000ms", "meta nfproto ipv4", "meta nfproto ipv6", "192.0.2.1", "2001:db8::1"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q: %s", want, script)
		}
	}
	for _, bad := range []string{"flush ruleset", "DOCKER", "hook forward", "2001:db8::2", "flags owner"} {
		if strings.Contains(script, bad) {
			t.Fatalf("unsafe/unexpected %q", bad)
		}
	}
	if strings.Index(script, "ct state established accept") > strings.Index(script, "saddr @permanent4") {
		t.Fatal("established connection retention must precede IP checks")
	}
	p.IPv6 = false
	script, e = Render(p, nil, now, 0)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(script, "meta nfproto ipv6") {
		t.Fatal("disabled IPv6 still protected")
	}
}

type fakeRunner struct {
	calls      []string
	checks     []bool
	err        error
	afterCheck func()
}

func (f *fakeRunner) Run(_ context.Context, check bool, s string) error {
	f.calls = append(f.calls, s)
	f.checks = append(f.checks, check)
	if check && f.afterCheck != nil {
		f.afterCheck()
	}
	return f.err
}
func TestCheckFailureDoesNotApply(t *testing.T) {
	f := &fakeRunner{err: errors.New("invalid rules")}
	e := Engine{Runner: f}
	if e.Apply(context.Background(), Policy{Ports: []uint16{22}, IPv4: true}, nil) == nil {
		t.Fatal("expected check error")
	}
	if len(f.calls) != 1 || !f.checks[0] {
		t.Fatal("applied after failed validation")
	}
}
func TestRecomputeTTLAfterValidation(t *testing.T) {
	now := time.Unix(1800000000, 0)
	deadline := now.Add(10 * time.Second).Unix()
	f := &fakeRunner{afterCheck: func() { now = now.Add(9 * time.Second) }}
	e := Engine{Runner: f, Now: func() time.Time { return now }}
	if err := e.Apply(context.Background(), Policy{Ports: []uint16{22}, IPv4: true}, []state.Grant{{IP: "192.0.2.1", ExpiresAt: deadline}}); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || !strings.Contains(f.calls[0], "192.0.2.1 timeout") || strings.Contains(f.calls[1], "192.0.2.1") {
		t.Fatalf("stale TTL reapplied: %+v", f.calls)
	}
}
func TestRejectInjectedAndDuplicateGrants(t *testing.T) {
	now := time.Now()
	p := Policy{Ports: []uint16{22}, IPv4: true}
	for _, grants := range [][]state.Grant{{{IP: "192.0.2.1; flush ruleset"}}, {{IP: "192.0.2.1"}, {IP: "::ffff:192.0.2.1"}}} {
		if _, e := Render(p, grants, now, 0); e == nil {
			t.Fatal("invalid input accepted")
		}
	}
}
