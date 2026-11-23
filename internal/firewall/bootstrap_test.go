package firewall

import (
	"os"
	"path/filepath"
	"reflect"
	"ssh-protecter/internal/config"
	"testing"
)

func TestPrivateIdentityRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "bootstrap.json")
	want := Bootstrap{Version: 1, Initialized: true, UserID: "owner", Secret: "TEST-SECRET-NOT-A-REAL-CREDENTIAL", StoragePath: "/var/lib/ssh-protecter/state.db", Policy: Policy{Ports: []uint16{22}, IPv4: true, IPv6: true}}
	if e := SaveIdentity(path, want); e != nil {
		t.Fatal(e)
	}
	got, e := LoadIdentity(path)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("identity did not survive reload")
	}
	baseline, e := LoadBootstrap(path)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(baseline, want.Policy) {
		t.Fatal("guard could not read initialized baseline")
	}
	if e := os.WriteFile(path, []byte("{broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadIdentity(path); e == nil {
		t.Fatal("corrupt identity accepted")
	}
}

func TestSnapshotAcceptsEmptyListAndPolicyOrdering(t *testing.T) {
	c := config.Defaults()
	c.SSH.Ports = []uint16{2222, 22}
	c.SSH.PermanentAllowIPs = []string{}
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	b := Bootstrap{Version: 1, Initialized: true, UserID: "owner", Secret: "test", StoragePath: c.Storage.Path, Policy: Policy{Ports: []uint16{22, 2222}, IPv4: true, IPv6: true, PermanentIPs: nil}, ActiveConfig: &c}
	if e := SaveIdentity(path, b); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadIdentity(path); e != nil {
		t.Fatal("equivalent policy rejected:", e)
	}
}

func TestUninitializedBootstrapRejected(t *testing.T) {
	for _, input := range []string{`{"version":1,"initialized":false,"policy":{"ports":[22]}}`, `{"version":2,"initialized":true,"policy":{"ports":[22]}}`, `{"version":1,"initialized":true,"policy":{"ports":[]}}`, `{"version":1,"initialized":true,"unknown":true,"policy":{"ports":[22]}}`} {
		p := filepath.Join(t.TempDir(), "bootstrap.json")
		if e := os.WriteFile(p, []byte(input), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := LoadBootstrap(p); e == nil {
			t.Fatal("invalid initialization snapshot accepted")
		}
	}
}
