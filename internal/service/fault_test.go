package service

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"ssh-protecter/internal/config"
	"ssh-protecter/internal/firewall"
	"ssh-protecter/internal/state"
	"ssh-protecter/internal/totp"
	"testing"
	"time"
)

type crashFirewall struct{ phase string }

func (f crashFirewall) Apply(_ context.Context, p firewall.Policy, _ []state.Grant) error {
	if f.phase == "before_snapshot" && p.Ports[0] == 2222 {
		crashBoundary()
	}
	return nil
}
func crashBoundary() { fmt.Println("FAULT_BOUNDARY"); select {} }

// Child processes are killed by the parent at real durability boundaries. No
// test hook exists in the production binary and no host firewall is touched.
func TestReloadInterruptedProcess(t *testing.T) {
	if phase := os.Getenv("SSH_TEST_CRASH_PHASE"); phase != "" {
		path := os.Getenv("SSH_TEST_IDENTITY")
		identity, e := firewall.LoadIdentity(path)
		if e != nil {
			t.Fatal(e)
		}
		store, e := state.OpenExisting(identity.StoragePath)
		if e != nil {
			t.Fatal(e)
		}
		defer store.Close()
		c := &Controller{Config: identity.ActiveConfig.Clone(), Identity: identity, Store: store, Firewall: crashFirewall{phase}, Now: func() time.Time { return time.Unix(1800000000, 0) }}
		next := c.Configuration()
		next.SSH.Ports = []uint16{2222}
		e = c.Reload(context.Background(), next, func(b firewall.Bootstrap) error {
			if e := firewall.SaveIdentity(path, b); e != nil {
				return e
			}
			if phase == "after_snapshot" {
				crashBoundary()
			}
			return nil
		}, nil)
		t.Fatalf("crash boundary was not reached: %v", e)
	}
	for _, phase := range []string{"before_snapshot", "after_snapshot"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "identity.json")
			db := filepath.Join(dir, "state.db")
			now := time.Unix(1800000000, 0)
			c := config.Defaults()
			c.Storage.Path = db
			secret, e := totp.NewSecret()
			if e != nil {
				t.Fatal(e)
			}
			identity := firewall.Bootstrap{Version: 1, Initialized: true, UserID: "owner", Secret: secret, StoragePath: db, Policy: Policy(c), ActiveConfig: &c}
			if e = firewall.SaveIdentity(path, identity); e != nil {
				t.Fatal(e)
			}
			s, e := state.Open(db)
			if e != nil {
				t.Fatal(e)
			}
			if e = s.SaveGrant(context.Background(), netip.MustParseAddr("192.0.2.1"), "owner", now.Add(5*time.Minute)); e != nil {
				t.Fatal(e)
			}
			s.Close()
			exe, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestReloadInterruptedProcess$", "-test.timeout=12s")
			cmd.Env = append(os.Environ(), "SSH_TEST_CRASH_PHASE="+phase, "SSH_TEST_IDENTITY="+path)
			pipe, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			scanner := bufio.NewScanner(pipe)
			boundary := false
			for scanner.Scan() {
				if scanner.Text() == "FAULT_BOUNDARY" {
					boundary = true
					break
				}
			}
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if !boundary {
				t.Fatal("child did not reach durability boundary")
			}
			restored, e := firewall.LoadIdentity(path)
			if e != nil {
				t.Fatal(e)
			}
			want := uint16(22)
			if phase == "after_snapshot" {
				want = 2222
			}
			if restored.Policy.Ports[0] != want {
				t.Fatal("restarted into wrong committed configuration")
			}
			s, e = state.OpenExisting(db)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			snap, e := s.Snapshot(context.Background(), now.Add(time.Minute))
			if e != nil {
				t.Fatal(e)
			}
			if len(snap.Grants) != 1 || snap.Grants[0].ExpiresAt != now.Add(5*time.Minute).Unix() {
				t.Fatal("crash lost or prolonged grant")
			}
		})
	}
}

type brokenClock struct{}

func (brokenClock) Check(context.Context) error { return fmt.Errorf("clock/storage checkpoint failed") }
func TestClockFaultRestoresBaselineWithoutGrant(t *testing.T) {
	c, f := controller(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.1")
	code, _ := totp.Code(c.Identity.Secret, c.now())
	if _, status := c.Authorize(ctx, ip, ip, code); status != 200 {
		t.Fatal(status)
	}
	c.Clock = brokenClock{}
	if _, status := c.Authorize(ctx, ip, ip, code); status != 503 {
		t.Fatal("accepted authorization with faulty clock")
	}
	if len(f.grants) != 0 {
		t.Fatal("temporary opening retained on clock failure")
	}
}

func TestReadOnlyStorageFailureCannotOpenPort(t *testing.T) {
	c, f := controller(t)
	path := filepath.Join(t.TempDir(), "readonly.db")
	s, e := state.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	ro, e := state.OpenReadOnly(path)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	c.Store = ro
	ip := netip.MustParseAddr("192.0.2.1")
	code, _ := totp.Code(c.Identity.Secret, c.now())
	if _, status := c.Authorize(context.Background(), ip, ip, code); status != 503 {
		t.Fatal("storage write failure reported success")
	}
	if len(f.grants) != 0 {
		t.Fatal("opened kernel before durable write")
	}
}
