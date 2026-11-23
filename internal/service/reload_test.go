package service

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"ssh-protecter/internal/config"
	"ssh-protecter/internal/firewall"
	"ssh-protecter/internal/state"
	"ssh-protecter/internal/totp"
	"sync"
	"testing"
	"time"
)

type sequenceFirewall struct {
	policies []firewall.Policy
	results  []error
	grants   []state.Grant
}

func (f *sequenceFirewall) Apply(_ context.Context, p firewall.Policy, g []state.Grant) error {
	f.policies = append(f.policies, p)
	f.grants = append([]state.Grant(nil), g...)
	i := len(f.policies) - 1
	if i < len(f.results) {
		return f.results[i]
	}
	return nil
}

func TestReloadKeepsDeadlinesAndCommitsRecoverySnapshot(t *testing.T) {
	c, _ := controller(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.1")
	code, _ := totp.Code(c.Identity.Secret, c.now())
	first, status := c.Authorize(ctx, ip, ip, code)
	if status != 200 {
		t.Fatal(status)
	}
	// Keep an active ban while changing the future ban policy.
	banned := netip.MustParseAddr("192.0.2.2")
	for i := 0; i < 5; i++ {
		c.Authorize(ctx, banned, banned, "bad")
	}
	before, e := c.Store.Snapshot(ctx, c.now())
	if e != nil {
		t.Fatal(e)
	}
	c.Identity.Version = 1
	c.Identity.Initialized = true
	c.Identity.StoragePath = c.Config.Storage.Path
	f := &sequenceFirewall{}
	c.Firewall = f
	next := c.Configuration()
	next.SSH.Ports = []uint16{2222}
	next.SSH.PermanentAllowIPs = []string{"2001:db8::5"}
	next.Authorization.Duration = config.Duration(2 * time.Minute)
	next.Verification.BanDuration = config.Duration(time.Hour)
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	published := false
	if e = c.Reload(ctx, next, func(b firewall.Bootstrap) error { return firewall.SaveIdentity(path, b) }, func() { published = true }); e != nil {
		t.Fatal(e)
	}
	restored, e := firewall.LoadIdentity(path)
	if e != nil {
		t.Fatal(e)
	}
	if !published || restored.ActiveConfig == nil || !reflect.DeepEqual(restored.Policy, Policy(next)) {
		t.Fatal("new generation not committed")
	}
	after, e := c.Store.Snapshot(ctx, c.now())
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, after) || f.grants[0].ExpiresAt != first.ExpiresAt {
		t.Fatal("reload modified existing deadlines")
	}
	renewed, status := c.Authorize(ctx, ip, ip, code)
	if status != 200 || renewed.ExpiresAt != c.now().Add(2*time.Minute).Unix() {
		t.Fatal("new requests did not use new policy")
	}
}
func TestReloadRollbackStages(t *testing.T) {
	for _, stage := range []string{"kernel", "disk", "uncertain disk"} {
		t.Run(stage, func(t *testing.T) {
			c, _ := controller(t)
			old := c.Configuration()
			next := old.Clone()
			next.SSH.Ports = []uint16{2222}
			f := &sequenceFirewall{}
			if stage == "kernel" {
				f.results = []error{errors.New("apply failed"), nil}
			}
			c.Firewall = f
			saves := 0
			published := false
			e := c.Reload(context.Background(), next, func(firewall.Bootstrap) error {
				saves++
				if saves == 1 || stage == "uncertain disk" {
					return errors.New("disk failure")
				}
				return nil
			}, func() { published = true })
			if e == nil || published || !reflect.DeepEqual(c.Configuration(), old) {
				t.Fatal("failed reload published new config")
			}
			if len(f.policies) != 2 || !reflect.DeepEqual(f.policies[1], c.Identity.Policy) {
				t.Fatal("old firewall not restored")
			}
			if stage == "uncertain disk" {
				if c.Reconcile(context.Background()) == nil {
					t.Fatal("reconcile cleared unrecoverable snapshot failure")
				}
				if _, status := c.Authorize(context.Background(), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1"), "bad"); status != 503 {
					t.Fatal("authorized with uncertain generation")
				}
			} else if c.Reconcile(context.Background()) != nil {
				t.Fatal("successful rollback left service unusable")
			}
		})
	}
}
func TestReloadRejectsImmutableAndInvalidBeforeMutation(t *testing.T) {
	for _, change := range []func(*config.Config){func(c *config.Config) { c.HTTP.Listen = ":8443" }, func(c *config.Config) { c.Storage.Path = "new.db" }, func(c *config.Config) { c.SSH.Ports = nil }} {
		c, _ := controller(t)
		f := &sequenceFirewall{}
		c.Firewall = f
		next := c.Configuration()
		change(&next)
		if c.Reload(context.Background(), next, func(firewall.Bootstrap) error { t.Fatal("persisted invalid candidate"); return nil }, nil) == nil {
			t.Fatal("invalid reload accepted")
		}
		if len(f.policies) > 0 {
			t.Fatal("mutated firewall before validation")
		}
	}
}

func TestReloadSerializesWithAuthorization(t *testing.T) {
	c, _ := controller(t)
	f := &sequenceFirewall{}
	c.Firewall = f
	before := c.Configuration()
	code, _ := totp.Code(c.Identity.Secret, c.now())
	ip := netip.MustParseAddr("192.0.2.1")
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			next := before.Clone()
			next.Authorization.Duration = config.Duration(time.Duration(60+i) * time.Second)
			errs <- c.Reload(context.Background(), next, func(firewall.Bootstrap) error { return nil }, nil)
		}(i)
		go func() {
			defer wg.Done()
			_, status := c.Authorize(context.Background(), ip, ip, code)
			if status != 200 {
				errs <- errors.New("concurrent authorization failed")
			} else {
				errs <- nil
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	snap, e := c.Store.Snapshot(context.Background(), c.now())
	if e != nil {
		t.Fatal(e)
	}
	if len(snap.Grants) != 1 {
		t.Fatal("concurrent renewal created duplicate or lost authorization")
	}
}
