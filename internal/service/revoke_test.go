package service

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestRevokeRemovesOnlyTargetAndSurvivesReconciliation(t *testing.T) {
	c, f := controller(t)
	ctx := context.Background()
	target := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("2001:db8::1")
	for _, ip := range []netip.Addr{target, other} {
		if e := c.Store.SaveGrant(ctx, ip, "owner", c.now().Add(5*time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	// The mapped spelling must remove the canonical IPv4 entry.
	if e := c.Revoke(ctx, netip.MustParseAddr("::ffff:192.0.2.1")); e != nil {
		t.Fatal(e)
	}
	if len(f.grants) != 1 || f.grants[0].IP != other.String() {
		t.Fatal("wrong firewall authorization removed")
	}
	if e := c.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	if len(f.grants) != 1 {
		t.Fatal("reconciliation resurrected revoked IP")
	}
	if e := c.Revoke(ctx, target); e != nil {
		t.Fatal("repeated revoke should be idempotent:", e)
	}
	if e := c.Revoke(ctx, other); e != nil {
		t.Fatal(e)
	}
	snapshot, e := c.Store.Snapshot(ctx, c.now())
	if e != nil {
		t.Fatal(e)
	}
	if len(snapshot.Grants) != 0 || len(f.grants) != 0 {
		t.Fatal("IPv6 authorization retained")
	}
}
func TestRevokeKernelFailureRemainsDurable(t *testing.T) {
	c, f := controller(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.1")
	if e := c.Store.SaveGrant(ctx, ip, "owner", c.now().Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	f.err = errors.New("kernel unavailable")
	if e := c.Revoke(ctx, ip); e == nil {
		t.Fatal("kernel failure was reported as success")
	}
	snapshot, e := c.Store.Snapshot(ctx, c.now())
	if e != nil {
		t.Fatal(e)
	}
	if len(snapshot.Grants) != 0 {
		t.Fatal("failed kernel call restored revoked permission")
	}
	f.err = nil
	if e = c.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	if len(f.grants) != 0 {
		t.Fatal("recovery resurrected revoked permission")
	}
}
func TestRevokePermanentOrInvalidIPDoesNotMutate(t *testing.T) {
	c, f := controller(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.1")
	c.Identity.Policy.PermanentIPs = []string{"::ffff:192.0.2.1"}
	if e := c.Store.SaveGrant(ctx, ip, "owner", c.now().Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := c.Revoke(ctx, ip); e == nil {
		t.Fatal("permanently allowlisted IP reported as revoked")
	}
	if e := c.Revoke(ctx, netip.Addr{}); e == nil {
		t.Fatal("invalid address accepted")
	}
	snapshot, e := c.Store.Snapshot(ctx, c.now())
	if e != nil {
		t.Fatal(e)
	}
	if len(snapshot.Grants) != 1 || f.grants != nil {
		t.Fatal("rejected revoke changed state")
	}
}
