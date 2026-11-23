package service

import (
	"context"
	"fmt"
	"net/netip"
	"ssh-protecter/internal/config"
	"ssh-protecter/internal/firewall"
	"ssh-protecter/internal/state"
	"ssh-protecter/internal/totp"
	"sync"
	"time"
)

type Applier interface {
	Apply(context.Context, firewall.Policy, []state.Grant) error
}
type Controller struct {
	mu        sync.Mutex
	Config    config.Config
	Identity  firewall.Bootstrap
	Store     *state.Store
	Firewall  Applier
	Now       func() time.Time
	unhealthy error
	poisoned  bool
	Clock     interface{ Check(context.Context) error }
}
type Result struct {
	IP          string `json:"ip,omitempty"`
	ExpiresAt   int64  `json:"expires_at,omitempty"`
	Error       string `json:"error,omitempty"`
	BannedUntil int64  `json:"banned_until,omitempty"`
}

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
func (c *Controller) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconcile(ctx)
}
func (c *Controller) reconcile(ctx context.Context) error {
	if c.poisoned {
		return fmt.Errorf("reload recovery failed; restart required: %w", c.unhealthy)
	}
	if e := c.checkClock(ctx); e != nil {
		return e
	}
	snap, e := c.Store.Snapshot(ctx, c.now())
	if e == nil {
		e = c.Firewall.Apply(ctx, c.Identity.Policy, snap.Grants)
	}
	c.unhealthy = e
	return e
}
func (c *Controller) Authorize(ctx context.Context, source, target netip.Addr, code string) (Result, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authorize(ctx, source, target, code)
}
func (c *Controller) authorize(ctx context.Context, source, target netip.Addr, code string) (Result, int) {
	now := c.now()
	fail := func(e error) (Result, int) { c.unhealthy = e; return Result{Error: "service unavailable"}, 503 }
	if c.unhealthy != nil {
		return Result{Error: "service unavailable"}, 503
	}
	if e := c.checkClock(ctx); e != nil {
		return fail(e)
	}
	until, e := c.Store.BanUntil(ctx, source, now)
	if e != nil {
		return fail(e)
	}
	if until > 0 {
		return Result{Error: "verification source is banned", BannedUntil: until}, 429
	}
	if !totp.Verify(c.Identity.Secret, code, now) {
		r, e := c.Store.RecordFailure(ctx, source, now, c.Config.Verification.FailureWindow.Value(), c.Config.Verification.MaxFailures, c.Config.Verification.BanDuration.Value())
		if e != nil {
			return fail(e)
		}
		if r.BannedUntil > 0 {
			return Result{Error: "verification source is banned", BannedUntil: r.BannedUntil}, 429
		}
		return Result{Error: "invalid verification code"}, 401
	}
	if !target.IsValid() || target.Zone() != "" {
		return Result{Error: "invalid target IP"}, 400
	}
	target = target.Unmap()
	if (target.Is4() && !c.Identity.Policy.IPv4) || (target.Is6() && !c.Identity.Policy.IPv6) {
		return Result{Error: "target address family is not protected"}, 400
	}
	// Desired-state-first: a verified request is durable before kernel mutation.
	// A failed/lost response may still take effect during restart reconciliation.
	deadline := now.Add(c.Config.Authorization.Duration.Value())
	if e = c.Store.SaveGrant(ctx, target, c.Identity.UserID, deadline); e != nil {
		return fail(e)
	}
	if e = c.reconcile(ctx); e != nil {
		return fail(fmt.Errorf("reconcile verified request: %w", e))
	}
	return Result{IP: target.String(), ExpiresAt: deadline.Unix()}, 200
}

func (c *Controller) checkClock(ctx context.Context) error {
	if c.Clock == nil {
		return nil
	}
	if e := c.Clock.Check(ctx); e != nil {
		c.unhealthy = e
		recovery, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if fwErr := c.Firewall.Apply(recovery, c.Identity.Policy, nil); fwErr != nil {
			return fmt.Errorf("clock error: %v; baseline restore: %w", e, fwErr)
		}
		return e
	}
	return nil
}
