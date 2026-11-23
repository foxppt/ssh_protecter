package service

import (
	"context"
	"fmt"
	"ssh-protecter/internal/config"
	"ssh-protecter/internal/firewall"
	"time"
)

func Policy(c config.Config) firewall.Policy {
	return firewall.Policy{Ports: append([]uint16(nil), c.SSH.Ports...), IPv4: c.SSH.ProtectIPv4, IPv6: c.SSH.ProtectIPv6, PermanentIPs: append([]string(nil), c.SSH.PermanentAllowIPs...)}
}
func (c *Controller) Configuration() config.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Config.Clone()
}

// Reload serializes publication with authorization and reconciliation. persist must
// durably replace the bootstrap file; publish must be an infallible pointer swap.
// The bootstrap file is the crash-recovery commit point, not the edited YAML file.
func (c *Controller) Reload(ctx context.Context, next config.Config, persist func(firewall.Bootstrap) error, publish func()) error {
	return c.reload(ctx, next, persist, publish, false)
}

// ConfigureOffline may change listener settings only when the caller owns the
// exclusive process lock and no HTTP listener is running.
func (c *Controller) ConfigureOffline(ctx context.Context, next config.Config, persist func(firewall.Bootstrap) error) error {
	return c.reload(ctx, next, persist, nil, true)
}
func (c *Controller) reload(ctx context.Context, next config.Config, persist func(firewall.Bootstrap) error, publish func(), offline bool) error {
	next = next.Clone()
	if e := next.Validate(); e != nil {
		return e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.unhealthy != nil {
		return fmt.Errorf("cannot reload an unhealthy service")
	}
	if e := c.checkClock(ctx); e != nil {
		return e
	}
	if next.Storage.Path != c.Config.Storage.Path {
		return fmt.Errorf("storage path changes require explicit data migration")
	}
	if !offline && (next.HTTP.Listen != c.Config.HTTP.Listen || next.HTTP.Mode != c.Config.HTTP.Mode) {
		return fmt.Errorf("listen address and HTTP mode require offline configure; reload rejected")
	}
	if persist == nil {
		return fmt.Errorf("missing durable configuration writer")
	}
	snap, e := c.Store.Snapshot(ctx, c.now())
	if e != nil {
		return e
	}
	old := c.Identity
	// Migrate earlier identities to a full old snapshot for unambiguous rollback.
	if old.ActiveConfig == nil {
		v := c.Config.Clone()
		old.ActiveConfig = &v
	}
	candidate := old
	candidate.Policy = Policy(next)
	candidate.ActiveConfig = &next
	rollback := func(cause error, restoreFile bool) error {
		recovery, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var diskErr error
		if restoreFile {
			diskErr = persist(old)
		}
		fwErr := c.Firewall.Apply(recovery, old.Policy, snap.Grants)
		if diskErr != nil || fwErr != nil {
			c.poisoned = true
			c.unhealthy = fmt.Errorf("reload failed: %v; disk rollback: %v; firewall rollback: %v", cause, diskErr, fwErr)
			return c.unhealthy
		}
		return fmt.Errorf("reload rejected; previous configuration restored: %w", cause)
	}
	if e = c.Firewall.Apply(ctx, candidate.Policy, snap.Grants); e != nil {
		return rollback(e, false)
	}
	// Even a failed fsync may follow a successful rename, so always restore the old
	// file after any persist error. Never assume a reported failure had no effect.
	if e = persist(candidate); e != nil {
		return rollback(e, true)
	}
	c.Identity = candidate
	c.Config = next
	if publish != nil {
		publish()
	}
	return nil
}
