package service

import (
	"context"
	"fmt"
	"net/netip"
	"ssh-protecter/internal/config"
)

// Revoke removes desired state before kernel reconciliation, under the same lock
// as authorization. Never restore a revoked permission on a kernel failure.
func (c *Controller) Revoke(ctx context.Context, ip netip.Addr) error {
	if !ip.IsValid() || ip.Zone() != "" {
		return fmt.Errorf("invalid IP address")
	}
	ip = ip.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, value := range c.Identity.Policy.PermanentIPs {
		allowed, e := config.ParseIP(value)
		if e != nil {
			return e
		}
		if allowed == ip {
			return fmt.Errorf("%s is permanently allowlisted; remove it from ssh.permanent_allow_ips and reload", ip)
		}
	}
	if e := c.Store.RevokeGrant(ctx, ip); e != nil {
		return fmt.Errorf("persist revocation: %w", e)
	}
	if e := c.reconcile(ctx); e != nil {
		return fmt.Errorf("temporary grant removed from storage, but firewall reconciliation failed: %w", e)
	}
	return nil
}
