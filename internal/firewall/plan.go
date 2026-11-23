// Package firewall owns only the inet ssh_protecter table.
package firewall

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"ssh-protecter/internal/state"
)

const Table = "ssh_protecter"

// ApplyBudget is reserved from relative kernel timeouts, so a delayed nft commit
// cannot extend an absolute deadline. Restoration can expire up to this much early.
const ApplyBudget = 2 * time.Second

// EqualPolicy compares meaning, so nil/empty lists, ordering and IPv4-mapped
// spellings do not create false snapshot conflicts.
func EqualPolicy(a, b Policy) bool {
	if a.IPv4 != b.IPv4 || a.IPv6 != b.IPv6 || len(a.Ports) != len(b.Ports) || len(a.PermanentIPs) != len(b.PermanentIPs) {
		return false
	}
	ports := func(p Policy) string {
		v := append([]uint16(nil), p.Ports...)
		sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
		return fmt.Sprint(v)
	}
	ips := func(p Policy) string {
		var v []string
		for _, s := range p.PermanentIPs {
			a, e := address(s)
			if e != nil {
				return "invalid:" + s
			}
			v = append(v, a.String())
		}
		sort.Strings(v)
		return strings.Join(v, ",")
	}
	return ports(a) == ports(b) && ips(a) == ips(b)
}

type Policy struct {
	Ports        []uint16 `json:"ports"`
	IPv4         bool     `json:"ipv4"`
	IPv6         bool     `json:"ipv6"`
	PermanentIPs []string `json:"permanent_ips"`
}

func (p Policy) Validate() error {
	if len(p.Ports) == 0 {
		return fmt.Errorf("empty protected port set")
	}
	seen := map[uint16]bool{}
	for _, v := range p.Ports {
		if v == 0 || seen[v] {
			return fmt.Errorf("invalid or duplicate port %d", v)
		}
		seen[v] = true
	}
	addresses := map[netip.Addr]bool{}
	for _, v := range p.PermanentIPs {
		a, e := address(v)
		if e != nil {
			return e
		}
		if addresses[a] {
			return fmt.Errorf("duplicate IP %s", a)
		}
		addresses[a] = true
	}
	return nil
}
func address(s string) (netip.Addr, error) {
	a, e := netip.ParseAddr(s)
	if e != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid firewall IP %q", s)
	}
	return a.Unmap(), nil
}

// Render returns one nft transaction; no shell-interpolated input is accepted.
// now is sampled again immediately before application, not reused from validation.
func Render(p Policy, grants []state.Grant, now time.Time, reserve time.Duration) (string, error) {
	if e := p.Validate(); e != nil {
		return "", e
	}
	if reserve < 0 {
		return "", fmt.Errorf("negative execution reserve")
	}
	ports := append([]uint16(nil), p.Ports...)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	var b strings.Builder
	// destroy is idempotent; destroy+recreate must be submitted in one nft batch.
	fmt.Fprintf(&b, "destroy table inet %s\ntable inet %s {\n", Table, Table)
	b.WriteString(" set ports { type inet_service; elements = { ")
	for i, v := range ports {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d", v)
	}
	b.WriteString(" }; }\n")
	permanent := map[bool][]string{true: {}, false: {}}
	for _, s := range p.PermanentIPs {
		a, _ := address(s)
		permanent[a.Is4()] = append(permanent[a.Is4()], a.String())
	}
	temporary := map[bool][]string{true: {}, false: {}}
	seen := map[netip.Addr]bool{}
	for _, g := range grants {
		a, e := address(g.IP)
		if e != nil {
			return "", e
		}
		if seen[a] {
			return "", fmt.Errorf("duplicate grant IP %s", a)
		}
		seen[a] = true
		remaining := time.Unix(g.ExpiresAt, 0).Sub(now) - reserve
		if remaining < time.Millisecond {
			continue
		}
		temporary[a.Is4()] = append(temporary[a.Is4()], fmt.Sprintf("%s timeout %dms", a, remaining.Milliseconds()))
	}
	for _, v := range []struct {
		name, kind string
		v4         bool
	}{{"4", "ipv4_addr", true}, {"6", "ipv6_addr", false}} {
		sort.Strings(permanent[v.v4])
		sort.Strings(temporary[v.v4])
		for _, s := range []struct {
			name    string
			values  []string
			timeout bool
		}{{"permanent", permanent[v.v4], false}, {"temporary", temporary[v.v4], true}} {
			fmt.Fprintf(&b, " set %s%s { type %s; ", s.name, v.name, v.kind)
			if s.timeout {
				b.WriteString("flags timeout; ")
			}
			if len(s.values) > 0 {
				fmt.Fprintf(&b, "elements = { %s }; ", strings.Join(s.values, ", "))
			}
			b.WriteString("}\n")
		}
	}
	b.WriteString(" chain input_gate {\n  type filter hook input priority -10; policy accept;\n")
	if p.IPv4 {
		b.WriteString("  meta nfproto ipv4 tcp dport @ports jump ssh4\n")
	}
	if p.IPv6 {
		b.WriteString("  meta nfproto ipv6 tcp dport @ports jump ssh6\n")
	}
	b.WriteString(" }\n")
	for _, v := range []struct{ suffix, proto string }{{"4", "ip"}, {"6", "ip6"}} {
		fmt.Fprintf(&b, " chain ssh%s {\n  ct state established accept\n  ct state invalid drop\n  %s saddr @permanent%s accept\n  %s saddr @temporary%s accept\n  drop\n }\n", v.suffix, v.proto, v.suffix, v.proto, v.suffix)
	}
	b.WriteString("}\n")
	return b.String(), nil
}
