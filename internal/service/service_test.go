package service

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"ssh-protecter/internal/config"
	"ssh-protecter/internal/firewall"
	"ssh-protecter/internal/state"
	"ssh-protecter/internal/totp"
	"strings"
	"testing"
	"time"
)

type fakeFirewall struct {
	grants []state.Grant
	err    error
}

func (f *fakeFirewall) Apply(_ context.Context, _ firewall.Policy, g []state.Grant) error {
	f.grants = append([]state.Grant(nil), g...)
	return f.err
}
func controller(t *testing.T) (*Controller, *fakeFirewall) {
	t.Helper()
	store, e := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	secret, e := totp.NewSecret()
	if e != nil {
		t.Fatal(e)
	}
	f := &fakeFirewall{}
	now := time.Unix(1800000000, 0)
	return &Controller{Config: config.Defaults(), Identity: firewall.Bootstrap{UserID: "owner", Secret: secret, Policy: firewall.Policy{Ports: []uint16{22}, IPv4: true, IPv6: true}}, Store: store, Firewall: f, Now: func() time.Time { return now }}, f
}
func TestAuthorizationReplayRenewalAndRecovery(t *testing.T) {
	c, f := controller(t)
	ctx := context.Background()
	source := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("2001:db8::1")
	code, _ := totp.Code(c.Identity.Secret, c.now())
	r, status := c.Authorize(ctx, source, target, code)
	if status != 200 || len(f.grants) != 1 {
		t.Fatalf("%+v %d", r, status)
	}
	// Same code may authorize another address; source identity is not the grant key.
	if _, status = c.Authorize(ctx, source, source, code); status != 200 {
		t.Fatal("replay rejected")
	}
	now := c.now().Add(3 * time.Minute)
	c.Now = func() time.Time { return now }
	code, _ = totp.Code(c.Identity.Secret, now)
	r, status = c.Authorize(ctx, source, target, code)
	if status != 200 || r.ExpiresAt != now.Add(5*time.Minute).Unix() {
		t.Fatalf("renewal %+v %d", r, status)
	}
	c.Now = func() time.Time { return now.Add(time.Minute) }
	if e := c.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	for _, g := range f.grants {
		if g.IP == target.String() && g.ExpiresAt != r.ExpiresAt {
			t.Fatal("recovery extended deadline")
		}
	}
}
func TestSourceBanAndKernelFailureRecovery(t *testing.T) {
	c, f := controller(t)
	ctx := context.Background()
	source := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("192.0.2.2")
	for i := 0; i < 5; i++ {
		_, status := c.Authorize(ctx, source, target, "wrong")
		if i == 4 && status != 429 {
			t.Fatal("source not banned")
		}
	}
	code, _ := totp.Code(c.Identity.Secret, c.now())
	if _, status := c.Authorize(ctx, source, target, code); status != 429 {
		t.Fatal("valid code bypassed ban")
	}
	f.err = errors.New("kernel unavailable")
	if _, status := c.Authorize(ctx, target, target, code); status != 503 {
		t.Fatal("kernel failure returned success")
	}
	if _, status := c.Authorize(ctx, netip.MustParseAddr("192.0.2.3"), target, code); status != 503 {
		t.Fatal("continued accepting while unhealthy")
	}
	f.err = nil
	if e := c.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	if len(f.grants) != 1 || f.grants[0].IP != target.String() {
		t.Fatal("verified durable request not recovered")
	}
}
func TestSourceHeaderTrust(t *testing.T) {
	c := config.Defaults()
	r := httptest.NewRequest("GET", "https://example.test/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	got, e := SourceIP(r, c)
	if e != nil || got.String() != "192.0.2.1" {
		t.Fatal("direct client spoofed source")
	}
	c.HTTP.Mode = "reverse_proxy"
	c.HTTP.TrustedProxies = []string{"127.0.0.1/32"}
	if _, e = SourceIP(r, c); e == nil {
		t.Fatal("untrusted proxy accepted")
	}
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.1")
	got, e = SourceIP(r, c)
	if e != nil || got.String() != "198.51.100.1" {
		t.Fatalf("trusted spoofed leftmost: %s %v", got, e)
	}
}
func TestHTTPFormCSRFAndAuthorization(t *testing.T) {
	c, _ := controller(t)
	h := Handler(c)
	get := httptest.NewRequest("GET", "https://example.test/", nil)
	get.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, get)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatal("unsafe csrf cookie")
	}
	code, _ := totp.Code(c.Identity.Secret, c.now())
	form := url.Values{"ip": {"2001:db8::1"}, "code": {code}, "csrf": {cookies[0].Value}}
	post := func(origin string, withCookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://example.test/authorize", strings.NewReader(form.Encode()))
		r.RemoteAddr = get.RemoteAddr
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		if withCookie {
			r.AddCookie(cookies[0])
		}
		out := httptest.NewRecorder()
		h.ServeHTTP(out, r)
		return out
	}
	if out := post("https://evil.test", true); out.Code != 403 {
		t.Fatal("cross-origin request accepted", out.Code)
	}
	if out := post("https://example.test", false); out.Code != 403 {
		t.Fatal("missing cookie accepted", out.Code)
	}
	if out := post("https://example.test", true); out.Code != 200 || !strings.Contains(out.Body.String(), "2001:db8::1") {
		t.Fatalf("authorization: %d %s", out.Code, out.Body.String())
	}
}
