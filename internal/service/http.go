package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"ssh-protecter/internal/config"
	"strings"
	"time"
)

func (c *Controller) requestSource(r *http.Request) (netip.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SourceIP(r, c.Config)
}
func (c *Controller) authorizeRequest(r *http.Request, targetString, code string) (Result, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	source, e := SourceIP(r, c.Config)
	if e != nil {
		return Result{Error: "invalid request source"}, 400
	}
	target := source
	if targetString != "" {
		target, e = config.ParseIP(targetString)
		if e != nil {
			return Result{Error: "invalid target IP"}, 400
		}
	}
	return c.authorize(r.Context(), source, target, code)
}

func SourceIP(r *http.Request, c config.Config) (netip.Addr, error) {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return netip.Addr{}, e
	}
	peer, e := config.ParseIP(host)
	if e != nil {
		return peer, e
	}
	if c.HTTP.Mode != "reverse_proxy" {
		return peer, nil
	}
	trusted := func(a netip.Addr) bool {
		for _, s := range c.HTTP.TrustedProxies {
			p, e := netip.ParsePrefix(s)
			if e == nil && p.Contains(a) {
				return true
			}
		}
		return false
	}
	if !trusted(peer) {
		return netip.Addr{}, http.ErrNotSupported
	}
	// Walk from the actual peer toward the client; stop at the first untrusted hop.
	values := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	if len(values) > 16 {
		return netip.Addr{}, http.ErrNotSupported
	}
	current := peer
	for i := len(values) - 1; i >= 0; i-- {
		if !trusted(current) {
			break
		}
		current, e = config.ParseIP(strings.TrimSpace(values[i]))
		if e != nil {
			return netip.Addr{}, e
		}
	}
	return current, nil
}

var page = template.Must(template.New("authorize").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SSH 访问授权</title><body><main><h1>SSH 访问授权</h1><p>输入验证器动态验证码，临时允许指定 IP 建立 SSH 连接。</p><form method="post" action="/authorize"><input type="hidden" name="csrf" value="{{.Token}}"><p><label>待放行 IP <input name="ip" value="{{.IP}}" required></label></p><p><label>动态验证码 <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label></p><button>申请放行</button></form><p>再次授权将从本次成功重新计时；已有 SSH 连接不因到期而中断。返回结果中 expires_at 是 Unix 秒。</p></main></body></html>`))

func Handler(c *Controller) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.unhealthy != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		if _, e := c.Store.Snapshot(r.Context(), c.now()); e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.WriteHeader(200)
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		ip, e := c.requestSource(r)
		if e != nil {
			http.Error(w, "invalid request source", 400)
			return
		}
		b := make([]byte, 32)
		if _, e = rand.Read(b); e != nil {
			http.Error(w, "service unavailable", 503)
			return
		}
		token := hex.EncodeToString(b)
		http.SetCookie(w, &http.Cookie{Name: "__Host-ssh-csrf", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 600})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, struct{ Token, IP string }{token, ip.String()})
	})
	mux.HandleFunc("POST /authorize", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if e := r.ParseForm(); e != nil {
			http.Error(w, "invalid form", 400)
			return
		}
		cookie, e := r.Cookie("__Host-ssh-csrf")
		token := r.PostForm.Get("csrf")
		if e != nil || len(token) != 64 || len(cookie.Value) != 64 || subtle.ConstantTimeCompare([]byte(token), []byte(cookie.Value)) != 1 {
			http.Error(w, "invalid request token", 403)
			return
		}
		result, status := c.authorizeRequest(r, r.PostForm.Get("ip"), r.PostForm.Get("code"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(result)
	})
	protected := http.NewCrossOriginProtection().Handler(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		protected.ServeHTTP(w, r.WithContext(ctx))
	})
}
