package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"ssh-protecter/internal/config"
	"ssh-protecter/internal/firewall"
	"ssh-protecter/internal/service"
	"ssh-protecter/internal/state"
	"ssh-protecter/internal/timeguard"
	"ssh-protecter/internal/totp"
)

func policy(c config.Config) firewall.Policy {
	return service.Policy(c)
}

func runRuntime(command string, args []string, out, errs io.Writer) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(errs)
	path := fs.String("config", "/etc/ssh-protecter/config.yaml", "configuration path")
	snapshot := fs.String("snapshot", "/etc/ssh-protecter/bootstrap.json", "private identity and baseline path")
	adminSocket := fs.String("socket", "/run/ssh-protecter/admin.sock", "local control socket")
	revokeGrants := fs.Bool("revoke-grants", false, "acknowledge revoking all temporary grants for clock-reset")
	showQR := fs.Bool("qr", true, "show a terminal QR code during initial binding/rebinding; use --qr=false for plain text")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	runner, release, e := firewall.AcquireNative()
	if e != nil {
		return e
	}
	defer release()
	engine := &firewall.Engine{Runner: runner}
	if command == "init" || command == "rebind" {
		return bind(*path, *snapshot, command == "rebind", *showQR, out, engine)
	}
	identity, e := firewall.LoadIdentity(*snapshot)
	if os.IsNotExist(e) {
		if command != "serve" {
			return fmt.Errorf("not initialized; run init from the local console")
		}
		if e = bind(*path, *snapshot, false, *showQR, out, engine); e != nil {
			return fmt.Errorf("first startup initialization: %w", e)
		}
		identity, e = firewall.LoadIdentity(*snapshot)
	}
	if e != nil {
		return e
	}
	if _, e = totp.Code(identity.Secret, time.Now()); e != nil {
		return fmt.Errorf("invalid stored identity")
	}
	// Install the last confirmed baseline before loading possibly broken current config.
	if e = engine.Apply(context.Background(), identity.Policy, nil); e != nil {
		return e
	}
	var c config.Config
	if identity.ActiveConfig != nil {
		c = identity.ActiveConfig.Clone()
		e = c.Validate()
	} else {
		c, e = config.Load(*path)
	}
	if e != nil {
		return e
	}
	if !firewall.EqualPolicy(policy(c), identity.Policy) {
		return fmt.Errorf("SSH policy differs from initialized baseline")
	}
	if identity.StoragePath != c.Storage.Path {
		return fmt.Errorf("storage path differs from initialized identity; migration is required")
	}
	var cert *tls.Certificate
	if command != "configure" && command != "clock-reset" {
		cert, e = service.PrepareCertificate(c)
		if e != nil {
			return e
		}
	}
	certificates := &service.Certificates{}
	certificates.Publish(cert)
	store, e := state.OpenExisting(c.Storage.Path)
	if e != nil {
		return e
	}
	defer store.Close()
	if command == "clock-reset" {
		if !*revokeGrants {
			return fmt.Errorf("clock-reset requires --revoke-grants; stop the service and correct/synchronize time first")
		}
		if e = timeguard.CheckSynchronized(); e != nil {
			return e
		}
		if e = engine.Apply(context.Background(), identity.Policy, nil); e != nil {
			return e
		}
		if e = store.ResetClock(context.Background(), time.Now()); e != nil {
			return e
		}
		fmt.Fprintln(out, "clock checkpoint reset; all temporary grants revoked; ban deadlines retained")
		return nil
	}
	clock := timeguard.New(store, c.Clock.RequireSync, c.Clock.MaxSkew.Value())
	controller := &service.Controller{Config: c, Identity: identity, Store: store, Firewall: engine, Clock: clock}
	if command == "configure" {
		next, err := config.Load(*path)
		if err != nil {
			return err
		}
		if _, err = service.PrepareCertificate(next); err != nil {
			return err
		}
		if next.Clock.RequireSync {
			if err = timeguard.CheckSynchronized(); err != nil {
				return err
			}
		}
		if err = controller.ConfigureOffline(context.Background(), next, func(b firewall.Bootstrap) error { return firewall.SaveIdentity(*snapshot, b) }); err != nil {
			return err
		}
		fmt.Fprintln(out, "configuration activated; start serve to open the configured listener")
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e = controller.Reconcile(ctx); e != nil {
		return e
	}
	ln, e := net.Listen("tcp", c.HTTP.Listen)
	if e != nil {
		return e
	}
	defer ln.Close()
	if c.HTTP.Mode == "direct_tls" {
		ln = tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certificates.GetCertificate})
	}
	server := &http.Server{Handler: service.Handler(controller), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	defer server.Close()
	closeAdmin, e := startAdmin(*adminSocket, func(reloadCtx context.Context) error {
		err := reloadFile(reloadCtx, controller, *path, *snapshot, certificates, clock)
		if err != nil {
			fmt.Fprintln(errs, "reload failed:", err)
		} else {
			fmt.Fprintln(out, "configuration reloaded")
		}
		return err
	}, controller.Revoke)
	if e != nil {
		return e
	}
	defer closeAdmin()
	probeAddr := ln.Addr().(*net.TCPAddr)
	probeHost := probeAddr.IP.String()
	if probeAddr.IP.IsUnspecified() {
		if probeAddr.IP.To4() != nil {
			probeHost = "127.0.0.1"
		} else {
			probeHost = "::1"
		}
	}
	probeURL := "http://" + net.JoinHostPort(probeHost, fmt.Sprint(probeAddr.Port)) + "/health"
	if c.HTTP.Mode == "direct_tls" {
		probeURL = "https" + strings.TrimPrefix(probeURL, "http")
	}
	// Probe only the listener's numeric loopback/local address, never an external URL.
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	probe := func() error {
		response, err := client.Get(probeURL)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return fmt.Errorf("HTTP health probe failed")
		}
		return nil
	}
	if e = probe(); e != nil {
		return e
	}
	if e = notify("READY=1"); e != nil {
		return e
	}
	fmt.Fprintln(out, "authorization service ready on", c.HTTP.Listen)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = notify("STOPPING=1")
			return server.Shutdown(shutdown)
		case e = <-done:
			if errors.Is(e, http.ErrServerClosed) {
				return nil
			}
			return e
		case <-ticker.C:
			now := time.Now()
			check, cancel := context.WithTimeout(ctx, 8*time.Second)
			e = controller.Reconcile(check)
			if e == nil {
				e = store.Cleanup(check, now, controller.Configuration().Verification.FailureWindow.Value())
			}
			cancel()
			if e != nil {
				return e
			}
			if e = probe(); e != nil {
				return e
			}
			if e = notify("WATCHDOG=1"); e != nil {
				return e
			}
		}
	}
}

func reloadFile(ctx context.Context, controller *service.Controller, path, snapshot string, certificates *service.Certificates, clock *timeguard.Guard) error {
	next, err := config.Load(path)
	if err != nil {
		return err
	}
	prepared, err := service.PrepareCertificate(next)
	if err != nil {
		return err
	}
	if next.Clock.RequireSync {
		if err = timeguard.CheckSynchronized(); err != nil {
			return err
		}
	}
	return controller.Reload(ctx, next, func(b firewall.Bootstrap) error { return firewall.SaveIdentity(snapshot, b) }, func() {
		certificates.Publish(prepared)
		if clock != nil {
			clock.Configure(next.Clock.RequireSync, next.Clock.MaxSkew.Value())
		}
	})
}

func bind(configPath, snapshot string, rebind, showQR bool, out io.Writer, engine *firewall.Engine) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("binding requires a local interactive terminal; run init from the server console")
	}
	_, statErr := os.Stat(snapshot)
	if !rebind && statErr == nil {
		return fmt.Errorf("already initialized; use rebind to replace the authenticator")
	}
	if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	if rebind && os.IsNotExist(statErr) {
		return fmt.Errorf("not initialized; use init")
	}
	c, e := config.Load(configPath)
	if e != nil {
		return e
	}
	if rebind {
		old, err := firewall.LoadIdentity(snapshot)
		if err != nil {
			return err
		}
		if old.StoragePath != c.Storage.Path {
			return fmt.Errorf("rebind cannot change storage path")
		}
	}
	if c.Clock.RequireSync {
		if e = timeguard.CheckSynchronized(); e != nil {
			return e
		}
	}
	secret, e := totp.NewSecret()
	if e != nil {
		return e
	}
	host, _ := os.Hostname()
	columns, _, sizeErr := term.GetSize(int(os.Stdout.Fd()))
	if sizeErr != nil {
		columns = 80
	}
	if e = writeBindingInfo(out, secret, host, showQR, columns); e != nil {
		return e
	}
	fmt.Fprint(out, "Verification code: ")
	input, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	if e != nil {
		return e
	}
	if !totp.Verify(secret, strings.TrimSpace(string(input)), time.Now()) {
		return fmt.Errorf("invalid code; no binding or firewall change applied")
	}
	var store *state.Store
	if rebind {
		store, e = state.OpenExisting(c.Storage.Path)
	} else {
		store, e = state.Open(c.Storage.Path)
	}
	if e != nil {
		return e
	}
	defer store.Close()
	clock := timeguard.New(store, c.Clock.RequireSync, c.Clock.MaxSkew.Value())
	if e = clock.Check(context.Background()); e != nil {
		return e
	}
	// Rebinding revokes durable grants before applying the restrictive baseline.
	if rebind {
		if e = store.RevokeAll(context.Background()); e != nil {
			return e
		}
		if e = engine.Apply(context.Background(), policy(c), nil); e != nil {
			return e
		}
	}
	savedConfig := c.Clone()
	identity := firewall.Bootstrap{Version: 1, Initialized: true, Policy: policy(c), UserID: "owner", Secret: secret, StoragePath: c.Storage.Path, ActiveConfig: &savedConfig}
	if e = firewall.SaveIdentity(snapshot, identity); e != nil {
		return e
	}
	if e = engine.Apply(context.Background(), identity.Policy, nil); e != nil {
		return fmt.Errorf("binding saved but baseline application failed; retry serve after repair: %w", e)
	}
	fmt.Fprintln(out, "Authenticator bound and baseline protection applied. Identity:", filepath.Clean(snapshot))
	return nil
}

func writeBindingInfo(out io.Writer, secret, account string, showQR bool, columns int) error {
	if _, e := fmt.Fprintln(out, "Add a TOTP account in your authenticator using the QR code or manual secret below."); e != nil {
		return e
	}
	if showQR {
		graphic, width, e := totp.TerminalQR(secret, account)
		if e != nil {
			return fmt.Errorf("generate local binding QR: %w", e)
		}
		if columns >= width {
			if _, e = io.WriteString(out, graphic); e != nil {
				return e
			}
		} else {
			if _, e = fmt.Fprintf(out, "QR needs %d columns; widen this terminal or enter the secret manually.\n", width); e != nil {
				return e
			}
		}
	}
	if _, e := fmt.Fprintln(out, "Manual secret (SHA1, 6 digits, 30 seconds):", secret); e != nil {
		return e
	}
	_, e := fmt.Fprintln(out, totp.URI(secret, account))
	return e
}

func notify(message string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if strings.HasPrefix(path, "@") {
		path = "\x00" + path[1:]
	}
	conn, e := net.DialTimeout("unixgram", path, time.Second)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, e = io.WriteString(conn, message)
	return e
}
