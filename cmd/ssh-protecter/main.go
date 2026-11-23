package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"ssh-protecter/internal/config"
	"ssh-protecter/internal/firewall"
	"ssh-protecter/internal/state"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func run(args []string, out, errs io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ssh-protecter <version|config-check|state-inspect|firewall-plan|guard|init|rebind|serve|reload|configure|clock-reset>")
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return fmt.Errorf("version takes no arguments")
		}
		fmt.Fprintln(out, version)
		return nil
	}
	if args[0] == "guard" {
		return runGuard(args[1:], out, errs)
	}
	if args[0] == "reload" {
		return runReload(args[1:], out, errs)
	}
	if args[0] == "init" || args[0] == "rebind" || args[0] == "serve" || args[0] == "configure" || args[0] == "clock-reset" {
		return runRuntime(args[0], args[1:], out, errs)
	}
	if args[0] != "config-check" && args[0] != "state-inspect" && args[0] != "firewall-plan" {
		return fmt.Errorf("unknown command %q", args[0])
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(errs)
	path := fs.String("config", "/etc/ssh-protecter/config.yaml", "configuration path")
	resources := fs.Bool("resources", false, "also check TLS files (config-check only)")
	restore := fs.Bool("restore", false, "include unexpired persisted grants (firewall-plan only)")
	installation := fs.Bool("installation", false, "require default paths for managed installer (config-check only)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *restore && args[0] != "firewall-plan" {
		return fmt.Errorf("--restore is only supported by firewall-plan")
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	if *installation {
		if args[0] != "config-check" {
			return fmt.Errorf("--installation is only for config-check")
		}
		if c.Storage.Path != "/var/lib/ssh-protecter/state.db" {
			return fmt.Errorf("managed installation requires /var/lib/ssh-protecter/state.db; use manual units for custom storage")
		}
	}
	if args[0] == "config-check" {
		if *resources && c.HTTP.Mode == "direct_tls" {
			if _, err = tls.LoadX509KeyPair(c.HTTP.TLSCertFile, c.HTTP.TLSKeyFile); err != nil {
				return fmt.Errorf("TLS files: %w", err)
			}
		}
		fmt.Fprintln(out, "configuration valid (firewall and systemd not checked)")
		return nil
	}
	if *resources {
		return fmt.Errorf("--resources is only supported by config-check")
	}
	if args[0] == "firewall-plan" {
		var grants []state.Grant
		if *restore {
			s, e := state.OpenReadOnly(c.Storage.Path)
			if e != nil {
				return e
			}
			defer s.Close()
			snap, e := s.Snapshot(context.Background(), time.Now())
			if e != nil {
				return e
			}
			grants = snap.Grants
		}
		script, e := firewall.Render(firewall.Policy{Ports: c.SSH.Ports, IPv4: c.SSH.ProtectIPv4, IPv6: c.SSH.ProtectIPv6, PermanentIPs: c.SSH.PermanentAllowIPs}, grants, time.Now(), firewall.ApplyBudget)
		if e != nil {
			return e
		}
		_, e = io.WriteString(out, script)
		return e
	}
	s, err := state.OpenReadOnly(c.Storage.Path)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := s.Snapshot(ctx, time.Now())
	if err != nil {
		return err
	}
	// This command intentionally does not claim to show the actual kernel firewall state.
	return json.NewEncoder(out).Encode(struct {
		Kind string `json:"kind"`
		state.Snapshot
	}{"desired_state_only", snapshot})
}

func runGuard(args []string, out, errs io.Writer) error {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	fs.SetOutput(errs)
	snapshot := fs.String("snapshot", "/etc/ssh-protecter/bootstrap.json", "last confirmed initialized protection snapshot")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	// This path does not load HTTP/TLS configuration or open/migrate the state DB.
	p, e := firewall.LoadBootstrap(*snapshot)
	if e != nil {
		return fmt.Errorf("load baseline: %w", e)
	}
	runner, release, e := firewall.AcquireNative()
	if e != nil {
		return e
	}
	defer release()
	engine := firewall.Engine{Runner: runner}
	if e = engine.Apply(context.Background(), p, nil); e != nil {
		return e
	}
	fmt.Fprintln(out, "baseline protection applied; existing SSH connections retained")
	return nil
}
