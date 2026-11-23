package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigCheckDoesNotCreateState(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	db := filepath.Join(dir, "missing.db")
	data := "storage:\n  path: '" + strings.ReplaceAll(db, "'", "''") + "'\n"
	if err := os.WriteFile(cfg, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if err := run([]string{"config-check", "--config", cfg}, &out, &errs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatal("configuration check touched database")
	}
	if err := run([]string{"state-inspect", "--config", cfg}, &out, &errs); err == nil {
		t.Fatal("inspection accepted missing database")
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatal("inspection created database")
	}
	if err := run([]string{"config-check", "--config", cfg, "--resources"}, &out, &errs); err == nil {
		t.Fatal("resource check accepted missing certificate")
	}
}

func TestFirewallPlanIsOfflineAndGuardRequiresBootstrap(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("ssh:\n  ports: [2222]\n  protect_ipv6: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if err := run([]string{"firewall-plan", "--config", cfg}, &out, &errs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "elements = { 2222 }") || strings.Contains(out.String(), "meta nfproto ipv6") {
		t.Fatalf("wrong offline plan: %s", out.String())
	}
	if err := run([]string{"guard", "--snapshot", filepath.Join(dir, "missing.json")}, &out, &errs); err == nil {
		t.Fatal("guard accepted missing initialization")
	}
}
