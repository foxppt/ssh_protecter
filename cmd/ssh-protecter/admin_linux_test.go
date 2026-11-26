//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixReloadWaitsForResult(t *testing.T) {
	// Keep below Linux's sockaddr_un path length limit regardless of checkout path.
	dir, e := os.MkdirTemp("", "sshctl-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "admin.sock")
	calls := 0
	close, e := startAdmin(socket, func(context.Context) error {
		calls++
		if calls == 2 {
			return errors.New("candidate rejected")
		}
		return nil
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	var out bytes.Buffer
	if e = requestReload(socket, &out); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "reloaded") {
		t.Fatal("missing completion acknowledgement")
	}
	if e = requestReload(socket, &out); e == nil || !strings.Contains(e.Error(), "candidate rejected") {
		t.Fatal("reload failure not propagated")
	}
	info, e := os.Stat(socket)
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe socket permissions")
	}
}

func TestUnixRevokeCanonicalAddressAndFailure(t *testing.T) {
	dir, e := os.MkdirTemp("", "sshrevoke-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "admin.sock")
	calls := 0
	close, e := startAdmin(socket, func(context.Context) error { return nil }, func(_ context.Context, ip netip.Addr) error {
		calls++
		if ip.String() != "192.0.2.1" {
			return errors.New("IP was not canonicalized")
		}
		if calls == 2 {
			return errors.New("permanent allowlist conflict")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	var out bytes.Buffer
	if e = requestAdmin(socket, "/revoke?ip=%3A%3Affff%3A192.0.2.1", &out); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "revoked for 192.0.2.1") {
		t.Fatal("missing completion acknowledgement")
	}
	if e = requestAdmin(socket, "/revoke?ip=192.0.2.1", &out); e == nil || !strings.Contains(e.Error(), "permanent allowlist") {
		t.Fatal("controller failure not propagated")
	}
	if e = requestAdmin(socket, "/revoke?ip=invalid", &out); e == nil {
		t.Fatal("invalid address accepted")
	}
	if calls != 2 {
		t.Fatal("invalid request reached controller")
	}
}
