//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
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
	})
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
