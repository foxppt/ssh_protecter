package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"ssh-protecter/internal/config"
	"ssh-protecter/internal/firewall"
	"ssh-protecter/internal/service"
	"testing"
)

func TestCorruptReloadFileLeavesLastGoodSnapshotUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	snapshot := filepath.Join(dir, "bootstrap.json")
	old := config.Defaults()
	identity := firewall.Bootstrap{Version: 1, Initialized: true, UserID: "owner", Secret: "test", StoragePath: old.Storage.Path, Policy: policy(old), ActiveConfig: &old}
	if e := firewall.SaveIdentity(snapshot, identity); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(snapshot)
	if e != nil {
		t.Fatal(e)
	}
	c := &service.Controller{Config: old, Identity: identity}
	certificates := &service.Certificates{}
	for _, data := range []string{"ssh: [broken", "unknown: true", "http:\n  tls_cert_file: missing-cert.pem\n  tls_key_file: missing-key.pem\n"} {
		if e = os.WriteFile(path, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
		if e = reloadFile(context.Background(), c, path, snapshot, certificates, nil); e == nil {
			t.Fatal("invalid file accepted")
		}
		after, e := os.ReadFile(snapshot)
		if e != nil {
			t.Fatal(e)
		}
		if string(before) != string(after) || !reflect.DeepEqual(c.Configuration(), old) {
			t.Fatal("bad file changed committed state")
		}
	}
	restored, e := firewall.LoadIdentity(snapshot)
	if e != nil || restored.ActiveConfig == nil || !reflect.DeepEqual(*restored.ActiveConfig, old) {
		t.Fatal("last good startup configuration was lost")
	}
}
