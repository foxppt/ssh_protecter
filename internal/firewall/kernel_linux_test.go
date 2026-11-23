//go:build linux

package firewall

import (
	"context"
	"os"
	"os/exec"
	"ssh-protecter/internal/state"
	"strings"
	"testing"
	"time"
)

// Opt-in only. All kernel mutations happen inside a fresh network namespace.
func TestKernelNamespace(t *testing.T) {
	if os.Getenv("SSH_PROTECTER_NFT_CHILD") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r := nativeRunner{}
		if e := r.Run(ctx, false, "add table inet unrelated\n"); e != nil {
			t.Fatal(e)
		}
		engine := Engine{Runner: r}
		p := Policy{Ports: []uint16{22}, IPv4: true, IPv6: true, PermanentIPs: []string{"192.0.2.5", "2001:db8::5"}}
		grants := []state.Grant{{IP: "192.0.2.6", ExpiresAt: time.Now().Add(time.Minute).Unix()}, {IP: "2001:db8::6", ExpiresAt: time.Now().Add(time.Minute).Unix()}}
		for i := 0; i < 2; i++ {
			if e := engine.Apply(ctx, p, grants); e != nil {
				t.Fatal(e)
			}
		}
		if e := r.Run(ctx, false, "destroy table inet ssh_protecter\nthis is invalid syntax\n"); e == nil {
			t.Fatal("invalid transaction accepted")
		}
		out, e := exec.CommandContext(ctx, "/usr/sbin/nft", "list", "tables").CombinedOutput()
		if e != nil {
			t.Fatalf("%s: %v", out, e)
		}
		if !strings.Contains(string(out), "inet unrelated") || !strings.Contains(string(out), "inet ssh_protecter") {
			t.Fatalf("lost tables after replacement/failed batch: %s", out)
		}
		return
	}
	if os.Getenv("SSH_PROTECTER_NFT_TEST") != "1" {
		t.Skip("set SSH_PROTECTER_NFT_TEST=1 as root on Linux to run isolated nft integration")
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("unshare", "--net", exe, "-test.run=^TestKernelNamespace$", "-test.v")
	cmd.Env = append(os.Environ(), "SSH_PROTECTER_NFT_CHILD=1")
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("isolated kernel test: %v\n%s", e, out)
	}
	t.Log(string(out))
}
