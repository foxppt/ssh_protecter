//go:build linux

package state

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestFilesystemENOSPC(t *testing.T) {
	if os.Getenv("SSH_TEST_TMPFS_CHILD") == "1" {
		dir := t.TempDir()
		if e := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=8m"); e != nil {
			t.Fatal(e)
		}
		defer unix.Unmount(dir, 0)
		path := filepath.Join(dir, "state.db")
		s := mustOpen(t, path)
		ctx := context.Background()
		now := time.Unix(1800000000, 0)
		ip := netip.MustParseAddr("192.0.2.1")
		if e := s.SaveGrant(ctx, ip, "owner", now.Add(time.Minute)); e != nil {
			t.Fatal(e)
		}
		filler := filepath.Join(dir, "filler")
		f, e := os.Create(filler)
		if e != nil {
			t.Fatal(e)
		}
		block := make([]byte, 65536)
		for {
			_, e = f.Write(block)
			if e != nil {
				break
			}
		}
		f.Close()
		if !errors.Is(e, unix.ENOSPC) {
			t.Fatalf("expected actual ENOSPC: %v", e)
		}
		if e = s.SaveGrant(ctx, netip.MustParseAddr("192.0.2.2"), string(make([]byte, 1<<20)), now.Add(time.Hour)); e == nil {
			t.Fatal("disk-full write succeeded")
		}
		s.Close()
		if e = os.Remove(filler); e != nil {
			t.Fatal(e)
		}
		s, e = OpenExisting(path)
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		snapshot, e := s.Snapshot(ctx, now)
		if e != nil {
			t.Fatal(e)
		}
		if len(snapshot.Grants) != 1 || snapshot.Grants[0].IP != ip.String() {
			t.Fatal("ENOSPC lost prior state or committed new grant")
		}
		return
	}
	if os.Getenv("SSH_PROTECTER_TMPFS_TEST") != "1" {
		t.Skip("opt-in mount-namespace disk-full test")
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("unshare", "--mount", "--propagation", "private", exe, "-test.run=^TestFilesystemENOSPC$", "-test.timeout=20s", "-test.v")
	cmd.Env = append(os.Environ(), "SSH_TEST_TMPFS_CHILD=1")
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("isolated disk-full test: %v\n%s", e, out)
	}
	t.Log(string(out))
}
