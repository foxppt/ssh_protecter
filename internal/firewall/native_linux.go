//go:build linux

package firewall

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strings"
)

type nativeRunner struct{}

func (nativeRunner) Run(ctx context.Context, check bool, script string) error {
	args := []string{"-f", "-"}
	if check {
		args = append([]string{"--check"}, args...)
	}
	cmd := exec.CommandContext(ctx, "/usr/sbin/nft", args...)
	cmd.Stdin = strings.NewReader(script)
	out, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("nft: %w: %s", e, strings.TrimSpace(string(out)))
	}
	return nil
}

// AcquireNative prevents multiple cooperating writers. Stale files are safe:
// flock is released by the kernel on process death, not by deleting the path.
func AcquireNative() (Runner, func(), error) {
	if os.Geteuid() != 0 {
		return nil, nil, fmt.Errorf("firewall application requires local root")
	}
	fd, e := unix.Open("/run/ssh-protecter.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, nil, e
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		unix.Close(fd)
		return nil, nil, fmt.Errorf("another firewall writer is running: %w", e)
	}
	return nativeRunner{}, func() { unix.Close(fd) }, nil
}
