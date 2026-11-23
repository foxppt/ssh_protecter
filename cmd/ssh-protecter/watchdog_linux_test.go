//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A uniquely named transient unit, never the installed application service.
func TestSystemdRecoversStoppedProcess(t *testing.T) {
	if os.Getenv("SSH_TEST_WATCHDOG_CHILD") == "1" {
		marker := os.Getenv("SSH_TEST_WATCHDOG_MARKER")
		f, e := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		first := e == nil
		if f != nil {
			f.Close()
		}
		if e != nil && !os.IsExist(e) {
			t.Fatal(e)
		}
		if e = notify("READY=1\nWATCHDOG=1"); e != nil {
			t.Fatal(e)
		}
		if first {
			_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
		}
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			if e = notify("WATCHDOG=1"); e != nil {
				t.Fatal(e)
			}
		}
		return
	}
	if os.Getenv("SSH_PROTECTER_SYSTEMD_TEST") != "1" {
		t.Skip("opt-in isolated transient systemd watchdog test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	dir, e := os.MkdirTemp("", "ssh-watchdog-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	unit := "ssh-protecter-test-watchdog-" + strconv.Itoa(os.Getpid()) + ".service"
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	defer func() {
		_ = exec.Command("systemctl", "stop", unit).Run()
		_ = exec.Command("systemctl", "reset-failed", unit).Run()
	}()
	args := []string{"--no-block", "--collect", "--unit=" + unit, "--property=Type=notify", "--property=NotifyAccess=main", "--property=WatchdogSec=2s", "--property=TimeoutAbortSec=1s", "--property=Restart=always", "--property=RestartSec=100ms", "--property=RuntimeMaxSec=30s", "--property=LimitCORE=0", "--setenv=SSH_TEST_WATCHDOG_CHILD=1", "--setenv=SSH_TEST_WATCHDOG_MARKER=" + filepath.Join(dir, "once"), exe, "-test.run=^TestSystemdRecoversStoppedProcess$"}
	out, e := exec.CommandContext(ctx, "systemd-run", args...).CombinedOutput()
	if e != nil {
		t.Fatalf("systemd-run: %v %s", e, out)
	}
	for ctx.Err() == nil {
		out, e = exec.CommandContext(ctx, "systemctl", "show", unit, "--property=NRestarts", "--property=ActiveState").CombinedOutput()
		if e == nil && strings.Contains(string(out), "ActiveState=active") {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "NRestarts=") {
					n, _ := strconv.Atoi(strings.TrimPrefix(line, "NRestarts="))
					if n >= 1 {
						t.Log("stopped process was killed and restarted by watchdog")
						return
					}
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal(fmt.Sprintf("watchdog did not recover stopped child: %s", out))
}
