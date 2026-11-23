package timeguard

import (
	"context"
	"errors"
	"path/filepath"
	"ssh-protecter/internal/state"
	"testing"
	"time"
)

func TestRestartRollbackIsLatchedAndResetRevokesGrants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, e := state.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	if e = s.CheckpointClock(ctx, now, 2*time.Second); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = state.OpenExisting(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.CheckpointClock(ctx, now.Add(-time.Hour), 2*time.Second); e == nil {
		t.Fatal("reboot rollback accepted")
	}
	s.Close()
	s, e = state.OpenExisting(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.CheckpointClock(ctx, now.Add(time.Hour), 2*time.Second); e == nil {
		t.Fatal("restart cleared durable fault")
	}
	if e = s.ResetClock(ctx, now); e != nil {
		t.Fatal(e)
	}
	if e = s.CheckpointClock(ctx, now, 2*time.Second); e != nil {
		t.Fatal(e)
	}
}
func TestRuntimeForwardAndBackwardSteps(t *testing.T) {
	for _, step := range []time.Duration{-time.Hour, time.Hour} {
		t.Run(step.String(), func(t *testing.T) {
			s, e := state.Open(filepath.Join(t.TempDir(), "db"))
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			ctx := context.Background()
			wall := time.Unix(1800000000, 0)
			mono := time.Duration(0)
			g := New(s, false, 2*time.Second)
			g.Now = func() time.Time { return wall }
			g.Monotonic = func() time.Duration { return mono }
			if e = g.Check(ctx); e != nil {
				t.Fatal(e)
			}
			wall = wall.Add(10*time.Second + step)
			mono += 10 * time.Second
			if e = g.Check(ctx); e == nil {
				t.Fatal("clock step accepted")
			}
			other := New(s, false, 2*time.Second)
			other.Now = func() time.Time { return time.Unix(1800000010, 0) }
			if e = other.Check(ctx); e == nil {
				t.Fatal("new process forgot step fault")
			}
		})
	}
}
func TestUnsynchronizedBootDoesNotAdvanceAnchor(t *testing.T) {
	s, e := state.Open(filepath.Join(t.TempDir(), "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	g := New(s, true, 2*time.Second)
	g.Now = func() time.Time { return time.Unix(2000000000, 0) }
	g.Synchronized = func() error { return errors.New("unsynchronized") }
	if g.Check(ctx) == nil {
		t.Fatal("untrusted boot time accepted")
	}
	// A bad RTC in the future must not poison a checkpoint before NTP sync.
	g.Now = func() time.Time { return time.Unix(1800000000, 0) }
	g.Synchronized = func() error { return nil }
	if e = g.Check(ctx); e != nil {
		t.Fatal("NTP correction could not recover unsynchronized boot:", e)
	}
}
