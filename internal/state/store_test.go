package state

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func mustOpen(t *testing.T, path string) *Store {
	t.Helper()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestDeadlinesSurviveRestartAndExpire(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s := mustOpen(t, path)
	now := time.Unix(1800000000, 0)
	ip := netip.MustParseAddr("2001:db8::1")
	if e := s.SaveGrant(ctx, ip, "owner", now.Add(5*time.Minute)); e != nil {
		t.Fatal(e)
	}
	// Renewal replaces the original deadline rather than adding remaining time.
	if e := s.SaveGrant(ctx, ip, "owner", now.Add(8*time.Minute)); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		if _, e := s.RecordFailure(ctx, ip, now, time.Hour, 5, 24*time.Hour); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s = mustOpen(t, path)
	defer s.Close()
	got, e := s.Snapshot(ctx, now.Add(6*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Grants) != 1 || got.Grants[0].ExpiresAt != now.Add(8*time.Minute).Unix() || len(got.Bans) != 1 || got.Bans[0].ExpiresAt != now.Add(24*time.Hour).Unix() {
		t.Fatalf("wrong restored state: %+v", got)
	}
	got, e = s.Snapshot(ctx, now.Add(8*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Grants) != 0 {
		t.Fatal("grant active at deadline")
	}
	got, e = s.Snapshot(ctx, now.Add(24*time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Bans) != 0 {
		t.Fatal("ban active at deadline")
	}
}
func TestFailureWindowAndBanNotExtended(t *testing.T) {
	s := mustOpen(t, filepath.Join(t.TempDir(), "state.db"))
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	ip := netip.MustParseAddr("192.0.2.1")
	for i := 0; i < 4; i++ {
		r, e := s.RecordFailure(ctx, ip, now, time.Hour, 5, 24*time.Hour)
		if e != nil || r.BannedUntil != 0 {
			t.Fatalf("unexpected: %+v %v", r, e)
		}
	}
	// An event exactly one hour old falls outside the rolling interval.
	r, e := s.RecordFailure(ctx, ip, now.Add(time.Hour), time.Hour, 5, 24*time.Hour)
	if e != nil || r.Failures != 1 || r.BannedUntil != 0 {
		t.Fatalf("window: %+v %v", r, e)
	}
	for i := 0; i < 4; i++ {
		r, e = s.RecordFailure(ctx, ip, now.Add(time.Hour), time.Hour, 5, 24*time.Hour)
		if e != nil {
			t.Fatal(e)
		}
	}
	deadline := r.BannedUntil
	r, e = s.RecordFailure(ctx, ip, now.Add(2*time.Hour), time.Hour, 5, 24*time.Hour)
	if e != nil || !r.AlreadyBanned || r.BannedUntil != deadline {
		t.Fatalf("ban was extended: %+v %v", r, e)
	}
}
func TestConcurrentFailuresAndMappedIP(t *testing.T) {
	s := mustOpen(t, filepath.Join(t.TempDir(), "state.db"))
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := "192.0.2.1"
			if i%2 == 0 {
				a = "::ffff:192.0.2.1"
			}
			_, e := s.RecordFailure(ctx, netip.MustParseAddr(a), now, time.Hour, 5, 24*time.Hour)
			errs <- e
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	got, e := s.Snapshot(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Bans) != 1 || got.Bans[0].IP != "192.0.2.1" {
		t.Fatalf("wrong canonicalization: %+v", got)
	}
}
func TestReadOnlyInspectionAndCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a path with spaces", "state.db")
	s := mustOpen(t, path)
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	if e := s.SaveGrant(ctx, netip.MustParseAddr("192.0.2.1"), "owner", now); e != nil {
		t.Fatal(e)
	}
	if e := s.Cleanup(ctx, now, time.Hour); e != nil {
		t.Fatal(e)
	}
	s.Close()
	ro, e := OpenReadOnly(path)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	got, e := ro.Snapshot(ctx, now)
	if e != nil || len(got.Grants) != 0 {
		t.Fatalf("inspection: %+v %v", got, e)
	}
	if e = ro.SaveGrant(ctx, netip.MustParseAddr("192.0.2.2"), "owner", now); e == nil {
		t.Fatal("read-only database accepted write")
	}
}
