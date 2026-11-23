package state

import (
	"context"
	"errors"
	"modernc.org/sqlite"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDiskFullDoesNotCommitPartialState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s := mustOpen(t, path)
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	ip := netip.MustParseAddr("192.0.2.1")
	if e := s.SaveGrant(ctx, ip, "owner", now.Add(5*time.Minute)); e != nil {
		t.Fatal(e)
	}
	var pages int
	if e := s.db.QueryRow(`PRAGMA page_count`).Scan(&pages); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`PRAGMA max_page_count=` + strconv.Itoa(pages)); e != nil {
		t.Fatal(e)
	}
	err := s.SaveGrant(ctx, netip.MustParseAddr("192.0.2.2"), strings.Repeat("x", 1<<20), now.Add(time.Hour))
	var sqliteError *sqlite.Error
	if !errors.As(err, &sqliteError) || sqliteError.Code() != 13 {
		t.Fatalf("expected real SQLITE_FULL, got %v", err)
	}
	s.Close()
	s = mustOpen(t, path)
	defer s.Close()
	snapshot, e := s.Snapshot(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	if len(snapshot.Grants) != 1 || snapshot.Grants[0].IP != ip.String() {
		t.Fatal("disk full committed partial/new grant")
	}
}

func TestMissingOrCorruptStateNeverReinitialized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	if _, e := OpenExisting(path); e == nil {
		t.Fatal("missing state recreated")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("missing database was created")
	}
	if e := os.WriteFile(path, []byte("not a database"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenExisting(path); e == nil {
		t.Fatal("corrupt state reinitialized")
	}
}

func TestClockResetPreservesBanDeadlinesAndRemovesGrants(t *testing.T) {
	s := mustOpen(t, filepath.Join(t.TempDir(), "db"))
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	ip := netip.MustParseAddr("2001:db8::1")
	if e := s.SaveGrant(ctx, ip, "owner", now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	var until int64
	for i := 0; i < 5; i++ {
		r, e := s.RecordFailure(ctx, ip, now, time.Hour, 5, 24*time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		until = r.BannedUntil
	}
	if e := s.ResetClock(ctx, now); e != nil {
		t.Fatal(e)
	}
	got, e := s.Snapshot(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Grants) != 0 || len(got.Bans) != 1 || got.Bans[0].ExpiresAt != until {
		t.Fatal("reset lost ban or retained grant")
	}
}

func TestVersionOneMigrationPreservesRestrictions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s := mustOpen(t, path)
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	ip := netip.MustParseAddr("192.0.2.1")
	if e := s.SaveGrant(ctx, ip, "owner", now.Add(5*time.Minute)); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		if _, e := s.RecordFailure(ctx, ip, now, time.Hour, 5, 24*time.Hour); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.db.Exec(`DROP TABLE clock_state; PRAGMA user_version=1`); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e := OpenExisting(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.Snapshot(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Grants) != 1 || got.Grants[0].ExpiresAt != now.Add(5*time.Minute).Unix() || len(got.Bans) != 1 || got.Bans[0].ExpiresAt != now.Add(24*time.Hour).Unix() {
		t.Fatal("migration changed deadlines")
	}
	if e = s.CheckpointClock(ctx, now, 2*time.Second); e != nil {
		t.Fatal(e)
	}
}
