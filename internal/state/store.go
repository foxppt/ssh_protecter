package state

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

// Existing identities must never silently recreate lost state and erase bans.
func OpenExisting(path string) (*Store, error) {
	s, e := OpenReadOnly(path)
	if e != nil {
		return nil, e
	}
	if e = s.Close(); e != nil {
		return nil, e
	}
	return Open(path)
}

type Grant struct {
	IP        string `json:"ip"`
	UserID    string `json:"user_id"`
	ExpiresAt int64  `json:"expires_at"`
}
type Ban struct {
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_at"`
}
type Snapshot struct {
	Grants []Grant `json:"grants"`
	Bans   []Ban   `json:"bans"`
}
type FailureResult struct {
	Failures      int
	BannedUntil   int64
	AlreadyBanned bool
}

// OpenReadOnly never creates or migrates a database, including for CLI inspection.
func OpenReadOnly(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat(abs); err != nil {
		return nil, err
	}
	p := filepath.ToSlash(abs)
	if len(p) > 1 && p[1] == ':' {
		p = "/" + p
	}
	uri := url.URL{Scheme: "file", Path: p, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var v int
	if err = db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		db.Close()
		return nil, err
	}
	if v != 1 && v != 2 {
		db.Close()
		return nil, fmt.Errorf("unsupported state schema version %d", v)
	}
	return &Store{db: db}, nil
}

// Open initializes an owner-only local database. It must not be used on a shared filesystem.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*Store, error) { db.Close(); return nil, e }
	// A single connection makes these settings apply to every operation.
	for _, q := range []string{"PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if _, err = db.Exec(q); err != nil {
			return fail(err)
		}
	}
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version > 2 {
		return fail(fmt.Errorf("unsupported state schema version %d", version))
	}
	tx, err := db.Begin()
	if err != nil {
		return fail(err)
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS grants(ip TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS failures(id INTEGER PRIMARY KEY,ip TEXT NOT NULL,occurred_at INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS failures_by_ip_time ON failures(ip,occurred_at)`,
		`CREATE TABLE IF NOT EXISTS bans(ip TEXT PRIMARY KEY,expires_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS clock_state(id INTEGER PRIMARY KEY CHECK(id=1), high_water_ns INTEGER NOT NULL, fault TEXT NOT NULL DEFAULT '')`,
		`PRAGMA user_version=2`,
	} {
		if _, err = tx.Exec(q); err != nil {
			tx.Rollback()
			return fail(err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fail(err)
	}
	return &Store{db: db}, nil
}
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) BanUntil(ctx context.Context, ip netip.Addr, now time.Time) (int64, error) {
	key, e := canonical(ip)
	if e != nil {
		return 0, e
	}
	var until int64
	e = s.db.QueryRowContext(ctx, `SELECT expires_at FROM bans WHERE ip=? AND expires_at>?`, key, now.Unix()).Scan(&until)
	if e == sql.ErrNoRows {
		return 0, nil
	}
	return until, e
}
func (s *Store) RevokeAll(ctx context.Context) error {
	_, e := s.db.ExecContext(ctx, `DELETE FROM grants`)
	return e
}
func (s *Store) RevokeGrant(ctx context.Context, ip netip.Addr) error {
	key, e := canonical(ip)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, `DELETE FROM grants WHERE ip=?`, key)
	return e
}
func canonical(ip netip.Addr) (string, error) {
	if !ip.IsValid() || ip.Zone() != "" {
		return "", fmt.Errorf("invalid IP")
	}
	return ip.Unmap().String(), nil
}

// SaveGrant persists desired authorization state only. It does not open a firewall port.
// The future firewall coordinator must track pending/applied operations separately.
func (s *Store) SaveGrant(ctx context.Context, ip netip.Addr, user string, expires time.Time) error {
	key, err := canonical(ip)
	if err != nil {
		return err
	}
	if user == "" {
		return fmt.Errorf("user ID is required")
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO grants(ip,user_id,expires_at) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET user_id=excluded.user_id,expires_at=excluded.expires_at`, key, user, expires.Unix())
	return err
}

// RecordFailure is atomic, does not reset on success, and never extends an active ban.
// The rolling interval is (now-window, now].
func (s *Store) RecordFailure(ctx context.Context, ip netip.Addr, now time.Time, window time.Duration, max int, ban time.Duration) (FailureResult, error) {
	var result FailureResult
	key, err := canonical(ip)
	if err != nil {
		return result, err
	}
	if window < time.Second || ban < time.Second || max < 1 {
		return result, fmt.Errorf("invalid failure policy")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT expires_at FROM bans WHERE ip=?`, key).Scan(&result.BannedUntil)
	if err != nil && err != sql.ErrNoRows {
		return result, err
	}
	if result.BannedUntil > now.Unix() {
		result.AlreadyBanned = true
		return result, tx.Commit()
	}
	result.BannedUntil = 0
	// Old failures for this IP are no longer relevant to the current rolling window.
	if _, err = tx.ExecContext(ctx, `DELETE FROM failures WHERE ip=? AND occurred_at<=?`, key, now.Add(-window).Unix()); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO failures(ip,occurred_at) VALUES(?,?)`, key, now.Unix()); err != nil {
		return result, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM failures WHERE ip=? AND occurred_at>? AND occurred_at<=?`, key, now.Add(-window).Unix(), now.Unix()).Scan(&result.Failures); err != nil {
		return result, err
	}
	if result.Failures >= max {
		result.BannedUntil = now.Add(ban).Unix()
		if _, err = tx.ExecContext(ctx, `INSERT INTO bans(ip,expires_at) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET expires_at=excluded.expires_at`, key, result.BannedUntil); err != nil {
			return result, err
		}
	}
	return result, tx.Commit()
}

// Snapshot returns live desired state; expired rows are never resurrected by a read.
func (s *Store) Snapshot(ctx context.Context, now time.Time) (Snapshot, error) {
	out := Snapshot{Grants: []Grant{}, Bans: []Ban{}}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT ip,user_id,expires_at FROM grants WHERE expires_at>? ORDER BY ip`, now.Unix())
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var g Grant
		if err = rows.Scan(&g.IP, &g.UserID, &g.ExpiresAt); err != nil {
			rows.Close()
			return out, err
		}
		out.Grants = append(out.Grants, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT ip,expires_at FROM bans WHERE expires_at>? ORDER BY ip`, now.Unix())
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var b Ban
		if err = rows.Scan(&b.IP, &b.ExpiresAt); err != nil {
			rows.Close()
			return out, err
		}
		out.Bans = append(out.Bans, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Store) Cleanup(ctx context.Context, now time.Time, window time.Duration) error {
	if window < time.Second {
		return fmt.Errorf("invalid cleanup window")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []struct {
		sql    string
		before int64
	}{{`DELETE FROM grants WHERE expires_at<=?`, now.Unix()}, {`DELETE FROM bans WHERE expires_at<=?`, now.Unix()}, {`DELETE FROM failures WHERE occurred_at<=?`, now.Add(-window).Unix()}} {
		if _, err = tx.ExecContext(ctx, q.sql, q.before); err != nil {
			return err
		}
	}
	return tx.Commit()
}
