package state

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CheckpointClock commits a high-water mark before time-dependent operations.
func (s *Store) CheckpointClock(ctx context.Context, now time.Time, tolerance time.Duration) error {
	if tolerance < 0 {
		return fmt.Errorf("negative clock tolerance")
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var high int64
	var fault string
	e = tx.QueryRowContext(ctx, `SELECT high_water_ns,fault FROM clock_state WHERE id=1`).Scan(&high, &fault)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if fault != "" {
		return fmt.Errorf("clock fault requires local recovery: %s", fault)
	}
	value := now.UnixNano()
	if high > value && high-value > int64(tolerance) {
		if _, e = tx.ExecContext(ctx, `UPDATE clock_state SET fault='wall clock is behind persisted high-water mark' WHERE id=1`); e != nil {
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		return fmt.Errorf("clock rollback detected across restart; temporary grants not restored")
	}
	if value > high {
		high = value
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO clock_state(id,high_water_ns,fault) VALUES(1,?,'') ON CONFLICT(id) DO UPDATE SET high_water_ns=excluded.high_water_ns`, high); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) LatchClockFault(ctx context.Context, reason string) error {
	_, e := s.db.ExecContext(ctx, `INSERT INTO clock_state(id,high_water_ns,fault) VALUES(1,0,?) ON CONFLICT(id) DO UPDATE SET fault=excluded.fault`, reason)
	return e
}

// Explicit local recovery: revoke grants, retain original ban/failure timestamps.
func (s *Store) ResetClock(ctx context.Context, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `DELETE FROM grants`); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO clock_state(id,high_water_ns,fault) VALUES(1,?,'') ON CONFLICT(id) DO UPDATE SET high_water_ns=excluded.high_water_ns,fault=''`, now.UnixNano()); e != nil {
		return e
	}
	return tx.Commit()
}
