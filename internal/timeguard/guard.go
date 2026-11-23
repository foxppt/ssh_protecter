package timeguard

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Checkpoints interface {
	CheckpointClock(context.Context, time.Time, time.Duration) error
	LatchClockFault(context.Context, string) error
}
type Guard struct {
	mu           sync.Mutex
	Store        Checkpoints
	Now          func() time.Time
	Monotonic    func() time.Duration
	Synchronized func() error
	requireSync  bool
	maxSkew      time.Duration
	last         time.Time
	lastMono     time.Duration
	fault        error
}

func New(store Checkpoints, requireSync bool, maxSkew time.Duration) *Guard {
	start := time.Now()
	return &Guard{Store: store, Now: time.Now, Monotonic: func() time.Duration { return time.Since(start) }, Synchronized: CheckSynchronized, requireSync: requireSync, maxSkew: maxSkew}
}
func (g *Guard) Configure(requireSync bool, maxSkew time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requireSync = requireSync
	g.maxSkew = maxSkew
}
func (g *Guard) Check(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fault != nil {
		return g.fault
	}
	if g.requireSync {
		if e := g.Synchronized(); e != nil {
			return fmt.Errorf("time is not synchronized; authorization paused: %w", e)
		}
	}
	now := g.Now()
	mono := g.Monotonic()
	if !g.last.IsZero() {
		wall := now.Round(0).Sub(g.last.Round(0))
		elapsed := mono - g.lastMono
		skew := wall - elapsed
		if skew < 0 {
			skew = -skew
		}
		if skew > g.maxSkew {
			e := g.Store.LatchClockFault(ctx, "runtime wall clock step exceeds configured maximum")
			g.fault = fmt.Errorf("runtime clock step detected; local clock-reset required (persist fault: %v)", e)
			return g.fault
		}
	}
	if e := g.Store.CheckpointClock(ctx, now, g.maxSkew); e != nil {
		return e
	}
	g.last = now
	g.lastMono = mono
	return nil
}
