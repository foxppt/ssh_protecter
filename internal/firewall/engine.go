package firewall

import (
	"context"
	"fmt"
	"ssh-protecter/internal/state"
	"sync"
	"time"
)

type Runner interface {
	Run(context.Context, bool, string) error
}
type Engine struct {
	Runner Runner
	mu     sync.Mutex
	Now    func() time.Time
}

// Apply validates and replaces only our table. No cleanup runs on error or exit.
// Callers must serialize this with durable desired-state updates, and hold the
// process-wide Linux lock for their lifetime.
func (e *Engine) Apply(ctx context.Context, p Policy, grants []state.Grant) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Runner == nil {
		return fmt.Errorf("missing nft runner")
	}
	now := e.Now
	if now == nil {
		now = time.Now
	}
	script, err := Render(p, grants, now(), ApplyBudget)
	if err != nil {
		return err
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = e.Runner.Run(check, true, script)
	cancel()
	if err != nil {
		return fmt.Errorf("nft validation: %w", err)
	}
	// Validation may have taken seconds. Never reuse its relative timeouts.
	script, err = Render(p, grants, now(), ApplyBudget)
	if err != nil {
		return err
	}
	apply, cancel := context.WithTimeout(ctx, ApplyBudget)
	defer cancel()
	if err = e.Runner.Run(apply, false, script); err != nil {
		return fmt.Errorf("nft application outcome may be unknown; reconcile before new authorization: %w", err)
	}
	return nil
}
