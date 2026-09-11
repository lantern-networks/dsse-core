package agenttuning

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// sync.go — the L3 tuning delivery. Mirrors the signed steer-exclusion sync: the agent PULLs the signed tuning
// envelope from the CP over the (T) transport, verifies it (agenttuning.Load), and applies it via a callback.
// A fetch/verify failure keeps the current settings (never regresses to unsafe values). This is the transport
// wrapper only; agent-side application of the resolved settings to the live captive controller is the caller's
// Apply callback.

// Applier receives a verified tuning policy to apply to the running agent (e.g. ApplyCaptive onto live settings).
type Applier func(TuningPolicy)

// Doer is the minimal HTTP client (http.Client satisfies it; the agent passes its (T) transport client).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Syncer periodically fetches + verifies + applies the tuning policy.
type Syncer struct {
	URL    string
	PinHex string
	// Keys, when set, supplies the accepted signing keys for THIS fetch — the pin plus whatever the device has
	// adopted. A callback rather than a slice because the set changes underneath a long-running Syncer: a device
	// adopts the next key from a trust bundle mid-run, and a set captured at construction would still be the old
	// one at the moment the Edge starts signing with the new key. Nil = verify against PinHex alone (unchanged).
	Keys         func() []string
	Client       Doer
	Interval     time.Duration
	FetchTimeout time.Duration // per-fetch deadline (default 15s); bounds a slow/hung CP so Run never wedges
	Apply        Applier
	Logf         func(string, ...interface{})
}

// verificationKeys is the set this fetch accepts signatures from: the adopted set when one is available,
// otherwise the pin alone. Never silently empty — an empty result reaches VerifyAny, which refuses rather than
// treating "no keys" as "no checking".
func (s Syncer) verificationKeys() []string {
	if s.Keys != nil {
		if k := s.Keys(); len(k) > 0 {
			return k
		}
	}
	return []string{s.PinHex}
}

func (s Syncer) logf(format string, args ...interface{}) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// FetchOnce does one fetch → verify → apply. It bounds the fetch with its own timeout (so a slow/hung CP can
// never wedge Run) in addition to any deadline on ctx. Returns an error on any failure (caller keeps current
// settings).
func (s Syncer) FetchOnce(ctx context.Context) error {
	timeout := s.FetchTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	fctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return err
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("agenttuning: fetch status %d", resp.StatusCode)
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return fmt.Errorf("agenttuning: read body: %w", rerr)
	}
	policy, verified, verr := LoadWithKeys(body, s.verificationKeys())
	if verr != nil {
		return fmt.Errorf("agenttuning: %w", verr)
	}
	if !verified {
		return fmt.Errorf("agenttuning: policy not verified")
	}
	if s.Apply != nil {
		s.Apply(policy)
	}
	return nil
}

// Run polls FetchOnce every Interval until ctx is done. It does an immediate fetch first so tuning applies at
// startup, then on the interval. Fetch errors are logged, not fatal (current settings persist).
func (s Syncer) Run(ctx context.Context) {
	interval := s.Interval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if err := s.FetchOnce(ctx); err != nil {
		s.logf("agenttuning: initial fetch: %v (keeping current settings)", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.FetchOnce(ctx); err != nil {
				s.logf("agenttuning: fetch: %v (keeping current settings)", err)
			}
		}
	}
}
