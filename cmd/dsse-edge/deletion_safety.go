package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
)

// A permit records an operator's reconciliation for one process and one CP
// term. It is not a time-based lease: a successor must never infer that failed
// preservation requests were absent merely because their writer disappeared.
type deletionSafetyPermit struct {
	Process string `json:"process"`
	Term    string `json:"term"`
}

func (p deletionSafetyPermit) valid() bool {
	b, err := hex.DecodeString(p.Process)
	if err != nil || len(b) != 16 {
		return false
	}
	if p.Term == "local" {
		return true
	}
	n, err := strconv.ParseInt(p.Term, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == p.Term
}

type deletionSafetyGuard struct {
	process            string
	configurationError string
	shared             bool
}

// Called once before starting the pruner or exposing administration handlers.
// There is deliberately no automatic permit on first boot or on a missing row.
func configureDeletionSafety(h *legalHoldStore, r *retentionOverrideStore, shared bool) error {
	if h == nil || r == nil {
		return fmt.Errorf("protection stores required")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	g := &deletionSafetyGuard{process: hex.EncodeToString(nonce[:]), shared: shared}
	if shared {
		hp, hok := h.persister.(postgresBlobPersister)
		rp, rok := r.persister.(postgresBlobPersister)
		if !hok || !rok || hp.db != rp.db {
			g.configurationError = "shared deletion requires hold and retention on the same PostgreSQL authority"
		}
	} else if h.persister == nil || r.persister == nil {
		g.configurationError = "deletion requires durable hold and retention stores"
	}
	h.deletionGuard = g
	log.Printf("deletion safety: process=%s; pruning and tenant erasure require reconciliation for this process and current leader term", g.process)
	return nil
}

func (s *legalHoldStore) checkDeletionSafety(ctx context.Context, permit *deletionSafetyPermit) error {
	if s == nil || s.deletionGuard == nil {
		return nil
	} // Unwired, isolated Store fixtures only.
	g := s.deletionGuard
	if g.configurationError != "" {
		return fmt.Errorf("deletion paused: %s", g.configurationError)
	}
	term := "local"
	lease, leased := ctx.Value(cpWriteLeaseKey{}).(cpWriteLease)
	if g.shared && !leased {
		return fmt.Errorf("deletion paused: an active control-plane leader term is required")
	}
	if leased {
		if lease.epoch == 0 {
			return errCPLeadershipChanged
		}
		term = strconv.FormatInt(lease.epoch, 10)
	}
	if permit == nil || permit.Process != g.process || permit.Term != term {
		err := fmt.Errorf("deletion paused: reconcile protection requests before authorizing process=%s term=%s (see docs/deletion-safety-recovery.md)", g.process, term)
		// Purge responses intentionally hide internal failure details. Keep the
		// non-secret recovery identity observable even when the pruner is disabled.
		log.Printf("%v", err)
		return err
	}
	return nil
}

// File-mode recovery edits only the permit by full-snapshot CAS while other
// administrative writers are quiesced. Read it under writeMu without treating
// an out-of-band policy change as an authorization. Never reload local pending.
// SQL mode checks the permit in the same transaction as the deletion instead.
func (s *legalHoldStore) refreshLocalDeletionPermit(ctx context.Context) error {
	if s == nil || s.deletionGuard == nil {
		return nil
	}
	if _, shared := s.persister.(retentionSharedUpdater); shared {
		return nil
	}
	if s.persister == nil {
		return s.checkDeletionSafety(ctx, nil)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := s.persister.Load()
	if err != nil {
		return fmt.Errorf("deletion safety state unavailable: %w", err)
	}
	v, err := decodeHoldSnapshot(raw, true)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Ignore format/permit differences, but refuse any changed confirmed policy.
	before, err := encodeHoldSnapshot(s.held, s.erasures, 2)
	if err != nil {
		return err
	}
	after, err := encodeHoldSnapshot(v.held(), v.Erasures, 2)
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) {
		return fmt.Errorf("deletion paused: file policy changed outside this process")
	}
	s.deletionPermit, s.snapshotVersion = v.DeletionPermit, v.Version
	return nil
}
