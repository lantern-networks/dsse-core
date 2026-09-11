// Package catalogfeed is the PROPRIETARY signed predefined-catalog feed: it ships and updates the predefined
// pinned-bypass catalog out-of-band, replacing the OSS built-in default (knownbypass.Catalog()) when a valid
// feed is applied. The feed is a signed envelope (reusing oss/signedconfig: ed25519 signature + sha256
// checksum + expiry + trusted-key ring), so an edge only adopts a catalog the vendor actually published.
//
// Guarantees (design "feed requirements"):
//   - Signed + trusted: a feed is applied only if signedconfig.Validate passes against the configured keyring.
//   - Monotonic version: Apply refuses a catalog version that is not newer than the applied one (anti-rollback);
//     going back is an explicit Rollback to a version in history.
//   - Never empty / last-known-good: an invalid/expired/older feed is REJECTED and the current catalog is kept;
//     when no feed is applied the OSS built-in default is served. An applied feed past its expiry is still
//     served (last-known-good) and reported stale rather than dropped — never break traffic.
//   - Durable: the applied feed + version history survive an edge restart (SetStatePath).
package catalogfeed

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

// FeedType is the signedconfig envelope type a predefined-catalog feed must declare.
const FeedType = "predefined_catalog_feed"

const historyLimit = 20

// AppliedFeed is a catalog feed that passed validation and was applied (or is retained for rollback).
type AppliedFeed struct {
	CatalogVersion  int                   `json:"catalog_version"`
	Entries         []knownbypass.Group   `json:"entries"`
	EnvelopeVersion string                `json:"envelope_version"`
	SigningKeyID    string                `json:"signing_key_id"`
	CreatedAt       string                `json:"created_at"`
	ExpiresAt       string                `json:"expires_at"`
	AppliedAt       string                `json:"applied_at"`
	Envelope        signedconfig.Envelope `json:"envelope"` // retained so a rollback target can be re-served verbatim
}

// Status is the feed view returned to admins.
type Status struct {
	Source         string        `json:"source"` // "feed" | "builtin"
	CatalogVersion int           `json:"catalog_version"`
	Stale          bool          `json:"stale"` // an applied feed is past its expiry (still served as last-known-good)
	Current        *AppliedFeed  `json:"current"`
	History        []AppliedFeed `json:"history"`
}

type snapshot struct {
	Current *AppliedFeed  `json:"current"`
	History []AppliedFeed `json:"history"`
}

// Store holds the applied feed + version history, guarded by the trusted keyring.
type Store struct {
	mu          sync.RWMutex
	current     *AppliedFeed
	history     []AppliedFeed
	trustedKeys map[string]ed25519.PublicKey
	statePath   string
}

// NewStore builds a feed store trusting the given ed25519 public keys (keyed by signing_key_id). An empty
// keyring means no feed can ever be applied (every Apply fails) — the built-in default is served.
func NewStore(trustedKeys map[string]ed25519.PublicKey) *Store {
	return &Store{trustedKeys: trustedKeys}
}

// Apply validates a signed feed envelope and, if it is newer than the applied catalog, makes it current. On any
// validation failure the current catalog is left untouched (last-known-good).
func (s *Store) Apply(raw []byte, now time.Time) (AppliedFeed, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var env signedconfig.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return AppliedFeed{}, fmt.Errorf("parse feed envelope: %w", err)
	}
	if err := signedconfig.Validate(env, FeedType, now, s.trustedKeys); err != nil {
		return AppliedFeed{}, fmt.Errorf("feed validation failed (current catalog kept): %w", err)
	}
	doc, err := signedconfig.PayloadInto[knownbypass.CatalogDocument](env)
	if err != nil {
		return AppliedFeed{}, fmt.Errorf("parse feed payload: %w", err)
	}
	if len(doc.Entries) == 0 {
		return AppliedFeed{}, fmt.Errorf("refusing to apply an empty catalog (never fall back to no bypass)")
	}
	for _, e := range doc.Entries {
		if strings.TrimSpace(e.ID) == "" {
			return AppliedFeed{}, fmt.Errorf("feed catalog entry is missing an id")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil && doc.Version <= s.current.CatalogVersion {
		return AppliedFeed{}, fmt.Errorf("feed catalog version %d is not newer than the applied version %d (use rollback to go back)", doc.Version, s.current.CatalogVersion)
	}
	af := AppliedFeed{
		CatalogVersion:  doc.Version,
		Entries:         doc.Entries,
		EnvelopeVersion: env.Version,
		SigningKeyID:    env.SigningKeyID,
		CreatedAt:       env.CreatedAt,
		ExpiresAt:       env.ExpiresAt,
		AppliedAt:       now.UTC().Format(time.RFC3339),
		Envelope:        env,
	}
	s.current = &af
	s.history = appendHistory(s.history, af)
	if err := s.persistLocked(); err != nil {
		return af, fmt.Errorf("feed v%d applied in memory but not persisted (would revert on restart): %w", af.CatalogVersion, err)
	}
	return af, nil
}

// Rollback restores a previously-applied catalog version from history (the only way to go to an older version).
func (s *Store) Rollback(toCatalogVersion int, now time.Time) (AppliedFeed, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.history) - 1; i >= 0; i-- {
		if s.history[i].CatalogVersion == toCatalogVersion {
			af := s.history[i]
			af.AppliedAt = now.UTC().Format(time.RFC3339)
			s.current = &af
			s.history = appendHistory(s.history, af)
			if err := s.persistLocked(); err != nil {
				return af, fmt.Errorf("rollback to v%d applied in memory but not persisted (would revert on restart): %w", af.CatalogVersion, err)
			}
			return af, nil
		}
	}
	return AppliedFeed{}, fmt.Errorf("catalog version %d is not in the feed history", toCatalogVersion)
}

// EffectiveCatalog returns the catalog in force: the applied feed (even if stale — last-known-good) or, when no
// feed is applied, the OSS built-in default.
func (s *Store) EffectiveCatalog() knownbypass.CatalogDocument {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return knownbypass.Catalog()
	}
	return knownbypass.CatalogDocument{Version: s.current.CatalogVersion, Entries: s.current.Entries}
}

// Status reports the feed source/version/staleness + history for the admin view.
func (s *Store) Status(now time.Time) Status {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return Status{Source: "builtin", CatalogVersion: knownbypass.CatalogVersion, History: appendHistory(nil, s.history...)}
	}
	stale := false
	if exp := strings.TrimSpace(s.current.ExpiresAt); exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil && now.After(t) {
			stale = true
		}
	}
	cur := *s.current
	return Status{Source: "feed", CatalogVersion: cur.CatalogVersion, Stale: stale, Current: &cur, History: appendHistory(nil, s.history...)}
}

func appendHistory(history []AppliedFeed, items ...AppliedFeed) []AppliedFeed {
	history = append(history, items...)
	if len(history) > historyLimit {
		history = history[len(history)-historyLimit:]
	}
	return history
}

// SetStatePath enables durable persistence and loads any existing applied feed + history.
func (s *Store) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statePath = path
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.current = snap.Current
	s.history = snap.History
	return nil
}

// persistLocked atomically snapshots the applied feed + history. The error MUST reach the caller: a
// swallowed write meant an applied/rolled-back catalog was acknowledged while nothing hit disk, so the edge
// silently reverted to the previous catalog on restart. Caller holds s.mu.
func (s *Store) persistLocked() error {
	if s.statePath == "" {
		return nil
	}
	data, err := json.MarshalIndent(snapshot{Current: s.current, History: s.history}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal catalog-feed snapshot: %w", err)
	}
	tmp := s.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("persist catalog feed: %w", err)
	}
	if err := os.Rename(tmp, s.statePath); err != nil {
		return fmt.Errorf("persist catalog feed (rename): %w", err)
	}
	return nil
}
