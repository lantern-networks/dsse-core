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
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/durablefile"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

// FeedType is the signedconfig envelope type a predefined-catalog feed must declare.
const FeedType = "predefined_catalog_feed"

const historyLimit = 20

// ErrPersistence means the requested feed snapshot could not be confirmed saved.
var ErrPersistence = errors.New("catalog feed persistence failed")

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
	writeMu     sync.Mutex // serializes changes; readers keep the confirmed catalog during I/O
	mu          sync.RWMutex
	current     *AppliedFeed
	history     []AppliedFeed
	trustedKeys map[string]ed25519.PublicKey
	statePath   string // guarded by writeMu
	dirty       bool   // a failed save can have an uncertain on-disk outcome
	writeFile   func(string, []byte, os.FileMode) error
}

// NewStore builds a feed store trusting the given ed25519 public keys (keyed by signing_key_id). An empty
// keyring means no feed can ever be applied (every Apply fails) — the built-in default is served.
func NewStore(trustedKeys map[string]ed25519.PublicKey) *Store {
	keys := make(map[string]ed25519.PublicKey, len(trustedKeys))
	for id, key := range trustedKeys {
		keys[id] = bytes.Clone(key)
	}
	return &Store{trustedKeys: keys, writeFile: durablefile.Write}
}

// Apply validates a signed feed envelope and, if it is newer than the applied catalog, makes it current. On any
// validation failure the current catalog is left untouched (last-known-good).
func (s *Store) Apply(raw []byte, now time.Time) (AppliedFeed, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var env signedconfig.Envelope
	if err := feedJSON(raw, &env); err != nil {
		return AppliedFeed{}, fmt.Errorf("parse feed envelope: %w", err)
	}
	doc, err := s.validateEnvelope(env, now)
	if err != nil {
		return AppliedFeed{}, fmt.Errorf("feed validation failed (current catalog kept): %w", err)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.RLock()
	current := s.current
	history := cloneHistory(s.history)
	s.mu.RUnlock()
	if current != nil && doc.Version <= current.CatalogVersion {
		return AppliedFeed{}, fmt.Errorf("feed catalog version %d is not newer than the applied version %d (use rollback to go back)", doc.Version, current.CatalogVersion)
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
	if err := s.commitLocked(af, appendHistory(history, af)); err != nil {
		return AppliedFeed{}, err
	}
	return cloneApplied(af), nil
}

// Rollback restores a previously-applied catalog version from history (the only way to go to an older version).
func (s *Store) Rollback(toCatalogVersion int, now time.Time) (AppliedFeed, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.RLock()
	history := cloneHistory(s.history)
	s.mu.RUnlock()
	for i := len(history) - 1; i >= 0; i-- {
		if history[i].CatalogVersion == toCatalogVersion {
			af := history[i]
			af.AppliedAt = now.UTC().Format(time.RFC3339)
			if err := s.commitLocked(af, appendHistory(history, af)); err != nil {
				return AppliedFeed{}, err
			}
			return cloneApplied(af), nil
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
		cat := knownbypass.Catalog()
		cat.Entries = cloneEntries(cat.Entries)
		return cat
	}
	return knownbypass.CatalogDocument{Version: s.current.CatalogVersion, Entries: cloneEntries(s.current.Entries)}
}

// Status reports the feed source/version/staleness + history for the admin view.
func (s *Store) Status(now time.Time) Status {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return Status{Source: "builtin", CatalogVersion: knownbypass.CatalogVersion, History: cloneHistory(s.history)}
	}
	stale := false
	if exp := strings.TrimSpace(s.current.ExpiresAt); exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil && now.After(t) {
			stale = true
		}
	}
	cur := cloneApplied(*s.current)
	return Status{Source: "feed", CatalogVersion: cur.CatalogVersion, Stale: stale, Current: &cur, History: cloneHistory(s.history)}
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
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.dirty {
		return fmt.Errorf("%w: retry the feed change before replacing storage", ErrPersistence)
	}
	if path == "" {
		s.statePath = ""
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.statePath = path
			return nil
		}
		return err
	}
	snap, err := s.decodeSnapshot(data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.current = snap.Current
	s.history = snap.History
	s.mu.Unlock()
	s.statePath = path
	return nil
}

// SetOverride checks the actual effective catalog and serializes that check with
// feed updates. The override cannot be accepted against a superseded feed while
// its save is in progress. Feed readers do not wait on that persistence operation.
func (s *Store) SetOverride(overrides *knownbypass.OverrideStore, tenant string, override knownbypass.Override, now time.Time) (knownbypass.Override, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return overrides.SetFromCatalog(tenant, override, s.EffectiveCatalog().Entries, now)
}

// commitLocked saves a candidate before publishing it. writeMu is held; mu is not
// held during disk I/O. A failed replacement/flush can still have changed disk,
// so keep live state and require a successful retry before switching storage.
func (s *Store) commitLocked(current AppliedFeed, history []AppliedFeed) error {
	if s.statePath != "" {
		data, err := json.MarshalIndent(snapshot{Current: &current, History: history}, "", "  ")
		if err == nil {
			write := s.writeFile
			if write == nil {
				write = durablefile.Write
			}
			err = write(s.statePath, data, 0o600)
		}
		if err != nil {
			s.dirty = true
			return fmt.Errorf("%w: %w", ErrPersistence, err)
		}
	}
	s.mu.Lock()
	s.current = &current
	s.history = history
	s.mu.Unlock()
	s.dirty = false
	return nil
}

func cloneEntries(entries []knownbypass.Group) []knownbypass.Group {
	if entries == nil {
		return nil
	}
	out := append([]knownbypass.Group{}, entries...)
	for i := range out {
		out[i].Patterns = append([]string(nil), out[i].Patterns...)
	}
	return out
}

func cloneApplied(af AppliedFeed) AppliedFeed {
	af.Entries = cloneEntries(af.Entries)
	af.Envelope.Payload = bytes.Clone(af.Envelope.Payload)
	if af.Envelope.Metadata != nil {
		af.Envelope.Metadata = cloneJSON(af.Envelope.Metadata).(map[string]any)
	}
	return af
}

func cloneHistory(history []AppliedFeed) []AppliedFeed {
	if history == nil {
		return nil
	}
	out := make([]AppliedFeed, len(history))
	for i := range history {
		out[i] = cloneApplied(history[i])
	}
	return out
}

// Envelope metadata came from JSON; copy its nested mutable containers as well.
func cloneJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[k] = cloneJSON(v)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = cloneJSON(v)
		}
		return out
	default:
		return v
	}
}
