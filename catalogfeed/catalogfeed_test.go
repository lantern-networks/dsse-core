package catalogfeed

import (
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

// signFeed builds a signed feed envelope for the given catalog version/entries.
func signFeed(t *testing.T, priv ed25519.PrivateKey, keyID string, version int, entries []knownbypass.Group, createdAt, expiresAt string) []byte {
	t.Helper()
	doc := knownbypass.CatalogDocument{Version: version, Entries: entries}
	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := signedconfig.PayloadChecksum(payload)
	if err != nil {
		t.Fatal(err)
	}
	env := signedconfig.Envelope{
		Type:         FeedType,
		Version:      "v" + time.Now().UTC().Format("20060102"),
		Payload:      payload,
		Checksum:     checksum,
		SigningKeyID: keyID,
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
		Status:       "active",
	}
	signed, err := signedconfig.Sign(env, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func entries(ids ...string) []knownbypass.Group {
	out := []knownbypass.Group{}
	for _, id := range ids {
		out = append(out, knownbypass.Group{ID: id, Name: id, Vendor: "Vendor", Category: "cat", Risk: "low", Patterns: []string{id + ".example.com"}})
	}
	return out
}

func newTrust(t *testing.T) (ed25519.PrivateKey, string, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID := "ed25519-public:test"
	return priv, keyID, map[string]ed25519.PublicKey{keyID: pub}
}

func TestApplyValidFeedReplacesBuiltinAndIsMonotonic(t *testing.T) {
	priv, keyID, trust := newTrust(t)
	s := NewStore(trust)
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)

	// No feed yet -> built-in default in force.
	if s.EffectiveCatalog().Version != knownbypass.CatalogVersion {
		t.Fatal("with no feed the built-in default must be in force")
	}

	raw := signFeed(t, priv, keyID, 5, entries("vendor_a", "vendor_b"), now.Format(time.RFC3339), now.Add(720*time.Hour).Format(time.RFC3339))
	if _, err := s.Apply(raw, now); err != nil {
		t.Fatalf("apply valid feed: %v", err)
	}
	eff := s.EffectiveCatalog()
	if eff.Version != 5 || len(eff.Entries) != 2 {
		t.Fatalf("feed must replace the catalog: %+v", eff)
	}

	// Same/older version is rejected (anti-rollback); current kept.
	older := signFeed(t, priv, keyID, 5, entries("vendor_a"), now.Format(time.RFC3339), now.Add(720*time.Hour).Format(time.RFC3339))
	if _, err := s.Apply(older, now); err == nil {
		t.Fatal("a non-newer version must be rejected")
	}
	if s.EffectiveCatalog().Version != 5 {
		t.Fatal("rejected apply must keep the current catalog")
	}

	// Newer version applies.
	newer := signFeed(t, priv, keyID, 6, entries("vendor_a", "vendor_b", "vendor_c"), now.Format(time.RFC3339), now.Add(720*time.Hour).Format(time.RFC3339))
	if _, err := s.Apply(newer, now); err != nil {
		t.Fatalf("apply newer: %v", err)
	}
	if s.EffectiveCatalog().Version != 6 {
		t.Fatal("newer feed must apply")
	}
}

func TestApplyRejectsUntrustedTamperedExpiredEmpty(t *testing.T) {
	priv, keyID, trust := newTrust(t)
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)

	// Untrusted signer.
	otherPriv, _, _ := func() (ed25519.PrivateKey, string, map[string]ed25519.PublicKey) { return newTrust(t) }()
	s := NewStore(trust)
	raw := signFeed(t, otherPriv, keyID, 2, entries("vendor_a"), now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	if _, err := s.Apply(raw, now); err == nil {
		t.Fatal("a feed signed by an untrusted key must be rejected")
	}

	// Tampered payload (checksum/signature mismatch).
	good := signFeed(t, priv, keyID, 2, entries("vendor_a"), now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	var env signedconfig.Envelope
	if err := json.Unmarshal(good, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload = json.RawMessage(`{"version":2,"entries":[{"id":"evil","patterns":["evil.example.com"]}]}`)
	tampered, _ := json.Marshal(env)
	if _, err := s.Apply(tampered, now); err == nil {
		t.Fatal("a tampered payload must be rejected")
	}

	// Expired.
	expired := signFeed(t, priv, keyID, 2, entries("vendor_a"), now.Add(-48*time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339))
	if _, err := s.Apply(expired, now); err == nil {
		t.Fatal("an expired feed must be rejected")
	}

	// Empty catalog.
	empty := signFeed(t, priv, keyID, 2, []knownbypass.Group{}, now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	if _, err := s.Apply(empty, now); err == nil {
		t.Fatal("an empty catalog must be rejected (never fall back to no bypass)")
	}

	// After all rejects, no feed was ever applied -> built-in still in force.
	if s.EffectiveCatalog().Version != knownbypass.CatalogVersion {
		t.Fatal("rejected applies must leave the built-in default in force")
	}
}

func TestRollbackAndStaleLastKnownGood(t *testing.T) {
	priv, keyID, trust := newTrust(t)
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	s := NewStore(trust)
	s.Apply(signFeed(t, priv, keyID, 3, entries("a"), now.Format(time.RFC3339), now.Add(720*time.Hour).Format(time.RFC3339)), now)
	s.Apply(signFeed(t, priv, keyID, 4, entries("a", "b"), now.Format(time.RFC3339), now.Add(720*time.Hour).Format(time.RFC3339)), now)

	// Rollback to 3.
	if _, err := s.Rollback(3, now); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if s.EffectiveCatalog().Version != 3 {
		t.Fatal("rollback must restore the older version")
	}
	// Rollback to a version not in history -> error.
	if _, err := s.Rollback(99, now); err == nil {
		t.Fatal("rollback to an unknown version must error")
	}

	// Stale (past expiry) feed is still served as last-known-good, reported stale.
	s2 := NewStore(trust)
	s2.Apply(signFeed(t, priv, keyID, 7, entries("a"), now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)), now)
	later := now.Add(48 * time.Hour)
	if s2.EffectiveCatalog().Version != 7 {
		t.Fatal("a past-expiry feed must still be served (last-known-good, never break traffic)")
	}
	if st := s2.Status(later); !st.Stale || st.Source != "feed" {
		t.Fatalf("status should report stale feed: %+v", st)
	}
}

func TestFeedDurability(t *testing.T) {
	priv, keyID, trust := newTrust(t)
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "feed.json")
	s := NewStore(trust)
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	s.Apply(signFeed(t, priv, keyID, 9, entries("a", "b"), now.Format(time.RFC3339), now.Add(720*time.Hour).Format(time.RFC3339)), now)

	s2 := NewStore(trust)
	if err := s2.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if s2.EffectiveCatalog().Version != 9 {
		t.Fatal("applied feed must survive a restart")
	}
}
