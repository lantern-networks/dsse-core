package configstore

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/installprofile"
)

func signProfile(t *testing.T, p installprofile.InstallProfile) (envJSON []byte, pubHex string) {
	t.Helper()
	p.Kind = installprofile.ProfileKind
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil || signer == nil {
		t.Fatalf("signer: %v", err)
	}
	env, err := signer.Sign(p, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b, signer.PublicKeyHex()
}

func TestApplyThenLoad_RoundTrip(t *testing.T) {
	b := NewMemoryBackend()
	env, pub := signProfile(t, installprofile.InstallProfile{
		Version: 3, TenantID: "acme", GroupID: "developers", TransportURL: "https://edge.acme:18543",
		Captive: installprofile.CaptiveSpec{TimeoutSec: 300},
	})
	prof, err := Apply(b, env, pub, "bundled", "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatalf("Apply verified profile must succeed: %v", err)
	}
	if prof.TenantID != "acme" || prof.Captive.TimeoutSec != 300 {
		t.Fatalf("resolved profile wrong: %+v", prof)
	}
	// the pin is NEVER persisted (S1): only the envelope + provenance are stored.
	if _, present, _ := b.Get(valPin); present {
		t.Fatalf("the pin must NOT be persisted to the store")
	}
	got, meta, err := Load(b, pub)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !meta.Present || !meta.Verified {
		t.Fatalf("expected present+verified: %+v", meta)
	}
	if got.TenantID != "acme" || got.TransportURL != "https://edge.acme:18543" {
		t.Fatalf("loaded profile lost fields: %+v", got)
	}
	if meta.Version != 3 || meta.Source != "bundled" || meta.TenantID != "acme" {
		t.Fatalf("meta wrong: %+v", meta)
	}
}

func TestApply_RefusesUnverified(t *testing.T) {
	b := NewMemoryBackend()
	env, _ := signProfile(t, installprofile.InstallProfile{Version: 1, TenantID: "acme"})
	// wrong pin => verification fails => Apply must refuse and persist NOTHING.
	_, err := Apply(b, env, "00"+"11223344556677889900112233445566778899001122334455667788990011", "bundled", "now")
	if err == nil {
		t.Fatalf("Apply must refuse an unverified profile")
	}
	if _, present, _ := b.Get(valEnvelope); present {
		t.Fatalf("refused Apply must not persist anything")
	}
}

func TestLoad_Missing_SafeDefaults(t *testing.T) {
	b := NewMemoryBackend()
	got, meta, err := Load(b, "anypin")
	if err != nil {
		t.Fatalf("Load empty store: %v", err)
	}
	if meta.Present {
		t.Fatalf("empty store must report Present=false: %+v", meta)
	}
	if got.Posture != installprofile.PostureFailClosed || got.TransportURL != "" {
		t.Fatalf("empty store must yield fail-closed SafeDefaults: %+v", got)
	}
}

func TestLoad_TamperedBlob_FailsSafe(t *testing.T) {
	b := NewMemoryBackend()
	env, pub := signProfile(t, installprofile.InstallProfile{
		Version: 5, TenantID: "acme", Posture: installprofile.PostureFailOpen, AckFailOpen: true,
		TransportURL: "https://edge.acme:18543",
	})
	if _, err := Apply(b, env, pub, "mdm", "now"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Directly corrupt the stored envelope (simulate a registry edit trying to KEEP fail-open but break the sig).
	_ = b.Set(valEnvelope, `{"tampered":true}`)
	got, meta, err := Load(b, pub)
	if err != nil {
		t.Fatalf("Load tampered: %v", err)
	}
	if !meta.Present || meta.Verified {
		t.Fatalf("tampered blob must be Present but NOT Verified: %+v", meta)
	}
	// The edit can only DOWNGRADE to fail-closed SafeDefaults — never keep the fail-open it tried to preserve.
	if got.FailOpenEnabled() || got.Posture != installprofile.PostureFailClosed {
		t.Fatalf("tampered store must fail safe to fail-closed, got: %+v", got)
	}
}

func TestClear(t *testing.T) {
	b := NewMemoryBackend()
	env, pub := signProfile(t, installprofile.InstallProfile{Version: 1, TenantID: "acme"})
	if _, err := Apply(b, env, pub, "bundled", "now"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := Clear(b); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, meta, _ := Load(b, pub); meta.Present {
		t.Fatalf("after Clear the store must be empty: %+v", meta)
	}
}

// TestLoad_S1_AttackerCannotSwapPin is the regression for review finding S1: the pin is the CALLER's anchor, so
// an attacker who writes their OWN validly-signed envelope into the store cannot get it accepted — Load verifies
// against the anchored pin, not anything from the store.
func TestLoad_S1_AttackerCannotSwapPin(t *testing.T) {
	b := NewMemoryBackend()
	// legitimate profile + the real anchor pin.
	realEnv, realPin := signProfile(t, installprofile.InstallProfile{Version: 1, TenantID: "acme"})
	if _, err := Apply(b, realEnv, realPin, "bundled", "now"); err != nil {
		t.Fatalf("apply real: %v", err)
	}
	// attacker forges a fully-weakened profile signed with THEIR OWN key, and writes both envelope AND (old
	// design) a pin directly into the store.
	evilEnv, evilPin := signProfile(t, installprofile.InstallProfile{
		Version: 99, TenantID: "acme", Posture: installprofile.PostureFailOpen, AckFailOpen: true,
		TransportURL: "https://attacker.example:443", BypassApps: []string{"everything"},
	})
	_ = b.Set(valEnvelope, string(evilEnv))
	_ = b.Set(valPin, evilPin) // attacker tries to plant their pin too — Load must ignore it
	// The agent Loads with the REAL anchored pin. The forged envelope does NOT verify against it.
	got, meta, err := Load(b, realPin)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if meta.Verified {
		t.Fatalf("S1: forged envelope must NOT verify against the anchored pin")
	}
	if got.FailOpenEnabled() || got.Posture != installprofile.PostureFailClosed || len(got.BypassApps) != 0 {
		t.Fatalf("S1: attacker profile must not take effect; must fail-closed: %+v", got)
	}
}

func TestLoad_WrongAnchorPin_FailsSafe(t *testing.T) {
	b := NewMemoryBackend()
	env, pub := signProfile(t, installprofile.InstallProfile{Version: 1, TenantID: "acme", TransportURL: "https://edge:1"})
	if _, err := Apply(b, env, pub, "bundled", "now"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// a different anchor (wrong key) must not verify the stored envelope.
	_, otherPub := signProfile(t, installprofile.InstallProfile{Version: 1})
	_, meta, _ := Load(b, otherPub)
	if meta.Verified {
		t.Fatalf("stored envelope must not verify against a different anchor pin")
	}
}

// oneSigner returns a signer and its pin, so a test can issue SEVERAL profiles a single device would accept.
//
// ★ signProfile mints a FRESH key per call, and that alone made the old anti-rollback test meaningless: each
// profile was verified against its own pin, which no real device does — a device has one anchor baked into
// its signed binary. Anti-rollback is only a question at all between profiles that share it.
func oneSigner(t *testing.T) (*agentpolicy.Signer, string) {
	t.Helper()
	s, err := agentpolicy.LoadOrGenerateSigner(filepath.Join(t.TempDir(), "seed.hex"), true)
	if err != nil || s == nil {
		t.Fatalf("signer: %v", err)
	}
	return s, s.PublicKeyHex()
}

func signWith(t *testing.T, s *agentpolicy.Signer, p installprofile.InstallProfile) []byte {
	t.Helper()
	p.Kind = installprofile.ProfileKind
	env, err := s.Sign(p, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// ★★ ANTI-ROLLBACK ORDERS BY issued_at, NOT BY version (2026-08-17).
//
// The previous version of this test applied Version 2 over 3 and 4 over 3 and passed — with a guard that
// could not fire in production, because dsse-genprofile stamps the literal 3 on every profile it has ever
// issued. The test was asserting the comparison, not the ordering key, and the ordering key was constant.
// The lesson is in the sibling test in cmd/dsse-genprofile: a guard is worth what the issuer's key is worth.
func TestApply_AntiRollbackOrdersByIssuedAt(t *testing.T) {
	b := NewMemoryBackend()
	s, pub := oneSigner(t)

	newer := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme", IssuedAt: "2026-08-17T03:00:00Z"})
	if _, err := Apply(b, newer, pub, "bundled", "t1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Validly signed by the SAME key, same schema version — and stale. This is the case the version comparison
	// could never catch, and the realistic one: an old envelope kept on disk and re-applied.
	older := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme", IssuedAt: "2026-08-16T03:00:00Z"})
	if _, err := Apply(b, older, pub, "bundled", "t2"); err == nil {
		t.Fatal("a profile issued a day earlier must be refused; the schema version is equal, which is exactly " +
			"how every real pair of profiles compares")
	}
	// Equal is a re-apply (MSI repair, an idempotent re-run), not a rollback.
	if _, err := Apply(b, newer, pub, "bundled", "t3"); err != nil {
		t.Fatalf("re-applying the same profile must succeed: %v", err)
	}
	// Forward moves, obviously.
	newest := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme", IssuedAt: "2026-08-18T03:00:00Z"})
	if _, err := Apply(b, newest, pub, "bundled", "t4"); err != nil {
		t.Fatalf("apply a newer profile: %v", err)
	}
	// And a LOWER schema version with a NEWER stamp must be accepted: version is not the ordering key, and a
	// guard that quietly kept using it would fail here.
	odd := signWith(t, s, installprofile.InstallProfile{Version: 1, TenantID: "acme", IssuedAt: "2026-08-19T03:00:00Z"})
	if _, err := Apply(b, odd, pub, "bundled", "t5"); err != nil {
		t.Fatalf("schema version must not order profiles: %v", err)
	}
}

// The migration cases. Every profile deployed before 2026-08-17 is unstamped, including the one on the lab
// box this was found from, so the rules have to be right in BOTH directions or the fix bricks the fleet.
func TestApply_UnstampedProfilesMigrateInOneDirectionOnly(t *testing.T) {
	s, pub := oneSigner(t)
	unstamped := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme"})
	stamped := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme", IssuedAt: "2026-08-17T03:00:00Z"})

	// An unstamped profile is stored: there is no floor, so anything may replace it. Refusing here would leave
	// every already-deployed device unable to receive the profile that arms the floor.
	b := NewMemoryBackend()
	if _, err := Apply(b, unstamped, pub, "bundled", "t1"); err != nil {
		t.Fatalf("apply unstamped: %v", err)
	}
	if _, err := Apply(b, stamped, pub, "path", "t2"); err != nil {
		t.Fatalf("a stamped profile must be able to replace an unstamped one — this is the migration: %v", err)
	}
	// ...and once the floor exists, going back to an unstamped profile is a downgrade by construction.
	if _, err := Apply(b, unstamped, pub, "path", "t3"); err == nil {
		t.Fatal("an unstamped profile over a stamped one must be refused; it necessarily predates the stamp, " +
			"and allowing it would leave the rollback path open through nothing more than keeping an old file")
	}
	if _, meta, _ := Load(b, pub); meta.IssuedAt != "2026-08-17T03:00:00Z" {
		t.Fatalf("the refused apply must not have disturbed the stored profile; issued_at = %q", meta.IssuedAt)
	}
}

// ★ A REFUSAL MUST SAY WHAT IS NOW IN FORCE, NOT ONLY WHAT WAS REJECTED (raised from the macOS side).
//
// The MSI's ApplyProfile action is Return="ignore", so this refusal produces a SUCCESSFUL install in which
// the bundled profile did not land. That is the correct outcome — the device keeps the newer profile — but
// to whoever opens the log afterwards it reads as a silent failure unless the message says otherwise. This
// asserts the message, because the message is the whole difference between the two readings.
func TestARefusalNamesTheProfileItKept(t *testing.T) {
	b := NewMemoryBackend()
	s, pub := oneSigner(t)
	stamped := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme", IssuedAt: "2026-08-17T04:56:40Z"})
	if _, err := Apply(b, stamped, pub, "path", "t1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	unstamped := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme"})
	_, err := Apply(b, unstamped, pub, "bundled", "t2")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	for _, want := range []string{"KEEPING", "2026-08-17T04:56:40Z", "Nothing was changed"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not contain %q, so a reader cannot tell the device is still configured: %s",
				want, msg)
		}
	}
}

// The floor is the STORED ENVELOPE's stamp, re-verified — not the convenience value written beside it. An
// admin who edits the registry can already do worse, but a floor read out of a mutable store is not a floor,
// and the store deliberately never trusts its own contents (S1).
func TestApply_TheFloorComesFromTheSignedEnvelopeNotTheRegistryValue(t *testing.T) {
	b := NewMemoryBackend()
	s, pub := oneSigner(t)
	stamped := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme", IssuedAt: "2026-08-17T03:00:00Z"})
	if _, err := Apply(b, stamped, pub, "bundled", "t1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Lower the convenience value, as tampering would. The floor must not move.
	if err := b.Set(valIssuedAt, "2000-01-01T00:00:00Z"); err != nil {
		t.Fatalf("set: %v", err)
	}
	older := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme", IssuedAt: "2026-08-16T03:00:00Z"})
	if _, err := Apply(b, older, pub, "bundled", "t2"); err == nil {
		t.Fatal("editing InstallProfileIssuedAt must not lower the anti-rollback floor — it is derived from the " +
			"signed envelope")
	}

	// Conversely, a store holding an envelope that does NOT verify has no say in what replaces it: the good
	// profile sent to repair a tampered box must be able to land.
	b2 := NewMemoryBackend()
	if _, err := Apply(b2, stamped, pub, "bundled", "t1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := b2.Set(valEnvelope, `{"type":"x","payload_b64":"eyJ4IjoxfQ==","signature":"ed25519:AA"}`); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := Apply(b2, older, pub, "path", "t2"); err != nil {
		t.Fatalf("a store holding junk must not be able to refuse the profile repairing it: %v", err)
	}
}

// A stamp the issuer got wrong is refused out loud, in both positions. Rounding it either way would turn the
// freshness check back into the no-op this whole change exists to remove.
func TestApply_AMalformedStampIsRefusedRatherThanGuessed(t *testing.T) {
	s, pub := oneSigner(t)
	good := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme", IssuedAt: "2026-08-17T03:00:00Z"})
	junk := signWith(t, s, installprofile.InstallProfile{Version: 3, TenantID: "acme", IssuedAt: "last tuesday"})

	b := NewMemoryBackend()
	if _, err := Apply(b, good, pub, "bundled", "t1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := Apply(b, junk, pub, "path", "t2"); err == nil {
		t.Fatal("an offered profile whose issued_at does not parse must be refused")
	}
	b2 := NewMemoryBackend()
	if _, err := Apply(b2, junk, pub, "bundled", "t1"); err != nil {
		t.Fatalf("with no floor yet there is nothing to compare, so it lands (and is caught above): %v", err)
	}
	if _, err := Apply(b2, good, pub, "path", "t2"); err == nil {
		t.Fatal("a STORED stamp that does not parse must refuse the comparison out loud, not silently pass")
	}
}
