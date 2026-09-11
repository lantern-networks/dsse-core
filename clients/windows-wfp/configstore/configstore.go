// Package configstore persists the L1 install profile in the agent's config store. On Windows the store is a
// registry key (HKLM\SOFTWARE\DSSE\Agent) whose ACL is SYSTEM/Admin-only; here the persistence is abstracted
// behind Backend so the verify/persist orchestration is platform-neutral and unit-tested, with a registry
// Backend (store_windows.go) for production and an in-memory Backend for tests.
//
// TAMPER MODEL (the important design choice): the store persists only the SIGNED ENVELOPE, NOT a plain resolved
// config AND NOT the pin. Every read RE-VERIFIES the stored envelope via installprofile.Load against a pin the
// CALLER supplies — a trust anchor baked into the Authenticode-signed agent binary, never read back from the
// mutable store. That is what makes editing the registry able to only DOWNGRADE the agent to SafeDefaults
// (fail-closed): a tampered envelope fails the signature check against the anchored pin, and an attacker cannot
// substitute their own pin because the pin does not live in the store. If the store held the pin, a local admin
// could write BOTH their own envelope AND their own pin and it would self-verify — defeating the whole model
// (that was the review finding S1). The pin therefore MUST come from the anchored caller, never from Backend.
package configstore

import (
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/installprofile"
)

// Backend is the raw string key/value persistence the store sits on (the Windows registry in production).
type Backend interface {
	Get(name string) (value string, ok bool, err error)
	Set(name, value string) error
	Clear() error // remove all stored values (uninstall)
}

// Registry value names under the config-store key. Stable — they are the on-disk contract.
const (
	valEnvelope  = "InstallProfileEnvelope"  // the signed agentpolicy.Envelope JSON (source of truth)
	valPin       = "InstallProfilePin"       // legacy — NO LONGER written/read (the pin is a caller anchor, S1); Clear still deletes it to scrub any pre-fix value
	valSource    = "InstallProfileSource"    // provenance: bundled | path | mdm
	valAppliedAt = "InstallProfileAppliedAt" // RFC3339 timestamp the profile was applied
	valVersion   = "InstallProfileVersion"   // applied profile SCHEMA version — MDM detection (see the S2 note in Apply)
	valIssuedAt  = "InstallProfileIssuedAt"  // issued_at of the applied profile, RFC3339 — the real anti-rollback floor (S2)
	valTenant    = "InstallProfileTenant"    // resolved tenant id (observability; NOT trusted for auth)
)

// ValueInstalledVersion is the version the MSI stamps under the same key when it installs, for the MDM
// detection rule. EXPORTED, unlike the values above, because it is the one thing here this package does not
// write: DsseAgent.wxs does, and the updater reads it to name the build a rollback is escaping. A name shared
// by a .wxs and a .go file with nothing comparing them is how a reader quietly starts finding nothing —
// TestTheWxsStampsTheInstalledVersionValueTheUpdaterReads is the comparison.
const ValueInstalledVersion = "InstalledVersion"

// Meta is the non-secret provenance of the stored profile (for the installer log / MDM detection rule / tray).
type Meta struct {
	Verified  bool   // did the stored envelope re-verify against the stored pin on this read?
	Version   int    // resolved profile version
	TenantID  string // resolved tenant id
	Source    string // bundled | path | mdm
	AppliedAt string // RFC3339 — when THIS DEVICE applied it
	IssuedAt  string // RFC3339 — when the ISSUER signed it; empty on profiles predating the field
	Present   bool   // was a profile stored at all?
}

// Apply verifies the signed envelope against pinHex — the CALLER'S trust anchor (baked into the signed agent
// binary), never a store value — and, ONLY if it verifies, persists the ENVELOPE (not the pin) plus provenance.
// It REFUSES to persist an unverifiable profile (an install fails visibly rather than silently seeding an
// untrusted config), and REFUSES a profile issued before the applied one (S2 anti-rollback on the apply path).
// Returns the resolved effective profile.
func Apply(b Backend, envelopeJSON []byte, pinHex, source, now string) (installprofile.InstallProfile, error) {
	prof, verified, err := installprofile.Load(envelopeJSON, pinHex)
	if err != nil || !verified {
		return prof, fmt.Errorf("configstore: refusing to persist an unverified install profile: %w", err)
	}
	// Anti-rollback (S2, apply path): never move to a profile OLDER than the one already applied.
	//
	// ★★ THIS USED TO COMPARE prof.Version, AND THAT GUARD COULD NEVER FIRE (2026-08-17, found from the macOS
	// side while checking whether a legitimate re-point would even be accepted). `version` is the SCHEMA
	// version, not an issue counter: the only place in this tree that sets it is dsse-genprofile, as the
	// literal 3. Every profile this product issues therefore compares EQUAL, `prof.Version < curV` is false for
	// all of them, and the refusal never happened — including for the case the comment claimed to guard, the
	// installer/MDM update path. A guard that cannot fire reads exactly like a guard that holds.
	//
	// The ordering key is issued_at, inside the signed payload. The rules, and why each is what it is:
	//
	//   both stamped      -> refuse a STRICTLY older one. Equal is allowed: re-applying the same profile is an
	//                        MSI repair and an idempotent re-run, not a rollback.
	//   stored stamped,
	//   incoming not      -> REFUSE. An unstamped profile was issued before this field existed, so it is older
	//                        by construction; accepting it would leave a downgrade path that consists of
	//                        keeping an old envelope around.
	//   stored not stamped-> allow, and record whatever the incoming one has. Every profile deployed before
	//                        today is unstamped; refusing here would brick the boxes this is meant to protect.
	//                        The floor establishes itself the first time a stamped profile lands.
	//   unparseable       -> refuse and say so. The payload is signed, so a malformed stamp is the ISSUER
	//                        emitting garbage, and guessing which way to round it is how a freshness check
	//                        quietly becomes a no-op (which is the defect above, again).
	//
	// The floor comes from RE-VERIFYING THE STORED ENVELOPE, not from the InstallProfileIssuedAt value beside
	// it. That value is written here for the installer log and the tray, and a floor read back out of a
	// mutable store is a floor whoever can write the store can lower. Re-deriving it costs one signature check
	// on a path that already does two, and it means the thing being compared is signed at both ends — the same
	// argument this package makes for never storing the pin (S1).
	//
	// Scope, stated so it is not mistaken for more than it is: this is the APPLY path. Runtime replay by an
	// admin writing the registry directly is still only bounded by the signature — installprofile.Load has no
	// not_after — and closing that needs an expiry in the schema plus a clock the agent trusts.
	if cur := storedIssuedAt(b, pinHex); cur != "" {
		curAt, e := time.Parse(time.RFC3339, cur)
		if e != nil {
			return prof, fmt.Errorf("configstore: the applied profile's issued_at %q is not RFC3339, so rollback cannot be judged: %w", cur, e)
		}
		// ★ THE WORDING IS PART OF THE FIX (raised from the macOS side, 2026-08-17). The MSI runs this with
		// Return="ignore", so the install SUCCEEDS while the bundled profile does not land — which is correct,
		// and which reads to whoever opens the log as "the install worked but the profile silently didn't".
		// Every refusal below therefore says what is now in force, not just what was rejected.
		newRaw := strings.TrimSpace(prof.IssuedAt)
		if newRaw == "" {
			return prof, fmt.Errorf("configstore: KEEPING the profile issued %s; the offered one carries no issued_at, "+
				"which means it was issued before profiles were stamped and is therefore older. Nothing was changed. "+
				"This is the expected outcome of installing a package built before %s onto a device the control "+
				"plane has already reached; re-issue the profile to move this device", cur, cur)
		}
		newAt, e := time.Parse(time.RFC3339, newRaw)
		if e != nil {
			return prof, fmt.Errorf("configstore: KEEPING the profile issued %s; the offered one's issued_at %q is not "+
				"RFC3339, so which is newer cannot be decided. Nothing was changed", cur, newRaw)
		}
		if newAt.Before(curAt) {
			return prof, fmt.Errorf("configstore: KEEPING the profile issued %s; the offered one was issued earlier (%s). "+
				"Nothing was changed", cur, newRaw)
		}
	}
	if err := setAll(b, map[string]string{
		valEnvelope:  string(envelopeJSON),
		valSource:    source,
		valAppliedAt: now,
		valVersion:   fmt.Sprintf("%d", prof.Version),
		valIssuedAt:  strings.TrimSpace(prof.IssuedAt),
		valTenant:    prof.TenantID,
	}); err != nil {
		return prof, fmt.Errorf("configstore: persist: %w", err)
	}
	return prof, nil
}

// Load reads the stored envelope and RE-VERIFIES it against pinHex — the CALLER'S anchored trust key, NOT a
// store value (S1). It never errors on a missing or tampered profile: a missing store yields the resolved
// SafeDefaults (Present=false); a tampered/wrong-key/attacker-substituted stored envelope ALSO yields
// SafeDefaults (Present=true, Verified=false) — the agent runs fail-closed rather than trusting edited bytes.
// A backend I/O error is the only returned error.
func Load(b Backend, pinHex string) (installprofile.InstallProfile, Meta, error) {
	env, present, err := b.Get(valEnvelope)
	if err != nil {
		return safeProfile(), Meta{}, fmt.Errorf("configstore: read: %w", err)
	}
	if !present || env == "" {
		return safeProfile(), Meta{Present: false, Verified: false}, nil
	}
	prof, verified, _ := installprofile.Load([]byte(env), pinHex) // tamper/wrong-key => resolved SafeDefaults, verified=false
	source, _, _ := b.Get(valSource)
	appliedAt, _, _ := b.Get(valAppliedAt)
	meta := Meta{
		Verified:  verified,
		Version:   prof.Version,
		TenantID:  prof.TenantID,
		Source:    source,
		AppliedAt: appliedAt,
		// From the re-verified payload, not from the stored value: the registry copy is convenience for the
		// Apply-path comparison, and reporting it would report an attacker's edit as the profile's own stamp.
		IssuedAt: prof.IssuedAt,
		Present:  true,
	}
	return prof, meta, nil
}

// storedIssuedAt is the anti-rollback floor: the issued_at of the currently stored profile, taken from a
// re-verification against the caller's anchor. Anything that does not verify has no say in what may replace
// it — a store holding junk must not be able to refuse the good profile sent to repair it.
func storedIssuedAt(b Backend, pinHex string) string {
	env, present, err := b.Get(valEnvelope)
	if err != nil || !present || env == "" {
		return ""
	}
	prof, verified, _ := installprofile.Load([]byte(env), pinHex)
	if !verified {
		return ""
	}
	return strings.TrimSpace(prof.IssuedAt)
}

// Clear removes the stored profile (uninstall). Best-effort per the backend.
func Clear(b Backend) error { return b.Clear() }

// safeProfile is the resolved fail-closed default (reuses installprofile.Load's own safe fallback path).
func safeProfile() installprofile.InstallProfile {
	p, _, _ := installprofile.Load(nil, "") // no key => resolved SafeDefaults
	return p
}

func setAll(b Backend, kv map[string]string) error {
	for k, v := range kv {
		if err := b.Set(k, v); err != nil {
			return err
		}
	}
	return nil
}

// MemoryBackend is an in-memory Backend for tests and non-Windows builds.
type MemoryBackend struct{ m map[string]string }

func NewMemoryBackend() *MemoryBackend { return &MemoryBackend{m: map[string]string{}} }

func (b *MemoryBackend) Get(name string) (string, bool, error) { v, ok := b.m[name]; return v, ok, nil }
func (b *MemoryBackend) Set(name, value string) error          { b.m[name] = value; return nil }
func (b *MemoryBackend) Clear() error                          { b.m = map[string]string{}; return nil }
