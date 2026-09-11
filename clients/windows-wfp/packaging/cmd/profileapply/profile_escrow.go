//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/configstore"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// The signed install profile used to exist in exactly ONE place on a device: the config-store registry key.
// Uninstall scrubs that key on purpose (`--clear`), because an organization's configuration should not linger
// on a machine the organization removed the product from. The consequence was measured on win-dev-1 on
// 2026-08-21 and it is severe:
//
//	msiexec /x ...   -> exit 0        (the profile is cleared)
//	msiexec /i ...   -> exit 0        (nothing restores it — see below)
//	sc start DsseSteer -> 1053        (the agent starts, finds no profile, and exits)
//
// Nothing in the package can put it back. The profile.json the MSI carries is a SAMPLE for a different tenant
// signed by a different key; it is refused, correctly, by the pin baked into this binary. And profiles are
// issued by the control plane, not here — so an administrator who uninstalls and reinstalls to "fix" something
// (the first thing an administrator tries) ends up with a device that cannot be made to steer again without
// going back to the issuer for a new envelope.
//
// The escrow copy closes that. On every successful apply the VERIFIED envelope is also written to
// %ProgramData%\DSSE, which is outside MSI component tracking and therefore survives an uninstall the same way
// the rollback store does. A later install can restore from it.
//
// What the escrow copy is NOT:
//
//   - It is not a second authority. Restoring runs the envelope back through configstore.Apply, so it is
//     re-verified against this binary's pin and re-checked against the anti-rollback floor exactly like any
//     other apply. Editing the escrowed file gets an administrator a refusal, not a configuration.
//   - It is not a secret. The envelope is a signed public document; its confidentiality was never what made it
//     trustworthy. It is written with the ordinary ProgramData ACL for that reason.
//   - It is not a decision about whether uninstall SHOULD scrub the config store. That question belongs to
//     whoever owns the product's uninstall semantics; this only makes the answer recoverable either way.
const escrowFileName = "install-profile.json"

// escrowDirOverride lets the tests point the escrow somewhere disposable. Empty means the real device path, so
// a test that forgets to set it writes nowhere near a machine's actual configuration.
var escrowDirOverride string

func escrowDir() string {
	if escrowDirOverride != "" {
		return escrowDirOverride
	}
	// Read ProgramData rather than hardcoding C:\ProgramData: it is not always on C:, and a path that is wrong
	// on a redirected machine fails at the worst moment — the reinstall someone is doing to recover.
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "DSSE")
	}
	return filepath.Join(`C:\ProgramData`, "DSSE")
}

func escrowPath() string { return filepath.Join(escrowDir(), escrowFileName) }

// escrowProfile keeps a copy of an envelope that has ALREADY been verified and persisted. It is called after
// the apply succeeds, never before: escrowing bytes that failed verification would hand the next install a
// document this one refused.
//
// A failure here is reported and swallowed by the caller. The profile is in force either way, and an install
// must not be rolled back because a convenience copy could not be written — that would trade a real outage for
// a hypothetical one.
func escrowProfile(envelopeJSON []byte) error {
	dir := escrowDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %q: %w", dir, err)
	}
	// Write-then-rename: a half-written escrow file is worse than no escrow file, because it is only ever read
	// on the recovery path, where nobody is watching and the failure looks like "the profile is just gone".
	//
	// ★ AND THAT IS durablefile.Write (2026-08-21, caught by the one-durable-write gate on the shared branch).
	// Spelling the sequence out again — create temp, write, sync, close, rename — is how that family
	// reproduces: every copy is individually reasonable, and the one that gets a platform fix is never the one
	// that needed it. On Windows in particular the rename semantics live in that package, not here.
	if err := durablefile.Write(escrowPath(), envelopeJSON, 0o600); err != nil {
		return fmt.Errorf("write the escrow copy at %q: %w", escrowPath(), err)
	}
	return nil
}

// restoreProfileFromEscrow is safe to run on EVERY install and upgrade, which is the only way it is any use:
// the install that needs it is the one nobody knew was going to need it.
//
// It changes nothing on a box that already holds a verified profile — the overwhelmingly common case, and the
// one where acting would be wrong, because the store may legitimately hold something NEWER than the escrow
// (a re-point issued after this copy was taken). It acts only on the shape that was actually broken: a store
// with no usable profile and an escrowed envelope to put in it.
//
// The returned line is what the installer log shows. It says what is in force afterwards in every branch,
// including the branches where nothing happened, because "the install worked but the profile silently didn't"
// is precisely the reading this whole path exists to prevent.
func restoreProfileFromEscrow(be configstore.Backend, pin, now string) (restored bool, line string, err error) {
	_, meta, err := configstore.Load(be, pin)
	if err != nil {
		return false, "", fmt.Errorf("read the config store: %w", err)
	}
	if meta.Present && meta.Verified {
		return false, fmt.Sprintf("profile restore: not needed — the config store already holds a verified profile "+
			"(tenant=%q issued_at=%q). Nothing was changed", meta.TenantID, meta.IssuedAt), nil
	}
	env, readErr := os.ReadFile(escrowPath())
	if readErr != nil {
		if os.IsNotExist(readErr) {
			// Stated as a fact about this device, not as an error. A box that has never had a profile applied by
			// a build carrying the escrow will land here, and that is not a fault — but it IS the box that
			// cannot recover from an uninstall, so the line says so rather than staying quiet.
			if meta.Present {
				return false, "profile restore: the stored profile does not verify against this binary's anchor and " +
					"there is no escrowed copy at " + escrowPath() + " to fall back to. This device needs a re-issued " +
					"profile from the control plane before DsseSteer can steer", nil
			}
			return false, "profile restore: no profile in the config store and no escrowed copy at " + escrowPath() +
				". If this device is meant to steer, apply a signed profile (--apply --config <envelope>)", nil
		}
		return false, "", fmt.Errorf("read the escrowed profile %q: %w", escrowPath(), readErr)
	}
	prof, applyErr := configstore.Apply(be, env, pin, "escrow", now)
	if applyErr != nil {
		// Re-verification refused it. Say which copy was refused, because the operator's next move differs:
		// a tampered escrow is deleted, a legitimately superseded one is replaced by the issuer.
		return false, "", fmt.Errorf("the escrowed profile at %s was refused on re-verification: %w", escrowPath(), applyErr)
	}
	return true, fmt.Sprintf("profile restore: RESTORED from the escrowed copy at %s — version=%d tenant=%q "+
		"posture=%q transport=%q. The config store had no usable profile; an uninstall or a failed apply is the "+
		"usual reason", escrowPath(), prof.Version, prof.TenantID, prof.Posture, prof.TransportURL), nil
}
