package updateplatform

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// intent.go — how a DELIBERATE downgrade is told apart from an accidental one, on a Mac.
//
// The installer package refuses to install an older build over a newer one, and must keep refusing: a
// downgrade nobody asked for leaves a system extension whose version goes backwards, and the activation
// request's replacement path then has to reason about it. That guard is correct — and it is also what made the
// stored rollback package unusable by hand, so this device kept material for a rollback that its own product
// would have rejected.
//
// The resolution is not to weaken the guard but to give the ONE path entitled to downgrade a way to say so:
// this file, written by the root updater immediately before it launches the installer, and read by the
// preinstall script. An override that any install could use is not an override, it is a hole; so the intent is
//
//   - writable only by root, in a directory only root can write (the installer chowns it root:wheel 750),
//   - bound to ONE version — it names the exact agent version being installed, and the preinstall compares
//     that against the version baked into the package it belongs to, so an intent for 0.2.0 cannot wave
//     through a package for anything else,
//   - short-lived, with the deadline as a plain integer so a shell can compare it without parsing dates or
//     reasoning about time zones,
//   - single-use: the preinstall deletes it before proceeding, so a file left behind by a rollback that never
//     completed cannot authorise a downgrade tomorrow.
//
// ★ WHY A FILE AND NOT AN ENVIRONMENT VARIABLE, which is the obvious answer and was the first design. Package
// scripts for `installer -target /` are run by installd, a launchd daemon — not as children of the process
// that invoked installer — so a DSSE_ROLLBACK=1 in the updater's environment is not something the preinstall
// can be relied on to see. A mechanism that works when tested by hand in a terminal and silently fails under
// the daemon that actually performs updates is the worst of both.

// IntentSchema is the on-disk marker. It is checked, so a future incompatible shape cannot be read as a
// permissive one by an old script.
const IntentSchema = "dsse_rollback_intent.v1"

// IntentTTL is how long an authorisation to downgrade remains valid.
//
// Long enough to cover the installer starting on a loaded machine, short enough that a rollback abandoned
// half-way does not leave a live override sitting on the disk. The window only has to cover the gap between
// the updater writing this file and the preinstall reading it, which is seconds.
const IntentTTL = 15 * time.Minute

// IntentPath is where the intent lives: inside the rollback store, which is already root-only.
// Concatenated rather than path.Join: this file has a local variable named `path`, and a package that shadows
// it is a worse trap than a slash. Same rule as RollbackRoot — a macOS target path is not a host path, so
// filepath.Join (which yields backslashes on a Windows build host) must not spell it.
func IntentPath() string { return RollbackRoot() + "/rollback_intent.json" }

// Intent is the authorisation itself.
type Intent struct {
	Schema string `json:"schema"`
	// ToVersion is the agent version of the package being installed, in the form the app reports it
	// ("<CFBundleShortVersionString>+<CFBundleVersion>"). The preinstall compares it against its own baked-in
	// version, so the two agree by construction rather than by anyone remembering.
	ToVersion string `json:"to_version"`
	// FromVersion is what the device was running when the rollback was ordered, for the operator reading this
	// afterwards. Nothing is decided by it.
	FromVersion string `json:"from_version,omitempty"`
	Package     string `json:"package"`
	IssuedAt    string `json:"issued_at"`
	// ExpiresAt is human-readable; ExpiresAtUnix is what the check uses. A shell comparing seconds cannot be
	// wrong about a time zone, and `date -j -f` on a UTC string would be interpreted in local time.
	ExpiresAt     string `json:"expires_at"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
}

// NewIntent builds an authorisation valid for IntentTTL from now.
func NewIntent(toVersion, fromVersion, pkg string, now time.Time) Intent {
	exp := now.Add(IntentTTL).UTC()
	return Intent{
		Schema:        IntentSchema,
		ToVersion:     toVersion,
		FromVersion:   fromVersion,
		Package:       pkg,
		IssuedAt:      now.UTC().Format(time.RFC3339),
		ExpiresAt:     exp.Format(time.RFC3339),
		ExpiresAtUnix: exp.Unix(),
	}
}

// WriteIntent puts the authorisation where the preinstall will look for it.
//
// Written to a temporary file in the same directory and renamed, like everything else this design persists: a
// torn intent is one the preinstall would reject, which would turn a rollback into a refusal at the moment
// somebody needs it. Mode 0600 and a 0700 directory, because this file is the one thing that can talk a
// root installer out of its downgrade guard.
func WriteIntent(path string, in Intent) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	// ★ THE SHARED DURABLE WRITE (2026-08-14, thirty-first review #12). This was the same create/write/flush/
	// close/chmod/rename by hand — durablefile.Write, spelled out, including setting the mode before the file
	// becomes visible — and it ended in a plain os.Rename, so the directory entry was never flushed at all.
	//
	// That matters here in a specific way: this file is read by a preinstall script running under installd,
	// moments after it is written, to authorise the one downgrade a rollback is entitled to. A rename the
	// filesystem has not committed is exactly the state a machine is in when somebody is rolling it back
	// because something has just gone wrong on it.
	if werr := durablefile.Write(path, b, 0o600); werr != nil {
		return fmt.Errorf("write the rollback intent to %s: %w", path, werr)
	}
	return nil
}

// ReadIntent is for reporting — `--status` says whether a live authorisation is sitting on this device, since
// one that outlives its rollback is something an operator should see rather than discover.
func ReadIntent(path string) (Intent, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Intent{}, err
	}
	var in Intent
	if err := json.Unmarshal(b, &in); err != nil {
		return Intent{}, fmt.Errorf("the rollback intent at %s is unreadable: %w", path, err)
	}
	if in.Schema != IntentSchema {
		return Intent{}, fmt.Errorf("the rollback intent at %s has schema %q, want %q", path, in.Schema, IntentSchema)
	}
	return in, nil
}

// Expired reports whether this authorisation is past its deadline — the same comparison the preinstall makes,
// in the same units.
func (in Intent) Expired(now time.Time) bool { return now.Unix() >= in.ExpiresAtUnix }

// AcceptsIntentMarker is written beside a stashed package by the postinstall of the package that installed it,
// and names the authorisation schema that package's own preinstall honours.
//
// ★ WHY THIS IS NEEDED AT ALL, and it is the sharpest consequence of where the check lives. The script that
// reads an authorisation is the preinstall INSIDE THE PACKAGE BEING INSTALLED — so a package built before the
// authorisation existed refuses the downgrade no matter what the updater writes. The first version that can be
// rolled back TO is the first one built with it. Every package this fleet has stored so far predates it.
//
// That is unavoidable (an old package cannot learn a new exception) but it must not be discovered by running
// it. Without this marker, a rollback ordered during an incident launches an installer that refuses, and what
// the operator sees is an opaque failure at the worst possible moment. With it, the refusal comes from the
// updater, before anything is touched, saying exactly which property the stored package lacks.
//
// The marker is written by the same package whose preinstall does the honouring, so it cannot lie about a
// third party. The suffix deliberately does not match rollbackstore's naming rules, so List and Prune ignore it.
func AcceptsIntentMarker(pkg string) string { return pkg + ".accepts-rollback-intent" }

// PackageAcceptsIntent reports whether a stored package's own preinstall will honour an authorisation of the
// schema this updater writes.
func PackageAcceptsIntent(pkg string) error {
	marker := AcceptsIntentMarker(pkg)
	raw, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return fmt.Errorf("%s predates the rollback authorisation: its own preinstall refuses every downgrade, so "+
			"installing it would fail no matter what this updater writes. The first version that can be rolled back "+
			"TO is the first one built with the authorisation — until this device installs one and stores it, it has "+
			"no rollback and this is the honest form of saying so", filepath.Base(pkg))
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", marker, err)
	}
	// Compared, not merely present: a future schema change would otherwise be waved through by a marker written
	// for the old one, which is the same "declared capability nobody checked" this file exists to end.
	if got := strings.TrimSpace(string(raw)); got != IntentSchema {
		return fmt.Errorf("%s honours authorisation schema %q; this updater writes %q, and its preinstall would "+
			"refuse the downgrade", filepath.Base(pkg), got, IntentSchema)
	}
	return nil
}
