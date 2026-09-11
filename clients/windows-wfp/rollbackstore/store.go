// Package rollbackstore is the on-disk answer to one question: if this update goes wrong, what do we put
// back?
//
// The updater refuses to start when the answer is "nothing" (agentupdate.Platform.CaptureRestoreMaterial
// returns an error and Run aborts), because an update that cannot be rolled back is the same as having no
// rollback — and the moment to discover that is before the installer runs, not after. That refusal is only
// honest if something is actually putting packages here, which is what this package and the installer's
// --stash-rollback-msi mode exist to do.
//
// THE CASE THIS EXISTS FOR is not the fresh box. It is the box installed months ago: it is running a version
// whose MSI nobody kept, so it has no restore material and will refuse every update forever, silently, while
// looking healthy. Stashing has to start happening at INSTALL time for that to stop being true, which is why
// this ships with the installer rather than with the updater.
//
// Nothing here is //go:build windows. Where the store lives is Windows-specific (one function), but what goes
// in it, under what name, and what happens when the name is hostile are decisions — and decisions that gate a
// rollback should not go unexercised because the test host was the wrong OS. Only DefaultRoot reads a Windows
// environment variable, and it degrades rather than failing.
package rollbackstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrNoMaterial is returned by Lookup when this box holds no package for the version asked about. It is a
// distinct sentinel because the caller must treat it differently from an I/O failure: "no rollback material"
// is a normal, expected state on an older box and the correct response is to refuse the update and say so,
// whereas a read error on a directory we own is a fault worth surfacing as one.
var ErrNoMaterial = errors.New("rollbackstore: no installer package stored for this version")

// namePrefix and nameSuffix bracket the version in a stored file name. The prefix also removes a class of
// Windows problem for free: a reserved device name (CON, PRN, NUL, AUX, COM1…) can never be produced, because
// every name this package writes begins with these literal bytes.
const (
	namePrefix = "dsse-agent-"
	nameSuffix = ".msi"
)

// maxVersionLen bounds what is allowed to reach a path. Real versions are short ("0.1.0+2e39256d.dirty" is
// 20); anything approaching this is not a version and the store is not the place to find that out gently.
const maxVersionLen = 96

// Store is a directory holding the installer packages this box could roll back to.
//
// The root is a parameter rather than a constant so the whole package is testable on any host with a
// temporary directory, and so a test can never be one bug away from writing into the real ProgramData tree.
type Store struct {
	root string
	// ext is the installer package extension: ".msi" on Windows, ".pkg" on macOS.
	//
	// ★ It is a field because it is NOT cosmetic. The installer writes the file and the updater looks it up,
	// and those are different programs — on macOS a postinstall script storing dsse-agent-X.pkg while Lookup
	// asked for dsse-agent-X.msi produces ErrNoMaterial on every device forever, which presents as "nobody
	// implemented stashing" while all the code is there and running. Caught by building the package and running
	// the script rather than by reading either.
	//
	// Empty means the Windows default, so every existing caller is unchanged.
	ext string
}

// New returns a Store rooted at dir. It does not touch the filesystem; nothing is created until Stash.
func New(dir string) *Store { return &Store{root: dir} }

// NewForPackages returns a Store whose packages carry a different extension — ".pkg" for macOS. The naming
// rules, the torn-copy refusal and the content-idempotency are the same code; only the suffix differs, which
// is the whole reason this is a parameter rather than a second package.
func NewForPackages(dir, ext string) *Store { return &Store{root: dir, ext: ext} }

// suffix is the extension this store uses.
func (s *Store) suffix() string {
	if strings.TrimSpace(s.ext) == "" {
		return nameSuffix
	}
	return s.ext
}

// Root reports the directory this Store manages.
func (s *Store) Root() string { return s.root }

// DefaultRoot is where the store lives on a real endpoint: %ProgramData%\DSSE\rollback.
//
// ProgramData rather than the install directory, deliberately. The install directory is what an upgrade
// rewrites and an uninstall removes, so a rollback package kept beside the binaries is a rollback package
// that disappears at exactly the moment it is needed.
//
// The environment variable is read rather than hardcoding C:\ProgramData because it is not always C:, and a
// wrong absolute path here would be discovered as "every update refuses" much later. If it is unset — which
// on Windows means something is badly wrong, and on any other OS simply means this is not Windows — the
// relative fallback keeps callers from having to handle an empty string; it is not a usable production path
// and is not meant to be.
func DefaultRoot() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "DSSE", "rollback")
	}
	return filepath.Join("DSSE", "rollback")
}

// FileName is the stored name for a version, and the single place a version becomes part of a path.
//
// It is strict on purpose. The version reaching this function comes from a signed manifest or from a registry
// value written by an installer, and both are inputs rather than constants: a version of `..\..\Windows\
// System32\x` would otherwise let a stash write, and a prune delete, outside the store. Allowing only the
// characters real versions actually use (digits, letters, dot, plus, hyphen, underscore) rejects that whole
// class without needing to reason about how many separators a given OS honours.
//
// A leading dot or hyphen is refused separately: neither appears in a real version, and both produce names
// that behave oddly for tools that later have to list or clean this directory.
func FileName(version string) (string, error) { return fileNameWithSuffix(version, nameSuffix) }

// FileNameFor is FileName for a store with a non-default extension.
func FileNameFor(version, ext string) (string, error) { return fileNameWithSuffix(version, ext) }

func fileNameWithSuffix(version, suffix string) (string, error) {
	if version == "" {
		return "", errors.New("rollbackstore: empty version")
	}
	if len(version) > maxVersionLen {
		return "", fmt.Errorf("rollbackstore: version too long (%d > %d)", len(version), maxVersionLen)
	}
	if version[0] == '.' || version[0] == '-' {
		return "", fmt.Errorf("rollbackstore: version %q may not begin with %q", version, version[:1])
	}
	for _, r := range version {
		switch {
		case r >= '0' && r <= '9',
			r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r == '.', r == '+', r == '-', r == '_':
		default:
			return "", fmt.Errorf("rollbackstore: version %q contains disallowed character %q", version, string(r))
		}
	}
	return namePrefix + version + suffix, nil
}

// versionFromName is FileName's inverse, used only when listing. It returns "" for anything this package did
// not write, so a stray file dropped into the directory is ignored rather than mistaken for restore material.
func versionFromName(name, suffix string) string {
	if !strings.HasPrefix(name, namePrefix) || !strings.HasSuffix(name, suffix) {
		return ""
	}
	v := name[len(namePrefix) : len(name)-len(suffix)]
	if _, err := FileName(v); err != nil {
		return ""
	}
	return v
}

// Path is where a version's package would live. It does not report whether it is there.
func (s *Store) Path(version string) (string, error) {
	name, err := fileNameWithSuffix(version, s.suffix())
	if err != nil {
		return "", err
	}
	return filepath.Join(s.root, name), nil
}

// Lookup returns the stored package for version, or ErrNoMaterial if this box has none.
//
// A zero-length file counts as absent. That is not defensive noise: a torn copy is the one way this directory
// can hold a name that promises a rollback and a body that cannot perform one, and treating it as present
// would convert "we refused to start" into "we started and could not go back".
func (s *Store) Lookup(version string) (string, error) {
	p, err := s.Path(version)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: version %s", ErrNoMaterial, version)
		}
		return "", fmt.Errorf("rollbackstore: stat %s: %w", p, err)
	}
	if st.IsDir() {
		return "", fmt.Errorf("rollbackstore: %s is a directory, not an installer package", p)
	}
	if st.Size() == 0 {
		return "", fmt.Errorf("%w: version %s is present but empty (torn copy)", ErrNoMaterial, version)
	}
	return p, nil
}

// Stash copies src into the store as the package for version and returns the stored path.
//
// It is idempotent: if a non-empty package for this version is already stored, src is not read and the
// existing path is returned. Re-running an installer, or a repair, must not spend time rewriting a file whose
// name already pins its contents — and must not risk replacing a good package with a worse one.
//
// The copy is written to a temporary file in the SAME directory and renamed into place, so a crash, a full
// disk, or a killed installer leaves either the old state or the complete new file, never a half one under
// the real name. Same directory specifically: a rename across volumes is not atomic, and %ProgramData% and
// %TEMP% are not guaranteed to be on one.
func (s *Store) Stash(src, version string) (string, error) {
	dst, err := s.Path(version)
	if err != nil {
		return "", err
	}

	// ★ Idempotent on CONTENT, not on name — a correction, and the assumption it corrects was mine.
	//
	// This used to return early whenever a package for the version existed at all, on the reasoning that "the
	// version is the identity, so the name already pins the contents". That premise does not hold for the
	// version strings this product actually produces. agentVersion() appends ".dirty" for a modified tree, so
	// two DIFFERENT builds of one commit share a version string — which is the daily case on a development
	// box. The first stash would win, and a later rollback would install bytes that were never the ones
	// running.
	//
	// Comparing digests keeps the property that mattered (identical bytes are not rewritten, so a repair or a
	// re-run is cheap and cannot replace a good package with a worse one) and drops the one that was false.
	// Last install wins when they differ, which is correct: the last install is what is running.
	// ★★★ VERIFIED BEFORE ANY PATH THAT SUCCEEDS. The content-
	// idempotent early return below, the stale-marker removal, and the copy all reported success without ever
	// reaching the check that used to sit further down — so a repair or reinstall into an unsafe store, with
	// bytes already present, passed straight through. The gate is now the first thing Stash does.
	//
	// ★ AND FOR EVERY ROOT, NOT ONLY %%ProgramData%% (point 2). Scoping it to the production path meant the
	// Stash regression could never be exercised by a test, which is the same as not having it: a test fixture
	// is cheap to make administrator-owned, and protect_windows_test.go does exactly that.
	if err := prepareStoreForWriting(s.root); err != nil {
		return "", err
	}
	if err := verifyStoreForWriting(s.root); err != nil {
		return "", err
	}

	if existing, lerr := s.Lookup(version); lerr == nil {
		if err := verifyStoredPackageForWriting(s.root, existing); err != nil {
			return "", err
		}
		same, cerr := sameContents(existing, src)
		if cerr != nil {
			return "", cerr
		}
		if same {
			// ★ TOUCH IT, AND THIS IS NOT COSMETIC (2026-08-12, found on the lab MAC and carried here because
			// this store has the same shape). Prune keeps the newest by modification time. A ROLLBACK reinstalls
			// a package whose bytes are already stored and lands exactly here — so without this, the version the
			// device JUST WENT BACK TO keeps its original mtime, becomes the oldest entry, and is the first one
			// pruned by the next two updates. The one package that matters is the one thrown away.
			//
			// The macOS device was found in precisely that state: running 0.2.7, rollback target 0.2.4, and a
			// store holding 0.2.5, 0.2.6 and 0.2.7. mtime now means "when this package was last INSTALLED",
			// which is what Prune was always reading it as.
			//
			// Best-effort: a store that cannot be touched is still a store, and failing an install over a
			// timestamp would be the worse trade.
			now := time.Now()
			_ = os.Chtimes(existing, now, now)
			return existing, nil
		}
		// Fall through and replace. Deliberately not logged from here — this package has no logger and the
		// event is normal on a dev box; the installer's own output says which package it stored.
		//
		// ★ The rollback marker describes THESE BYTES, so it does not survive them. Two builds of one commit
		// share a version string (".dirty"), so the package being replaced here may be one that honoured a
		// declared rollback while the new one does not — and inheriting the marker would let the updater
		// launch a downgrade the incoming package will refuse. The installer re-marks after a successful
		// stash if its own package carries the mechanism; silence is the safe direction.
		if rerr := os.Remove(IntentMarkerPath(existing)); rerr != nil && !os.IsNotExist(rerr) {
			return "", fmt.Errorf("rollbackstore: clear the stale rollback marker for %s: %w", version, rerr)
		}
	} else if !errors.Is(lerr, ErrNoMaterial) {
		return "", lerr
	}

	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("rollbackstore: open source %s: %w", src, err)
	}
	defer in.Close()

	si, err := in.Stat()
	if err != nil {
		return "", fmt.Errorf("rollbackstore: stat source %s: %w", src, err)
	}
	// An empty source is refused rather than stored. Storing it would satisfy every later Lookup by name and
	// fail only when someone tried to actually roll back, which is the worst possible time to find out.
	if si.Size() == 0 {
		return "", fmt.Errorf("rollbackstore: source %s is empty; refusing to store it as restore material", src)
	}

	// Create the store protected before writing a package into it. This was
	// a bare MkdirAll, so the store inherited BUILTIN\Users Read AND Write from %ProgramData% and held two
	// 26 MB installers a standard user could extract the agent from — or replace. Hardening it afterwards
	// proves nothing about a package already inside; see protect_windows.go.
	_, err = createProtected(s.root)
	if err != nil {
		return "", err
	}
	// ★ AND AGAIN AFTER CREATION, which covers the newly-created and lost-the-race cases point 2 names: the
	// directory that exists now is not necessarily the one checked a moment ago.
	if err := verifyStoreForWriting(s.root); err != nil {
		return "", fmt.Errorf("rollbackstore: refusing to store restore material: %w", err)
	}

	// durable-write: staged — this copies a package from a reader (io.Copy), so the bytes never exist as a
	// slice this function could hand to durablefile.Write. Same reasoning as the publish path: buffering a
	// whole installer in memory to use the shared writer would be a worse trade than staging here.
	tmp, err := os.CreateTemp(s.root, namePrefix+"tmp-*")
	if err != nil {
		return "", fmt.Errorf("rollbackstore: create temp in %s: %w", s.root, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup for every path that does not reach the successful rename. Harmless once the rename
	// has happened, because the name no longer exists.
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if _, err := io.Copy(tmp, in); err != nil {
		return "", fmt.Errorf("rollbackstore: copy %s: %w", src, err)
	}
	// Sync before the rename. Without it the directory entry can reach disk ahead of the contents, which is
	// precisely the torn file Lookup would have to catch later — and it would only be caught on the box that
	// lost power, at the moment it needed to roll back.
	if err := tmp.Sync(); err != nil {
		return "", fmt.Errorf("rollbackstore: sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("rollbackstore: close %s: %w", tmpName, err)
	}

	if err := os.Rename(tmpName, dst); err != nil {
		// ★ THE FALLBACK USED TO REPORT SUCCESS OVER THE WRONG BYTES (2026-08-12, sixth review).
		//
		// It returned whatever was at dst on ANY rename failure, on the reasoning that "losing a race with
		// another installer is not worth failing an install over — the file that won holds the same version's
		// package". That reasoning holds only when the file that won holds the SAME BYTES. Two builds of one
		// commit share a version string (".dirty"), and on Windows a rename can also fail because something has
		// the destination open — so the caller could be told its package was stored while the store still held
		// a DIFFERENT build of that version. A later rollback would then install a build that was never running,
		// which is the one thing this store exists to prevent.
		//
		// (The old comment also said a rename onto an existing name simply fails on Windows. It does not:
		// os.Rename uses MoveFileEx with MOVEFILE_REPLACE_EXISTING. The real failures are a locked or open
		// destination, which is exactly the case where the bytes there are NOT the ones just written.)
		if existing, lerr := s.Lookup(version); lerr == nil {
			if err := verifyStoredPackageForWriting(s.root, existing); err != nil {
				return "", err
			}
			if same, cerr := sameContents(existing, tmpName); cerr == nil && same {
				return existing, nil
			}
			return "", fmt.Errorf("rollbackstore: %s could not be replaced (%w) and the package already stored "+
				"for %s holds DIFFERENT bytes: refusing to report that this build's package is stored when the "+
				"store would roll back to another one", dst, err, version)
		}
		return "", fmt.Errorf("rollbackstore: rename %s -> %s: %w", tmpName, dst, err)
	}
	// Owned before it is verified: the file was created by this process, and an owner holds WRITE_DAC.
	if err := claimStoredPackage(dst); err != nil {
		return "", err
	}
	if err := verifyStoredPackageForWriting(s.root, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// sameContents reports whether two files hold identical bytes.
//
// Size first, because it settles the common case without reading tens of megabytes twice, and a size
// difference is already a definite answer. The digest is only computed when the sizes agree.
//
// An unreadable STORED file is treated as "not the same" rather than as an error: a package that cannot be
// read is not restore material, and refusing to replace it would leave the box holding something it cannot
// use. An unreadable SOURCE is a real error — that is the package being installed.
func sameContents(stored, src string) (bool, error) {
	sfi, err := os.Stat(stored)
	if err != nil {
		return false, nil
	}
	ifi, err := os.Stat(src)
	if err != nil {
		return false, fmt.Errorf("rollbackstore: stat source %s: %w", src, err)
	}
	if sfi.Size() != ifi.Size() {
		return false, nil
	}
	sh, err := fileDigest(stored)
	if err != nil {
		return false, nil
	}
	ih, err := fileDigest(src)
	if err != nil {
		return false, fmt.Errorf("rollbackstore: read source %s: %w", src, err)
	}
	return sh == ih, nil
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Entry is one stored package.
type Entry struct {
	Version string
	Path    string
	Size    int64
}

// List reports the packages currently stored, sorted by version string for a stable order. Files this package
// did not write are skipped rather than reported, so nothing else in the directory can be mistaken for
// restore material. A missing root is not an error: a box that has never stashed anything holds nothing,
// which is a fact rather than a fault.
func (s *Store) List() ([]Entry, error) {
	ents, err := os.ReadDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("rollbackstore: read %s: %w", s.root, err)
	}
	var out []Entry
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		v := versionFromName(e.Name(), s.suffix())
		if v == "" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.Size() == 0 {
			continue
		}
		out = append(out, Entry{Version: v, Path: filepath.Join(s.root, e.Name()), Size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Prune keeps at most keep packages and deletes the rest, oldest-modified first, never deleting any version
// listed in protect.
//
// It exists because nothing else would ever remove these: an MSI is tens of megabytes and a box that updates
// monthly for two years would otherwise accumulate them all. protect is how the caller keeps the one package
// that matters — the running version's — regardless of how old it is, which is exactly the one a
// last-modified rule would throw away first on a box that has been stable for a long time.
//
// Deletion failures are collected rather than aborting: this is housekeeping, and a locked file is not a
// reason to fail the install that called it.
func (s *Store) Prune(keep int, protect ...string) error {
	if keep < 0 {
		return fmt.Errorf("rollbackstore: keep must not be negative (got %d)", keep)
	}
	entries, err := s.List()
	if err != nil {
		return err
	}
	protected := make(map[string]bool, len(protect))
	for _, v := range protect {
		protected[v] = true
	}

	type aged struct {
		Entry
		modUnix int64
	}
	var candidates []aged
	kept := 0
	for _, e := range entries {
		if protected[e.Version] {
			kept++
			continue
		}
		info, err := os.Stat(e.Path)
		if err != nil {
			continue
		}
		candidates = append(candidates, aged{Entry: e, modUnix: info.ModTime().Unix()})
	}
	// Newest first, so the ones that survive are the most recently written.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].modUnix > candidates[j].modUnix })

	var errs []error
	for _, c := range candidates {
		if kept < keep {
			kept++
			continue
		}
		if err := os.Remove(c.Path); err != nil {
			errs = append(errs, fmt.Errorf("rollbackstore: remove %s: %w", c.Path, err))
			continue
		}
		// The marker goes with the package it describes. Left behind it becomes a claim about a file that is
		// not there — and worse, a claim that would be inherited by a NEW package stashed for the same version
		// later, which might be one that does not honour a rollback at all. Missing is not an error: only
		// packages stored by a build carrying the mechanism have one.
		if err := os.Remove(IntentMarkerPath(c.Path)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("rollbackstore: remove the rollback marker for %s: %w", c.Version, err))
		}
	}
	return errors.Join(errs...)
}

// --- Can this stored package actually be rolled back TO? ----------------------------------------------------

// intentMarkerSuffix names the file written beside a stored package to record that the package HONOURS a
// declared rollback. Same name the macOS side uses beside its stashed .pkg, so one question has one spelling
// across both platforms.
const intentMarkerSuffix = ".accepts-rollback-intent"

// IntentMarkerPath is where the marker for a stored package lives.
func IntentMarkerPath(pkgPath string) string { return pkgPath + intentMarkerSuffix }

// MarkAcceptsRollbackIntent records that the package stored for version honours a declared rollback.
//
// ★ THE BOOTSTRAP PROBLEM THIS SOLVES. The check that admits a deliberate downgrade ships INSIDE the package
// being installed — on Windows it is the MSI's launch condition on DSSEROLLBACK. So the first version that can
// be rolled back TO is the first one built with that condition, and every package stashed before it will refuse
// the downgrade no matter what the updater declares. Nothing about the file says which kind it is.
//
// The marker is written by the installer that stashes the package, so it is evidence rather than assumption:
// present means "the profileapply inside this package wrote it, and that profileapply shipped in the same
// package as the launch condition". Absent means the stored package predates the mechanism, and the updater
// refuses BEFORE launching anything — on a good day, when somebody is asking, instead of during the incident
// with a journal that says a rollback is running on a machine nothing has touched.
func (s *Store) MarkAcceptsRollbackIntent(version string) error {
	pkg, err := s.Path(version)
	if err != nil {
		return err
	}
	if _, err := os.Stat(pkg); err != nil {
		return fmt.Errorf("rollbackstore: cannot mark a package that is not stored: %w", err)
	}
	// Content is for a human reading the directory, never parsed: the marker's EXISTENCE is the fact, and a
	// parser here would be a second thing to get wrong about a file whose whole job is to be present.
	return os.WriteFile(IntentMarkerPath(pkg), []byte(
		"This package's installer honours a declared rollback ("+RollbackIntentProperty+"). Written by the "+
			"installer that stored it. Its absence means the package predates the mechanism.\n"), 0o644)
}

// RollbackIntentProperty is the name the marker's text refers to. It is duplicated from updateplatform on
// purpose — this package must not import the platform layer — and pinned by a test so the two cannot drift.
const RollbackIntentProperty = "DSSEROLLBACK"

// AcceptsRollbackIntent reports whether the stored package for version can be rolled back to. A missing
// package is an error; a present package with no marker is a clean false, because that is the ordinary state
// of every box that has not yet installed a build carrying the mechanism.
func (s *Store) AcceptsRollbackIntent(version string) (bool, error) {
	pkg, err := s.Lookup(version)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(IntentMarkerPath(pkg)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("rollbackstore: read the rollback marker for %s: %w", version, err)
	}
	return true, nil
}
