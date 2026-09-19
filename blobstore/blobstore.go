// Package blobstore is the durable-snapshot seam for the control plane's authored-state stores.
//
// Several CP stores (policy rules, grants, approvals, catalogs, overlays, …) persist by marshaling their WHOLE
// in-memory state to a single opaque snapshot on every mutation and reloading it on boot. Historically that
// snapshot was a JSON file with an atomic temp+rename. That makes the state NODE-LOCAL, which blocks CP HA: a
// standby on another host cannot serve state the active authored. Persister abstracts "load/save one snapshot
// blob" so the same stores can be backed by shared, replicated storage (Postgres — see cmd/edge) instead, making
// the CP stateless-over-Postgres and its state survive a failover. The blob is opaque here; each store owns its
// own marshaling.
package blobstore

import (
	"errors"
	"fmt"
	"os"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// Persister loads and saves one store's opaque snapshot blob. Load returns (nil, nil) when no snapshot exists yet
// (first boot). Implementations must be safe for the store's single-writer-under-lock call pattern.
type Persister interface {
	Load() ([]byte, error)
	Save(data []byte) error
}

// AppendPersister is an OPTIONAL capability on top of Persister: O(1) appends plus a size probe, so a
// high-volume append-only store (e.g. inspection/decision events under decrypt-all + log-all) never re-serializes
// its whole snapshot on every flush. A store type-asserts for it; a persister that does not implement it (e.g. the
// Postgres blob) makes the store fall back to Save() full-snapshot. Save() doubles as the atomic compaction path
// (rewrite the whole file), so no separate Compact() method is needed. Append writes the caller's bytes verbatim
// (the caller frames its own records, e.g. NDJSON with trailing newlines).
type AppendPersister interface {
	Persister
	Append(data []byte) error // append data to the end of the blob (single write; caller frames records)
	Size() (int64, error)     // current blob size in bytes (0 when it does not exist yet) — drives compaction
}

// FilePersister is the historical behaviour: one file per store, written via an atomic temp+rename so a crash
// mid-write never leaves a torn snapshot.
type FilePersister struct {
	Path string
	// Perm is the file mode for the snapshot; defaults to 0o600 when zero.
	Perm os.FileMode
	// KeepVersions, when > 0, retains that many previous snapshots as Path.1 (most recent) … Path.N before
	// each write. Zero keeps none, which is the historical behaviour and right for a store whose content can
	// be rebuilt from somewhere else.
	//
	// It is NOT right for a store that is the only copy of something. The admin runtime state holds the
	// enabled/disabled status of security controls, is gitignored, and has no version history anywhere: when
	// an east-west posture was found reverted on 2026-08-05 there was no earlier copy to compare against, so
	// what it had been could only be reconstructed from an unrelated table that happened to record it. Keeping
	// the last few writes turns "it changed and we cannot tell when or from what" into an answerable question.
	KeepVersions int
}

func (f FilePersister) Load() ([]byte, error) {
	data, err := os.ReadFile(f.Path)
	if os.IsNotExist(err) {
		if _, statErr := os.Lstat(f.Path); os.IsNotExist(statErr) {
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Save writes atomically where it can, and in place where it cannot.
//
// Temp-file-then-rename is the right shape: a crash mid-write leaves the previous contents rather than a
// truncated file. But renaming ONTO a path that is a bind-mounted FILE fails — the kernel refuses with "device
// or resource busy" — and a container that mounts a single config file rather than its directory is an
// ordinary thing to do. Every write then failed, forever, and the only sign was one log line per attempt.
//
// That is not a hypothetical: the reference control plane mounted its enrolled inventory that way, so the
// admission ledger for the whole fleet had never once persisted. Its file was months old while the process
// happily reported every change as applied, and each restart quietly reverted to the seed.
//
// So a failed rename falls back to writing the file in place. That gives up atomicity — an interrupted write
// can truncate — and it is unambiguously better than never persisting at all. The caller is told which of the
// two happened via ErrSavedWithoutAtomicity, so a store that cares can surface the weaker guarantee rather
// than have it discovered later.
func (f FilePersister) Save(data []byte) error {
	perm := f.Perm
	if perm == 0 {
		perm = 0o600
	}
	f.rotateVersions(perm)
	// ★ THROUGH THE SHARED PACKAGE (2026-08-13, thirtieth review #20). This was the fifth hand-written copy of
	// temp-write-fsync-rename — the one the extraction was named after and did not reach. Two gains beyond
	// removing the duplicate: the temporary file now has a UNIQUE name, where this used to be a fixed
	// "<path>.tmp" that two savers would share (the hazard the cross-process test warns about); and the replace
	// carries the Windows semantics the shared package learned from a real failure.
	//
	// ★ THE BYTES ARE FLUSHED BEFORE THE RENAME (2026-08-13, twenty-ninth review). This wrote and renamed with
	// no fsync at all, so everything the checked-persist seam calls "durable" — a spent enrolment marker, an
	// operator's revocation — could be back to the old file, an empty one, or an unlinked directory entry after
	// a power cut, and a consumed identity becomes enrollable again.
	werr := writeFile(f.Path, data, perm)
	if werr == nil {
		return nil
	}
	// ★★ THE REPLACEMENT MAY HAVE HAPPENED ANYWAY, AND THE FALLBACK BELOW WOULD THEN CORRUPT IT (2026-08-13,
	// thirtieth review #14). The recovery here was written against os.Rename, whose error means the destination
	// was not touched. The shared replace is rename THEN fsync on this platform, so it can fail with the new
	// file already in place — and reopening the LIVE store with O_TRUNC to "repair" it is a torn window over
	// spent enrolment markers and revocations, on the main path, in the function that exists to protect exactly
	// that file. The data is saved and atomically so; only the flush is missing, which is the weaker promise
	// ErrSavedWithoutAtomicity was introduced to make honestly.
	if errors.Is(werr, durablefile.ErrReplacedNotFlushed) {
		return savedDurabilityWarning{}
	}
	// ★ AND A STAGING FAILURE MUST NOT COME HERE AT ALL (2026-08-13, thirty-first review #3). The rewrite in the
	// previous round sent EVERY non-flush error down this path, including "the temporary file could not be
	// written" — where the destination is untouched and there is nothing to recover. On a full disk the truncate
	// below succeeds and the rewrite does not, so the store holding spent enrolment markers and revocations ends
	// up empty: the corruption #14 removed, reappearing through the neighbouring error class.
	if errors.Is(werr, durablefile.ErrStagingFailed) {
		return werr
	}
	// The destination could not be replaced at all (a bind-mounted file is the case this exists for). Write
	// through it instead and say that it was not atomic.
	if err := writeFileSynced(f.Path, data, perm); err != nil {
		return err
	}
	return ErrSavedWithoutAtomicity
}

// writeFile is durablefile.Write behind a seam, so the fallback above can be exercised by a test. The failure
// it exists for — a destination that cannot be replaced because it is a mount point — cannot be produced
// portably in a unit test, and a fallback nobody has executed is a fallback nobody knows works.
var writeFile = durablefile.Write

// ErrSavedWithoutAtomicity reports that the data IS saved, but not atomically — the destination could not be
// replaced by a rename, so it was written through. Returned rather than swallowed because "saved" and "saved
// safely" are different promises, and a caller logging this as a failure would be wrong in the other direction.
var ErrSavedWithoutAtomicity = errors.New("saved in place: the destination could not be replaced atomically (a bind-mounted file?), so an interrupted write could truncate it")

// ErrDurabilityUnconfirmed means replacement completed, but its durable commit
// could not be confirmed. This differs from a completed, synced in-place save.
var ErrDurabilityUnconfirmed = durablefile.ErrReplacedNotFlushed

// Preserve the legacy weak-save classification for existing callers while
// allowing authorization stores to distinguish the missing flush guarantee.
type savedDurabilityWarning struct{}

func (savedDurabilityWarning) Error() string { return ErrDurabilityUnconfirmed.Error() }
func (savedDurabilityWarning) Is(target error) bool {
	return target == ErrSavedWithoutAtomicity || target == ErrDurabilityUnconfirmed
}

// Append implements AppendPersister: append data to the file in one O_APPEND write (no full rewrite). The caller
// frames its own records (e.g. NDJSON). A single write of a batch keeps the WAL torn-write window to one syscall;
// compaction (Save) periodically collapses the WAL back to the live set so an interrupted append only ever loses
// the tail, which the store tolerates (durability of the record itself is off-Edge — this file is a hot-cache WAL).
func (f FilePersister) Append(data []byte) error {
	perm := f.Perm
	if perm == 0 {
		perm = 0o600
	}
	file, err := os.OpenFile(f.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// Size implements AppendPersister: the current file size (0 when it does not exist yet).
func (f FilePersister) Size() (int64, error) {
	fi, err := os.Stat(f.Path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// rotateVersions shifts Path.(N-1) → Path.N … Path.1 → Path.2 and copies the current snapshot to Path.1, so
// the most recent KeepVersions writes survive the next one.
//
// Best-effort by design: this runs on the write path of stores that must keep working, so a failure to retain
// history must never prevent the current state from being saved. Losing a backup is bad; refusing to persist
// because a backup could not be made is worse.
func (f FilePersister) rotateVersions(perm os.FileMode) {
	if f.KeepVersions <= 0 {
		return
	}
	current, err := os.ReadFile(f.Path)
	if err != nil {
		return // nothing to keep yet (first write), or unreadable — the save itself will report real problems
	}
	for i := f.KeepVersions - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", f.Path, i), fmt.Sprintf("%s.%d", f.Path, i+1))
	}
	_ = os.WriteFile(f.Path+".1", current, perm)
}

// writeFileSynced writes and FLUSHES, so the bytes are on the disk before anything renames over them.
func writeFileSynced(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		f.Close()
		return werr
	}
	if serr := f.Sync(); serr != nil {
		f.Close()
		return serr
	}
	return f.Close()
}
