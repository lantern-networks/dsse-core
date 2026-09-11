// Package durablefile replaces a file so that a crash leaves either the old contents or the new ones, and
// never half of either — on every platform this product runs on.
//
// ★ WHY IT IS A PACKAGE (2026-08-13). Four places in this repository had written this by hand: the update
// journal, the hotstore spool, the blob store, and the agent-update signing floor. Every copy was individually
// reasonable — the neighbours' versions were unexported, so the next author wrote the nearest thing again —
// and three of the four shipped the same defect, because the obvious portable implementation cannot work on
// Windows:
//
//	os.Open(dir)  // SUCCEEDS on Windows; Go passes FILE_FLAG_BACKUP_SEMANTICS
//	d.Sync()      // FlushFileBuffers on a directory handle → ERROR_ACCESS_DENIED, always
//
// Not a degradation — a total failure of the write, on a platform where the affected stores were the agent's
// journal and the control plane's downgrade floor. The fourth copy was written on 2026-08-13, with a comment
// explaining why it was written rather than borrowed, and was broken within the hour by the Windows gate. That
// is a defect the structure produces, so the structure is what changes: this is the one implementation, and
// the guard in ops/checks refuses a fifth.
//
// The Windows half is not a no-op. There is no user-mode call that flushes a directory there; what there is,
// is a rename that flushes itself — MoveFileEx with MOVEFILE_WRITE_THROUGH — which buys exactly what the
// directory fsync buys elsewhere. Plain REPLACE_EXISTING is not enough: Go documents rename on non-Unix
// platforms as not guaranteed atomic.
package durablefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrReplacedNotFlushed says the replacement HAPPENED and only its durability is in doubt: the rename went
// through, and the directory entry could not be flushed afterwards.
//
// ★ THE DISTINCTION IS LOAD-BEARING FOR CALLERS WITH A FALLBACK (2026-08-13, thirtieth review #14). os.Rename
// has a simple contract — an error means the destination was not touched — and callers wrote their recovery
// against it. This package's unix replace is rename THEN fsync, so it can fail after the destination has
// already changed. blobstore's fallback, written for the old contract, reopened the LIVE file with O_TRUNC and
// rewrote it: a torn window over the store holding spent enrolment markers and revocations, reachable on the
// main path, in code whose whole subject is not losing that file.
//
// So a caller can ask which of the two happened instead of assuming. Never returned on Windows, where the
// replace is a single MoveFileEx that either happened or did not.
var ErrReplacedNotFlushed = errors.New("durablefile: the file was replaced but the directory entry could not be flushed")

// ErrStagingFailed says the DESTINATION WAS NEVER TOUCHED: the temporary file could not be created, written,
// flushed or chmod'd, so whatever was there is exactly as it was.
//
// ★ CALLERS WITH A WRITE-THROUGH FALLBACK NEED THIS ONE TOO (2026-08-13, thirty-first review #3). blobstore
// recovers from a failed replace by opening the live store O_TRUNC and writing through it. Treating a STAGING
// failure as a failed replace sends it down that path for the one class of error where nothing was wrong with
// the destination — and on a full disk the truncate succeeds and the rewrite does not, so the store holding
// spent enrolment markers ends up empty. The previous round fixed that corruption for one error and opened it
// for another.
var ErrStagingFailed = errors.New("durablefile: the file could not be staged, so the destination is unchanged")

// Write puts data at path so that a reader — or a power cut — sees the old file or the new one, never a
// partial one.
//
// The order is the point: write to a temporary file in the SAME directory (a rename across filesystems is not
// atomic), flush the bytes, then durably replace. Flushing after the rename would be too late; renaming an
// unflushed file leaves a valid directory entry pointing at nothing in particular.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("%w: create a temporary file beside %q: %v", ErrStagingFailed, path, err)
	}
	name := tmp.Name()
	// A no-op once the replace has succeeded; the safety net is for every path that returns before it.
	defer os.Remove(name)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: write %q: %v", ErrStagingFailed, name, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: flush %q: %v", ErrStagingFailed, name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: close %q: %v", ErrStagingFailed, name, err)
	}
	// CreateTemp makes the file 0600. A caller asking for something else is usually asking for something
	// NARROWER or for a file another uid must read; either way the mode has to be set before it becomes
	// visible under the real name, or there is a window in which the permissions are wrong.
	if err := os.Chmod(name, perm); err != nil {
		return fmt.Errorf("%w: set the mode on %q: %v", ErrStagingFailed, name, err)
	}
	return Replace(name, path)
}

// Replace moves from onto to durably: after it returns, a crash cannot bring the old contents back.
//
// Exported separately because some callers build their temporary file themselves — streaming a large artifact,
// or writing through a hash — and only need the replace half.
func Replace(from, to string) error { return durableReplace(from, to) }
