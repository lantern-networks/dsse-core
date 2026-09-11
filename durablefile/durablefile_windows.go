//go:build windows

package durablefile

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// durableReplace uses the only mechanism this platform offers for the guarantee the directory fsync provides
// elsewhere: a rename that does not return until the change is on the disk.
//
// MOVEFILE_REPLACE_EXISTING alone would not do — Go documents rename on non-Unix platforms as not guaranteed
// atomic, and for the stores that use this package (an update journal, a downgrade floor) a value that can
// move BACKWARDS after a power cut is precisely the state an attacker would want.
func durableReplace(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return fmt.Errorf("durablefile: replace from %q: %w", from, err)
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return fmt.Errorf("durablefile: replace to %q: %w", to, err)
	}
	cleared, err := clearReadOnly(toPtr)
	if err != nil {
		return err
	}
	if err := moveFileEx(fromPtr, toPtr,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		// ★ A FAILED WRITE MUST NOT LEAVE THE FILE LESS PROTECTED THAN IT FOUND IT (2026-08-13). The clear above
		// is a means to an end, and if the end does not happen the means has to be undone: otherwise a caller
		// that asked for a read-only file, and was TOLD the write failed, is left with a writable one — the
		// protection quietly relaxed by the operation that failed to change anything.
		if cleared {
			if rerr := setReadOnly(toPtr); rerr != nil {
				// Never swallowed. "The write failed" and "the write failed AND the file is now writable" call
				// for different actions from whoever reads it.
				return fmt.Errorf("durablefile: durably replace %q: %w — and the destination has been LEFT "+
					"WRITABLE: its read-only attribute was cleared to make the replacement possible and could "+
					"not be restored (%v)", to, err, rerr)
			}
		}
		return fmt.Errorf("durablefile: durably replace %q: %w", to, err)
	}
	return nil
}

// moveFileEx is windows.MoveFileEx behind a seam, so the restore-on-failure path above can be exercised. The
// same idiom blobstore uses for its rename, and for the same reason: the interesting branch is the one that
// only happens when the OS says no, which a test cannot otherwise arrange.
var moveFileEx = windows.MoveFileEx

// setReadOnly puts FILE_ATTRIBUTE_READONLY back after a failed replacement.
func setReadOnly(toPtr *uint16) error {
	attrs, err := windows.GetFileAttributes(toPtr)
	if err != nil {
		return err
	}
	return windows.SetFileAttributes(toPtr, attrs|windows.FILE_ATTRIBUTE_READONLY)
}

// clearReadOnly takes FILE_ATTRIBUTE_READONLY off the destination if it is set.
//
// ★ WITHOUT THIS, A READ-ONLY PERM MAKES THE FILE WRITE-ONCE ON THIS PLATFORM (2026-08-13, measured on
// win-dev-1, not reasoned about). Windows has no permission bits — Go maps `perm&0200 == 0` to
// FILE_ATTRIBUTE_READONLY — and MoveFileEx will not replace a file carrying it:
//
//	Write(p, x, 0o444)  -> ok, the file really is -r--r--r--
//	Write(p, y, 0o444)  -> durablefile: durably replace "...\b.json": Access is denied.
//
// On Unix the same sequence succeeds, because rename depends on the DIRECTORY's permissions and not the
// file's. So the divergence was silent and one-directional: a store written with a read-only mode would take
// its first value and then fail every update forever, on Windows only. For a signing floor or a journal that
// is the failure mode the package exists to prevent, arriving by a different door.
//
// No caller passes such a mode today — the one live caller uses 0600 — but this package is now where new code
// goes, and "one durable write" has to mean one BEHAVIOUR, not merely one import path.
func clearReadOnly(toPtr *uint16) (cleared bool, err error) {
	attrs, gerr := windows.GetFileAttributes(toPtr)
	if gerr != nil {
		return false, nil // the destination does not exist yet (or cannot be read); let MoveFileEx report it
	}
	if attrs&windows.FILE_ATTRIBUTE_READONLY == 0 {
		return false, nil
	}
	if serr := windows.SetFileAttributes(toPtr, attrs&^windows.FILE_ATTRIBUTE_READONLY); serr != nil {
		return false, fmt.Errorf("durablefile: clear the read-only attribute before replacing: %w", serr)
	}
	return true, nil
}

// SyncDir is a no-op here, and this is the one place in this package where "does nothing" is the correct
// implementation rather than a gap: there is no user-mode call that flushes a directory on Windows, and the
// durability it would buy is provided by durableReplace above instead.
//
// ★ Stated at this length because a bare `return nil` under a name that promises an fsync is indistinguishable
// from somebody silencing an inconvenient error — and because the portable version of this function does not
// merely degrade here, it fails: os.Open on a directory SUCCEEDS (FILE_FLAG_BACKUP_SEMANTICS) and Sync() then
// returns ERROR_ACCESS_DENIED, every time, for every caller.
func SyncDir(string) error { return nil }
