//go:build !windows

package durablefile

import (
	"fmt"
	"os"
	"path/filepath"
)

// durableReplace is rename-then-fsync-the-directory. Two different guarantees: rename(2) is atomic with
// respect to a concurrent reader, and the directory fsync is what makes the replacement survive a power cut.
// Only the second one needs a call, and it is REPORTED rather than swallowed — a caller that could not flush
// the directory has not got the durability this package's name promises.
func durableReplace(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("durablefile: replace %q: %w", to, err)
	}
	if err := SyncDir(filepath.Dir(to)); err != nil {
		// ★ WRAPPED, NOT RETURNED PLAIN. Past this line the destination has ALREADY changed, and a caller whose
		// recovery assumes otherwise — os.Rename's contract — would repair a file that does not need repairing.
		// See ErrReplacedNotFlushed.
		return fmt.Errorf("%w: %v", ErrReplacedNotFlushed, err)
	}
	return nil
}

// SyncDir persists a directory entry, so a rename into it survives a power cut. On Windows it is a documented
// no-op; see the note there.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("durablefile: open %q to persist the rename: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("durablefile: fsync %q to persist the rename: %w", dir, err)
	}
	return d.Close()
}
