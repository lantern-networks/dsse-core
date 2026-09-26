package blobstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// SingleWriterFilePersister is a FilePersister that REFUSES to overwrite a change it did not make.
//
// ★ TWO EDGES SHARED ONE LEDGER FILE AND EACH SAVED ITS OWN SNAPSHOT (2026-08-12, twenty-third review). The
// enrolled inventory is written by every Edge that holds it — after each config-bundle apply — and a
// reference topology gave three of them the same bind-mounted path. Last writer wins, so: a device enrols on
// one node, which records that the identity is spent; another node applies a bundle from a snapshot taken
// before that and saves; the record is gone and the identity can be enrolled a second time. The startup guard
// refuses a shared POSTGRES store for an issuing Edge and cannot tell one bind-mounted path from another.
//
// This can. It remembers the exact bytes it last saw on disk — from its own write or its own load — and checks
// them still there before replacing them. A file somebody else changed in between is reported rather than
// overwritten, which turns a silent lost write into an operator-visible refusal naming the store.
//
// It is deliberately NOT a lock. A lock answers "may I write", which needs liveness and cleanup and gets a
// deployment stuck when a node dies holding it. This answers "is what I am replacing what I read", which is
// the question a lost update actually asks, needs no coordination, and cannot strand anybody.
type SingleWriterFilePersister struct {
	File FilePersister

	mu   sync.Mutex
	seen string // hex sha256 of the bytes last loaded or saved; "" until the first of either
	have bool
}

// NewSingleWriterFilePersister wraps a path whose writes must not be silently overwritten.
func NewSingleWriterFilePersister(f FilePersister) *SingleWriterFilePersister {
	return &SingleWriterFilePersister{File: f}
}

func (p *SingleWriterFilePersister) Load() ([]byte, error) {
	data, err := p.File.Load()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.seen, p.have = digestOf(data), true
	p.mu.Unlock()
	return data, nil
}

func (p *SingleWriterFilePersister) Save(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// ★ THE COMPARE AND THE WRITE ARE ONE OPERATION, ACROSS PROCESSES (2026-08-12, twenty-fourth review).
	// Without the lock, two processes could both read the same old contents, both find them unchanged, and
	// both write — the second erasing the first, which is exactly the lost update this type exists to stop.
	// p.mu is this process's; the file lock is the kernel's.
	return withFileLock(p.File.Path, func() error { return p.saveLocked(data) })
}

func (p *SingleWriterFilePersister) saveLocked(data []byte) error {
	current, err := p.File.Load()
	if err != nil {
		return err
	}
	if p.have {
		if got := digestOf(current); got != p.seen {
			// Do NOT write. The bytes underneath are somebody else's and this save would erase them.
			return fmt.Errorf("%w: %q changed underneath this process (expected %s, found %s) — another "+
				"process is writing the same store, and saving would erase what it recorded",
				ErrConcurrentWriter, p.File.Path, short(p.seen), short(got))
		}
	}
	if serr := p.File.Save(data); serr != nil && !errors.Is(serr, ErrSavedWithoutAtomicity) {
		return serr
	} else if errors.Is(serr, ErrSavedWithoutAtomicity) {
		p.seen, p.have = digestOf(data), true
		return serr
	}
	p.seen, p.have = digestOf(data), true
	return nil
}

// ErrConcurrentWriter reports that the store was modified by another process. Distinct so a caller can say
// which of the two things went wrong: the disk, or the deployment.
var ErrConcurrentWriter = fmt.Errorf("store has another writer")

func digestOf(data []byte) string {
	if data == nil {
		return "absent"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

var _ Persister = (*SingleWriterFilePersister)(nil)
