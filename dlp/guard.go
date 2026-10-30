package dlp

import (
	"errors"
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

// ErrBlocked is returned by a GuardReader's Read when a DLP-blocking identifier is detected before its bytes
// are released to the destination. The upload has been interrupted and the detected secret was NOT forwarded.
var ErrBlocked = errors.New("dlp: blocked by policy")

// ErrInspectionFailed means the guard could not establish whether held bytes
// were safe. The caller must abort forwarding; those bytes were not released.
var ErrInspectionFailed = errors.New("dlp: inspection failed")

// GuardReader wraps an upload body and enforces DLP block/authenticate with hold-before-release (Option C, see
// docs/dlp_minimal_design.md): it yields only bytes the scan frontier has cleared, holding the trailing
// window. When a governed identifier reaches its trip threshold, Read returns ErrBlocked WITHOUT releasing the
// offending window — the detected secret never leaves the perimeter. An unfinished email is held in an
// encrypted private spill until its end and allowlist identity are known.
// Bytes streamed to the caller in earlier Reads (the benign prefix, never the secret) may already have reached
// the destination (definition-1). For a trip threshold > 1 only the threshold-crossing occurrence is withheld;
// earlier occurrences were released as benign — an inherent limit of streaming threshold blocking.
type GuardReader struct {
	readMu          sync.Mutex // serializes Reads and protects all fields below
	closeOnce       sync.Once
	closed          atomic.Bool
	closeErr        error
	src             io.Reader
	trip            map[IdentifierType]int
	counts          map[IdentifierType]int
	hold            []byte // read from src, not yet released
	origin          int64
	custom          *customStreamState
	email           *emailStream
	spool           *encryptedSpill
	ready           []byte // cleared, ready to hand to the caller
	tmp             []byte
	eof             bool
	tripped         atomic.Bool
	resourceLimited atomic.Bool
	failed          error
	opts            Options
	lease           *retentionLease
}

// NewGuardReader wraps src, tripping (ErrBlocked) when any identifier reaches its trip count. trip is
// typically Policy.TripThresholds(); an empty trip never blocks (prefer a plain observe tee in that case).
func NewGuardReader(src io.Reader, trip map[IdentifierType]int) *GuardReader {
	return NewGuardReaderWithOptions(src, trip, Options{})
}

// NewGuardReaderWith is NewGuardReader plus operator-defined custom classifiers (so a custom identifier can also
// trip a block/authenticate hold, nil set = built-ins only).
func NewGuardReaderWith(src io.Reader, trip map[IdentifierType]int, set *ClassifierSet) *GuardReader {
	return NewGuardReaderWithOptions(src, trip, Options{Classifiers: set})
}

// NewGuardReaderWithOptions is NewGuardReader honoring custom classifiers and/or an allowlist (a known-safe value
// never trips a block).
func NewGuardReaderWithOptions(src io.Reader, trip map[IdentifierType]int, opts Options) *GuardReader {
	lease, err := opts.RetentionBudget.acquire()
	if err != nil {
		g := &GuardReader{src: src, failed: err}
		g.resourceLimited.Store(true)
		return g
	}
	return &GuardReader{src: src, trip: trip, counts: map[IdentifierType]int{}, lease: lease,
		custom: newCustomStreamState(opts.Classifiers), email: newEmailStream(opts.Allowlist),
		tmp: make([]byte, chunkSize), opts: opts}
}

// ResourceLimited reports inability to retain undecided bytes, not a secret
// detection. Callers must refuse the upload rather than ask for authentication.
func (g *GuardReader) ResourceLimited() bool {
	return g.resourceLimited.Load()
}

func (g *GuardReader) releaseWorking() {
	clear(g.tmp)
	clear(g.hold[:cap(g.hold)])
	clear(g.ready[:cap(g.ready)])
	g.tmp, g.hold, g.ready = nil, nil, nil
	if g.email != nil {
		clear(g.email.local[:cap(g.email.local)])
	}
	g.email, g.custom = nil, nil
	g.lease.releaseWorking()
}

// Findings returns the non-secret findings accumulated so far (final once Read has returned ErrBlocked or io.EOF).
func (g *GuardReader) Findings() []Finding {
	g.readMu.Lock()
	defer g.readMu.Unlock()
	return findings(g.counts)
}

// Tripped reports whether the guard blocked the upload.
func (g *GuardReader) Tripped() bool {
	return g.tripped.Load()
}

// Close interrupts a Read blocked on an io.ReadCloser source before waiting
// for the guard's state lock, then removes any encrypted pending body. HTTP
// request bodies implement io.ReadCloser. A plain io.Reader without Close
// cannot be interrupted by this wrapper if its Read blocks forever.
func (g *GuardReader) Close() error {
	g.closeOnce.Do(func() {
		g.closed.Store(true)
		if closer, ok := g.src.(io.Closer); ok {
			g.closeErr = closer.Close()
		}
		g.readMu.Lock()
		g.closeErr = errors.Join(g.closeErr, g.closeSpool())
		g.releaseWorking()
		g.readMu.Unlock()
	})
	return g.closeErr
}

func (g *GuardReader) closeSpool() error {
	if g.spool == nil {
		return nil
	}
	err := g.spool.close()
	g.spool = nil
	return err
}

func (g *GuardReader) fail(err error) error {
	if errors.Is(err, ErrRetentionLimit) {
		g.resourceLimited.Store(true)
	}
	if cleanupErr := g.closeSpool(); cleanupErr != nil {
		err = errors.Join(err, ErrInspectionFailed)
	}
	g.releaseWorking()
	g.failed = err
	return err
}

func (g *GuardReader) block() error {
	g.tripped.Store(true)
	return g.fail(ErrBlocked)
}

func (g *GuardReader) countEmail(matches []emailStreamMatch) error {
	for _, m := range matches {
		if m.allowed {
			continue
		}
		g.counts[Email]++
		if th, ok := g.trip[Email]; ok && g.counts[Email] >= th {
			return g.block()
		}
	}
	return nil
}

func (g *GuardReader) Read(p []byte) (int, error) {
	g.readMu.Lock()
	defer g.readMu.Unlock()
	if g.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if g.closed.Load() {
			return 0, io.ErrClosedPipe
		}
		if g.failed != nil {
			return 0, g.failed
		}
		if len(g.ready) > 0 {
			n := copy(p, g.ready)
			clear(g.ready[:n])
			g.ready = g.ready[n:]
			return n, nil
		}
		if g.spool != nil {
			safeUntil := g.spool.end
			if pending, ok := g.email.pendingStart(); ok && pending < safeUntil {
				safeUntil = pending
			}
			if safeUntil < g.spool.readPos {
				return 0, g.fail(ErrInspectionFailed)
			}
			n, err := g.spool.readSafe(p, safeUntil)
			if err != nil {
				return 0, g.fail(ErrInspectionFailed)
			}
			if g.spool.readPos == g.spool.end {
				if err := g.closeSpool(); err != nil {
					return 0, g.fail(ErrInspectionFailed)
				}
			}
			if n > 0 {
				return n, nil
			}
		}
		if g.eof {
			g.releaseWorking()
			return 0, io.EOF
		}
		m, err := g.src.Read(g.tmp)
		if g.closed.Load() {
			return 0, io.ErrClosedPipe
		}
		if m > 0 {
			g.hold = append(g.hold, g.tmp[:m]...)
			if err := g.countEmail(g.email.write(g.tmp[:m])); err != nil {
				return 0, err
			}
		}
		if err == io.EOF {
			g.eof = true
			if err := g.countEmail(g.email.finish()); err != nil {
				return 0, err
			}
			if err := g.advance(true); err != nil {
				return 0, err
			}
		} else if err != nil {
			return 0, g.fail(err)
		} else if m > 0 {
			if err := g.advance(false); err != nil {
				return 0, err
			}
		}
	}
}

// advance scans the held bytes, commits (counts) matches within the releasable prefix in position order, and
// either trips (withholding the whole held window + any not-yet-released cleared bytes) or moves the cleared
// prefix into ready.
func (g *GuardReader) advance(final bool) error {
	matches := scanBaseAll(g.hold, g.opts)
	dropTo := windowCommit(g.hold, matches, final)
	if dropTo <= 0 {
		return nil
	}
	type event struct {
		match
		custom *stableCustomMatch
	}
	events := make([]event, 0, len(matches))
	for _, mt := range matches {
		if mt.end <= dropTo {
			events = append(events, event{match: mt})
		}
	}
	for _, mt := range g.custom.stable(g.hold, g.origin, dropTo, g.opts.Allowlist) {
		mt := mt
		events = append(events, event{match: mt.match, custom: &mt})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].start < events[j].start })
	for _, ev := range events {
		if ev.custom != nil {
			g.custom.commit(*ev.custom)
			if ev.custom.allowed {
				continue
			}
		}
		g.counts[ev.typ]++
		if th, ok := g.trip[ev.typ]; ok && g.counts[ev.typ] >= th {
			// Block: withhold the held window and any bytes not yet handed out. Only the benign prefix
			// already streamed in earlier Reads reached the destination — never this secret.
			return g.block()
		}
	}
	stable := g.hold[:dropTo]
	if g.spool != nil {
		if g.spool.end != g.origin {
			return g.fail(ErrInspectionFailed)
		}
		if err := g.spool.append(stable); err != nil {
			return g.fail(errors.Join(ErrInspectionFailed, err))
		}
	} else if pending, ok := g.email.pendingStart(); ok && pending < g.origin+int64(dropTo) {
		clear := pending - g.origin
		if clear < 0 {
			return g.fail(ErrInspectionFailed)
		}
		g.ready = append(g.ready, stable[:int(clear)]...)
		spool, err := newEncryptedSpillWithLease(pending, g.lease)
		if err != nil {
			return g.fail(ErrInspectionFailed)
		}
		g.spool = spool
		if err := g.spool.append(stable[int(clear):]); err != nil {
			return g.fail(errors.Join(ErrInspectionFailed, err))
		}
	} else {
		g.ready = append(g.ready, stable...)
	}
	g.hold = append(g.hold[:0], g.hold[dropTo:]...)
	g.origin += int64(dropTo)
	return nil
}
