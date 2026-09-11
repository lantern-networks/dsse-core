package dlp

import (
	"errors"
	"io"
	"sort"
)

// ErrBlocked is returned by a GuardReader's Read when a DLP-blocking identifier is detected before its bytes
// are released to the destination. The upload has been interrupted and the detected secret was NOT forwarded.
var ErrBlocked = errors.New("dlp: blocked by policy")

// GuardReader wraps an upload body and enforces DLP block/authenticate with hold-before-release (Option C, see
// docs/dlp_minimal_design.md): it yields only bytes the scan frontier has cleared, holding the trailing
// window. When a governed identifier reaches its trip threshold, Read returns ErrBlocked WITHOUT releasing the
// offending window — the detected secret never leaves the perimeter, at constant memory for any body size.
// Bytes streamed to the caller in earlier Reads (the benign prefix, never the secret) may already have reached
// the destination (definition-1). For a trip threshold > 1 only the threshold-crossing occurrence is withheld;
// earlier occurrences were released as benign — an inherent limit of streaming threshold blocking.
type GuardReader struct {
	src     io.Reader
	trip    map[IdentifierType]int
	counts  map[IdentifierType]int
	hold    []byte // read from src, not yet released
	ready   []byte // cleared, ready to hand to the caller
	tmp     []byte
	eof     bool
	tripped bool
	opts    Options
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
	return &GuardReader{src: src, trip: trip, counts: map[IdentifierType]int{}, tmp: make([]byte, chunkSize), opts: opts}
}

// Findings returns the non-secret findings accumulated so far (final once Read has returned ErrBlocked or io.EOF).
func (g *GuardReader) Findings() []Finding { return findings(g.counts) }

// Tripped reports whether the guard blocked the upload.
func (g *GuardReader) Tripped() bool { return g.tripped }

func (g *GuardReader) Read(p []byte) (int, error) {
	for {
		if len(g.ready) > 0 {
			n := copy(p, g.ready)
			g.ready = g.ready[n:]
			return n, nil
		}
		if g.tripped {
			return 0, ErrBlocked
		}
		if g.eof {
			return 0, io.EOF
		}
		m, err := g.src.Read(g.tmp)
		if m > 0 {
			g.hold = append(g.hold, g.tmp[:m]...)
			if g.advance(false) {
				return 0, ErrBlocked
			}
		}
		if err == io.EOF {
			g.eof = true
			if g.advance(true) {
				return 0, ErrBlocked
			}
		} else if err != nil {
			return 0, err
		}
	}
}

// advance scans the held bytes, commits (counts) matches within the releasable prefix in position order, and
// either trips (withholding the whole held window + any not-yet-released cleared bytes) or moves the cleared
// prefix into ready.
func (g *GuardReader) advance(final bool) (tripped bool) {
	matches := scanAll(g.hold, g.opts)
	dropTo := windowCommit(g.hold, matches, final)
	if dropTo <= 0 {
		return false
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].start < matches[j].start })
	for _, mt := range matches {
		if mt.end > dropTo {
			continue
		}
		g.counts[mt.typ]++
		if th, ok := g.trip[mt.typ]; ok && g.counts[mt.typ] >= th {
			// Block: withhold the held window and any bytes not yet handed out. Only the benign prefix
			// already streamed in earlier Reads reached the destination — never this secret.
			g.hold = nil
			g.ready = nil
			g.tripped = true
			return true
		}
	}
	g.ready = append(g.ready, g.hold[:dropTo]...)
	g.hold = append(g.hold[:0], g.hold[dropTo:]...)
	return false
}
