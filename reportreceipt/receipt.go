// Package reportreceipt tracks additive reports across redelivery and reordering.
package reportreceipt

import (
	"errors"
	"time"
)

// ReplayWindow bounds retained sequence positions per reporter and stream. It is
// a receiver replay budget, not a claim about the sender queue or delivery time.
const ReplayWindow uint64 = 4096

// ErrExpired means the receiver no longer knows whether this report was applied.
// It must never be acknowledged as a duplicate or applied as a new report.
var ErrExpired = errors.New("observation report outside retained replay window")

// Gap is an inclusive interval of sequence numbers not yet applied.
type Gap struct {
	First uint64 `json:"first"`
	Last  uint64 `json:"last"`
}

// Receipt keeps a high watermark and the holes below it. A high watermark alone
// cannot distinguish a retry from a report displaced by the sender's refusal queue.
// Legacy receipts without gaps retain their original contiguous-prefix meaning.
type Receipt struct {
	Seq  uint64 `json:"seq"`
	At   string `json:"at"`
	Gaps []Gap  `json:"gaps,omitempty"`
	// RetiredThrough is an inclusive refused prefix while this receipt is retained.
	RetiredThrough uint64 `json:"retired_through,omitempty"`
}

func (r Receipt) Valid() bool {
	if r.Seq == 0 || r.RetiredThrough >= r.Seq {
		return false
	}
	if _, err := time.Parse(time.RFC3339, r.At); err != nil {
		return false
	}
	previous := r.RetiredThrough
	for _, g := range r.Gaps {
		if g.First == 0 || g.First > g.Last || g.Last >= r.Seq || g.First <= previous {
			return false
		}
		previous = g.Last
	}
	return true
}

func (r Receipt) Contains(seq uint64) bool {
	if seq == 0 || seq <= r.RetiredThrough || seq > r.Seq {
		return false
	}
	for _, g := range r.Gaps {
		if seq < g.First {
			break
		}
		if seq <= g.Last {
			return false
		}
	}
	return true
}

// Applied returns a detached receipt to publish with the counts in one commit.
// It never mutates a previous receipt's slice, including on failed saves.
func (r Receipt) Applied(seq uint64, now time.Time) (Receipt, error) {
	if seq != 0 && seq <= r.RetiredThrough {
		return r, ErrExpired
	}
	if seq == 0 || r.Contains(seq) {
		return r, nil
	}
	high := r.Seq
	if seq > high {
		high = seq
	}
	floor := r.RetiredThrough
	if high > ReplayWindow && high-ReplayWindow > floor {
		floor = high - ReplayWindow
	}
	// This also handles a large legacy receipt without applying an old gap first.
	if seq <= floor {
		return r, ErrExpired
	}
	next := Receipt{Seq: r.Seq, At: now.UTC().Format(time.RFC3339), RetiredThrough: floor}
	for _, g := range r.Gaps {
		if g.Last <= floor {
			continue
		}
		if g.First <= floor {
			g.First = floor + 1
		}
		if seq < g.First || seq > g.Last {
			next.Gaps = append(next.Gaps, g)
			continue
		}
		if seq > g.First {
			next.Gaps = append(next.Gaps, Gap{g.First, seq - 1})
		}
		if seq < g.Last {
			next.Gaps = append(next.Gaps, Gap{seq + 1, g.Last})
		}
	}
	if seq > r.Seq {
		if seq-r.Seq > 1 {
			first := r.Seq + 1
			if first <= floor {
				first = floor + 1
			}
			next.Gaps = append(next.Gaps, Gap{first, seq - 1})
		}
		next.Seq = seq
	}
	return next, nil
}
