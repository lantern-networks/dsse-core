// Package reportreceipt tracks additive reports across redelivery and reordering.
package reportreceipt

import "time"

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
}

func (r Receipt) Valid() bool {
	if r.Seq == 0 {
		return false
	}
	if _, err := time.Parse(time.RFC3339, r.At); err != nil {
		return false
	}
	var previous uint64
	for _, g := range r.Gaps {
		if g.First == 0 || g.First > g.Last || g.Last >= r.Seq || g.First <= previous {
			return false
		}
		previous = g.Last
	}
	return true
}

func (r Receipt) Contains(seq uint64) bool {
	if seq == 0 || seq > r.Seq {
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
func (r Receipt) Applied(seq uint64, now time.Time) Receipt {
	if seq == 0 || r.Contains(seq) {
		return r
	}
	next := Receipt{Seq: r.Seq, At: now.UTC().Format(time.RFC3339)}
	for _, g := range r.Gaps {
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
			next.Gaps = append(next.Gaps, Gap{r.Seq + 1, seq - 1})
		}
		next.Seq = seq
	}
	return next
}
