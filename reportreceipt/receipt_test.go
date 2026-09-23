package reportreceipt

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestReorderedSequencesKeepOnlyUnappliedGaps(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var r Receipt
	seen := map[uint64]bool{}
	for _, seq := range []uint64{8, 2, 5, 1, 7, 3, 5, 6, 4, 8, 10, 9} {
		if r.Contains(seq) != seen[seq] {
			t.Fatalf("before %d: %+v", seq, r)
		}
		previous, _ := json.Marshal(r)
		next := r.Applied(seq, now)
		after, _ := json.Marshal(r)
		if !reflect.DeepEqual(previous, after) {
			t.Fatal("mutated the previous receipt before commit")
		}
		r = next
		seen[seq] = true
		if !r.Valid() {
			t.Fatalf("invalid receipt %+v", r)
		}
		for n := uint64(1); n <= 11; n++ {
			if r.Contains(n) != seen[n] {
				t.Fatalf("after %d, sequence %d: %+v", seq, n, r)
			}
		}
	}
	if len(r.Gaps) != 0 {
		t.Fatalf("completed prefix retains gaps: %+v", r)
	}
}

func TestLegacyReceiptAndLargeGaps(t *testing.T) {
	stamp := time.Now().UTC().Format(time.RFC3339)
	r := Receipt{Seq: 5, At: stamp}
	if !r.Valid() || !r.Contains(1) || r.Contains(6) {
		t.Fatal("legacy prefix changed")
	}
	r = r.Applied(math.MaxUint64, time.Now())
	if !r.Valid() || len(r.Gaps) != 1 || r.Contains(6) || !r.Contains(math.MaxUint64) {
		t.Fatalf("large gap %+v", r)
	}
	for _, gaps := range [][]Gap{{{0, 1}}, {{2, 1}}, {{1, 5}}, {{1, 3}, {2, 4}}} {
		if (Receipt{Seq: 5, At: stamp, Gaps: gaps}).Valid() {
			t.Fatalf("accepted invalid gaps %+v", gaps)
		}
	}
}
