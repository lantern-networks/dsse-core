package reportreceipt

import (
	"encoding/json"
	"errors"
	"math"
	"math/rand"
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
		next, err := r.Applied(seq, now)
		if err != nil {
			t.Fatal(err)
		}
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
	r, _ = r.Applied(math.MaxUint64, time.Now())
	if !r.Valid() || len(r.Gaps) != 1 || r.Contains(6) || !r.Contains(math.MaxUint64) {
		t.Fatalf("large gap %+v", r)
	}
	for _, gaps := range [][]Gap{{{0, 1}}, {{2, 1}}, {{1, 5}}, {{1, 3}, {2, 4}}} {
		if (Receipt{Seq: 5, At: stamp, Gaps: gaps}).Valid() {
			t.Fatalf("accepted invalid gaps %+v", gaps)
		}
	}
}

func TestReceiptStorageRemainsBounded(t *testing.T) {
	var r Receipt
	now := time.Now()
	for seq := uint64(2); seq <= 40000; seq += 2 {
		var err error
		r, err = r.Applied(seq, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(r)
	t.Logf("reports=20000 gaps=%d receipt_bytes=%d", len(r.Gaps), len(raw))
	if len(r.Gaps) > 4096 || len(raw) > 200000 {
		t.Fatal("receipt grows beyond the replay budget")
	}
}

func TestRetiredReportsAreUnknownNotDuplicates(t *testing.T) {
	now := time.Now()
	r, err := (Receipt{}).Applied(2, now)
	if err != nil {
		t.Fatal(err)
	}
	r, err = r.Applied(ReplayWindow+2, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{1, 2} {
		before, _ := json.Marshal(r)
		next, err := r.Applied(seq, now)
		after, _ := json.Marshal(next)
		if !errors.Is(err, ErrExpired) || r.Contains(seq) || string(before) != string(after) {
			t.Fatalf("retired %d: %v %+v", seq, err, next)
		}
	}
	// The first retained missing report is still accepted exactly once.
	r, err = r.Applied(3, now)
	if err != nil || !r.Contains(3) {
		t.Fatalf("boundary: %v %+v", err, r)
	}
	next, err := r.Applied(3, now.Add(time.Hour))
	if err != nil || !reflect.DeepEqual(r, next) {
		t.Fatal("duplicate changed receipt")
	}
	raw, _ := json.Marshal(r)
	var fresh Receipt
	if err := json.Unmarshal(raw, &fresh); err != nil || !fresh.Valid() {
		t.Fatalf("reload: %v", err)
	}
	if _, err := fresh.Applied(1, now); !errors.Is(err, ErrExpired) {
		t.Fatal("retirement lost on reload")
	}
}

func TestReplayWindowReferenceModel(t *testing.T) {
	now := time.Now()
	var r Receipt
	seen := map[uint64]bool{}
	rng := rand.New(rand.NewSource(37))
	for i := 0; i < 25000; i++ {
		seq := uint64(rng.Intn(5000) + 1)
		if i%3 == 0 {
			seq = r.Seq + uint64(rng.Intn(9)+1)
		}
		old := r
		next, err := r.Applied(seq, now)
		if seq <= old.RetiredThrough {
			if !errors.Is(err, ErrExpired) || old.Contains(seq) {
				t.Fatalf("expired %d", seq)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		seen[seq] = true
		r = next
		if !r.Valid() || len(r.Gaps) > int(ReplayWindow/2) {
			t.Fatalf("invalid/bloated: %+v", r)
		}
		for j := 0; j < 5; j++ {
			probe := uint64(rng.Intn(int(r.Seq) + 1))
			if r.Contains(probe) != (probe > r.RetiredThrough && seen[probe]) {
				t.Fatalf("sequence %d", probe)
			}
		}
	}
}
