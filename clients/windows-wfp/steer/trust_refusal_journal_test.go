package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRefusalJournalCollapsesRetries(t *testing.T) {
	j := newTrustRefusalJournal(t.TempDir())
	leaf := []byte("served-cert-der")
	j.record(leaf, "x509: certificate signed by unknown authority", time.Now())
	j.record(leaf, "x509: certificate signed by unknown authority", time.Now())
	j.record(leaf, "x509: certificate signed by unknown authority", time.Now())

	p := j.pending()
	if len(p) != 1 {
		t.Fatalf("a hard-retrying device must collapse to ONE (cert,reason) pair, got %d", len(p))
	}
	if p[0].Count != 3 {
		t.Fatalf("count = %d, want 3 (retries folded)", p[0].Count)
	}
	sum := sha256.Sum256(leaf)
	if p[0].ServedSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("served_sha256 mismatch")
	}
	// A DIFFERENT reason for the same cert is a distinct pair — the reason is the evidence.
	j.record(leaf, "x509: certificate has expired or is not yet valid", time.Now())
	if len(j.pending()) != 2 {
		t.Fatalf("a distinct reason must be its own entry")
	}
}

func TestRefusalJournalCapsEntriesOldestOut(t *testing.T) {
	j := newTrustRefusalJournal(t.TempDir())
	for i := 0; i < maxRefusalEntries+8; i++ {
		j.record([]byte{byte(i)}, "reason", time.Now()) // distinct cert each time
	}
	p := j.pending()
	if len(p) != maxRefusalEntries {
		t.Fatalf("entries = %d, want capped at %d", len(p), maxRefusalEntries)
	}
	// The newest survive: the last-recorded cert (byte maxRefusalEntries+7) must be present.
	last := sha256.Sum256([]byte{byte(maxRefusalEntries + 7)})
	found := false
	for _, e := range p {
		if e.ServedSHA256 == hex.EncodeToString(last[:]) {
			found = true
		}
	}
	if !found {
		t.Fatal("the newest refusal was evicted — oldest-out was violated")
	}
}

func TestRefusalJournalReasonTruncated(t *testing.T) {
	j := newTrustRefusalJournal(t.TempDir())
	long := make([]byte, maxRefusalReasonLen+50)
	for i := range long {
		long[i] = 'x'
	}
	j.record([]byte("c"), string(long), time.Now())
	if got := len(j.pending()[0].Reason); got != maxRefusalReasonLen {
		t.Fatalf("reason length = %d, want %d", got, maxRefusalReasonLen)
	}
}

// clear drops ONLY what the Edge accepted, at the count it accepted. A refusal that recurred while the report
// was in flight has a higher count and MUST survive — its acknowledged copy is gone, what happened since is not.
func TestRefusalJournalClearKeepsMidFlightIncrement(t *testing.T) {
	j := newTrustRefusalJournal(t.TempDir())
	leaf := []byte("c")
	j.record(leaf, "reason", time.Now())
	reported := j.pending() // count == 1

	// It recurs while the report is "in flight".
	j.record(leaf, "reason", time.Now()) // count == 2

	j.clear(reported) // clears the count==1 snapshot only
	p := j.pending()
	if len(p) != 1 || p[0].Count != 2 {
		t.Fatalf("the mid-flight increment (count=2) must be kept, got %+v", p)
	}

	// Now clearing the current snapshot empties it.
	j.clear(j.pending())
	if len(j.pending()) != 0 {
		t.Fatal("clearing the exact reported set must empty the journal")
	}
}

func TestRefusalJournalPersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	j := newTrustRefusalJournal(dir)
	j.record([]byte("c"), "reason", time.Now())
	// A device refusing its Edge may restart before it can report; the record must survive.
	reloaded := newTrustRefusalJournal(dir)
	if len(reloaded.pending()) != 1 {
		t.Fatal("refusals did not persist across reload")
	}
	if _, err := os.Stat(filepath.Join(dir, "trust_refusals.json")); err != nil {
		t.Fatalf("journal file missing: %v", err)
	}
}

// A nil journal (no state dir) is a no-op everywhere — recording must never depend on a journal existing, or a
// handshake path could break on a device with no on-disk state.
func TestRefusalJournalNilSafe(t *testing.T) {
	var j *trustRefusalJournal // nil
	j.record([]byte("c"), "reason", time.Now())
	if j.pending() != nil {
		t.Fatal("nil journal pending must be nil")
	}
	j.clear([]trustRefusal{{ServedSHA256: "x", Reason: "y", Count: 1}})
	if newTrustRefusalJournal("") != nil {
		t.Fatal("empty state dir must yield a nil (disabled) journal")
	}
}
