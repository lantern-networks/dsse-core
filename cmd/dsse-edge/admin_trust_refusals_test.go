package main

import (
	"path/filepath"
	"testing"
	"time"
)

// The distinction an operator acts on: is this device refusing what I am serving RIGHT NOW, or telling me
// why the thing I already backed out of failed? Both are worth showing; confusing them is not.
func TestTrustRefusalsSeparateTheCurrentCertificateFromAnOldOne(t *testing.T) {
	now := time.Now().UTC()
	serving := "aa11"
	entries := []observedExclusionEntry{{
		DeviceIdentity: "mac-1",
		TrustRefusals: []observedTrustRefusal{
			{ServedSHA256: "bb22", Reason: "certificate is not trusted", FirstAt: now.Add(-time.Hour), LastAt: now.Add(-time.Hour), Count: 12},
			{ServedSHA256: serving, Reason: "certificate has expired", FirstAt: now, LastAt: now, Count: 3},
		},
	}}

	got := buildTrustRefusals(entries, serving)
	if len(got.Refusals) != 2 {
		t.Fatalf("both refusals must be reported: %+v", got.Refusals)
	}
	// Most recent first.
	if got.Refusals[0].ServedIsCurrent == nil || !*got.Refusals[0].ServedIsCurrent {
		t.Fatal("a refusal of the certificate being served now must say so, and must sort first")
	}
	if got.Refusals[1].ServedIsCurrent == nil || *got.Refusals[1].ServedIsCurrent {
		t.Fatal("a refusal of a replaced certificate must not read as a live failure")
	}
	if got.Refusals[0].Count != 3 || got.Refusals[1].Count != 12 {
		t.Fatalf("the retry count travels with the refusal: %+v", got.Refusals)
	}
}

// A node that cannot say what it is serving must answer null, never false: false means "this is about a
// certificate we replaced", which is what the Console hides on. Hiding a live refusal on an unknown is the
// defect this three-valued answer exists to prevent.
func TestServedIsCurrentIsUnknownWhenNothingIsServed(t *testing.T) {
	now := time.Now().UTC()
	entries := []observedExclusionEntry{{
		DeviceIdentity: "mac-1",
		TrustRefusals: []observedTrustRefusal{
			{ServedSHA256: "aa11", Reason: "certificate is not trusted", FirstAt: now, LastAt: now, Count: 1},
		},
	}}
	got := buildTrustRefusals(entries, "")
	if len(got.Refusals) != 1 {
		t.Fatalf("the refusal must still be reported: %+v", got.Refusals)
	}
	if got.Refusals[0].ServedIsCurrent != nil {
		t.Fatalf("with no serving fingerprint the answer is unknown, not false: %+v", *got.Refusals[0].ServedIsCurrent)
	}
}

// A device may say anything; it is bounded before it is stored.
func TestReportedRefusalsAreBounded(t *testing.T) {
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'x'
	}
	in := []observedTrustRefusal{
		{Reason: string(long), ServedSHA256: "not-hex", Count: -4},
		{Reason: "   ", Count: 1},
	}
	out := normalizeReportedTrustRefusals(in)
	if len(out) != 1 {
		t.Fatalf("a refusal with no reason is dropped, not shown as an empty row: %+v", out)
	}
	if len(out[0].Reason) != 300 {
		t.Fatalf("the reason is length-capped, got %d", len(out[0].Reason))
	}
	if out[0].ServedSHA256 != "" {
		t.Fatal("a fingerprint that is not one must not be stored as if it were")
	}
	if out[0].Count != 1 {
		t.Fatalf("a nonsense count becomes one occurrence, got %d", out[0].Count)
	}

	many := make([]observedTrustRefusal, 100)
	for i := range many {
		many[i] = observedTrustRefusal{Reason: "reason", Count: 1}
	}
	if got := len(normalizeReportedTrustRefusals(many)); got != 32 {
		t.Fatalf("the list is capped, got %d", got)
	}
}

// The evidence must outlive the report that carried it. A device clears its journal once the Edge accepts
// it, so the NEXT report carries no refusals — and replacing the stored list with that empty one destroys
// the only copy, moments after finally receiving it. Found live: the refusal was visible for one poll.
func TestARefusalSurvivesTheNextReportThatCarriesNone(t *testing.T) {
	now := time.Now().UTC()
	stored := []observedTrustRefusal{
		{ServedSHA256: "bb22", Reason: "certificate is not trusted", FirstAt: now, LastAt: now, Count: 23},
	}

	if got := mergeTrustRefusals(stored, nil); len(got) != 1 || got[0].Count != 23 {
		t.Fatalf("an empty report must not erase what was already reported: %+v", got)
	}

	// A device still failing reports a higher count for the same pair: one row, updated.
	again := []observedTrustRefusal{
		{ServedSHA256: "bb22", Reason: "certificate is not trusted", FirstAt: now, LastAt: now.Add(time.Minute), Count: 40},
	}
	got := mergeTrustRefusals(stored, again)
	if len(got) != 1 {
		t.Fatalf("the same refusal must stay one row: %+v", got)
	}
	if got[0].Count != 40 || !got[0].LastAt.After(now) {
		t.Fatalf("the row must move forward, not duplicate: %+v", got[0])
	}

	// A different certificate is a different row.
	other := []observedTrustRefusal{
		{ServedSHA256: "cc33", Reason: "certificate is not trusted", FirstAt: now, LastAt: now, Count: 1},
	}
	if got := mergeTrustRefusals(stored, other); len(got) != 2 {
		t.Fatalf("a refusal of a different certificate is its own row: %+v", got)
	}
}

// The record must outlive the Edge, not only the report. A device empties its journal once we accept its
// refusals, so it will never send them again — and restarting the Edge is exactly what an operator does
// during a certificate incident. Found live: replacing the transport certificate wiped the evidence.
func TestRefusalsSurviveAnEdgeRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust_refusals.json")
	now := time.Now().UTC()

	first := newTrustRefusalStore(path)
	first.Merge("t", "mac-1", []observedTrustRefusal{
		{ServedSHA256: "bb22", Reason: "certificate is not trusted", FirstAt: now, LastAt: now, Count: 36},
	})

	restarted := newTrustRefusalStore(path)
	got := restarted.ForTenant("t")
	if len(got["mac-1"]) != 1 || got["mac-1"][0].Count != 36 {
		t.Fatalf("the only copy of the evidence must survive a restart: %+v", got)
	}

	// And the empty report that follows acceptance must not erase it.
	restarted.Merge("t", "mac-1", nil)
	if again := newTrustRefusalStore(path).ForTenant("t"); len(again["mac-1"]) != 1 {
		t.Fatalf("an empty report must not erase what was already recorded: %+v", again)
	}

	// A different tenant's devices are not visible here.
	restarted.Merge("other", "win-9", []observedTrustRefusal{
		{ServedSHA256: "cc33", Reason: "certificate has expired", FirstAt: now, LastAt: now, Count: 1},
	})
	if got := restarted.ForTenant("t"); len(got) != 1 {
		t.Fatalf("refusals are scoped to their tenant: %+v", got)
	}
}
