package regionfailover

import (
	"strings"
	"testing"
)

// TestParseRefusesZeroBecauseZeroMeansLast is the refusal worth having, and the only one whose absence would be
// invisible.
//
// effectiveRegionPriority maps 0 to LAST. An operator writing `tokyo=0` is reaching for "first" — zero-based is
// the ordinary instinct — and would get the exact inverse, on every device the profile reaches, with a healthy
// log and a working tunnel to the wrong PoP. There is no later signal.
func TestParseRefusesZeroBecauseZeroMeansLast(t *testing.T) {
	for _, raw := range []string{"jp-tokyo=0", "jp-tokyo=1,jp-osaka=0", "jp-tokyo=-1"} {
		got, err := ParsePriority(raw)
		if err == nil {
			t.Fatalf("ParsePriority(%q) accepted a non-rank; the selector ranks it LAST, the inverse of what the "+
				"operator wrote", raw)
		}
		if !strings.Contains(err.Error(), "1 is the highest") {
			t.Fatalf("ParsePriority(%q) does not tell the operator what to write instead: %v", raw, err)
		}
		if got != nil {
			t.Fatalf("ParsePriority(%q) returned a map alongside its error: %v", raw, got)
		}
	}
}

func TestParseRefusesAContradiction(t *testing.T) {
	_, err := ParsePriority("jp-tokyo=1,jp-osaka=2,JP-TOKYO=3")
	if err == nil {
		t.Fatal("a region given two priorities was accepted; one of the operator's two intentions was discarded silently")
	}
	if !strings.Contains(err.Error(), "jp-tokyo") {
		t.Fatalf("the error does not name the contradicted region: %v", err)
	}
}

func TestParseRefusesMalformedEntries(t *testing.T) {
	for _, raw := range []string{"jp-tokyo", "jp-tokyo=", "=1", "jp-tokyo=high", "jp-tokyo=1.5"} {
		if _, err := ParsePriority(raw); err == nil {
			t.Fatalf("ParsePriority(%q) accepted a malformed entry", raw)
		}
	}
}

// TestUnsetIsNotAnError pins the ordinary state. Every fleet that exists today is in it, and a feature that
// errored without configuration would be a breaking change dressed as a safety check.
func TestUnsetIsNotAnError(t *testing.T) {
	for _, raw := range []string{"", "   ", ",", " , "} {
		got, err := ParsePriority(raw)
		if err != nil {
			t.Fatalf("ParsePriority(%q) errored on an unconfigured value: %v", raw, err)
		}
		if got != nil {
			t.Fatalf("ParsePriority(%q) = %v, want nil so the selector sees every region as unspecified", raw, got)
		}
	}
}

func TestParseAcceptsTheAuthoredForm(t *testing.T) {
	got, err := ParsePriority(" JP-Tokyo = 1 , jp-osaka=2 ")
	if err != nil {
		t.Fatalf("ParsePriority: %v", err)
	}
	if got["jp-tokyo"] != 1 || got["jp-osaka"] != 2 || len(got) != 2 {
		t.Fatalf("parsed %v, want jp-tokyo=1 jp-osaka=2 (ids lowercased, whitespace tolerated)", got)
	}
}

// ★ TestValidateAndParseAgreeOnWhatARankIs is the reason checkRank exists as one function.
//
// The flag goes through ParsePriority; a hand-authored signed profile goes through ValidatePriority and never
// touches the parser. If those two drifted, a profile could carry a value the flag refuses — and the profile is
// the production path, so the drift would only ever be discovered in the direction that matters.
func TestValidateAndParseAgreeOnWhatARankIs(t *testing.T) {
	for _, bad := range []int{0, -1, -100} {
		if _, err := ParsePriority("jp-tokyo=" + itoa(bad)); err == nil {
			t.Fatalf("ParsePriority accepted rank %d", bad)
		}
		if errs := ValidatePriority(map[string]int{"jp-tokyo": bad}); len(errs) == 0 {
			t.Fatalf("ValidatePriority accepted rank %d that ParsePriority refuses — the signed profile can now "+
				"express what the flag cannot", bad)
		}
	}
	for _, good := range []int{1, 2, 99} {
		if _, err := ParsePriority("jp-tokyo=" + itoa(good)); err != nil {
			t.Fatalf("ParsePriority refused rank %d: %v", good, err)
		}
		if errs := ValidatePriority(map[string]int{"jp-tokyo": good}); len(errs) != 0 {
			t.Fatalf("ValidatePriority refused rank %d that ParsePriority accepts: %v", good, errs)
		}
	}
}

// ★ TestOneDocumentMeansOneThingOnBothPlatforms is the fix the macOS side asked for, and the reason it is a
// fix rather than a nicety.
//
// Until 2026-08-10 only the SERVED id was lowercased, so a preference written `JP-Tokyo` was not wrong-looking,
// it was INERT here — while the macOS agent lowercased its keys and honoured it. The same signed document did
// two different things on two platforms, so an operator who tested on a Mac would ship a file that silently
// configured nothing on every Windows box. Both sides of the lookup are normalised now.
func TestOneDocumentMeansOneThingOnBothPlatforms(t *testing.T) {
	out := ApplyPriority([]RegionEndpoint{
		{Region: "jp-tokyo", Endpoint: "https://tok:443"},
		{Region: "JP-Osaka", Endpoint: "https://osa:443"}, // the SERVED id has capitals too
	}, map[string]int{"JP-Tokyo": 1, " jp-osaka ": 2}) // and so does the WRITTEN one, plus stray spaces

	got := map[string]int{}
	for _, ep := range out {
		got[ep.Region] = ep.Priority
	}
	if got["jp-tokyo"] != 1 {
		t.Fatalf("a capitalised WRITTEN id did not match a lowercase served region: %v", got)
	}
	if got["JP-Osaka"] != 2 {
		t.Fatalf("a padded written id did not match a capitalised served region: %v", got)
	}
	// Capitals are no longer worth a warning, precisely because they now work.
	if errs := ValidatePriority(map[string]int{"JP-Tokyo": 1}); len(errs) != 0 {
		t.Fatalf("a capitalised id is still reported as a problem though it now works: %v", errs)
	}
}

// TestValidateReportsASpellingCollision is what replaced the capitals warning. Two spellings of one region with
// DIFFERENT ranks is a contradiction the operator wrote, and the resolution is ours, not theirs — so it has to
// be said out loud, and it has to be deterministic, because map iteration order is not.
func TestValidateReportsASpellingCollision(t *testing.T) {
	pri := map[string]int{"JP-Tokyo": 3, "jp-tokyo": 1}
	errs := ValidatePriority(pri)
	if len(errs) != 1 {
		t.Fatalf("got %d problems, want 1 collision report: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), "same region with different") {
		t.Fatalf("the report does not name the collision: %v", errs[0])
	}
	// The STRONGER rank wins, every time, whichever spelling the map happens to yield first.
	for i := 0; i < 20; i++ {
		out := ApplyPriority([]RegionEndpoint{{Region: "jp-tokyo", Endpoint: "https://tok:443"}}, pri)
		if out[0].Priority != 1 {
			t.Fatalf("collision resolved to %d, want the stronger rank 1 — the outcome depends on map order",
				out[0].Priority)
		}
	}
	// Two spellings agreeing is not a contradiction and must stay quiet.
	if errs := ValidatePriority(map[string]int{"JP-Tokyo": 2, "jp-tokyo": 2}); len(errs) != 0 {
		t.Fatalf("two spellings with the SAME rank were reported as a problem: %v", errs)
	}
}

// TestValidateReportsEveryProblem: the caller is a human editing a document they then have to re-sign. One
// error per edit-and-resign cycle is an expensive way to find three.
func TestValidateReportsEveryProblem(t *testing.T) {
	errs := ValidatePriority(map[string]int{"jp-tokyo": 0, "jp-osaka": -1, "jp-nagoya": 2})
	if len(errs) != 2 {
		t.Fatalf("got %d problems, want 2 (both bad ranks, not the good one): %v", len(errs), errs)
	}
}

// ★ TestApplyCanOnlyReorderNeverWiden is the property that lets the preference be less trusted than the list.
//
// The served list IS the residency boundary. If a configured region the Edge did NOT serve could enter here,
// a preference would have become a way to steer a device to a region its tenant's residency rules exclude.
func TestApplyCanOnlyReorderNeverWiden(t *testing.T) {
	served := []RegionEndpoint{
		{Region: "jp-tokyo", Endpoint: "https://tok:443"},
		{Region: "jp-osaka", Endpoint: "https://osa:443"},
	}
	// us-east is ranked FIRST and is not served: the strongest form of the mistake.
	out := ApplyPriority(served, map[string]int{"us-east": 1, "jp-osaka": 2})

	if len(out) != len(served) {
		t.Fatalf("ApplyPriority returned %d endpoints from a served list of %d; a preference widened the "+
			"residency boundary", len(out), len(served))
	}
	for _, ep := range out {
		if ep.Region == "us-east" {
			t.Fatal("a region the Edge never served entered the allowed list from local configuration")
		}
	}
}

// TestAnUnrankedRegionStaysUnspecified: a partially-configured fleet must still prefer the regions that WERE
// ranked. Defaulting the rest to some middling number would let an unranked region outrank an explicit choice.
func TestAnUnrankedRegionStaysUnspecified(t *testing.T) {
	out := ApplyPriority([]RegionEndpoint{
		{Region: "jp-tokyo", Endpoint: "https://tok:443"},
		{Region: "jp-osaka", Endpoint: "https://osa:443"},
	}, map[string]int{"jp-osaka": 1})

	got := map[string]int{}
	for _, ep := range out {
		got[ep.Region] = ep.Priority
	}
	if got["jp-osaka"] != 1 {
		t.Fatalf("jp-osaka priority = %d, want 1", got["jp-osaka"])
	}
	if got["jp-tokyo"] != 0 {
		t.Fatalf("jp-tokyo priority = %d, want 0 (unspecified ranks last); anything else can outrank an explicit choice", got["jp-tokyo"])
	}
}

// TestApplyIsSafeUnconfigured: callers apply this unconditionally on every path a list arrives by, so with
// nothing configured it must be a no-op on content — including on a list that already carries priorities.
func TestApplyIsSafeUnconfigured(t *testing.T) {
	in := []RegionEndpoint{
		{Region: "jp-tokyo", Endpoint: "https://tok:443", Priority: 7},
		{Region: "jp-osaka", Endpoint: "https://osa:443"},
	}
	for _, pri := range []map[string]int{nil, {}} {
		out := ApplyPriority(in, pri)
		if len(out) != len(in) {
			t.Fatalf("length changed with no preference configured: %d != %d", len(out), len(in))
		}
		for i := range in {
			if out[i] != in[i] {
				t.Fatalf("endpoint %d changed with no preference configured: %+v != %+v", i, out[i], in[i])
			}
		}
	}
}

// TestRenderIsStableAcrossDevices: the startup line is how an operator confirms what a machine actually got, so
// two machines with the same configuration must print the same string. Map iteration order would not.
func TestRenderIsStableAcrossDevices(t *testing.T) {
	pri := map[string]int{"jp-osaka": 2, "jp-tokyo": 1, "jp-ishikari": 3}
	const want = "jp-tokyo=1,jp-osaka=2,jp-ishikari=3"
	for i := 0; i < 20; i++ {
		if got := RenderPriority(pri); got != want {
			t.Fatalf("RenderPriority = %q, want %q (ordered by preference, not by map iteration)", got, want)
		}
	}
	if got := RenderPriority(nil); got != "" {
		t.Fatalf("RenderPriority(nil) = %q, want empty so an unconfigured device logs nothing", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
