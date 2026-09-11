package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A counter that is zero because nothing happened, and a counter that is zero because nothing counts it, look
// identical on a scrape. That is the house failure mode, and this surface had a live instance of it: the
// outcome buckets covered `allow`, `deny` and `require_*`, while the evaluator also produces
// `authenticate_required` and `observe`. Fourteen authenticate_required decisions are on record. An operator
// watching "are step-ups happening" would have read zero while they were happening.
//
// The fix is not to add two cases and move on — the next decision value would fall through exactly the same
// way. It is to make the buckets SUM TO THE TOTAL, and to check that against the evaluator's own vocabulary
// rather than against a list somebody remembers to update.

var decisionLiteralPattern = regexp.MustCompile(`"(allow|deny|observe|authenticate_required|require_[a-z_]+)"`)

// decisionVocabularyFromEvaluator reads the decision values out of the evaluator source. Read, not hardcoded:
// a hardcoded list drifts silently, which is the failure this test exists to prevent, one level up.
func decisionVocabularyFromEvaluator(t *testing.T) []string {
	t.Helper()
	const evaluator = "../../decision/evaluator.go"
	src, err := os.ReadFile(evaluator)
	if err != nil {
		t.Fatalf("read %s: %v", evaluator, err)
	}
	seen := map[string]bool{}
	for _, m := range decisionLiteralPattern.FindAllStringSubmatch(string(src), -1) {
		seen[m[1]] = true
	}
	if len(seen) < 5 {
		t.Fatalf("found only %d decision values in %s — the pattern has stopped matching, and a test that "+
			"matches nothing passes everything", len(seen), evaluator)
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func TestDecisionMetricBucketsCoverEveryOutcomeTheEvaluatorProduces(t *testing.T) {
	vocabulary := decisionVocabularyFromEvaluator(t)

	reset := func() {
		metricDecisionsTotal.Store(0)
		metricDecisionsAllow.Store(0)
		metricDecisionsDeny.Store(0)
		metricDecisionsStepUp.Store(0)
		metricDecisionsObserve.Store(0)
		metricDecisionsOther.Store(0)
	}
	t.Cleanup(reset)

	// Every value, one at a time, so a failure names the value rather than a sum.
	for _, decision := range vocabulary {
		reset()
		recordDecisionMetric(decision)
		if got := metricDecisionsOther.Load(); got != 0 {
			t.Errorf("decision %q lands in outcome=\"other\" — no bucket claims it, so it is counted in the "+
				"total and invisible in every outcome an operator reads", decision)
		}
	}

	// And together: the buckets must sum to the total. This is the invariant that survives someone adding a
	// tenth decision value without reading this file.
	reset()
	for _, decision := range vocabulary {
		recordDecisionMetric(decision)
	}
	sum := metricDecisionsAllow.Load() + metricDecisionsDeny.Load() +
		metricDecisionsStepUp.Load() + metricDecisionsObserve.Load() + metricDecisionsOther.Load()
	if total := metricDecisionsTotal.Load(); sum != total {
		t.Fatalf("buckets sum to %d but the total is %d — the difference is decisions counted as having "+
			"happened while belonging to no outcome. vocabulary: %s", sum, total, strings.Join(vocabulary, ", "))
	}
}

// The specific value that was being lost, pinned so a regression names itself instead of showing up as a
// bucket-sum mismatch nobody can attribute.
func TestAuthenticateRequiredCountsAsAStepUp(t *testing.T) {
	metricDecisionsStepUp.Store(0)
	metricDecisionsOther.Store(0)
	t.Cleanup(func() { metricDecisionsStepUp.Store(0); metricDecisionsOther.Store(0) })

	recordDecisionMetric("authenticate_required")
	if metricDecisionsStepUp.Load() != 1 {
		t.Fatalf("authenticate_required did not count as a step-up — it is one in everything but its name, and "+
			"an operator watching step_up would read zero while enforcement was happening (step_up=%d other=%d)",
			metricDecisionsStepUp.Load(), metricDecisionsOther.Load())
	}
}
