package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/policycandidate"
)

// A stopped candidate store must not be answered with "reload and retry":
// retrying cannot clear an unknown COMMIT.
func TestPolicyCandidateReconciliationIsNotAnsweredWithRetry(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("%w: %w", policycandidate.ErrPersistence, policycandidate.ErrReconciliationRequired),
		fmt.Errorf("%w: %w", policycandidate.ErrUnavailable, policycandidate.ErrReconciliationRequired),
	} {
		rec := httptest.NewRecorder()
		writePolicyCandidateError(rec, err)
		body := rec.Body.String()
		if rec.Code != http.StatusServiceUnavailable || strings.Contains(body, "reload and retry") || !strings.Contains(body, "restart this control plane") {
			t.Fatalf("%v -> %d %s", err, rec.Code, body)
		}
	}
	rec := httptest.NewRecorder()
	writePolicyCandidateError(rec, fmt.Errorf("%w: busy", policycandidate.ErrUnavailable))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "reload and retry") {
		t.Fatalf("ordinary unavailability changed: %d %s", rec.Code, rec.Body.String())
	}
}
