package policycandidate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PublicationReviewer confirms that the candidate used to create an application
// is still pending and still names the same publication target.
type PublicationReviewer interface {
	ApprovePublication(context.Context, Candidate, string, time.Time) (Candidate, bool, error)
}

var ErrPublicationChanged = errors.New("candidate changed during application publication; reconcile the saved application and latest review")

func (s *Store) ApprovePublication(ctx context.Context, expected Candidate, reason string, now time.Time) (Candidate, bool, error) {
	reason = strings.TrimSpace(reason)
	if reason != "" && !safeAdminCatalogRef(reason) {
		return Candidate{}, false, fmt.Errorf("review_reason_code is invalid")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.persister.(candidateSharedPersister); ok {
		result, err := sharedCandidateMutation(s, ctx, func(next *Store) (candidateLookup, error) {
			c, found, err := next.ApprovePublication(ctx, expected, reason, now)
			return candidateLookup{c, found}, err
		})
		return result.candidate, result.found, err
	}
	if err := ctx.Err(); err != nil {
		return Candidate{}, false, err
	}
	current, found := s.candidates[expected.TenantID][expected.CandidateID]
	if !found {
		return Candidate{}, false, nil
	}
	if !samePublicationReview(current, expected) {
		return copyCandidate(current), true, ErrPublicationChanged
	}
	return s.applyReviewLocked(current, ReviewRequest{Decision: "approved", ReviewReasonCode: reason}, now)
}
func samePublicationReview(a, b Candidate) bool {
	sameTime := a.ReviewedAt == nil && b.ReviewedAt == nil || a.ReviewedAt != nil && b.ReviewedAt != nil && *a.ReviewedAt == *b.ReviewedAt
	return a.Status == "pending" && b.Status == "pending" && a.Source == SourceConnectorDiscovered && a.Source == b.Source &&
		a.CandidateType == b.CandidateType && a.ProposedAction == b.ProposedAction && a.Host == b.Host && a.SNI == b.SNI && a.Port == b.Port &&
		a.PublishProtocol == b.PublishProtocol && a.ObservedFromSite == b.ObservedFromSite && a.ReviewReasonCode == b.ReviewReasonCode && sameTime
}
