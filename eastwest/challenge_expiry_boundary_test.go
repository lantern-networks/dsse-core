package eastwest

import (
	"testing"
	"time"
)

func TestChallengeExpiryIsExclusiveAndMalformedExpiryIsRejected(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	for _, expiry := range []string{now.Format(time.RFC3339), "invalid"} {
		t.Run(expiry, func(t *testing.T) {
			store := NewAuthChallengeStore()
			challenge := store.Create(AuthChallenge{TenantID: "tenant", SubjectUserID: "user"}, now)
			challenge.ExpiresAt = expiry
			store.challenges[challenge.ID] = challenge
			if pending := store.ListPending("tenant", now); len(pending) != 0 {
				t.Fatal("expired or malformed challenge was listed as usable")
			}
			if _, ok := store.Complete(challenge.ID, now); ok {
				t.Fatal("expired or malformed challenge was completed")
			}
		})
	}
	store := NewAuthChallengeStore()
	challenge := store.Create(AuthChallenge{TenantID: "tenant", SubjectUserID: "user"}, now)
	if _, ok := store.Complete(challenge.ID, now.Add(AuthChallengeTTL-time.Nanosecond)); !ok {
		t.Fatal("still-valid challenge rejected")
	}
}
