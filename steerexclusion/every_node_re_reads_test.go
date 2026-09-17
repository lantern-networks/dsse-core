package steerexclusion

import (
	"context"
	"testing"
	"time"
)

// countingPersistence is a durable store two nodes share. Writes from one appear to the other only if the
// other asks again — which is the whole question.
type countingPersistence struct {
	policies []*Policy
	loads    int
	fail     error
}

func (c *countingPersistence) LoadAll(context.Context) ([]*Policy, error) {
	c.loads++
	if c.fail != nil {
		return nil, c.fail
	}
	out := make([]*Policy, len(c.policies))
	copy(out, c.policies)
	return out, nil
}
func (c *countingPersistence) Upsert(_ context.Context, p *Policy) error {
	for i, existing := range c.policies {
		if existing.ID == p.ID {
			c.policies[i] = p
			return nil
		}
	}
	c.policies = append(c.policies, p)
	return nil
}
func (c *countingPersistence) Delete(_ context.Context, id, _ string) error {
	for i, existing := range c.policies {
		if existing.ID == id {
			c.policies = append(c.policies[:i], c.policies[i+1:]...)
			return nil
		}
	}
	return nil
}

// ★★★ EVERY NODE LOADED ONCE AND NEVER LOOKED AGAIN (2026-08-29, measured on a two-region deployment). An
// operator authored an exclusion in the Console; the control plane that served the write had it and the other
// three did not, and would not until they restarted. The Console reads whichever node answers, so the policy
// was present on one refresh and absent on the next — and the install profile issued to a device carried four
// identifiers or none depending on which node signed it.
//
// Steering exclusions decide whether the tools managing this deployment stay off the steered path, so
// "sometimes" is not a state this may be in.
func TestANodeSeesWhatAnotherNodeAuthored(t *testing.T) {
	shared := &countingPersistence{}

	wrote, err := NewStoreWithPersistence(shared)
	if err != nil {
		t.Fatal(err)
	}
	reads, err := NewStoreWithPersistence(shared)
	if err != nil {
		t.Fatal(err)
	}
	// The second node has looked once and found nothing — exactly the state the defect was hiding in.
	if got := len(reads.List("tenant_a")); got != 0 {
		t.Fatalf("the second node started with %d", got)
	}

	if _, err := wrote.Upsert(Policy{TenantID: "tenant_a", ScopeType: "tenant",
		ExcludedAppSigningIDs: []string{"com.example.tool"}}, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Past the refresh window: the node that did NOT serve the write must answer with it.
	reads.refreshedAt = time.Now().Add(-2 * refreshWindow)
	got := reads.List("tenant_a")
	if len(got) != 1 || len(got[0].ExcludedAppSigningIDs) != 1 {
		t.Fatalf("the node that did not serve the write answers %v — the Console reads whichever node "+
			"answers, so this is a policy that exists on one refresh and not the next", got)
	}

	// ★ AND THE ENFORCING READ TOO, not only the screen's.
	reads.refreshedAt = time.Now().Add(-2 * refreshWindow)
	if ids := reads.ResolveForDevice("tenant_a", "dev-1", ""); len(ids) != 1 {
		t.Fatalf("what the device is told is %v", ids)
	}
}

// ★ A DATABASE THAT BLINKS MUST NOT EMPTY THE LIST. These are the identifiers that keep the tools managing
// this deployment off the steered path; dropping them on a transient error would arm steering against the
// session doing the work.
func TestATransientFailureKeepsWhatIsHeld(t *testing.T) {
	shared := &countingPersistence{policies: []*Policy{
		{ID: "p1", TenantID: "tenant_a", ScopeType: "tenant", Status: "active", ExcludedAppSigningIDs: []string{"com.example.tool"}},
	}}
	store, err := NewStoreWithPersistence(shared)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.List("tenant_a")) != 1 {
		t.Fatal("did not load what was there")
	}
	shared.fail = context.DeadlineExceeded
	store.refreshedAt = time.Now().Add(-2 * refreshWindow)
	if got := store.List("tenant_a"); len(got) != 1 {
		t.Fatalf("a failed re-read emptied the list: %v — every exclusion would drop on a blink", got)
	}
}
