package humanapproval

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestApprovedActiveAndRevoke(t *testing.T) {
	now := time.Now().UTC()
	store := NewStore(8)
	exp := now.Add(time.Hour).Format(time.RFC3339)
	approved := model.HumanApprovalEvent{ID: "h1", TenantID: "acme", ApprovalResult: "approved", ExpiresAt: &exp}
	if _, err := store.Upsert(approved); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.GetActive("h1", now); !ok {
		t.Fatal("an approved, unexpired event should be active")
	}
	// a denied event is never active
	denied := model.HumanApprovalEvent{ID: "h2", TenantID: "acme", ApprovalResult: "denied"}
	_, _ = store.Upsert(denied)
	if _, ok := store.GetActive("h2", now); ok {
		t.Fatal("a non-approved event must not be active")
	}
	if _, ok, err := store.Revoke("h1", "test"); !ok || err != nil {
		t.Fatal("revoke should succeed")
	}
	if _, ok := store.GetActive("h1", now); ok {
		t.Fatal("a revoked event must not be active")
	}
}

// TestIsActiveFailsClosedOnMalformedTimes pins fail-open review finding #12: a non-empty but UNPARSEABLE
// expires_at (or activated_at) must NOT leave an approval active forever — it fails closed for that record. An
// empty timestamp still means "no gate" (unchanged), so a legitimate no-expiry approval stays active.
func TestIsActiveFailsClosedOnMalformedTimes(t *testing.T) {
	now := time.Now().UTC()
	s := func(v string) *string { return &v }
	future := now.Add(time.Hour).Format(time.RFC3339)

	// malformed expiry -> expired (was: active forever).
	if IsActive(model.HumanApprovalEvent{ApprovalResult: "approved", ExpiresAt: s("not-a-time")}, now) {
		t.Fatal("malformed expires_at must be treated as expired, not active-forever")
	}
	// malformed activation -> not yet active.
	if IsActive(model.HumanApprovalEvent{ApprovalResult: "approved", ActivatedAt: s("garbage"), ExpiresAt: &future}, now) {
		t.Fatal("malformed activated_at must be treated as not-yet-active")
	}
	// empty expiry = no expiry -> still active (no disruption to legit no-expiry approvals).
	if !IsActive(model.HumanApprovalEvent{ApprovalResult: "approved", ExpiresAt: s("")}, now) {
		t.Fatal("empty expires_at must remain active (no-expiry)")
	}
	// well-formed future expiry -> active (control).
	if !IsActive(model.HumanApprovalEvent{ApprovalResult: "approved", ExpiresAt: &future}, now) {
		t.Fatal("valid future expiry must be active")
	}
}
