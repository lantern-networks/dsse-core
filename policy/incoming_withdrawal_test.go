package policy

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

func TestIncomingRuntimeHonorsExplicitWithdrawal(t *testing.T) {
	base := decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant"}, ServerInitiatedEnabled: true, LegacyExceptions: []decision.LegacyException{{ID: "startup", SourceServer: "patchsrv", ServiceFamily: "smb", Port: 445, Mode: "allow", Active: true, ExpiresAt: time.Now().Add(time.Hour)}}}
	req := model.DecisionRequest{TenantID: "tenant", ActorType: "human", ConnectionInitiator: "server", SourceServer: "patchsrv", ServiceFamily: "smb", DestinationPort: 445}
	t.Run("last exception deleted", func(t *testing.T) {
		s := NewStore(nil)
		s.ApplyBundle("tenant", nil, TenantConfigBundle{ServerInitiatedEnabled: true}, time.Now())
		ev := s.RuntimeEvaluator(base)
		if got := ev.Evaluate(req); got.Decision != "deny" {
			t.Fatalf("deleted startup exception still allows: %+v", got)
		}
		if len(ev.LegacyExceptions) != 0 {
			t.Fatal("startup exception resurrected")
		}
	})
	t.Run("default disabled", func(t *testing.T) {
		s := NewStore(nil)
		s.ApplyBundle("tenant", nil, TenantConfigBundle{}, time.Now())
		if s.RuntimeEvaluator(base).ServerInitiatedEnabled {
			t.Fatal("explicit disabled state ignored")
		}
	})
	t.Run("unconfigured tenant keeps startup settings", func(t *testing.T) {
		s := NewStore(nil)
		s.ApplyBundle("other", nil, TenantConfigBundle{}, time.Now())
		ev := s.RuntimeEvaluator(base)
		if !ev.ServerInitiatedEnabled || len(ev.LegacyExceptions) != 1 {
			t.Fatal("unrelated tenant withdrew startup settings")
		}
	})
}
