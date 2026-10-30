package decision

import (
	"github.com/lantern-networks/dsse-core/model"
	"testing"
	"time"
)

func TestMalformedLegacyExceptionCannotBecomeUnlimitedAllow(t *testing.T) {
	req := model.DecisionRequest{TenantID: "tenant", ConnectionInitiator: "server", SourceServer: "patchsrv", ServiceFamily: "smb", DestinationPort: 445}
	for _, tc := range []struct{ name, mode, expiry string }{
		{"invalid expiry", "allow", "not-a-timestamp"},
		{"unknown mode", "alllow", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := []model.LegacyException{{ID: "invalid", SourceServer: "patchsrv", Mode: tc.mode, ExpiresAt: tc.expiry, Status: "active"}}
			eval := Evaluator{ServerInitiatedEnabled: true, LegacyExceptions: LegacyExceptionsFromModel(rows)}
			got := eval.Evaluate(req)
			if got.Decision != "deny" {
				t.Fatalf("invalid persisted exception became %q", got.Decision)
			}
		})
	}
}
