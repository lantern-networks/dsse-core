package decision

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestServerInitiatedDefaultDenyAndLegacyException(t *testing.T) {
	now := time.Now()
	ev := Evaluator{
		ServerInitiatedEnabled: true,
		PolicyBundle:           model.PolicyBundle{TenantID: "t"},
		LegacyExceptions: []LegacyException{
			{ID: "le1", SourceServer: "patchsrv", ServiceFamily: "smb", Port: 445, Mode: "allow", Active: true, ExpiresAt: now.Add(time.Hour)},
			{ID: "le_expired", SourceServer: "oldsrv", ServiceFamily: "rdp", Mode: "allow", Active: true, ExpiresAt: now.Add(-time.Hour)},
		},
	}
	base := model.DecisionRequest{TenantID: "t", ActorType: "human", ConnectionInitiator: "server"}

	// No matching exception -> default deny.
	r := base
	r.SourceServer = "unknown"
	r.ServiceFamily = "smb"
	r.DestinationPort = 445
	if d := ev.Evaluate(r); d.Decision != "deny" {
		t.Fatalf("server-initiated with no exception should deny, got %q", d.Decision)
	}

	// Matching active exception -> allow.
	r2 := base
	r2.SourceServer = "patchsrv"
	r2.ServiceFamily = "smb"
	r2.DestinationPort = 445
	if d := ev.Evaluate(r2); d.Decision != "allow" {
		t.Fatalf("matching legacy exception should allow, got %q", d.Decision)
	}

	// Matching but EXPIRED exception -> deny.
	r3 := base
	r3.SourceServer = "oldsrv"
	r3.ServiceFamily = "rdp"
	if d := ev.Evaluate(r3); d.Decision != "deny" {
		t.Fatalf("expired exception should deny, got %q", d.Decision)
	}

	// Client-initiated flow is NOT subject to the server-initiated branch (falls to normal policy/default).
	c := model.DecisionRequest{TenantID: "t", ActorType: "human", ConnectionInitiator: "client", ServiceFamily: "https", DestinationPort: 443}
	d := ev.Evaluate(c)
	for _, rc := range d.ReasonCodes {
		if rc == "server_initiated_default_deny" {
			t.Fatalf("client-initiated flow must not hit server-initiated default-deny")
		}
	}
}
