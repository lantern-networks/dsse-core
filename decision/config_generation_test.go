package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func decisionWithMetadata(tenant string, metadata map[string]any) model.AccessDecision {
	return model.AccessDecision{TenantID: tenant, Metadata: metadata}
}

func labConfigMetadata() map[string]any {
	return map[string]any{
		"inspection_profile_id":    "ip_lab_001",
		"trust_profile_id":         "tp_lab_001",
		"tenant_root_ca_id":        "trca_lab_001",
		"tenant_root_ca_status":    "configured",
		"tls_interception_enabled": true,
		// per-request facts, deliberately NOT part of the generation
		"edge_tls_policy_decision": "intercept_candidate",
		"actor_type":               "human",
	}
}

// The id is a content hash: identical config -> identical generation, so the row is written once no matter how
// much traffic flows. This is the property the whole normalisation rests on.
func TestConfigGenerationIDIsStableForIdenticalConfig(t *testing.T) {
	a, ok := ConfigGenerationFromDecision(decisionWithMetadata("t1", labConfigMetadata()))
	if !ok {
		t.Fatal("no generation from a decision carrying config")
	}
	b, _ := ConfigGenerationFromDecision(decisionWithMetadata("t1", labConfigMetadata()))
	if a.ID != b.ID {
		t.Fatalf("id = %q and %q, want identical for identical config", a.ID, b.ID)
	}
}

// ...and a changed config MUST mint a new generation, or the audit trail silently resolves an old decision
// through the new config — the exact drift this design exists to prevent.
func TestConfigGenerationIDChangesWhenConfigChanges(t *testing.T) {
	base, _ := ConfigGenerationFromDecision(decisionWithMetadata("t1", labConfigMetadata()))
	changed := labConfigMetadata()
	changed["tenant_root_ca_status"] = "rotated"
	next, _ := ConfigGenerationFromDecision(decisionWithMetadata("t1", changed))
	if base.ID == next.ID {
		t.Fatalf("id = %q for both, want a new generation when the config changes", base.ID)
	}
}

// A per-request fact changing must NOT mint a generation: generations would then churn per request and the row
// would be written per decision — reintroducing the cost while adding a stream.
func TestConfigGenerationIgnoresPerRequestFacts(t *testing.T) {
	base, _ := ConfigGenerationFromDecision(decisionWithMetadata("t1", labConfigMetadata()))
	other := labConfigMetadata()
	other["edge_tls_policy_decision"] = "bypass"
	other["actor_type"] = "nhi"
	next, _ := ConfigGenerationFromDecision(decisionWithMetadata("t1", other))
	if base.ID != next.ID {
		t.Fatalf("id changed (%q -> %q) for a per-request difference; the generation must cover config only", base.ID, next.ID)
	}
	if _, leaked := base.Config["edge_tls_policy_decision"]; leaked {
		t.Fatalf("generation config = %#v, want per-request facts excluded", base.Config)
	}
	if _, leaked := base.Config["actor_type"]; leaked {
		t.Fatalf("generation config = %#v, want per-request facts excluded", base.Config)
	}
}

// Two tenants with byte-identical config must not share a generation: a shared id would make one tenant's audit
// trail resolve through a row owned by another tenant.
func TestConfigGenerationIsTenantScoped(t *testing.T) {
	a, _ := ConfigGenerationFromDecision(decisionWithMetadata("t1", labConfigMetadata()))
	b, _ := ConfigGenerationFromDecision(decisionWithMetadata("t2", labConfigMetadata()))
	if a.ID == b.ID {
		t.Fatalf("both tenants got %q, want tenant-scoped generations", a.ID)
	}
}

// A decision that never ran the readiness stamp has no config to normalise; it must keep its metadata untouched
// rather than acquire an empty generation that resolves to nothing.
func TestConfigGenerationAbsentWhenDecisionCarriesNoConfig(t *testing.T) {
	dec := decisionWithMetadata("t1", map[string]any{"ai_app": "chrome.exe"})
	if _, ok := ConfigGenerationFromDecision(dec); ok {
		t.Fatal("got a generation from a decision with no config keys")
	}
	log := AccessLogFromDecision(dec)
	if log.ConfigGenerationID != "" {
		t.Fatalf("config_generation_id = %q, want empty", log.ConfigGenerationID)
	}
	if log.Metadata["ai_app"] != "chrome.exe" {
		t.Fatalf("metadata = %#v, want it untouched", log.Metadata)
	}
}

// The record is pruned, never the evaluator's working map: usagemeter and hotstore read dec.Metadata, and the
// evaluator itself may consult it after the record is built.
func TestAccessLogFromDecisionDoesNotMutateDecisionMetadata(t *testing.T) {
	dec := decisionWithMetadata("t1", labConfigMetadata())
	_ = AccessLogFromDecision(dec)
	if dec.Metadata["tenant_root_ca_id"] != "trca_lab_001" {
		t.Fatalf("decision metadata = %#v, want the source map untouched", dec.Metadata)
	}
}
