package decision

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/lantern-networks/dsse-core/model"
)

// config_generation.go — the "config generation" projection.
//
// applyTLSInspectionReadinessMetadata stamps the tenant's inspection-profile + trust-profile + tenant-root-CA
// CONFIGURATION onto the metadata of every decision. Measured on 95 live decisions across 31 destinations: that
// block is 964 of a 3069-byte access record — 31% of every record — and it did not vary once, because it is a
// function of configuration, not of the request. Writing it per decision means the record's cost scales with
// TRAFFIC while its information scales with CONFIG CHANGES.
//
// It cannot simply be dropped: the record is what proves WHICH config was in force at decision time. Resolving
// `inspection_profile_id` against the live profile months later answers what the profile says NOW, not what it
// said then — the profile is mutable, so the audit answer would silently drift.
//
// So it is normalised, not deleted: the decision record carries ONE `config_generation_id`, and the snapshot is
// written ONCE per distinct generation to its own stream. The id is a content hash, so a new generation appears
// exactly when the config actually changes, and an old generation row is never rewritten — it stays true.
//
// The key set is deliberately derived from ONE function's output (applyTLSInspectionReadinessMetadata), not from
// "keys that looked constant in a sample". Sampling is how this goes wrong: `edge_tls_policy_decision`,
// `edge_tls_policy_bypass`, `inspection_route_category` and `inspection_execution_scope` were ALSO constant across
// those 95 decisions, but they are computed per request — freezing them into a shared generation would have made
// them lie for every destination that resolves differently. Config is a property of the SOURCE (ctx.Profile /
// ctx.TrustProfile / ctx.TenantRootCA), never of the observed variance.

// configGenerationKeys are exactly the metadata keys applyTLSInspectionReadinessMetadata writes — the tenant's
// inspection/trust/CA configuration. Every key here MUST be a pure function of the config context: if a key ever
// starts depending on the request, it must leave this list, or its value freezes across a generation.
var configGenerationKeys = []string{
	"certificate_issuance_mode",
	"certificate_pinning_policy",
	"inspection_mode",
	"inspection_profile_id",
	"network_extension_dependency",
	"network_extension_runtime_used",
	"payload_policy",
	"quic_policy_action",
	"quic_policy_mode",
	"quic_tcp_tls_redirect_required",
	"tenant_root_ca_distribution_mode",
	"tenant_root_ca_id",
	"tenant_root_ca_private_key_status",
	"tenant_root_ca_status",
	"tenant_root_ca_trust_store_target",
	"tls_inspection_readiness",
	"tls_interception_enabled",
	"trust_profile_id",
	"trust_profile_status",
	"trust_store_state",
}

// ConfigGenerationSnapshot is the config that was in force for a decision, recorded once per generation.
type ConfigGenerationSnapshot struct {
	ID       string         `json:"id"`
	TenantID string         `json:"tenant_id"`
	Config   map[string]any `json:"config"`
}

// configGenerationID is the content hash of the snapshot: same config -> same id, changed config -> new id.
// Tenant-scoped so two tenants with identical config still get distinct generations (a generation is a tenant's
// config, and a shared id would make one tenant's audit trail resolve through another's row).
func configGenerationID(tenantID string, config map[string]any) string {
	keys := make([]string, 0, len(config))
	for k := range config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{0})
	for _, k := range keys {
		v, err := json.Marshal(config[k])
		if err != nil {
			// A value that will not marshal cannot be hashed stably; fold in its key alone rather than
			// silently producing a colliding id for two different configs.
			v = []byte("\x00unmarshalable")
		}
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(v)
		h.Write([]byte{0})
	}
	return "cfg_gen_" + hex.EncodeToString(h.Sum(nil)[:8])
}

// ConfigGenerationFromDecision extracts the config block from a decision's metadata and returns the snapshot it
// belongs to. ok is false when the decision carries none of the config keys (e.g. a path that never ran the
// readiness stamp) — such a decision simply has no generation and keeps whatever metadata it has.
func ConfigGenerationFromDecision(dec model.AccessDecision) (ConfigGenerationSnapshot, bool) {
	if len(dec.Metadata) == 0 {
		return ConfigGenerationSnapshot{}, false
	}
	config := map[string]any{}
	for _, k := range configGenerationKeys {
		if v, ok := dec.Metadata[k]; ok {
			config[k] = v
		}
	}
	if len(config) == 0 {
		return ConfigGenerationSnapshot{}, false
	}
	return ConfigGenerationSnapshot{
		ID:       configGenerationID(dec.TenantID, config),
		TenantID: dec.TenantID,
		Config:   config,
	}, true
}

// stripConfigGenerationKeys removes the config block from a record's metadata. The caller must have recorded the
// generation id first, or the config becomes unrecoverable for that record.
func stripConfigGenerationKeys(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return metadata
	}
	for _, k := range configGenerationKeys {
		delete(metadata, k)
	}
	return metadata
}
