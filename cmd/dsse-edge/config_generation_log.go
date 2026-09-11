package main

import (
	"sync"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// config_generation_log.go — writes the config snapshot an access record's config_generation_id points at,
// once per generation. See a.
//
// The access record carries only the id; this stream carries the config it resolves to. Without the row, the
// id is a dangling reference and the record loses the "which config was in force" property the normalisation
// was supposed to PRESERVE — so the row is written before the record that cites it.

// configGenerationsSeen remembers which generations this process has already written, so the common case (every
// decision after the first of a generation) costs a map lookup and no I/O. It is only a de-duplication cache:
// correctness does not depend on it, because a generation row is idempotent — the id is a content hash, so
// re-writing it after a restart appends an identical row rather than a conflicting one.
var configGenerationsSeen sync.Map // generation id -> struct{}

// configGenerationRow is the persisted shape. Flat `config` map: the snapshot is a projection of the decision
// metadata, and keeping it a map means a new config key needs no schema change here.
type configGenerationRow struct {
	ID       string         `json:"id"`
	TenantID string         `json:"tenant_id"`
	Config   map[string]any `json:"config"`
	// Which region wrote it. Every shipped record carries this, so a question about a region can be answered
	// of the records rather than of whichever store they happened to land in.
	EdgeRegionID string `json:"edge_region_id"`
}

// appendConfigGenerationIfNew writes the generation row for dec's config, unless this process already wrote it.
//
// Deliberately best-effort: a failure here must NOT fail the access-log write. Losing the ability to resolve a
// generation is bad; losing the access record itself is worse, and the caller's error path drops the decision
// record. The failure is logged as ERROR (an unresolvable id is a real audit gap an operator must see) and the
// id is NOT cached, so the next decision of the same generation retries.
func appendConfigGenerationIfNew(writer *logs.Writer, dec model.AccessDecision) {
	if writer == nil {
		return
	}
	snapshot, ok := decision.ConfigGenerationFromDecision(dec)
	if !ok {
		return
	}
	if _, seen := configGenerationsSeen.Load(snapshot.ID); seen {
		return
	}
	row := configGenerationRow{ID: snapshot.ID, TenantID: snapshot.TenantID, Config: snapshot.Config,
		EdgeRegionID: edgeRuntimeRegionID}
	if err := writer.Append("config_generations.log.jsonl", row); err != nil {
		logErrorf("config_generation_write_failed id=%q tenant=%q: %v — access records citing this generation cannot be resolved", snapshot.ID, snapshot.TenantID, err)
		return
	}
	configGenerationsSeen.Store(snapshot.ID, struct{}{})
}
