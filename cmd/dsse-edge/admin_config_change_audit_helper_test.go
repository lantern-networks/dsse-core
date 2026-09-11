package main

import (
	logs "github.com/lantern-networks/dsse-core/logs"
)

// readAuditRowsExcludingWrapper reads the admin audit stream but drops the uniform per-mutation
// `admin_config_change` rows the adminEndpoint wrapper now emits (b).
// Domain-audit contract tests assert on their specific event row (admin_policy_upserted, …); the wrapper adds a
// second, always-last row per mutation, so a test that read the raw stream and asserted a single domain row now
// sees two. Excluding the wrapper row keeps those domain-focused assertions correct while the coverage floor it
// provides is exercised by its own dedicated tests. Signature mirrors writer.ReadJSONL for a drop-in swap.
func readAuditRowsExcludingWrapper(w *logs.Writer) ([]map[string]any, error) {
	rows, err := w.ReadJSONL("audit.log.jsonl")
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		if r["event_type"] == "admin_config_change" {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
