package grantstore

import "encoding/json"

// LegacyRollbackSnapshot preserves every row and unknown field, but revokes all
// grants. Older binaries cannot enforce request binding, so retaining any active
// authorization during downgrade would weaken it. Call only with writers stopped.
func LegacyRollbackSnapshot(raw []byte) ([]byte, int, error) {
	var outer map[string]json.RawMessage
	if json.Unmarshal(raw, &outer) != nil || outer == nil {
		return nil, 0, ErrInvalidGrant
	}
	rows := outer
	var version int
	if v, ok := outer["schema_version"]; ok && json.Unmarshal(v, &version) == nil {
		rows = nil
		if (version != 2 && version != 3) || len(outer) != 2 || json.Unmarshal(outer["grants"], &rows) != nil || rows == nil {
			return nil, 0, ErrInvalidGrant
		}
	}
	for id, rawRow := range rows {
		var g Grant
		var fields map[string]json.RawMessage
		if json.Unmarshal(rawRow, &g) != nil || g.GrantID != id || validateGrant(g) != nil || json.Unmarshal(rawRow, &fields) != nil {
			return nil, 0, ErrInvalidGrant
		}
		fields["revoked"] = json.RawMessage("true")
		updated, err := json.Marshal(fields)
		if err != nil {
			return nil, 0, err
		}
		rows[id] = updated
	}
	converted, err := json.Marshal(rows)
	return converted, len(rows), err
}
