package steerexclusion

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// ErrInvalidSnapshot deliberately omits saved values and storage paths.
var ErrInvalidSnapshot = errors.New("invalid steering exclusion snapshot")

// policySnapshot validates every tenant before adopting any row. A typed backend
// may return a nil slice for an empty result; the JSON decoder separately requires
// an explicit array so a missing file member is never treated as such a result.
func policySnapshot(policies []*Policy) (map[string]*Policy, error) {
	next := make(map[string]*Policy, len(policies))
	for i, p := range policies {
		if p == nil {
			return nil, fmt.Errorf("%w: null row %d", ErrInvalidSnapshot, i)
		}
		if _, exists := next[p.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate row %d", ErrInvalidSnapshot, i)
		}
		if err := ValidateTenantPolicies(p.TenantID, []Policy{*p}); err != nil {
			return nil, fmt.Errorf("%w: row %d", ErrInvalidSnapshot, i)
		}
		copied := clonePolicy(*p)
		next[p.ID] = &copied
	}
	return next, nil
}

func decodeFileSnapshot(data []byte) (map[string]*Policy, error) {
	if !utf8.Valid(data) {
		return nil, ErrInvalidSnapshot
	}
	root, err := snapshotObject(data, []string{"policies"})
	if err != nil {
		return nil, err
	}
	var rows []json.RawMessage
	if err = json.Unmarshal(root["policies"], &rows); err != nil || rows == nil {
		return nil, ErrInvalidSnapshot
	}
	policies := make([]*Policy, 0, len(rows))
	fields := []string{"id", "tenant_id", "scope_type", "scope_id", "excluded_app_signing_ids", "note", "status", "created_at", "updated_at"}
	for _, raw := range rows {
		if _, err = snapshotObject(raw, fields); err != nil {
			return nil, err
		}
		p := new(Policy)
		if err = json.Unmarshal(raw, p); err != nil {
			return nil, ErrInvalidSnapshot
		}
		policies = append(policies, p)
	}
	return policySnapshot(policies)
}

// Decode exact field names rather than accepting encoding/json's case aliases
// or last-value-wins behavior for duplicate keys. Existing writers emit all fields.
func snapshotObject(data []byte, fields []string) (map[string]json.RawMessage, error) {
	allowed := make(map[string]bool, len(fields))
	for _, f := range fields {
		allowed[f] = true
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalidSnapshot
	}
	out := make(map[string]json.RawMessage, len(fields))
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || !allowed[name] || out[name] != nil {
			return nil, ErrInvalidSnapshot
		}
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, ErrInvalidSnapshot
		}
		out[name] = raw
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(out) != len(fields) {
		return nil, ErrInvalidSnapshot
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrInvalidSnapshot
	}
	return out, nil
}
