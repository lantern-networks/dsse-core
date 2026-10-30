package grantstore

import (
	"context"
	"encoding/json"
	"errors"
)

// RollingBackend keeps the legacy grant map and modern evidence in separate
// keys. Read and update MUST cover both keys in one database transaction, taking
// the legacy key lock before the evidence key lock, also used by legacy writers.
// Merely saving two blobs in succession does not implement this contract.
type RollingBackend interface {
	LoadGrantPair(context.Context) (legacy, evidence []byte, err error)
	UpdateGrantPair(context.Context, func(legacy, evidence []byte) ([]byte, []byte, error)) error
}

// RollingPersister presents the current Store format while keeping the original
// shared "grants" key readable and writable by the released map-only binary.
// It is used for the shared PostgreSQL authority, not a pair of unrelated files.
type RollingPersister struct{ Backend RollingBackend }

func (p RollingPersister) Load() ([]byte, error) {
	a, b, e := p.Backend.LoadGrantPair(context.Background())
	if e != nil {
		return nil, e
	}
	if a == nil && b == nil {
		return nil, nil
	}
	rows, e := joinRolling(a, b)
	if e != nil {
		return nil, e
	}
	return encodeGrantSnapshot(rows)
}
func (p RollingPersister) Save(raw []byte) error {
	// Store mutations use UpdateContext; a whole-document save could overwrite
	// concurrent legacy writes and is intentionally unavailable.
	return errors.New("rolling grant authority requires transactional update")
}
func (p RollingPersister) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	return p.Backend.UpdateGrantPair(ctx, func(a, b []byte) ([]byte, []byte, error) {
		rows, e := joinRolling(a, b)
		if e != nil {
			return nil, nil, e
		}
		var current []byte
		if a != nil || b != nil {
			current, e = encodeGrantSnapshot(rows)
			if e != nil {
				return nil, nil, e
			}
		}
		next, e := edit(current)
		if e != nil {
			return nil, nil, e
		}
		result, e := decodeShared(next)
		if e != nil {
			return nil, nil, e
		}
		return splitRolling(result)
	})
}

// Fields understood by the released grantstore. New authorization requirements
// must never be smuggled into these fields as a reusable legacy grant.
var legacyFields = map[string]bool{
	"grant_id": true, "tenant_id": true, "user_id": true, "user_email": true,
	"username": true, "user_display_name": true, "device_id": true, "idp_id": true,
	"acr": true, "amr": true, "scope": true, "issued_at": true,
	"expires_at": true, "revoked": true,
}

func legacyProjection(g Grant) (json.RawMessage, error) {
	raw, e := json.Marshal(g)
	if e != nil {
		return nil, e
	}
	var f map[string]json.RawMessage
	if e = json.Unmarshal(raw, &f); e != nil {
		return nil, e
	}
	for k := range f {
		if !legacyFields[k] {
			delete(f, k)
		}
	}
	return json.Marshal(f)
}
func decodeRollingMap(raw []byte) (map[string]Grant, error) {
	if raw == nil {
		return map[string]Grant{}, nil
	}
	var rows map[string]json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || rows == nil {
		return nil, ErrInvalidGrant
	}
	// Do not silently convert a fenced development snapshot in a running fleet.
	if _, exists := rows["schema_version"]; exists {
		return nil, ErrInvalidGrant
	}
	out := map[string]Grant{}
	for id, rawRow := range rows {
		var g Grant
		if json.Unmarshal(rawRow, &g) != nil || g.GrantID != id {
			return nil, ErrInvalidGrant
		}
		if validateGrant(g) != nil {
			return nil, ErrInvalidGrant
		}
		out[id] = g
	}
	return out, nil
}
func joinRolling(a, b []byte) (map[string]Grant, error) {
	legacy, e := decodeRollingMap(a)
	if e != nil {
		return nil, e
	}
	evidence, e := decodeRollingMap(b)
	if e != nil {
		return nil, e
	}
	out := cloneGrants(legacy)
	for id, full := range evidence {
		old, present := legacy[id]
		if full.RequiresModernReader() {
			// Even a corrupt/stripped legacy copy must not revive a modern-only row.
			if present {
				full.Revoked = true
			}
			out[id] = full
			continue
		}
		if !present {
			// A legacy erasure is a denial. Preserve evidence, never restore an allow.
			full.Revoked = true
			out[id] = full
			continue
		}
		if old.TenantID != full.TenantID {
			return nil, ErrConflict
		}
		x, y := old, full
		x.Revoked = false
		y.Revoked = false
		xr, _ := legacyProjection(x)
		yr, _ := legacyProjection(y)
		if string(xr) != string(yr) {
			full.Revoked = true
		}
		full.Revoked = full.Revoked || old.Revoked
		out[id] = full
	}
	return out, nil
}
func splitRolling(rows map[string]Grant) ([]byte, []byte, error) {
	legacy := map[string]json.RawMessage{}
	evidence := map[string]Grant{}
	for id, g := range rows {
		if !g.RequiresModernReader() {
			raw, e := legacyProjection(g)
			if e != nil {
				return nil, nil, e
			}
			legacy[id] = raw
		}
		// Every row has an independent immutable copy, so an old whole-map write
		// cannot erase proof, undo revocation, or change a grant's attribution.
		evidence[id] = g
	}
	a, e := json.Marshal(legacy)
	if e != nil {
		return nil, nil, e
	}
	b, e := json.Marshal(evidence)
	return a, b, e
}

// SplitTransport prevents old CP/Edge JSON decoders from treating a modern-only
// grant as a reusable authorization. They see only the ordinary grants field.
func SplitTransport(rows []Grant) (ordinary, protected []Grant) {
	ordinary = []Grant{}
	protected = []Grant{}
	for _, g := range rows {
		if g.RequiresModernReader() {
			protected = append(protected, g)
		} else {
			ordinary = append(ordinary, g)
		}
	}
	return
}
