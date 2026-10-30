package grantstore

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLegacyRollbackPreservesRowsUnknownFieldsAndDenials(t *testing.T) {
	now := time.Now().UTC()
	g := grantFixture("active", now)
	r := grantFixture("revoked", now)
	r.Revoked = true
	raw, _ := encodeGrantSnapshot(map[string]Grant{g.GrantID: g, r.GrantID: r})
	var outer map[string]json.RawMessage
	json.Unmarshal(raw, &outer)
	var rows map[string]map[string]any
	json.Unmarshal(outer["grants"], &rows)
	rows["active"]["future_evidence"] = map[string]any{"version": 1}
	outer["grants"], _ = json.Marshal(rows)
	raw, _ = json.Marshal(outer)
	out, n, e := LegacyRollbackSnapshot(raw)
	if e != nil || n != 2 {
		t.Fatal(n, e)
	}
	var legacy map[string]Grant
	if json.Unmarshal(out, &legacy) != nil || len(legacy) != 2 {
		t.Fatal("old reader cannot load")
	}
	for _, g := range legacy {
		if !g.Revoked {
			t.Fatal("rollback revived authorization")
		}
	}
	var preserved map[string]map[string]any
	json.Unmarshal(out, &preserved)
	if preserved["active"]["future_evidence"] == nil {
		t.Fatal("unknown evidence dropped")
	}
	again, _, e := LegacyRollbackSnapshot(out)
	if e != nil || string(again) != string(out) {
		t.Fatal("not idempotent", e)
	}
	for _, bad := range []string{`{"schema_version":99,"grants":{}}`, `{"schema_version":3,"grants":{"x":{}}}`, `null`} {
		if _, _, e := LegacyRollbackSnapshot([]byte(bad)); e == nil {
			t.Fatal("invalid input accepted")
		}
	}
}
