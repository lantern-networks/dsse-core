package hotstore

import (
	"strings"
	"testing"
)

// The Logs screen's Destination box: an access decision keeps its destination at the top of the record, and a
// DLP finding keeps it in metadata (the column). Both are matched, as part of the field, like Postgres and JSONL.
func TestClickHouseDestinationFilterMatchesAccessDecisionsAndFindings(t *testing.T) {
	s := NewClickHouseStore("http://x:8123", "u", "p", "dsse", "events")
	where, params := s.buildWhere(SearchQuery{TenantID: "acme", Stream: "access", Filters: map[string]string{"destination": "10.40.1.30"}})
	want := "(positionCaseInsensitiveUTF8(JSONExtractString(raw, {k0:String}), {f0:String}) > 0 OR positionCaseInsensitiveUTF8(destination, {f0:String}) > 0)"
	if !strings.Contains(where, want) {
		t.Fatalf("destination is not matched in the record and the DLP column: %q", where)
	}
	if strings.Contains(where, "destination = {f0:String}") {
		t.Fatalf("destination is still compared exactly with the DLP-only column: %q", where)
	}
	if params["k0"] != "destination" || params["f0"] != "10.40.1.30" {
		t.Fatalf("params wrong: %+v", params)
	}
	if strings.Contains(where, "10.40.1.30") {
		t.Fatalf("value interpolated into SQL: %q", where)
	}
}

func TestClickHouseSubstringFieldsMatchAsPartOnTheirColumn(t *testing.T) {
	s := NewClickHouseStore("http://x:8123", "u", "p", "dsse", "events")
	where, _ := s.buildWhere(SearchQuery{TenantID: "acme", Filters: map[string]string{"user_id": "alice"}})
	if !strings.Contains(where, "positionCaseInsensitiveUTF8(user_id, {f0:String}) > 0") {
		t.Fatalf("user_id is not a partial match: %q", where)
	}
	where, _ = s.buildWhere(SearchQuery{TenantID: "acme", Filters: map[string]string{"tool_id": "fetch"}})
	if !strings.Contains(where, "positionCaseInsensitiveUTF8(JSONExtractString(raw, {k0:String}), {f0:String}) > 0") {
		t.Fatalf("tool_id is not a partial match: %q", where)
	}
	// Enum and id fields stay exact, as in the other stores.
	where, _ = s.buildWhere(SearchQuery{TenantID: "acme", Filters: map[string]string{"decision": "deny"}})
	if !strings.Contains(where, "JSONExtractString(raw, {k0:String}) = {f0:String}") {
		t.Fatalf("decision is not exact: %q", where)
	}
}
