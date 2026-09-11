package hotstore

import "testing"

// TestEventRegionAnswersFromEitherSpelling — the same fact was spelled two ways across streams, and a
// residency question cannot be answered of records that spell it differently.
func TestEventRegionAnswersFromEitherSpelling(t *testing.T) {
	for name, tc := range map[string]struct {
		row  map[string]any
		want string
	}{
		"the field itself": {
			row:  map[string]any{"edge_region_id": "region-a"},
			want: "region-a",
		},
		"device_state's <region>/<cluster>": {
			row:  map[string]any{"edge": "region-b/local-edge-001"},
			want: "region-b",
		},
		"the field wins over the compound": {
			row:  map[string]any{"edge_region_id": "region-a", "edge": "region-b/x"},
			want: "region-a",
		},
		"an empty field falls through to the compound": {
			row:  map[string]any{"edge_region_id": "  ", "edge": "region-c/x"},
			want: "region-c",
		},
		// ★ AND IT NEVER GUESSES. A record with no region is a defect to be counted, not a row to be assigned
		// to whichever region happens to be asking — which is the one way a residency answer can be worse than
		// having none.
		"nothing at all": {
			row:  map[string]any{"tenant_id": "acme"},
			want: "",
		},
		"a cluster with no region part": {
			row:  map[string]any{"edge": "/local-edge-001"},
			want: "",
		},
	} {
		if got := EventRegion(tc.row); got != tc.want {
			t.Errorf("%s: EventRegion = %q, want %q", name, got, tc.want)
		}
	}
}
