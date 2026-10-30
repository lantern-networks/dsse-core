package logs

import (
	"bytes"
	"fmt"
	"testing"
)

func TestFailedGeneratedObjectReplacementPreservesCommittedBytes(t *testing.T) {
	store, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := "domain-events/tenant/application/event.ndjson.gz"
	if _, err := store.WriteGzipJSONL(name, []map[string]any{{"id": "committed"}}); err != nil {
		t.Fatal(err)
	}
	before, err := store.ReadGeneratedFile(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, failEncoding := range []bool{false, true} {
		calls := 0
		_, err := store.WriteGzipJSONLStream(name, func() (map[string]any, bool, error) {
			calls++
			if calls == 1 {
				return map[string]any{"id": "uncommitted"}, true, nil
			}
			if failEncoding {
				return map[string]any{"invalid": make(chan int)}, true, nil
			}
			return nil, false, fmt.Errorf("source failed after one row")
		})
		if err == nil {
			t.Fatal("failed replacement was acknowledged")
		}
		after, err := store.ReadGeneratedFile(name)
		if err != nil || !bytes.Equal(before, after) {
			t.Errorf("committed object was removed or changed after failed replacement: error=%v", err)
		}
	}
}
