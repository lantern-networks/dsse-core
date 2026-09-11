package logs

import (
	"testing"
)

// BenchmarkWriterAppendConcurrent models the per-flow logging hot path: many concurrent
// goroutines each appending across the several JSONL files an Edge decision writes
// (access / decision_trace / audit / inspection). Measures append throughput and allocs.
func BenchmarkWriterAppendConcurrent(b *testing.B) {
	dir := b.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		b.Fatal(err)
	}
	files := []string{
		"access.log.jsonl",
		"decision_trace.log.jsonl",
		"audit.log.jsonl",
		"inspection_events.log.jsonl",
	}
	rec := map[string]any{
		"id":              "alog_433eb346ecbf2b1ca17ca13f89023fea",
		"tenant_id":       "tenant_swg_lab",
		"destination":     "www.example.com",
		"service_family":  "https",
		"decision":        "allow",
		"reason_codes":    []string{"policy_matched", "application_allowed"},
		"edge_cluster_id": "local-edge-001",
		"timestamp":       "2026-06-16T07:27:54Z",
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if err := w.Append(files[i%len(files)], rec); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

// BenchmarkWriterAppendSingleFile measures worst-case contention: all goroutines hammer one file.
func BenchmarkWriterAppendSingleFile(b *testing.B) {
	dir := b.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		b.Fatal(err)
	}
	rec := map[string]any{"id": "alog_x", "tenant_id": "t", "destination": "www.example.com", "decision": "allow"}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := w.Append("access.log.jsonl", rec); err != nil {
				b.Fatal(err)
			}
		}
	})
}
