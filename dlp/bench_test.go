package dlp

import (
	"bytes"
	"strings"
	"testing"
)

// Measured baseline (Apple M-series, go test -bench, 2026-07-06): DetectStream ~245 MB/s (~2 Gbps) at
// constant memory, ~22 allocs per 1 MB scan. The initial regex-only implementation was ~3.8 MB/s; replacing
// the numeric regexes with a linear digit-run scan and gating the API-key regex behind a bytes.Contains
// prefix check (memchr) sped it up ~64×. At ~2 Gbps the scan is faster than typical upload links, so for
// observe it does not throttle the forward; very fast internal bulk transfers should be scope-exempted
// (docs/dlp_minimal_design.md). This is the "numbers not feel" gate before enabling block-all.

// buildBody returns an ~sizeBytes text body of JSON-ish records, sprinkling valid identifiers every ~4 KB so
// the scanner exercises both the fast no-match path and the validator path.
func buildBody(sizeBytes int) []byte {
	var b strings.Builder
	b.Grow(sizeBytes + 256)
	filler := `{"id":"row","ts":"2026-07-06T00:00:00Z","msg":"lorem ipsum dolor sit amet consectetur"},`
	for b.Len() < sizeBytes {
		b.WriteString(filler)
		if b.Len()%4096 < len(filler) {
			b.WriteString(`{"my_number":"123456789018","card":"4111111111111111"},`)
		}
	}
	return []byte(b.String())
}

// BenchmarkDetectStream measures streaming-scan throughput on a 1 MB text body (constant memory, any size).
// Report MB/s = (1<<20)/(ns/op)*1000. Divide network egress cost by this to see the marginal DLP cost.
func BenchmarkDetectStream(b *testing.B) {
	body := buildBody(1 << 20) // 1 MB
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DetectStream(bytes.NewReader(body)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDetectStreamNoMatch measures the fast path (no identifiers) — the common case for most uploads.
func BenchmarkDetectStreamNoMatch(b *testing.B) {
	body := []byte(strings.Repeat(`{"id":"row","msg":"lorem ipsum dolor sit amet"},`, (1<<20)/48))
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DetectStream(bytes.NewReader(body)); err != nil {
			b.Fatal(err)
		}
	}
}
