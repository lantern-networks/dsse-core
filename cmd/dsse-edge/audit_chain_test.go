package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/archive"
)

type fakeArchive struct{ objs map[string][]byte }

func (f *fakeArchive) Put(ctx context.Context, key string, r io.Reader, size int64, opts archive.PutOptions) (archive.PutResult, error) {
	b, _ := io.ReadAll(r)
	f.objs[key] = b
	return archive.PutResult{Key: key, Size: int64(len(b))}, nil
}
func (f *fakeArchive) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	b, ok := f.objs[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}
func (f *fakeArchive) List(ctx context.Context, prefix string, limit int) ([]archive.ObjectInfo, error) {
	var out []archive.ObjectInfo
	for k := range f.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, archive.ObjectInfo{Key: k})
		}
	}
	return out, nil
}
func (f *fakeArchive) Backend() string { return "fake" }

func buildAuditSegment(seq int, prev string, records [][]byte) ([]byte, string) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(auditChainHeaderLine(seq, prev))
	for _, r := range records {
		gz.Write(r)
		gz.Write([]byte("\n"))
	}
	gz.Close()
	return buf.Bytes(), hashObjectBytes(buf.Bytes())
}

func TestAuditChainVerifyDetectsTampering(t *testing.T) {
	fa := &fakeArchive{objs: map[string][]byte{}}
	cs := newAuditChainStore(nil)
	ctx := context.Background()
	tenant := "t1"
	for i := 0; i < 3; i++ {
		seq, prev := cs.Next(tenant)
		seg, h := buildAuditSegment(seq, prev, [][]byte{[]byte(`{"event":"e` + strconv.Itoa(i) + `"}`)})
		fa.objs[fmt.Sprintf("hot_events/%s/audit/2026-01-0%d.ndjson.gz", tenant, i+1)] = seg
		cs.Commit(tenant, seq, h)
	}
	res, err := verifyAuditChain(ctx, fa, tenant)
	if err != nil || !res.OK || res.Segments != 3 {
		t.Fatalf("intact chain must verify OK: %+v err=%v", res, err)
	}
	// Tamper the middle segment → its bytes change → the chain must break.
	for k := range fa.objs {
		if strings.Contains(k, "0-02.") || strings.Contains(k, "01-02") {
			fa.objs[k] = append([]byte("tampered"), fa.objs[k]...)
		}
	}
	res2, _ := verifyAuditChain(ctx, fa, tenant)
	if res2.OK {
		t.Fatal("tampered chain must NOT verify OK")
	}
	if res2.BrokenAt == "" {
		t.Fatalf("must report where the chain broke: %+v", res2)
	}
	t.Logf("tamper detected at %s: %s", res2.BrokenAt, res2.Detail)
}
