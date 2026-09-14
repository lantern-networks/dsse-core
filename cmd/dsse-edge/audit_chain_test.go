package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/logs"
	"io"
	"net/http/httptest"
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
		seq, prev, err := cs.Next(tenant)
		if err != nil {
			t.Fatal(err)
		}
		seg, h := buildAuditSegment(seq, prev, [][]byte{[]byte(`{"event":"e` + strconv.Itoa(i) + `"}`)})
		fa.objs[fmt.Sprintf("hot_events/%s/audit/2026-01-0%d.ndjson.gz", tenant, i+1)] = seg
		if err := cs.Commit(tenant, seq, h); err != nil {
			t.Fatal(err)
		}
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

func TestAuditChainRejectsUnreadableOrMissingHeaders(t *testing.T) {
	gzipBytes := func(data string) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte(data))
		_ = gz.Close()
		return buf.Bytes()
	}
	valid, _ := buildAuditSegment(0, "", [][]byte{[]byte(`{"event":"ok"}`)})
	badCRC := append([]byte(nil), valid...)
	badCRC[len(badCRC)-8] ^= 0xff
	largeCRC := gzipBytes(string(auditChainHeaderLine(0, "")) + strings.Repeat("x", 200000))
	largeCRC[len(largeCRC)-8] ^= 0xff
	cases := map[string][]byte{
		"empty_gzip": gzipBytes(""), "missing_header": gzipBytes("{}\n"), "bad_json": gzipBytes("{\n"),
		"null_header":       gzipBytes("{\"_audit_chain\":null}\n"),
		"missing_seq":       gzipBytes("{\"_audit_chain\":{\"prev\":\"\"}}\n"),
		"missing_prev":      gzipBytes("{\"_audit_chain\":{\"seq\":0}}\n"),
		"wrong_seq":         gzipBytes("{\"_audit_chain\":{\"seq\":1,\"prev\":\"\"}}\n"),
		"truncated_trailer": valid[:len(valid)-4], "bad_crc": badCRC, "large_bad_crc": largeCRC,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			key := "hot_events/t1/audit/1.gz"
			res, err := verifyAuditChain(context.Background(), &fakeArchive{objs: map[string][]byte{key: data}}, "t1")
			if err != nil || res.OK || res.Status != "broken" || res.BrokenAt != key {
				t.Fatalf("invalid segment accepted: %+v %v", res, err)
			}
		})
	}
}

func TestAuditChainStatesDoNotClaimArchiveCompleteness(t *testing.T) {
	arc := &fakeArchive{objs: map[string][]byte{}}
	res, err := verifyAuditChain(context.Background(), arc, "t1")
	if err != nil || res.OK || res.Status != "empty" {
		t.Fatalf("empty archive: %+v %v", res, err)
	}
	first, hash := buildAuditSegment(0, "", nil)
	second, _ := buildAuditSegment(1, hash, nil)
	arc.objs["hot_events/t1/audit/1.gz"] = first
	arc.objs["hot_events/t1/audit/2.gz"] = second
	for _, removeSuffix := range []bool{false, true} {
		if removeSuffix {
			delete(arc.objs, "hot_events/t1/audit/2.gz")
		}
		res, err = verifyAuditChain(context.Background(), arc, "t1")
		if err != nil || !res.OK || res.Status != "links_verified" || res.Scope != "listed_segments_only" {
			t.Fatalf("scope: %+v %v", res, err)
		}
	}
	// A valid hash link cannot conceal a skipped sequence number.
	second, _ = buildAuditSegment(2, hash, nil)
	arc.objs["hot_events/t1/audit/2.gz"] = second
	res, err = verifyAuditChain(context.Background(), arc, "t1")
	if err != nil || res.OK || res.Status != "broken" {
		t.Fatalf("sequence gap accepted: %+v %v", res, err)
	}
}

func TestAuditChainHTTPReportsEmptyAndBrokenArchives(t *testing.T) {
	arc := &fakeArchive{objs: map[string][]byte{}}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, ColdArchive: arc})
	for _, state := range []string{"empty", "broken"} {
		if state == "broken" {
			arc.objs["hot_events/tenant_lab_001/audit/1.gz"] = []byte("bad gzip")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/audit-chain/verify", nil))
		if rec.Code != 200 {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var result auditChainVerifyResult
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Status != state || result.OK {
			t.Fatalf("state=%+v", result)
		}
	}
}
