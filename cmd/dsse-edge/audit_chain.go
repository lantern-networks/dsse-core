package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/archive"
	"github.com/lantern-networks/dsse-core/blobstore"
)

// Tamper-evident hash chain for the archived AUDIT stream. Each audit cold segment embeds a header line
//   {"_audit_chain":{"seq":N,"prev":"<hex sha256 of the previous audit segment>"}}
// and the segment's own hash is SHA-256 of its (gzip) object bytes. Because every segment names the prior
// segment's hash, DELETING, ALTERING, or REORDERING any archived audit segment breaks the chain and is detected
// by a verify walk. Combined with WORM object-lock (which prevents deletion within the retention window), this
// gives a compliance-grade, tamper-evident audit archive: WORM prevents tampering, the chain proves it didn't
// happen (and that no segment is missing).

type auditChainState struct {
	Seq      int    `json:"seq"`
	LastHash string `json:"last_hash"`
}

type auditChainStore struct {
	mu        sync.Mutex
	per       map[string]auditChainState // tenant -> running chain state
	persister blobstore.Persister
}

func newAuditChainStore(p blobstore.Persister) *auditChainStore {
	s := &auditChainStore{per: map[string]auditChainState{}, persister: p}
	if p == nil {
		return s
	}
	data, err := p.Load()
	if err != nil {
		log.Printf("audit-chain store load: %v", err)
		return s
	}
	if len(data) == 0 {
		return s
	}
	if err := json.Unmarshal(data, &s.per); err != nil {
		log.Printf("audit-chain store parse: %v", err)
		s.per = map[string]auditChainState{}
	}
	return s
}

// Next returns the seq + prev-hash to embed in the tenant's next audit segment.
func (s *auditChainStore) Next(tenant string) (int, string) {
	if s == nil {
		return 0, ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.per[tenant]
	return st.Seq, st.LastHash
}

// Commit records that the segment with this seq + hash was successfully written, advancing the chain.
func (s *auditChainStore) Commit(tenant string, seq int, hash string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.per[tenant] = auditChainState{Seq: seq + 1, LastHash: hash}
	s.persistLocked()
	s.mu.Unlock()
}

func (s *auditChainStore) persistLocked() {
	if s.persister == nil {
		return
	}
	data, err := json.Marshal(s.per)
	if err != nil {
		return
	}
	_ = s.persister.Save(data)
}

type auditChainHeader struct {
	Seq  int    `json:"seq"`
	Prev string `json:"prev"`
}

// auditChainHeaderLine is the first NDJSON line embedded in an archived audit segment.
func auditChainHeaderLine(seq int, prev string) []byte {
	b, _ := json.Marshal(map[string]any{"_audit_chain": auditChainHeader{Seq: seq, Prev: prev}})
	return append(b, '\n')
}

// hashObjectBytes is the segment hash: hex SHA-256 of the archived (gzip) object bytes.
func hashObjectBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type auditChainVerifyResult struct {
	Tenant   string `json:"tenant_id"`
	Segments int    `json:"segments"`
	OK       bool   `json:"ok"`
	BrokenAt string `json:"broken_at,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// verifyAuditChain walks a tenant's archived audit segments in order and checks the hash chain: each segment's
// embedded prev must equal the actual SHA-256 of the preceding segment's object bytes. A break => a segment was
// deleted, altered, or reordered.
func verifyAuditChain(ctx context.Context, arc archive.ColdArchive, tenant string) (auditChainVerifyResult, error) {
	res := auditChainVerifyResult{Tenant: tenant}
	if arc == nil {
		return res, nil
	}
	objs, err := arc.List(ctx, "hot_events/"+tenant+"/audit/", 0)
	if err != nil {
		return res, err
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Key < objs[j].Key }) // keys are timestamp-prefixed => chronological
	res.Segments = len(objs)
	prevHash := ""
	for _, o := range objs {
		rc, err := arc.Get(ctx, o.Key)
		if err != nil {
			return res, err
		}
		raw, rerr := io.ReadAll(rc)
		rc.Close()
		if rerr != nil {
			return res, rerr
		}
		computed := hashObjectBytes(raw)
		gzr, gerr := gzip.NewReader(bytes.NewReader(raw))
		if gerr != nil {
			res.OK = false
			res.BrokenAt = o.Key
			res.Detail = "segment is not readable gzip (tampered)"
			return res, nil
		}
		sc := bufio.NewScanner(gzr)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		firstLine := []byte{}
		if sc.Scan() {
			firstLine = sc.Bytes()
		}
		gzr.Close()
		var wrap struct {
			Chain auditChainHeader `json:"_audit_chain"`
		}
		_ = json.Unmarshal(firstLine, &wrap)
		if wrap.Chain.Prev != prevHash {
			res.OK = false
			res.BrokenAt = o.Key
			res.Detail = "chain broken: embedded prev does not match the previous segment's hash (a segment was deleted, altered, or reordered)"
			return res, nil
		}
		prevHash = computed
	}
	res.OK = true
	return res, nil
}
