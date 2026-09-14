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

// Audit archive segments link to the preceding object's hash. Verification checks
// the listed chain, not completeness against an independently trusted checkpoint.
// A removed suffix or a consistently rewritten chain needs an external anchor to detect.

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
	Status   string `json:"status"`
	Scope    string `json:"scope"`
	Tenant   string `json:"tenant_id"`
	Segments int    `json:"segments"`
	OK       bool   `json:"ok"`
	BrokenAt string `json:"broken_at,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// verifyAuditChain walks a tenant's archived audit segments in order and checks the hash chain: each segment's
// embedded prev must equal the actual SHA-256 of the preceding segment's object bytes. A break => a segment was
// inconsistent with the listed preceding segment. This does not verify a trusted terminal hash.
func verifyAuditChain(ctx context.Context, arc archive.ColdArchive, tenant string) (auditChainVerifyResult, error) {
	res := auditChainVerifyResult{Tenant: tenant, Status: "unavailable", Scope: "listed_segments_only"}
	if arc == nil {
		return res, nil
	}
	objs, err := arc.List(ctx, "hot_events/"+tenant+"/audit/", 0)
	if err != nil {
		return res, err
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Key < objs[j].Key }) // keys are timestamp-prefixed => chronological
	res.Segments = len(objs)
	if len(objs) == 0 {
		res.Status = "empty"
		return res, nil
	}
	res.Status = "broken"
	prevHash := ""
	for index, o := range objs {
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
			res.Detail = "segment is not readable gzip"
			return res, nil
		}
		sc := bufio.NewScanner(gzr)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		scanned := sc.Scan()
		firstLine := append([]byte(nil), sc.Bytes()...)
		// Scanner can retain a read error after returning the first line. Drain
		// the remaining gzip stream as well so trailer truncation/CRC errors count.
		_, drainErr := io.Copy(io.Discard, gzr)
		scanErr := sc.Err()
		gzr.Close()
		if !scanned || scanErr != nil || drainErr != nil {
			res.BrokenAt = o.Key
			res.Detail = "segment gzip stream or header could not be fully read"
			return res, nil
		}
		var wrap struct {
			Chain *struct {
				Seq  *int    `json:"seq"`
				Prev *string `json:"prev"`
			} `json:"_audit_chain"`
		}
		if err := json.Unmarshal(firstLine, &wrap); err != nil || wrap.Chain == nil || wrap.Chain.Seq == nil || wrap.Chain.Prev == nil {
			res.BrokenAt = o.Key
			res.Detail = "segment audit-chain header is missing or invalid"
			return res, nil
		}
		if *wrap.Chain.Seq != index {
			res.BrokenAt = o.Key
			res.Detail = "segment sequence does not match its position in the listed chain"
			return res, nil
		}
		if *wrap.Chain.Prev != prevHash {
			res.OK = false
			res.BrokenAt = o.Key
			res.Detail = "chain broken: embedded prev does not match the previous segment's hash"
			return res, nil
		}
		prevHash = computed
	}
	res.Status = "links_verified"
	res.OK = true
	return res, nil
}
