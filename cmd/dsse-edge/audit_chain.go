package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	operationMu sync.Mutex // Serialize archive/advance within this process.
	mu          sync.Mutex
	stateErr    error
	per         map[string]auditChainState // tenant -> running chain state
	persister   blobstore.Persister
}

func newAuditChainStore(p blobstore.Persister) *auditChainStore {
	s := &auditChainStore{per: map[string]auditChainState{}, persister: p}
	if p == nil {
		return s
	}
	data, err := p.Load()
	if err != nil {
		s.stateErr = fmt.Errorf("audit chain state could not be loaded")
		log.Printf("audit-chain store load: %v", err)
		return s
	}
	if len(data) == 0 {
		return s
	}
	loaded, err := decodeAuditChainState(data)
	if err != nil {
		s.stateErr = fmt.Errorf("audit chain state could not be loaded")
		log.Printf("audit-chain store parse: %v", err)
	} else {
		s.per = loaded
	}

	return s
}

func decodeAuditChainState(data []byte) (map[string]auditChainState, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("expected chain state object")
	}
	result := map[string]auditChainState{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		tenant, ok := token.(string)
		if !ok || tenant == "" {
			return nil, fmt.Errorf("invalid chain tenant")
		}
		if _, exists := result[tenant]; exists {
			return nil, fmt.Errorf("duplicate chain tenant")
		}
		var state struct {
			Seq      *int    `json:"seq"`
			LastHash *string `json:"last_hash"`
		}
		if err := d.Decode(&state); err != nil {
			return nil, err
		}
		if state.Seq == nil || state.LastHash == nil || *state.Seq < 0 {
			return nil, fmt.Errorf("invalid chain state")
		}
		hash, err := hex.DecodeString(*state.LastHash)
		if (*state.Seq == 0 && *state.LastHash != "") || (*state.Seq > 0 && (err != nil || len(hash) != sha256.Size)) {
			return nil, fmt.Errorf("invalid chain hash")
		}
		result[tenant] = auditChainState{Seq: *state.Seq, LastHash: *state.LastHash}
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing chain state data")
	}
	return result, nil
}

func (s *auditChainStore) Health() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stateErr
}

// Next returns the seq + prev-hash to embed in the tenant's next audit segment.
func (s *auditChainStore) Next(tenant string) (int, string, error) {
	if s == nil {
		return 0, "", fmt.Errorf("audit chain state is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErr != nil {
		return 0, "", s.stateErr
	}
	st := s.per[tenant]
	return st.Seq, st.LastHash, nil
}

// Commit records that the segment with this seq + hash was successfully written, advancing the chain.
func (s *auditChainStore) Commit(tenant string, seq int, hash string) error {
	if s == nil {
		return fmt.Errorf("audit chain state is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErr != nil {
		return s.stateErr
	}
	if s.per[tenant].Seq != seq {
		s.stateErr = fmt.Errorf("audit chain generation changed; reconciliation required")
		return s.stateErr
	}
	next := make(map[string]auditChainState, len(s.per)+1)
	for key, state := range s.per {
		next[key] = state
	}
	next[tenant] = auditChainState{Seq: seq + 1, LastHash: hash}
	if s.persister != nil {
		data, err := json.Marshal(next)
		if err == nil {
			err = s.persister.Save(data)
		}
		if err != nil {
			// The object already exists. Retrying with the old head could create a fork.
			s.stateErr = fmt.Errorf("audit chain state save failed; reconciliation required")
			log.Printf("audit-chain state save: %v", err)
			return s.stateErr
		}
	}
	s.per = next
	return nil
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
