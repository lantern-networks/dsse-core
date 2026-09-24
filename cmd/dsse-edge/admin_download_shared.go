package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"log"
	"strings"
	"time"
)

var errDownloadStoreUnavailable = errors.New("download token storage is unavailable; retry later")

// errDownloadNotLeader: storage is fine, but this control plane does not hold the
// write term. "Retry later" was wrong advice: retrying on this node never succeeds.
var errDownloadNotLeader = errors.New("this control plane is not the active one; open the download through the management address")
var errDownloadTokenAbsent = errors.New("download token is not active")

type downloadSharedUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

// Reject inactive bearers before acquiring a CP write lease or opening a write
// transaction. Shared state is read through the pool, not the leader session.
// This is only a preflight: the locked update must still validate and spend the
// token. Returned data is audit metadata, never permission to deliver bytes.
func (s *adminDownloadTokenStore) preflightDownload(ctx context.Context, value string, now time.Time) (adminDownloadToken, error) {
	if s == nil {
		return adminDownloadToken{}, errDownloadStoreUnavailable
	}
	value = strings.TrimSpace(value)
	s.mu.RLock()
	p, known, loadErr := s.persister, s.known, s.loadErr
	token := s.tokens[value]
	s.mu.RUnlock()
	token.Token, token.Payload, token.LocalFilename = "", nil, ""
	if ctx != nil && ctx.Err() != nil {
		return token, errDownloadStoreUnavailable
	}
	if _, shared := p.(downloadSharedUpdater); shared {
		raw, err := p.Load()
		if err != nil {
			return token, errDownloadStoreUnavailable
		}
		tokens, err := decodeDownloadTokens(raw, known)
		if err != nil {
			return token, errDownloadStoreUnavailable
		}
		token = tokens[value]
		token.Token, token.Payload, token.LocalFilename = "", nil, ""
	} else if loadErr != nil {
		return token, errDownloadStoreUnavailable
	}
	expires, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if token.Status != "active" || err != nil || !now.UTC().Before(expires) {
		return adminDownloadToken{}, errDownloadTokenAbsent
	}
	return token, nil
}

func decodeDownloadTokens(raw []byte, known bool) (map[string]adminDownloadToken, error) {
	if len(raw) == 0 {
		if known {
			return nil, fmt.Errorf("known download row is missing")
		}
		return map[string]adminDownloadToken{}, nil
	}
	var tokens map[string]adminDownloadToken
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return nil, err
	}
	if tokens == nil {
		return nil, fmt.Errorf("expected download token object")
	}
	for k, v := range tokens {
		if k == "" || k != v.Token || v.TenantID == "" || v.ExportJobID == "" || (v.Status != "active" && v.Status != "used" && v.Status != "expired") {
			return nil, fmt.Errorf("invalid download token state")
		}
		if _, err := time.Parse(time.RFC3339, v.ExpiresAt); err != nil {
			return nil, err
		}
	}
	return tokens, nil
}

func (s *adminDownloadTokenStore) updateTokens(ctx context.Context, now time.Time, edit func(map[string]adminDownloadToken) error) error {
	if s == nil {
		return errDownloadStoreUnavailable
	}
	ctx = retentionWriteContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	var next map[string]adminDownloadToken
	encode := func(tokens map[string]adminDownloadToken) ([]byte, error) {
		if err := edit(tokens); err != nil {
			return nil, err
		}
		for k, v := range tokens {
			expires, err := time.Parse(time.RFC3339, v.ExpiresAt)
			if err == nil && !now.UTC().Before(expires) {
				delete(tokens, k)
				continue
			}
			if v.Status != "active" {
				v.Payload = nil
				tokens[k] = v
			}
		}
		next = tokens
		return json.Marshal(tokens)
	}
	var err error
	if p, ok := s.persister.(downloadSharedUpdater); ok {
		err = p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			tokens, e := decodeDownloadTokens(raw, s.known)
			if e != nil {
				return nil, e
			}
			return encode(tokens)
		})
	} else {
		if s.loadErr != nil {
			log.Printf("export download token store: refusing writes after a failed load: %v", s.loadErr)
			return errDownloadStoreUnavailable
		}
		if err = ctx.Err(); err == nil {
			detached := make(map[string]adminDownloadToken, len(s.tokens))
			for k, v := range s.tokens {
				v.Payload = bytes.Clone(v.Payload)
				detached[k] = v
			}
			var raw []byte
			raw, err = encode(detached)
			if err == nil && s.persister != nil {
				err = blobstore.UnconfirmedSave(s.persister.Save(raw))
			}
		}
	}
	if err != nil {
		if errors.Is(err, errDownloadTokenAbsent) {
			return errDownloadTokenAbsent
		}
		// Callers answer a fixed "unavailable"; without this line "known row is
		// missing", "invalid token state", a leadership change and a database
		// outage were indistinguishable to an operator. No token value or payload
		// is part of these errors.
		log.Printf("export download token store: save not confirmed: %v", err)
		if errors.Is(err, errCPLeadershipChanged) {
			return errDownloadNotLeader
		}
		return errDownloadStoreUnavailable
	}
	s.tokens, s.loadErr = next, nil
	if s.persister != nil {
		s.known = true
	}
	return nil
}
