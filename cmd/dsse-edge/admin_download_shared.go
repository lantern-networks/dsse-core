package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var errDownloadStoreUnavailable = errors.New("download token storage is unavailable; retry later")
var errDownloadTokenAbsent = errors.New("download token is not active")

type downloadSharedUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
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
				err = s.persister.Save(raw)
			}
		}
	}
	if err != nil {
		if errors.Is(err, errDownloadTokenAbsent) {
			return errDownloadTokenAbsent
		}
		return errDownloadStoreUnavailable
	}
	s.tokens, s.loadErr = next, nil
	if s.persister != nil {
		s.known = true
	}
	return nil
}
