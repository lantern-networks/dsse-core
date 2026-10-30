package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// A result describes the original held TCP flow, not the browser ceremony. In
// particular, a callback or a minted grant never creates a resumed result.
type authFlowResult struct {
	RequestID string `json:"request_id"`
	TenantID  string `json:"tenant_id"`
	DeviceID  string `json:"device_id"`
	Principal string `json:"os_principal"`
	Session   string `json:"os_session"`
	Result    string `json:"result"`
	FinalAt   int64  `json:"final_at"`
	ExpiresAt int64  `json:"expires_at"`
}

const authFlowResultTTL = 10 * time.Minute
const authFlowResultLimit = 4096

var errAuthFlowResultConflict = errors.New("authentication flow result conflicts with an existing final result")

func validAuthResultRequestID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, ch := range id {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

type authResultUpdater interface {
	Load() ([]byte, error)
	Update(func([]byte) ([]byte, error)) error
}

// The in-memory variant supports standalone nodes and deterministic tests. A
// production CP uses postgresAuthResultStore and its per-request rows instead.
// restart-durability: ephemeral — standalone/test results become unknown after restart; production uses postgresAuthResultStore.
// populated-by: side_effect — only a held native flow's timeout/refusal or post-authorization upstream connection finalizes one.
type authResultLedger struct {
	mu      sync.Mutex
	rows    map[string]authFlowResult
	storage authResultUpdater
	clock   func() time.Time
}

func newAuthResultLedger(storage authResultUpdater) *authResultLedger {
	return &authResultLedger{rows: make(map[string]authFlowResult), storage: storage, clock: time.Now}
}

func validAuthFlowResult(r authFlowResult, now time.Time) bool {
	return validAuthResultRequestID(r.RequestID) && r.TenantID != "" && r.DeviceID != "" &&
		validAuthOwner(r.Principal, r.Session) &&
		(r.Result == "resumed" || r.Result == "not_resumed") &&
		r.FinalAt > 0 && r.FinalAt <= now.Unix()+30 &&
		r.ExpiresAt == r.FinalAt+int64(authFlowResultTTL/time.Second) &&
		now.Unix() < r.ExpiresAt
}

func decodeAuthFlowResults(raw []byte) (map[string]authFlowResult, error) {
	if len(raw) == 0 {
		return make(map[string]authFlowResult), nil
	}
	var rows map[string]authFlowResult
	if err := json.Unmarshal(raw, &rows); err != nil || rows == nil {
		return nil, fmt.Errorf("invalid authentication result ledger")
	}
	return rows, nil
}

func (l *authResultLedger) Record(r authFlowResult) error {
	if l == nil {
		return errors.New("authentication result ledger unavailable")
	}
	now := l.clock().UTC()
	if !validAuthFlowResult(r, now) {
		return errors.New("invalid authentication result")
	}
	insert := func(rows map[string]authFlowResult) error {
		for id, old := range rows {
			if old.ExpiresAt <= now.Unix() {
				delete(rows, id)
			}
		}
		if old, exists := rows[r.RequestID]; exists {
			if old == r {
				return nil
			}
			return errAuthFlowResultConflict
		}
		activeForTenant := 0
		for _, old := range rows {
			if old.TenantID == r.TenantID {
				activeForTenant++
			}
		}
		if activeForTenant >= authFlowResultLimit {
			return errors.New("authentication result ledger is full")
		}
		rows[r.RequestID] = r
		return nil
	}
	if l.storage != nil {
		return l.storage.Update(func(raw []byte) ([]byte, error) {
			rows, err := decodeAuthFlowResults(raw)
			if err != nil {
				return nil, err
			}
			if err := insert(rows); err != nil {
				return nil, err
			}
			return json.Marshal(rows)
		})
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return insert(l.rows)
}

// Lookup gives the same opaque miss for an absent ID, an expired result, and
// every mismatched tenant/device/login. Request IDs are never bearer tokens.
func (l *authResultLedger) Lookup(requestID, tenantID, deviceID, principal, session string) (string, error) {
	if l == nil {
		return "", errors.New("authentication result ledger unavailable")
	}
	if !validAuthResultRequestID(requestID) || tenantID == "" || deviceID == "" || !validAuthOwner(principal, session) {
		return "", nil
	}
	var rows map[string]authFlowResult
	if l.storage != nil {
		raw, err := l.storage.Load()
		if err != nil {
			return "", err
		}
		rows, err = decodeAuthFlowResults(raw)
		if err != nil {
			return "", err
		}
	} else {
		l.mu.Lock()
		defer l.mu.Unlock()
		rows = l.rows
	}
	r, ok := rows[requestID]
	if !ok || l.clock().Unix() >= r.ExpiresAt || r.TenantID != tenantID || r.DeviceID != deviceID ||
		r.Principal != principal || r.Session != session {
		return "", nil
	}
	return r.Result, nil
}
