package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type Store struct {
	mu       sync.RWMutex
	sessions map[string]model.Session
}

func NewStore() *Store {
	return &Store{sessions: map[string]model.Session{}}
}

func (s *Store) CreateFromAuthenticationEvent(event model.AuthenticationEvent, policyBundleID, expectedTenantID string, now time.Time) (model.Session, error) {
	if event.ID == "" {
		return model.Session{}, fmt.Errorf("authentication event id is required")
	}
	if event.SessionID == "" {
		return model.Session{}, fmt.Errorf("authentication event session_id is required")
	}
	if event.TenantID == "" {
		return model.Session{}, fmt.Errorf("authentication event tenant_id is required")
	}
	if expectedTenantID != "" && event.TenantID != expectedTenantID {
		return model.Session{}, fmt.Errorf("authentication event tenant_id %s does not match edge tenant_id %s", event.TenantID, expectedTenantID)
	}
	if event.UserID == "" {
		return model.Session{}, fmt.Errorf("authentication event user_id is required")
	}
	// A session may be minted only from an EXPLICITLY successful authentication (fail-open review #16). The old
	// check allowed an EMPTY result to create an active session — an auth event that proved nothing (e.g. an
	// external POST /auth/events with no result) silently became a live session. Require result == "success";
	// empty or any non-success value is surfaced as an error. Every internal caller already sets "success".
	if event.Result != "success" {
		return model.Session{}, fmt.Errorf("authentication event result %q is not success — cannot create an active session", event.Result)
	}

	createdAt := valueOrDefault(event.Timestamp, now.UTC().Format(time.RFC3339))
	expiresAt := ""
	if event.ExpiresAt != nil {
		expiresAt = *event.ExpiresAt
	}
	if expiresAt == "" {
		expiresAt = now.UTC().Add(time.Hour).Format(time.RFC3339)
	}
	metadata := map[string]any{"mfa_state": event.MFAState, "idp_id": event.IDPID, "auth_time": event.AuthTime, "auth_method": event.Method}
	if len(event.AMR) > 0 {
		metadata["amr"] = event.AMR
	}
	if event.ACR != nil {
		metadata["acr"] = *event.ACR
	}
	if event.Metadata != nil {
		for _, key := range []string{"issuer", "email", "groups", "break_glass_request_id", "break_glass_reason", "ticket_id"} {
			if value, ok := event.Metadata[key]; ok {
				metadata[key] = value
			}
		}
	}
	session := model.Session{
		ID:                    event.SessionID,
		TenantID:              event.TenantID,
		UserID:                event.UserID,
		SubjectUserID:         event.SubjectUserID,
		DeviceID:              event.DeviceID,
		AuthenticationEventID: event.ID,
		PolicyBundleID:        policyBundleID,
		CreatedAt:             createdAt,
		ExpiresAt:             expiresAt,
		LastActiveAt:          createdAt,
		Status:                "active",
		Metadata:              metadata,
	}

	s.mu.Lock()
	s.sessions[session.ID] = session
	s.mu.Unlock()
	return session, nil
}

func (s *Store) Get(id string) (model.Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	return session, ok
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
