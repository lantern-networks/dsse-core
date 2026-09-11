package eastwest

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// east_west_auth_challenge: E2 of the east-west per-hop authorization design. When the decision engine
// returns "authenticate_required" for an east-west flow, the Edge HOLDS the flow -- it does NOT dial the
// upstream destination -- and records a pending authentication challenge bound to (identity x device x
// destination x protocol). The out-of-band browser ceremony (E4) completes the challenge and an ephemeral
// grant (E3) is issued against it to release the flow. Per the design, the AUTHORITATIVE hold is on the
// Edge (the only bypass-resistant chokepoint that reaches the destination); the endpoint is untrusted, so
// release authority must not live there.

// AuthChallengeTTL is how long a held flow waits for the user to complete the ceremony before the
// challenge expires (the ceremony-completion window, NOT the resulting grant TTL).
const AuthChallengeTTL = 5 * time.Minute

// RequiresAuthentication reports whether a decision value means "hold the flow pending an
// interactive authentication ceremony" (east-west authenticate mode).
func RequiresAuthentication(decisionValue string) bool {
	return decisionValue == "authenticate_required"
}

type AuthChallenge struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	SubjectUserID string `json:"subject_user_id"`
	DeviceID      string `json:"device_id"`
	Destination   string `json:"destination"`
	ApplicationID string `json:"application_id"`
	Protocol      string `json:"protocol"`
	Status        string `json:"status"` // pending | completed | expired
	CreatedAt     string `json:"created_at"`
	ExpiresAt     string `json:"expires_at"`
}

// BuildAuthChallenge binds a held flow to the identity/device/destination/protocol it was held
// for. Pure: the store assigns the ID, timestamps, and status on Create. The device binding uses the
// AUTHORITATIVE identity (transport-bound when present, else the claim — decision.AuthoritativeDeviceIdentity):
// the resulting grant must be bound to the device that actually held the flow, not to a DeviceID the client
// typed into its request — otherwise completing a ceremony mints a grant for a spoofed device.
func BuildAuthChallenge(req model.DecisionRequest) AuthChallenge {
	return AuthChallenge{
		TenantID:      strings.TrimSpace(req.TenantID),
		SubjectUserID: strings.TrimSpace(valueOrDefault(req.SubjectUserID, req.UserID)),
		DeviceID:      decision.AuthoritativeDeviceIdentity(req),
		Destination:   strings.TrimSpace(valueOrDefault(req.Destination, req.ApplicationID)),
		ApplicationID: strings.TrimSpace(req.ApplicationID),
		Protocol:      strings.ToLower(strings.TrimSpace(req.ServiceFamily)),
	}
}

// AuthChallengeResponse is the 401 body returned to the held client/agent. It carries the
// challenge id and the OOB ceremony entry point (the agent opens this in a browser, E4). Non-secret.
type AuthChallengeResponse struct {
	SchemaVersion       string `json:"schema_version"`
	Decision            string `json:"decision"`
	ChallengeID         string `json:"challenge_id"`
	Destination         string `json:"destination"`
	Protocol            string `json:"protocol"`
	CeremonyURL         string `json:"ceremony_url"`
	ExpiresAt           string `json:"expires_at"`
	NoSecretAttestation bool   `json:"no_secret_attestation"`
}

type AuthChallengeStore struct {
	mu         sync.RWMutex
	challenges map[string]AuthChallenge
}

func NewAuthChallengeStore() *AuthChallengeStore {
	return &AuthChallengeStore{challenges: map[string]AuthChallenge{}}
}

func newID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "ewc_fallback"
	}
	return "ewc_" + hex.EncodeToString(buf)
}

// Create assigns an id/timestamps/status and stores the challenge, returning the stored value.
func (s *AuthChallengeStore) Create(challenge AuthChallenge, now time.Time) AuthChallenge {
	challenge.ID = newID()
	challenge.Status = "pending"
	challenge.CreatedAt = now.UTC().Format(time.RFC3339)
	challenge.ExpiresAt = now.UTC().Add(AuthChallengeTTL).Format(time.RFC3339)
	if s == nil {
		return challenge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[challenge.ID] = challenge
	return challenge
}

// Complete marks a pending challenge completed (its ceremony resolved and a grant was issued). Returns
// the completed challenge and whether it was a pending, non-expired challenge.
func (s *AuthChallengeStore) Complete(id string, now time.Time) (AuthChallenge, bool) {
	if s == nil {
		return AuthChallenge{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[strings.TrimSpace(id)]
	if !ok || c.Status != "pending" {
		return AuthChallenge{}, false
	}
	if expiresAt, err := time.Parse(time.RFC3339, c.ExpiresAt); err == nil && now.After(expiresAt) {
		return AuthChallenge{}, false
	}
	c.Status = "completed"
	s.challenges[c.ID] = c
	return c, true
}

func (s *AuthChallengeStore) Get(id string) (AuthChallenge, bool) {
	if s == nil {
		return AuthChallenge{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.challenges[strings.TrimSpace(id)]
	return c, ok
}

// ListPending returns the still-pending, non-expired challenges for a tenant.
func (s *AuthChallengeStore) ListPending(tenantID string, now time.Time) []AuthChallenge {
	out := []AuthChallenge{}
	if s == nil {
		return out
	}
	tenantID = strings.TrimSpace(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.challenges {
		if c.TenantID != tenantID || c.Status != "pending" {
			continue
		}
		if expiresAt, err := time.Parse(time.RFC3339, c.ExpiresAt); err == nil && now.After(expiresAt) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func (s *AuthChallengeStore) Count() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.challenges)
}

// valueOrDefault returns value, or fallback when value is empty — package-local copy of the shared helper.
func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
