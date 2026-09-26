// Package enrolltoken holds the enrolment tokens an administrator issues so a specific machine — and only that
// machine, once — can obtain a device certificate.
//
// It replaces the shared eligibility token, which was one non-expiring secret that had to exist on every machine
// that would ever enrol, named nobody, and let whoever learned it mint unlimited device certificates from
// anywhere. POST /enroll is public and cannot require a client certificate, because it is the endpoint that
// ISSUES the certificate everything else requires, so the credential presented there is the whole of the Day-0
// trust decision.
//
// The credential proves a MACHINE, not a person. An IT admin images a batch of laptops and hands them out later,
// so at install time nobody knows who will use one; requiring a login there fights the actual operation. Identity
// splits by time instead — a token authorises the device at enrolment, and the IdP authenticates the person at
// access, which is where this product already evaluates it. See docs/enrolment_authority_design.ja.md.
//
// What the store holds is deliberately NOT the token: only a SHA-256 of it, so a leak of this state does not
// yield a usable credential. The secret exists exactly once, in the response to Issue, and is never logged.
package enrolltoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Refusal reasons. Consume returns these so an operator's log says what actually happened; the enrolment endpoint
// collapses them into ONE message for the caller, because distinguishing them to an unauthenticated client turns
// a public endpoint into an oracle for which tokens exist and which have been spent.
var (
	ErrStateUnavailable  = errors.New("enrolment token state is unavailable")
	ErrUnknownToken      = errors.New("enrolment token is not recognised")
	ErrTokenUsed         = errors.New("enrolment token has already been used")
	ErrTokenRevoked      = errors.New("enrolment token was revoked")
	ErrTokenExpired      = errors.New("enrolment token has expired")
	ErrWrongTenant       = errors.New("enrolment token belongs to a different tenant")
	ErrOutstandingCap    = errors.New("too many unused enrolment tokens outstanding for this tenant")
	ErrLifetimeTooLong   = errors.New("requested lifetime exceeds the tenant maximum")
	ErrLifetimeNotFuture = errors.New("expiry must be in the future")
)

// Token is the NON-SECRET record of an issued token. It is what the Console lists and what audit reads months
// later, so it answers "which admin authorised this machine, and when" — the question an operator actually has
// when they find a device somewhere it should not be. The secret itself is not in here.
type Token struct {
	ID       string `json:"id"`   // non-secret handle: what the Console shows and revokes by
	Hash     string `json:"hash"` // SHA-256 of the secret, hex. Never the secret.
	TenantID string `json:"tenant_id"`
	Group    string `json:"group,omitempty"` // optional CP-assigned device group for the enrolled device
	Label    string `json:"label,omitempty"` // the admin's own note: which machine, which batch, which site
	IssuedBy string `json:"issued_by"`       // the admin. This is what attribution becomes.
	// IssuedByLabel is WHO that principal was, recorded at issuance rather than resolved later.
	//
	// A principal id resolves to a person only while the account exists. Approvals outlive the people who
	// granted them — that is the ordinary case, not the edge case — and an approval that becomes
	// unattributable the moment somebody leaves the company answers the wrong half of the question this
	// feature exists to answer. Written down at the moment of the act, like every other audit fact.
	IssuedByLabel string `json:"issued_by_label,omitempty"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	UsedAt        string `json:"used_at,omitempty"`
	UsedBy        string `json:"used_by,omitempty"` // the device_id that spent it
	RevokedAt     string `json:"revoked_at,omitempty"`
	RevokedBy     string `json:"revoked_by,omitempty"`
}

// Outstanding reports whether this token could still be spent at the given moment: issued, not used, not revoked,
// not expired. It is the quantity the issuance cap bounds and the one the Console must surface — a pile of
// long-lived unused tokens is the failure mode a variable lifetime introduces, and it is invisible unless counted.
func (t Token) Outstanding(now time.Time) bool {
	return t.UsedAt == "" && t.RevokedAt == "" && !t.expired(now)
}

func (t Token) expired(now time.Time) bool {
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return true // an unparseable expiry is treated as expired: fail closed, never open
	}
	return !now.Before(exp)
}

// Store is the tenant-scoped set of issued tokens.
//
// It persists through a blobstore.Persister for the same reason every other config store in this product does:
// an in-memory-only store loses its contents on restart, and for THIS store that would silently un-spend every
// used token — a one-time credential that resurrects on an Edge restart is not one-time. Durability here is a
// security property, not a convenience.
type Store struct {
	mu         sync.Mutex
	tokens     map[string]Token // by ID
	byHash     map[string]string
	persister  blobstore.Persister
	stateErr   error
	generation atomic.Int64
}

func NewStore() *Store {
	return &Store{tokens: map[string]Token{}, byHash: map[string]string{}}
}

// Generation advances on every mutation so callers can cheaply detect change.
func (s *Store) Generation() int64 { return s.generation.Load() }

// Policy bounds what an admin may ask for. The LIFETIME is chosen per token by the issuer, because the window
// between handing over an installer and the machine actually enrolling ranges from an afternoon at the next desk
// to a courier delivery — a fixed default breaks the shipping case outright. MaxLifetime keeps that choice from
// becoming unbounded when an admin slips or an admin account is taken over, and MaxOutstanding bounds how many
// unspent credentials can exist at once.
type Policy struct {
	MaxLifetime    time.Duration
	MaxOutstanding int
}

// DefaultPolicy is deliberately generous on lifetime and tight on count: 30 days covers shipping a laptop to a
// remote hire, while 200 unspent tokens is far more than a kitting run and far less than a runaway.
func DefaultPolicy() Policy {
	return Policy{MaxLifetime: 30 * 24 * time.Hour, MaxOutstanding: 200}
}

// Issue mints one token and returns the SECRET exactly once — it is not recoverable afterwards, because the store
// keeps only its hash. The caller hands the secret to the installer config and forgets it.
func (s *Store) Issue(policy Policy, tenantID, group, label, issuedBy, issuedByLabel string, expiresAt, now time.Time) (Token, string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Token{}, "", fmt.Errorf("tenant is required")
	}
	if strings.TrimSpace(issuedBy) == "" {
		// Without this the record cannot answer "who authorised this machine", which is the reason it exists.
		return Token{}, "", fmt.Errorf("issuing admin is required")
	}
	if !expiresAt.After(now) {
		return Token{}, "", ErrLifetimeNotFuture
	}
	if policy.MaxLifetime > 0 && expiresAt.Sub(now) > policy.MaxLifetime {
		return Token{}, "", ErrLifetimeTooLong
	}

	secret, err := newSecret()
	if err != nil {
		return Token{}, "", err
	}
	sum := hashSecret(secret)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErr != nil {
		return Token{}, "", s.stateErr
	}
	if policy.MaxOutstanding > 0 && s.outstandingLocked(tenantID, now) >= policy.MaxOutstanding {
		return Token{}, "", ErrOutstandingCap
	}
	id, err := newID()
	if err != nil {
		return Token{}, "", err
	}
	tok := Token{
		ID:            id,
		Hash:          sum,
		TenantID:      tenantID,
		Group:         strings.TrimSpace(group),
		Label:         strings.TrimSpace(label),
		IssuedBy:      strings.TrimSpace(issuedBy),
		IssuedByLabel: strings.TrimSpace(issuedByLabel),
		IssuedAt:      now.UTC().Format(time.RFC3339),
		ExpiresAt:     expiresAt.UTC().Format(time.RFC3339),
	}
	next := s.copyTokensLocked()
	next[id] = tok
	if err := s.commitTokensLocked(next); err != nil {
		return Token{}, "", err
	}
	return tok, secret, nil
}

// Consume spends a token for a specific device. It is the only path that turns a secret into an enrolment, and it
// is atomic: the token is marked used under the same lock that checked it, so two machines racing with a copied
// installer config cannot both win.
//
// It records WHICH device spent it. That is what makes the audit trail complete — the issuing admin on one end,
// the device_id on the other.
func (s *Store) Consume(secret, tenantID, deviceID string, now time.Time) (Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, err := s.verifyLocked(secret, tenantID, now)
	if err != nil {
		return Token{}, err
	}
	return s.spendLocked(tok.ID, deviceID, tenantID, now)
}

// Verify answers "would this token work right now" WITHOUT spending it, so a caller that has further checks to
// run — the enrolment endpoint refuses identities an admin disabled — can find out before burning the credential.
// A token consumed and then refused downstream would leave the admin re-issuing for a device that was never
// going to be admitted.
//
// Verify is not a reservation: another caller can spend the token between Verify and Spend, and Spend says so.
func (s *Store) Verify(secret, tenantID string, now time.Time) (Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyLocked(secret, tenantID, now)
}

// Spend marks a verified token used, atomically. It re-runs every check under the lock rather than trusting the
// earlier Verify, so two machines racing with a copied installer config still yield exactly one enrolment.
func (s *Store) Spend(id, tenantID, deviceID string, now time.Time) (Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spendLocked(id, deviceID, tenantID, now)
}

func (s *Store) verifyLocked(secret, tenantID string, now time.Time) (Token, error) {
	if s.stateErr != nil {
		return Token{}, s.stateErr
	}
	id, ok := s.byHash[hashSecret(secret)]
	if !ok {
		return Token{}, ErrUnknownToken
	}
	return s.checkLocked(id, tenantID, now)
}

func (s *Store) checkLocked(id, tenantID string, now time.Time) (Token, error) {
	if s.stateErr != nil {
		return Token{}, s.stateErr
	}
	tok, ok := s.tokens[id]
	if !ok {
		return Token{}, ErrUnknownToken
	}
	// Order matters for the operator's log, not for the caller: report the most specific true thing.
	if tok.RevokedAt != "" {
		return Token{}, ErrTokenRevoked
	}
	if tok.UsedAt != "" {
		return Token{}, &AlreadyUsedError{UsedBy: tok.UsedBy, UsedAt: tok.UsedAt}
	}
	if tok.expired(now) {
		return Token{}, ErrTokenExpired
	}
	if t := strings.TrimSpace(tenantID); t != "" && !strings.EqualFold(t, tok.TenantID) {
		// One tenant's token must not enrol a device into another, even on an Edge that serves both.
		return Token{}, ErrWrongTenant
	}
	return tok, nil
}

func (s *Store) spendLocked(id, deviceID, tenantID string, now time.Time) (Token, error) {
	tok, err := s.checkLocked(id, tenantID, now)
	if err != nil {
		return Token{}, err
	}
	tok.UsedAt = now.UTC().Format(time.RFC3339)
	tok.UsedBy = strings.TrimSpace(deviceID)
	next := s.copyTokensLocked()
	next[tok.ID] = tok
	if err := s.commitTokensLocked(next); err != nil {
		return Token{}, err
	}
	return tok, nil
}

// Revoke kills an unspent token — the answer to a config file going astray before it was used. Revoking a token
// that was already spent does nothing to the device it enrolled: that device holds a certificate, and taking it
// away is the enrolled-inventory disable and the admission overlay, not this.
func (s *Store) Revoke(id, revokedBy string, now time.Time) (Token, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[strings.TrimSpace(id)]
	if !ok || tok.RevokedAt != "" {
		return Token{}, false
	}
	tok.RevokedAt = now.UTC().Format(time.RFC3339)
	tok.RevokedBy = strings.TrimSpace(revokedBy)
	next := s.copyTokensLocked()
	next[tok.ID] = tok
	if err := s.commitTokensLocked(next); err != nil {
		return Token{}, false
	}
	return tok, true
}

// List returns a tenant's tokens, newest first. Records only — no secret is recoverable from here.
func (s *Store) List(tenantID string) []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		if tenantID == "" || strings.EqualFold(t.TenantID, tenantID) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuedAt != out[j].IssuedAt {
			return out[i].IssuedAt > out[j].IssuedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Outstanding counts tokens that could still be spent. The Console shows this next to the cap so an operator can
// see a backlog of unused credentials building up instead of discovering it when issuance starts failing.
func (s *Store) Outstanding(tenantID string, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outstandingLocked(tenantID, now)
}

func (s *Store) outstandingLocked(tenantID string, now time.Time) int {
	n := 0
	for _, t := range s.tokens {
		if strings.EqualFold(t.TenantID, tenantID) && t.Outstanding(now) {
			n++
		}
	}
	return n
}

// ExpiringWithin lists outstanding tokens that lapse inside the window, so a kitting run is warned before it
// stalls on a dead installer rather than after.
func (s *Store) ExpiringWithin(tenantID string, window time.Duration, now time.Time) []Token {
	cutoff := now.Add(window)
	var out []Token
	for _, t := range s.List(tenantID) {
		if !t.Outstanding(now) {
			continue
		}
		if exp, err := time.Parse(time.RFC3339, t.ExpiresAt); err == nil && exp.Before(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func newSecret() (string, error) {
	// 32 bytes: the token is checked on a public endpoint, so it has to be unguessable on its own merits.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate enrolment token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func newID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}
	return "ent_" + hex.EncodeToString(buf), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:])
}

// Authority is the set of operations the enrolment endpoint and the admin API depend on, so the backing store
// can be swapped without either of them knowing which one is in use.
//
// It exists because ONE of those operations has to be correct across processes and the others do not. Spend is
// what makes a token one-time, and the in-memory Store below can only guarantee that within a single Edge: it
// loads its persister once at boot and mutates a copy, so two Edges sharing a blob store would each hold their
// own idea of what has been spent and could both honour the same token. A deployment with more than one Edge
// therefore needs a backend whose spend is a single conditional write — see the Postgres implementation in
// cmd/edge. This interface is the seam that lets it be chosen at boot rather than assumed.
type Authority interface {
	Issue(policy Policy, tenantID, group, label, issuedBy, issuedByLabel string, expiresAt, now time.Time) (Token, string, error)
	Verify(secret, tenantID string, now time.Time) (Token, error)
	Spend(id, tenantID, deviceID string, now time.Time) (Token, error)
	Revoke(id, revokedBy string, now time.Time) (Token, bool)
	List(tenantID string) []Token
	Outstanding(tenantID string, now time.Time) int
	ExpiringWithin(tenantID string, window time.Duration, now time.Time) []Token
}

// The in-memory store satisfies it, for single-Edge deployments.
var _ Authority = (*Store)(nil)

// NewSecret and HashSecret are exported so a store implemented elsewhere (cmd/edge's Postgres one) mints and
// looks up tokens exactly the same way. Two implementations that hashed differently would silently refuse each
// other's tokens across a migration.
func NewSecret() (string, error)      { return newSecret() }
func HashSecret(secret string) string { return hashSecret(secret) }
func NewID() (string, error)          { return newID() }

// CountForTenant / RemoveTenant put enrolment tokens into a tenant's data footprint and its erasure
// (2026-08-18). A token is a credential that admits a device INTO this organization; leaving one behind after
// the organization is gone is an admission path outliving the thing it admits to. The Postgres backend's rows
// are already counted as a table — this covers the file/blob backend, which nothing counted.
//
// The hash index is rebuilt from what survives rather than edited in place: two maps that disagree about which
// tokens exist is how a revoked credential keeps working.
func (s *Store) CountForTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.tokens {
		if strings.EqualFold(strings.TrimSpace(t.TenantID), tenantID) {
			n++
		}
	}
	return n
}

func (s *Store) RemoveTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.copyTokensLocked()
	n := 0
	for id, t := range s.tokens {
		if strings.EqualFold(strings.TrimSpace(t.TenantID), tenantID) {
			delete(next, id)
			n++
		}
	}
	if n == 0 {
		return 0
	}
	if err := s.commitTokensLocked(next); err != nil {
		return 0
	}
	return n
}

// AlreadyUsedError is ErrTokenUsed with the two facts that make it actionable: which machine spent this token
// and when.
//
// ★★★ "ALREADY BEEN USED" DOES NOT SAY WHOSE (2026-09-01, an hour lost on a real Mac).
//
// A one-time token was written into an organization's handoff directory, and that directory was handed to two
// machines. The second could never enrol, and the deployment said, every time:
//
//	enroll_refused mode=token device="ShinnoMac-mini" reason="enrolment token has already been used"
//
// which is true and unusable. The obvious reading is "the token I just issued was somehow consumed", so the
// answer looked like issuing another — and the control plane meanwhile showed that token unused, because the
// machine was still sending a DIFFERENT one, spent by a DIFFERENT machine, days of debugging apart.
//
// The record has both facts already. Saying them turns the hour into one line. This is the operator's log, not
// the wire: /enroll keeps handing the caller its single sentence, so a machine holding a copied token still
// learns nothing about the fleet — see the split at the refusal site in enroll_endpoint.go.
type AlreadyUsedError struct {
	UsedBy string // the device_id that spent it
	UsedAt string // RFC3339
}

func (e *AlreadyUsedError) Error() string {
	who := strings.TrimSpace(e.UsedBy)
	if who == "" {
		who = "a machine this record does not name"
	} else {
		who = strconv.Quote(who)
	}
	when := strings.TrimSpace(e.UsedAt)
	if when != "" {
		when = " at " + when
	}
	return ErrTokenUsed.Error() + ", by device " + who + when +
		" — a token is one machine, once, so this machine needs one issued for it"
}

// Unwrap keeps every existing errors.Is(err, ErrTokenUsed) working: the sentinel is what callers branch on and
// this only adds the detail beside it.
func (e *AlreadyUsedError) Unwrap() error { return ErrTokenUsed }
