package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// First-party admin account onboarding + auth (proprietary control plane). The SaaS issues admin credentials
// itself: an owner invites by email -> single-use short-lived activation link -> the user sets a password and
// enrolls TOTP 2FA -> steady-state login is email + password + TOTP. Coexists with per-tenant IdP federation.
// See docs/admin_first_party_account_onboarding_design.md.

const (
	credentialStatusPending   = "pending_activation"
	credentialStatusActive    = "active"
	credentialStatusSuspended = "suspended"

	totpDigits       = 6
	totpPeriod       = 30 // seconds
	totpSkewSteps    = 1  // accept the previous/next step (clock skew)
	maxFailedLogins  = 5
	loginLockWindow  = 15 * time.Minute
	activationTTL    = 24 * time.Hour
	recoveryCodes    = 8
	minPasswordChars = 12

	// productionBcryptCost is what a real deployment hashes with. 12 is the number under review, and it is a
	// CONSTANT so that the test override below cannot move it: the risk of making hashing cheap for tests is
	// that it quietly becomes cheap for everyone, and that failure has no symptom until someone dumps the
	// store.
	productionBcryptCost = 12
)

// bcryptCost is the cost actually used. A var, and the only reason is the local CI gate.
//
// ★ MEASURED, 2026-08-10: cmd/edge's test suite took ~50 s of a push, and ~41 s of that was nine tests in the
// admin-account and credential paths — each of them hashing passwords at cost 12, which is ~0.3 s a hash by
// design. Those nine were the dominant cost of the pre-push gate on nearly every push, because oss is a
// dependency of main and any oss change invalidates this package's cached results.
//
// Lowering it for tests loses no coverage: not one of those tests asserts anything about how EXPENSIVE the
// hash is. What they exercise is the lifecycle around it. The one property that would be lost — that
// production hashes at a real cost — is asserted directly instead, by a test on productionBcryptCost, which
// is the honest place for it.
var bcryptCost = productionBcryptCost

// --- TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30s period) -----------------------------------------------------

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newTOTPSecret returns a fresh base32 TOTP shared secret (160 bits).
func newTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return totpBase32.EncodeToString(buf), nil
}

// totpCodeAt computes the TOTP code for a secret at a unix time-step counter.
func totpCodeForCounter(secret string, counter uint64) (string, error) {
	key, err := totpBase32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("invalid totp secret")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) | (uint32(sum[offset+1]) << 16) | (uint32(sum[offset+2]) << 8) | uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod), nil
}

// totpVerify checks a code against the secret, tolerating +/- totpSkewSteps of clock skew. It returns the
// time-step counter the code matched (so the caller can record it for replay protection, RFC 6238) and
// whether any step matched. The returned counter is meaningful only when ok is true.
func totpVerify(secret, code string, now time.Time) (matched uint64, ok bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	counter := uint64(now.Unix()) / totpPeriod
	for d := -totpSkewSteps; d <= totpSkewSteps; d++ {
		step := counter + uint64(d)
		want, err := totpCodeForCounter(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// totpProvisioningURI builds the otpauth:// URI a TOTP authenticator app imports (rendered as a QR client-side).
func totpProvisioningURI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// --- password ---------------------------------------------------------------------------------------------

func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func passwordMatches(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// validatePasswordPolicy enforces a minimal password policy (length; not the email/local-part).
func validatePasswordPolicy(pw, email string) error {
	if len(pw) < minPasswordChars {
		return fmt.Errorf("password must be at least %d characters", minPasswordChars)
	}
	if strings.EqualFold(strings.TrimSpace(pw), strings.TrimSpace(email)) {
		return fmt.Errorf("password must not equal the email address")
	}
	return nil
}

// --- credential + store -----------------------------------------------------------------------------------

type localAdminCredential struct {
	PrincipalID         string
	TenantID            string
	Email               string
	Roles               []string
	Status              string
	PasswordHash        string
	TOTPSecret          string
	TOTPEnrolled        bool
	RecoveryCodeHashes  []string
	FailedAttempts      int
	LockedUntil         time.Time
	ActivationTokenHash string
	ActivationExpiresAt time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	// LastLoginAt is updated on a successful second-factor login. Best-effort, in-memory only (not a durable
	// column): it is surfaced in the Administrators view and resets to zero on a control-plane restart.
	LastLoginAt time.Time
	// LastTOTPCounter is the TOTP time-step of the most recently CONSUMED code (RFC 6238 replay
	// protection): a code whose matched step is <= this is rejected as a replay, so a captured 6-digit code
	// cannot be reused within its ~90s validity window. In-memory only (like LastLoginAt) — a control-plane
	// restart resets it, which at worst re-opens the current 90s window once; the durable cost of a column +
	// migration is not worth that bounded, restart-only gap.
	LastTOTPCounter uint64
}

func (c *localAdminCredential) locked(now time.Time) bool {
	return !c.LockedUntil.IsZero() && now.Before(c.LockedUntil)
}

// credentialPersistence is an optional durable backing store. When set, the in-memory store loads all
// credentials on startup and write-through mirrors every mutation so accounts survive a restart. Implemented
// by postgresCredentialPersistence on the control plane (admin auth authority).
type credentialPersistence interface {
	LoadAll(ctx context.Context) ([]*localAdminCredential, error)
	Upsert(ctx context.Context, cred *localAdminCredential) error
	// Delete removes a credential durably. Tenant-scoped so a delete can never reach across tenants.
	Delete(ctx context.Context, tenantID, email string) error
}

// localAdminCredentialStore is the first-party admin credential store. Concurrency-safe. `issuer` labels the
// TOTP otpauth URI. `persistence` (optional) makes it durable across restarts.
type localAdminCredentialStore struct {
	mu          sync.Mutex
	byEmail     map[string]*localAdminCredential
	issuer      string
	persistence credentialPersistence
}

func newLocalAdminCredentialStore(issuer string) *localAdminCredentialStore {
	if strings.TrimSpace(issuer) == "" {
		issuer = "Lantern DSSE"
	}
	return &localAdminCredentialStore{byEmail: map[string]*localAdminCredential{}, issuer: issuer}
}

// newLocalAdminCredentialStoreWithPersistence builds a store backed by a durable persistence layer, loading
// any previously-persisted credentials so a restart preserves accounts. persistence may be nil (in-memory).
func newLocalAdminCredentialStoreWithPersistence(issuer string, persistence credentialPersistence) (*localAdminCredentialStore, error) {
	s := newLocalAdminCredentialStore(issuer)
	s.persistence = persistence
	if persistence != nil {
		creds, err := persistence.LoadAll(context.Background())
		if err != nil {
			return nil, fmt.Errorf("load persisted admin credentials: %w", err)
		}
		for _, c := range creds {
			s.byEmail[credentialEmailKey(c.Email)] = c
		}
		log.Printf("first-party admin credentials: loaded %d account(s) from the durable store", len(creds))
	}
	return s, nil
}

var errCredentialPersistence = fmt.Errorf("admin credential storage is unavailable")

// persistLocked publishes a candidate only after the durable store accepts it.
// Authentication failure counters may already be in memory: keep those restrictions
// even during an outage, but never issue a successful login after a failed save.
func (s *localAdminCredentialStore) persistLocked(cred *localAdminCredential) error {
	if s.persistence != nil {
		if err := s.persistence.Upsert(context.Background(), cred); err != nil {
			log.Printf("admin credential persistence failed: %v", err)
			return errCredentialPersistence
		}
	}
	s.byEmail[credentialEmailKey(cred.Email)] = cred
	return nil
}

func credentialEmailKey(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func randomToken(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return totpBase32.EncodeToString(buf), nil
}

// Invite creates (or re-invites) a pending admin credential for an email and returns a single-use activation
// token (the raw token is returned once; only its hash is stored).
// errCredentialBelongsToAnotherTenant reports an invite for an address that is already an administrator
// somewhere else. Distinct so the route can answer 409 (a collision the caller can see and reason about)
// rather than 400 (a malformed request, which it is not) — and so that no caller can mistake it for
// "the invite failed, try again".
var errCredentialBelongsToAnotherTenant = fmt.Errorf("this email address is already an administrator in another organization")

func (s *localAdminCredentialStore) Invite(email, tenantID, principalID string, roles []string, now time.Time) (string, error) {
	key := credentialEmailKey(email)
	if key == "" || !strings.Contains(key, "@") {
		return "", fmt.Errorf("a valid email is required")
	}
	rawToken, err := randomToken(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cred := cloneCredential(s.byEmail[key])
	// ★ AN EMAIL BELONGS TO A TENANT, AND AN INVITE MAY NOT MOVE IT (2026-08-15). This wrote the caller's
	// tenant, roles and a blank password over whatever was already here, so inviting an address that already
	// belonged to ANOTHER organization silently moved that administrator into the caller's: same principal,
	// new tenant, password erased, roles replaced, and a 201 saying it worked. Measured on the lab, both
	// directions. Inviting roles:["admin"] does not require admin.tenant.admin, so an ordinary tenant admin
	// could do it knowing nothing but the address.
	//
	// Refused HERE rather than in the route, because the route is not the only way in and the next caller
	// would open the same hole again. Re-inviting an address that is already in THIS tenant stays allowed —
	// that is how a lost activation link is reissued.
	if cred != nil && cred.TenantID != "" && !strings.EqualFold(strings.TrimSpace(cred.TenantID), strings.TrimSpace(tenantID)) {
		return "", errCredentialBelongsToAnotherTenant
	}
	if cred == nil {
		cred = &localAdminCredential{Email: key, CreatedAt: now.UTC()}
	}
	cred.TenantID = tenantID
	// ★★★ A RE-INVITE REISSUES A LINK; IT DOES NOT MAKE A NEW PERSON (2026-08-20, measured on the lab — and
	// this is the cause of a GOTCHA that had been written down as a rule to work around).
	//
	// Re-inviting an address already in this organization is deliberately allowed: it is how a lost activation
	// link is reissued. But it also overwrote the principal id with a freshly minted one, while the principal
	// ALREADY RECORDED for that person keeps the old one. Their identity in this system is (organization, IdP,
	// subject) — the database says so with a unique index on exactly those three — so the next sign-in tried to
	// insert a SECOND principal for the same person, the index refused, and the customer's screen showed
	//
	//     pq: duplicate key value violates unique constraint "admin_principals_subject_unique_idx"
	//
	// From then on that administrator could never sign in again. Measured on a real customer account
	// (tenant_acme) while setting up a cross-tenant isolation run: two ids for one person, an invite apart.
	if strings.TrimSpace(cred.PrincipalID) == "" {
		cred.PrincipalID = principalID
	}
	cred.Roles = append([]string(nil), roles...)
	cred.Status = credentialStatusPending
	cred.PasswordHash = ""
	cred.TOTPSecret = ""
	cred.TOTPEnrolled = false
	cred.FailedAttempts = 0
	cred.LockedUntil = time.Time{}
	cred.ActivationTokenHash = adminTokenHash(rawToken)
	cred.ActivationExpiresAt = now.UTC().Add(activationTTL)
	cred.UpdatedAt = now.UTC()
	if err := s.persistLocked(cred); err != nil {
		return "", err
	}
	return rawToken, nil
}

// credentialForActivation returns the pending credential a valid, unexpired activation token refers to.
func (s *localAdminCredentialStore) credentialForActivation(rawToken string, now time.Time) (*localAdminCredential, error) {
	hash := adminTokenHash(strings.TrimSpace(rawToken))
	for _, cred := range s.byEmail {
		if cred.ActivationTokenHash != "" && subtle.ConstantTimeCompare([]byte(cred.ActivationTokenHash), []byte(hash)) == 1 {
			if now.After(cred.ActivationExpiresAt) {
				return nil, fmt.Errorf("activation link has expired")
			}
			return cred, nil
		}
	}
	return nil, fmt.Errorf("activation link is invalid")
}

// ActivationEmail returns the email an activation token is for (for the activation form).
func (s *localAdminCredentialStore) ActivationEmail(rawToken string, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, err := s.credentialForActivation(rawToken, now)
	if err != nil {
		return "", err
	}
	return cred.Email, nil
}

// activationAuditTarget copies only the account identifiers of a valid activation token.
// The bearer is not yet an authenticated administrator; this identifies the target, not the actor.
func (s *localAdminCredentialStore) activationAuditTarget(token string, now time.Time) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, err := s.credentialForActivation(token, now)
	if err != nil {
		return "", ""
	}
	return cred.TenantID, cred.PrincipalID
}

// SetActivationPassword sets the password during activation (policy enforced).
func (s *localAdminCredentialStore) SetActivationPassword(rawToken, newPassword string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, err := s.credentialForActivation(rawToken, now)
	if err != nil {
		return err
	}
	cred = cloneCredential(cred)
	if err := validatePasswordPolicy(newPassword, cred.Email); err != nil {
		return err
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	cred.PasswordHash = hash
	cred.UpdatedAt = now.UTC()
	if err := s.persistLocked(cred); err != nil {
		return err
	}
	return nil
}

// BeginTOTPEnrollment generates (and stores, not-yet-enrolled) a TOTP secret and returns the otpauth URI.
func (s *localAdminCredentialStore) BeginTOTPEnrollment(rawToken string, now time.Time) (secret, uri string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, err := s.credentialForActivation(rawToken, now)
	if err != nil {
		return "", "", err
	}
	cred = cloneCredential(cred)
	if cred.PasswordHash == "" {
		return "", "", fmt.Errorf("set a password before enrolling 2FA")
	}
	secret, err = newTOTPSecret()
	if err != nil {
		return "", "", err
	}
	cred.TOTPSecret = secret
	cred.TOTPEnrolled = false
	cred.UpdatedAt = now.UTC()
	if err := s.persistLocked(cred); err != nil {
		return "", "", err
	}
	return secret, totpProvisioningURI(secret, cred.Email, s.issuer), nil
}

// CompleteActivation verifies the first TOTP code, marks the account active, consumes the activation token,
// and returns one-time recovery codes.
func (s *localAdminCredentialStore) CompleteActivation(rawToken, code string, now time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, err := s.credentialForActivation(rawToken, now)
	if err != nil {
		return nil, err
	}
	cred = cloneCredential(cred)
	if cred.PasswordHash == "" || cred.TOTPSecret == "" {
		return nil, fmt.Errorf("set a password and start 2FA enrollment first")
	}
	if _, ok := totpVerify(cred.TOTPSecret, code, now); !ok {
		return nil, fmt.Errorf("the 2FA code is incorrect")
	}
	// NOTE: the consumed step is deliberately NOT recorded here. CompleteActivation is already single-use
	// via the activation token (consumed below), and recording would reject the legitimate "enroll then
	// immediately log in with the current code" flow. Replay protection lives on the login path (VerifyTOTP),
	// where the FIRST login records the counter and every later reuse of that code is rejected.
	plain := make([]string, 0, recoveryCodes)
	hashes := make([]string, 0, recoveryCodes)
	for i := 0; i < recoveryCodes; i++ {
		raw, err := randomToken(8)
		if err != nil {
			return nil, err
		}
		plain = append(plain, raw)
		h, err := hashPassword(raw)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	cred.TOTPEnrolled = true
	cred.RecoveryCodeHashes = hashes
	cred.Status = credentialStatusActive
	cred.ActivationTokenHash = ""
	cred.ActivationExpiresAt = time.Time{}
	cred.UpdatedAt = now.UTC()
	if err := s.persistLocked(cred); err != nil {
		return nil, err
	}
	return plain, nil
}

// VerifyPassword performs the first login factor. On success it returns the (active) credential; on failure it
// records the attempt and locks the account after maxFailedLogins. The error is intentionally generic.
func (s *localAdminCredentialStore) VerifyPassword(email, password string, now time.Time) (*localAdminCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred := s.byEmail[credentialEmailKey(email)]
	if cred == nil || cred.Status != credentialStatusActive {
		return nil, fmt.Errorf("invalid credentials")
	}
	if cred.locked(now) {
		return nil, fmt.Errorf("account temporarily locked")
	}
	if cred.PasswordHash == "" || !passwordMatches(cred.PasswordHash, password) {
		cred.FailedAttempts++
		if cred.FailedAttempts >= maxFailedLogins {
			cred.LockedUntil = now.UTC().Add(loginLockWindow)
			cred.FailedAttempts = 0
		}
		cred.UpdatedAt = now.UTC()
		s.persistLocked(cred)
		return nil, fmt.Errorf("invalid credentials")
	}
	return cloneCredential(cred), nil
}

// VerifyTOTP performs the second login factor (a TOTP code or a one-time recovery code). On repeated failure
// it locks the account.
func (s *localAdminCredentialStore) VerifyTOTP(email, code string, now time.Time) (*localAdminCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred := s.byEmail[credentialEmailKey(email)]
	if cred == nil || cred.Status != credentialStatusActive || !cred.TOTPEnrolled {
		return nil, fmt.Errorf("invalid credentials")
	}
	if cred.locked(now) {
		return nil, fmt.Errorf("account temporarily locked")
	}
	if step, ok := totpVerify(cred.TOTPSecret, code, now); ok {
		// Replay protection (RFC 6238): a code whose step was already consumed is rejected, so a
		// captured code cannot be reused within its validity window. A never-consumed account has
		// LastTOTPCounter==0; a real TOTP step is always >0, so the "> 0" guard avoids a first-use edge.
		if cred.LastTOTPCounter != 0 && step <= cred.LastTOTPCounter {
			cred.FailedAttempts++
			if cred.FailedAttempts >= maxFailedLogins {
				cred.LockedUntil = now.UTC().Add(loginLockWindow)
				cred.FailedAttempts = 0
			}
			cred.UpdatedAt = now.UTC()
			s.persistLocked(cred)
			return nil, fmt.Errorf("invalid credentials")
		}
		cred = cloneCredential(cred)
		cred.LastTOTPCounter = step
		cred.FailedAttempts = 0
		cred.LastLoginAt = now.UTC()
		cred.UpdatedAt = now.UTC()
		if err := s.persistLocked(cred); err != nil {
			return nil, err
		}
		return cloneCredential(cred), nil
	}
	// recovery code fallback (one-time use)
	for i, h := range cred.RecoveryCodeHashes {
		if h != "" && passwordMatches(h, strings.TrimSpace(code)) {
			cred = cloneCredential(cred)
			cred.RecoveryCodeHashes[i] = "" // consume
			cred.FailedAttempts = 0
			cred.LastLoginAt = now.UTC()
			cred.UpdatedAt = now.UTC()
			if err := s.persistLocked(cred); err != nil {
				return nil, err
			}
			return cloneCredential(cred), nil
		}
	}
	cred.FailedAttempts++
	if cred.FailedAttempts >= maxFailedLogins {
		cred.LockedUntil = now.UTC().Add(loginLockWindow)
		cred.FailedAttempts = 0
	}
	cred.UpdatedAt = now.UTC()
	s.persistLocked(cred)
	return nil, fmt.Errorf("invalid credentials")
}

// --- tenant-scoped admin account management (Administrators view) -----------------------------------------
//
// These power the per-tenant Administrators backend (GET /admin/admins, suspend/reactivate/delete/roles). Every
// method is keyed by (tenantID, principalID) and never reads or mutates an account belonging to another tenant,
// preserving the tenant trust boundary. Mutations write-through to the durable persistence (if any).

// adminAccountSummary is the tenant-scoped, non-secret projection of a first-party admin credential returned by
// the Administrators view. Password/TOTP/recovery/activation material is deliberately excluded.
type adminAccountSummary struct {
	PrincipalID string   `json:"principal_id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Status      string   `json:"status"`
	CreatedAt   string   `json:"created_at,omitempty"`
	LastLoginAt string   `json:"last_login_at,omitempty"`
}

// errAdminAccountNotFound is returned when no account matches (tenantID, principalID) — including the case where
// the principal exists in a different tenant (cross-tenant lookups fail closed as not-found).
var errAdminAccountNotFound = fmt.Errorf("admin account is absent")

func adminAccountSummaryOf(c *localAdminCredential) adminAccountSummary {
	summary := adminAccountSummary{
		PrincipalID: c.PrincipalID,
		Email:       c.Email,
		Roles:       append([]string(nil), c.Roles...),
		Status:      c.Status,
	}
	if !c.CreatedAt.IsZero() {
		summary.CreatedAt = c.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !c.LastLoginAt.IsZero() {
		summary.LastLoginAt = c.LastLoginAt.UTC().Format(time.RFC3339)
	}
	return summary
}

// findByPrincipalLocked resolves the credential for (tenantID, principalID) within tenant scope. Caller holds
// s.mu. Returns nil when the tenant/principal is empty or the principal belongs to another tenant.
func (s *localAdminCredentialStore) findByPrincipalLocked(tenantID, principalID string) *localAdminCredential {
	tenantID = strings.TrimSpace(tenantID)
	principalID = strings.TrimSpace(principalID)
	if tenantID == "" || principalID == "" {
		return nil
	}
	for _, c := range s.byEmail {
		if c.TenantID == tenantID && c.PrincipalID == principalID {
			return c
		}
	}
	return nil
}

// List returns the non-secret summaries of every admin account in tenantID, sorted by email. Tenant-scoped:
// accounts of other tenants are never returned. Fail-closed — an empty tenantID returns no accounts.
func (s *localAdminCredentialStore) List(tenantID string) []adminAccountSummary {
	tenantID = strings.TrimSpace(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []adminAccountSummary{}
	if tenantID == "" {
		return out
	}
	for _, c := range s.byEmail {
		if c.TenantID != tenantID {
			continue
		}
		out = append(out, adminAccountSummaryOf(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
}

// SetStatus changes an account's status (suspend/reactivate) within a tenant. Reactivating to active is only
// permitted for a fully-activated account (password set + TOTP enrolled) so a never-activated invite can never
// be flipped into a usable login. Tenant-scoped: another tenant's account returns errAdminAccountNotFound.
func (s *localAdminCredentialStore) SetStatus(tenantID, principalID, status string, now time.Time) (adminAccountSummary, error) {
	status = strings.TrimSpace(status)
	s.mu.Lock()
	defer s.mu.Unlock()
	cred := cloneCredential(s.findByPrincipalLocked(tenantID, principalID))
	if cred == nil {
		return adminAccountSummary{}, errAdminAccountNotFound
	}
	if status == credentialStatusActive && (cred.PasswordHash == "" || !cred.TOTPEnrolled) {
		return adminAccountSummary{}, fmt.Errorf("account has not completed activation and cannot be set active")
	}
	cred.Status = status
	if status == credentialStatusSuspended {
		// A suspension is the authoritative login gate; clear any transient lockout counters.
		cred.FailedAttempts = 0
		cred.LockedUntil = time.Time{}
	}
	cred.UpdatedAt = now.UTC()
	if err := s.persistLocked(cred); err != nil {
		return adminAccountSummary{}, err
	}
	return adminAccountSummaryOf(cred), nil
}

// SetRoles replaces an account's roles within a tenant. Role-name validation and privilege-escalation guards
// live in the handler (which knows the RBAC catalog and the caller's roles). Tenant-scoped.
func (s *localAdminCredentialStore) SetRoles(tenantID, principalID string, roles []string, now time.Time) (adminAccountSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred := cloneCredential(s.findByPrincipalLocked(tenantID, principalID))
	if cred == nil {
		return adminAccountSummary{}, errAdminAccountNotFound
	}
	cred.Roles = append([]string(nil), roles...)
	cred.UpdatedAt = now.UTC()
	if err := s.persistLocked(cred); err != nil {
		return adminAccountSummary{}, err
	}
	return adminAccountSummaryOf(cred), nil
}

// Delete removes an account within a tenant (in-memory and durably). Tenant-scoped: another tenant's account
// returns errAdminAccountNotFound and is never removed. Self-delete / last-admin guards live in the handler.
func (s *localAdminCredentialStore) Delete(tenantID, principalID string, now time.Time) (adminAccountSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred := s.findByPrincipalLocked(tenantID, principalID)
	if cred == nil {
		return adminAccountSummary{}, errAdminAccountNotFound
	}
	summary := adminAccountSummaryOf(cred)
	if err := s.deleteLocked(cred); err != nil {
		return adminAccountSummary{}, err
	}
	delete(s.byEmail, credentialEmailKey(cred.Email))
	return summary, nil
}

// DeleteAllForTenant removes every account belonging to a tenant and returns the emails it removed, so the
// caller can record WHO was removed rather than only how many.
//
// ★ WHY THIS EXISTS (2026-08-15). Deleting an organization removed its registry row and left its
// administrators behind — and the ordinary per-account routes could not clean them up afterwards, because
// "cannot delete the last administrator able to manage admins in this tenant" is an invariant that outlived
// the tenant. Measured on the lab: after deleting tenant_delprobe2 its administrator still authenticated, and
// neither delete nor suspend would touch the account. An organization has to be able to take its accounts
// with it, or deleting one creates a credential nobody can reach.
//
// The last-admin guard is deliberately NOT consulted here. It exists to keep a tenant manageable; a tenant
// that is being deleted does not need to be manageable, and applying it would make the cascade stop on the
// last account — exactly the state this exists to prevent.
// EmailForPrincipal resolves an administrator id to their email ACROSS organizations.
//
// ★ DELIBERATELY UNSCOPED, AND ONLY FOR NAMING (2026-08-17). The principal who last moved an organization's
// standing delegation is often the OPERATOR — in another organization entirely — and that is exactly who the
// customer needs named on the screen that presents the control. Scoping this to the reading organization
// would answer "" for the one case it exists for, and the screen would print a raw id.
//
// It answers a NAME for an id the caller already holds; it does not let anyone enumerate accounts.
func (s *localAdminCredentialStore) EmailForPrincipal(principalID string) string {
	principalID = strings.TrimSpace(principalID)
	if s == nil || principalID == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.byEmail {
		if strings.EqualFold(strings.TrimSpace(c.PrincipalID), principalID) {
			return strings.TrimSpace(c.Email)
		}
	}
	return ""
}

func (s *localAdminCredentialStore) DeleteAllForTenant(tenantID string) ([]string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := []string{}
	var saveErr error
	for key, cred := range s.byEmail {
		if cred == nil || !strings.EqualFold(strings.TrimSpace(cred.TenantID), tenantID) {
			continue
		}
		if err := s.deleteLocked(cred); err != nil {
			saveErr = err
			continue
		}
		removed = append(removed, cred.Email)
		delete(s.byEmail, key)
	}
	sort.Strings(removed)
	return removed, saveErr
}

// deleteLocked removes a credential durably before its caller publishes the deletion (caller holds s.mu).
func (s *localAdminCredentialStore) deleteLocked(cred *localAdminCredential) error {
	if s.persistence == nil {
		return nil
	}
	if err := s.persistence.Delete(context.Background(), cred.TenantID, cred.Email); err != nil {
		log.Printf("admin credential deletion failed: %v", err)
		return errCredentialPersistence
	}
	return nil
}
