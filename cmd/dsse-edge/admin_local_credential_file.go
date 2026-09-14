package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// File-backed durable persistence for first-party admin credentials — the node-local sibling of
// postgresCredentialPersistence (see admin_local_credential_postgres.go). It exists so the reference,
// deliberately ZERO-DB Edge (the CP is the config authority, so Postgres would be durable-and-unread here) still
// keeps SaaS-issued admin accounts across a restart: without a durable store a restart wipes every locally
// created admin, and the operator can no longer sign in. Same shape as the connector-registry / device-inventory
// file backends — a single opaque JSON snapshot written atomically via blobstore.FilePersister.
//
// It holds the WHOLE credential set in an in-memory map under a mutex; every Upsert/Delete rewrites the entire
// snapshot; LoadAll reads it back on boot. Parity with the Postgres impl is exact: it persists the SAME fields
// (LastLoginAt is deliberately excluded — best-effort, in-memory only) and seals the TOTP secret at rest with the
// same sealTOTPSecretForStore / unsealTOTPSecretFromStore path. Secret material (password hash, TOTP secret,
// recovery-code hashes) is NEVER written to a log — only the email/tenant and the error are.

// fileCredentialPersistence implements credentialPersistence over a single blobstore snapshot file.
type fileCredentialPersistence struct {
	mu        sync.Mutex
	persister blobstore.FilePersister
	// byEmail is the durable set kept resident so every mutation can rewrite the whole snapshot. Keyed by the
	// normalized email (credentialEmailKey), the same key the in-memory store uses. Seeded by LoadAll on boot.
	byEmail map[string]*localAdminCredential
}

// persistedCredential is the on-disk JSON projection of a credential. It mirrors EXACTLY the columns the Postgres
// backend persists — no more, no less. LastLoginAt is intentionally absent (in-memory only, resets on restart).
// The TOTPSecret field carries the AT-REST (sealed) form, matching the Postgres totp_secret column.
type persistedCredential struct {
	Email               string    `json:"email"`
	PrincipalID         string    `json:"principal_id"`
	TenantID            string    `json:"tenant_id"`
	Roles               []string  `json:"roles"`
	Status              string    `json:"status"`
	PasswordHash        string    `json:"password_hash"`
	TOTPSecret          string    `json:"totp_secret"` // sealed at rest (sealTOTPSecretForStore)
	TOTPEnrolled        bool      `json:"totp_enrolled"`
	LastTOTPCounter     uint64    `json:"last_totp_counter"`
	RecoveryCodeHashes  []string  `json:"recovery_code_hashes"`
	FailedAttempts      int       `json:"failed_attempts"`
	LockedUntil         time.Time `json:"locked_until"`
	ActivationTokenHash string    `json:"activation_token_hash"`
	ActivationExpiresAt time.Time `json:"activation_expires_at"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// newFileCredentialPersistence builds a file-backed persistence over the snapshot at path. It does not read the
// file here; LoadAll (called once by the store on startup) is the read+parse+seed path, so a parse failure fails
// startup closed rather than being swallowed.
func newFileCredentialPersistence(path string) *fileCredentialPersistence {
	return &fileCredentialPersistence{
		persister: blobstore.FilePersister{Path: path},
		byEmail:   map[string]*localAdminCredential{},
	}
}

// LoadAll reads and parses the snapshot, seeds the in-memory set, and returns every credential. A missing or
// empty file is first boot: an empty slice, no error. A PARSE failure is returned (fail-closed) so the caller
// refuses to start rather than silently losing every admin account and rewriting the file empty on the next write.
func (f *fileCredentialPersistence) LoadAll(_ context.Context) ([]*localAdminCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := f.persister.Load()
	if err != nil {
		return nil, fmt.Errorf("read admin credential snapshot: %w", err)
	}
	f.byEmail = map[string]*localAdminCredential{}
	if len(strings.TrimSpace(string(data))) == 0 {
		return []*localAdminCredential{}, nil
	}
	var records []persistedCredential
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse admin credential snapshot: %w", err)
	}
	out := make([]*localAdminCredential, 0, len(records))
	for i := range records {
		cred, err := credentialFromPersisted(records[i])
		if err != nil {
			// Fail-closed: an unrecoverable secret (e.g. sealed TOTP with no KEK) must abort the load, not drop
			// the operator's 2FA silently. Do not include secret material in the error.
			return nil, fmt.Errorf("load admin credential %s: %w", records[i].Email, err)
		}
		f.byEmail[credentialEmailKey(cred.Email)] = cred
		out = append(out, cloneCredential(cred))
	}
	return out, nil
}

// Upsert and Delete roll back the resident snapshot if saving fails, so a later
// unrelated save cannot silently commit an earlier failed operation.
func (f *fileCredentialPersistence) Upsert(_ context.Context, cred *localAdminCredential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := credentialEmailKey(cred.Email)
	previous, existed := f.byEmail[key]
	f.byEmail[key] = cloneCredential(cred)
	if err := f.saveLocked(); err != nil {
		if existed {
			f.byEmail[key] = previous
		} else {
			delete(f.byEmail, key)
		}
		return err
	}
	return nil
}

func (f *fileCredentialPersistence) Delete(_ context.Context, tenantID, email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := credentialEmailKey(email)
	previous, existed := f.byEmail[key]
	if !existed || previous.TenantID != tenantID {
		return nil
	}
	delete(f.byEmail, key)
	if err := f.saveLocked(); err != nil {
		f.byEmail[key] = previous
		return err
	}
	return nil
}

// saveLocked serializes the whole in-memory set (TOTP secrets sealed at rest) and atomically rewrites the
// snapshot file. Caller holds f.mu.
func (f *fileCredentialPersistence) saveLocked() error {
	records := make([]persistedCredential, 0, len(f.byEmail))
	for _, cred := range f.byEmail {
		rec, err := credentialToPersisted(cred)
		if err != nil {
			return err
		}
		records = append(records, rec)
	}
	// Deterministic order keeps the snapshot stable across writes (easier diffing / no spurious churn).
	sort.Slice(records, func(i, j int) bool { return records[i].Email < records[j].Email })
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return f.persister.Save(data)
}

// credentialToPersisted projects an in-memory credential to its on-disk form, sealing the TOTP secret at rest.
func credentialToPersisted(c *localAdminCredential) (persistedCredential, error) {
	sealedTOTP, err := sealTOTPSecretForStore(c.TOTPSecret)
	if err != nil {
		return persistedCredential{}, err
	}
	return persistedCredential{
		Email:               c.Email,
		PrincipalID:         c.PrincipalID,
		TenantID:            c.TenantID,
		Roles:               append([]string(nil), c.Roles...),
		Status:              c.Status,
		PasswordHash:        c.PasswordHash,
		TOTPSecret:          sealedTOTP,
		TOTPEnrolled:        c.TOTPEnrolled,
		LastTOTPCounter:     c.LastTOTPCounter,
		RecoveryCodeHashes:  append([]string(nil), c.RecoveryCodeHashes...),
		FailedAttempts:      c.FailedAttempts,
		LockedUntil:         c.LockedUntil,
		ActivationTokenHash: c.ActivationTokenHash,
		ActivationExpiresAt: c.ActivationExpiresAt,
		CreatedAt:           c.CreatedAt,
		UpdatedAt:           c.UpdatedAt,
	}, nil
}

// credentialFromPersisted rebuilds an in-memory credential from its on-disk form, unsealing the TOTP secret.
func credentialFromPersisted(p persistedCredential) (*localAdminCredential, error) {
	totp, err := unsealTOTPSecretFromStore(p.TOTPSecret)
	if err != nil {
		return nil, err
	}
	return &localAdminCredential{
		PrincipalID:         p.PrincipalID,
		TenantID:            p.TenantID,
		Email:               p.Email,
		Roles:               append([]string(nil), p.Roles...),
		Status:              p.Status,
		PasswordHash:        p.PasswordHash,
		TOTPSecret:          totp,
		TOTPEnrolled:        p.TOTPEnrolled,
		LastTOTPCounter:     p.LastTOTPCounter,
		RecoveryCodeHashes:  append([]string(nil), p.RecoveryCodeHashes...),
		FailedAttempts:      p.FailedAttempts,
		LockedUntil:         p.LockedUntil.UTC(),
		ActivationTokenHash: p.ActivationTokenHash,
		ActivationExpiresAt: p.ActivationExpiresAt.UTC(),
		CreatedAt:           p.CreatedAt.UTC(),
		UpdatedAt:           p.UpdatedAt.UTC(),
	}, nil
}

// cloneCredential deep-copies a credential so the durable set never aliases the store's live pointer.
func cloneCredential(c *localAdminCredential) *localAdminCredential {
	if c == nil {
		return nil
	}
	dup := *c
	dup.Roles = append([]string(nil), c.Roles...)
	dup.RecoveryCodeHashes = append([]string(nil), c.RecoveryCodeHashes...)
	return &dup
}
