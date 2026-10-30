package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
)

// A signed device request can finish on a different Portal process behind the
// same HTTPS origin. The state contains the pending OIDC context encrypted with
// a key derived from the deployment's step-up secret. In particular, the PKCE
// verifier and OS identity never appear in cleartext in the IdP redirect.
// Anonymous clientless starts keep their process-local state.
const sealedAuthStatePrefix = "dsse1."
const maxSealedAuthPayload = 4096

type sealedAuthPayload struct {
	Version             int       `json:"v"`
	RequestID           string    `json:"r"`
	BrowserHash         [32]byte  `json:"b"`
	ProviderDigest      [32]byte  `json:"p"`
	TenantID            string    `json:"t"`
	BoundDevice         string    `json:"d"`
	OSPrincipal         string    `json:"op,omitempty"`
	OSSession           string    `json:"os,omitempty"`
	BindingRevision     string    `json:"br,omitempty"`
	IdPID               string    `json:"i"`
	Nonce               string    `json:"n"`
	CodeVerifier        string    `json:"cv"`
	RedirectURI         string    `json:"u"`
	ReturnTo            string    `json:"rt,omitempty"`
	RequiredACR         string    `json:"acr,omitempty"`
	RequiredAMR         []string  `json:"amr,omitempty"`
	MaxAgeSeconds       *int64    `json:"ma,omitempty"`
	GrantTTLSeconds     *int64    `json:"gt,omitempty"`
	ReauthenticateAfter time.Time `json:"ra,omitempty"`
	CreatedAt           time.Time `json:"c"`
	Deadline            time.Time `json:"x"`
}

func (b *clientlessBroker) ceremonyRecoveryReady() bool {
	return b.recoverySharedKey && b.signer != nil && len(b.signer.key) != 0 && b.rollout.featureEnabled(authrollout.CeremonyRecoveryFeature)
}

func (b *clientlessBroker) ceremonyStateAEAD() (cipher.AEAD, error) {
	h := sha256.New()
	_, _ = h.Write([]byte("dsse oidc ceremony state encryption v1\x00"))
	_, _ = h.Write(b.signer.key)
	key := h.Sum(nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (b *clientlessBroker) sealAuthState(p pendingAuth) (string, error) {
	if !b.ceremonyRecoveryReady() || p.requestID == "" || p.boundDevice == "" {
		return "", errors.New("fleet ceremony recovery unavailable")
	}
	version := 1
	if p.grantTTLSeconds != nil {
		if !validAuthGrantTTLSeconds(*p.grantTTLSeconds) {
			return "", errors.New("invalid grant lifetime")
		}
		// Old Portals must refuse this state rather than ignore the cap.
		version = 2
	}
	if !p.reauthenticateAfter.IsZero() {
		version = 3
	}
	body, err := json.Marshal(sealedAuthPayload{
		Version: version, RequestID: p.requestID, BrowserHash: p.browserHash,
		ProviderDigest: p.providerDigest, TenantID: p.tenantID, BoundDevice: p.boundDevice,
		OSPrincipal: p.osPrincipal, OSSession: p.osSession, BindingRevision: p.bindingRevision,
		IdPID: p.idpID, Nonce: p.nonce, CodeVerifier: p.codeVerifier,
		RedirectURI: p.redirectURI, ReturnTo: p.returnTo, RequiredACR: p.requiredACR,
		RequiredAMR: p.requiredAMR, MaxAgeSeconds: p.maxAgeSeconds, GrantTTLSeconds: p.grantTTLSeconds,
		ReauthenticateAfter: p.reauthenticateAfter,
		CreatedAt:           p.createdAt, Deadline: p.deadline,
	})
	if err != nil || len(body) > maxSealedAuthPayload {
		return "", errors.New("authentication context too large")
	}
	aead, err := b.ceremonyStateAEAD()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, body, []byte(b.selfBaseURL))
	return sealedAuthStatePrefix + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// Only the browser that began this signed request can recover it. No plaintext
// PKCE material is accepted from the callback, and a different deployment key,
// Portal origin, or expired ceremony fails closed. The OIDC authorization code
// is single-use at the IdP; the shared grant authority additionally rejects a
// second mint for the same signed request ID, including across processes.
func (b *clientlessBroker) recoverAuthState(r *http.Request, state string, now time.Time) (pendingAuth, bool) {
	if !b.ceremonyRecoveryReady() || !strings.HasPrefix(state, sealedAuthStatePrefix) || len(state) > 8192 {
		return pendingAuth{}, false
	}
	// A local callback reservation (including a failed or cancelled one) cannot
	// fall back to the sealed token and run twice on the same Portal.
	b.mu.Lock()
	_, local := b.pending[state]
	if !local {
		for _, ceremony := range b.ceremonies {
			if ceremony.state == state {
				local = true
				break
			}
		}
	}
	b.mu.Unlock()
	if local {
		return pendingAuth{}, false
	}
	session, ok := browserSession(r)
	if !ok {
		return pendingAuth{}, false
	}
	encoded := strings.TrimPrefix(state, sealedAuthStatePrefix)
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return pendingAuth{}, false
	}
	aead, err := b.ceremonyStateAEAD()
	if err != nil || len(data) <= aead.NonceSize()+aead.Overhead() {
		return pendingAuth{}, false
	}
	body, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(b.selfBaseURL))
	if err != nil || len(body) > maxSealedAuthPayload {
		return pendingAuth{}, false
	}
	var value sealedAuthPayload
	if json.Unmarshal(body, &value) != nil || (value.Version != 1 && value.Version != 2 && value.Version != 3) ||
		(value.Version < 3 && !value.ReauthenticateAfter.IsZero()) || (value.Version == 3 && value.ReauthenticateAfter.IsZero()) ||
		(value.Version == 1 && value.GrantTTLSeconds != nil) ||
		(value.Version == 2 && (value.GrantTTLSeconds == nil || !validAuthGrantTTLSeconds(*value.GrantTTLSeconds))) || value.BrowserHash != sha256.Sum256([]byte(session)) ||
		(value.Version == 3 && value.GrantTTLSeconds != nil && !validAuthGrantTTLSeconds(*value.GrantTTLSeconds)) ||
		value.RequestID == "" || value.TenantID == "" || value.BoundDevice == "" || value.IdPID == "" ||
		value.Nonce == "" || value.CodeVerifier == "" || value.ProviderDigest == ([32]byte{}) ||
		value.RedirectURI != b.selfBaseURL+"/clientless/auth/callback" ||
		value.CreatedAt.IsZero() || value.CreatedAt.After(now.Add(5*time.Second)) ||
		!now.Before(value.Deadline) || value.Deadline.After(value.CreatedAt.Add(pendingAuthTTL)) {
		return pendingAuth{}, false
	}
	requestID, err := base64.RawURLEncoding.DecodeString(value.RequestID)
	if err != nil || len(requestID) != 24 {
		return pendingAuth{}, false
	}
	return pendingAuth{
		requestID: value.RequestID, browserHash: value.BrowserHash, providerDigest: value.ProviderDigest,
		tenantID: value.TenantID, boundDevice: value.BoundDevice,
		osPrincipal: value.OSPrincipal, osSession: value.OSSession, bindingRevision: value.BindingRevision,
		idpID: value.IdPID, nonce: value.Nonce, codeVerifier: value.CodeVerifier,
		redirectURI: value.RedirectURI, returnTo: value.ReturnTo, requiredACR: value.RequiredACR,
		requiredAMR: value.RequiredAMR, maxAgeSeconds: value.MaxAgeSeconds, grantTTLSeconds: value.GrantTTLSeconds,
		reauthenticateAfter: value.ReauthenticateAfter,
		createdAt:           value.CreatedAt, deadline: value.Deadline, recovered: true,
	}, true
}
