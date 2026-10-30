package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/authportal"
	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/oidcbroker"
)

type authDestinationConfirmation struct {
	browser              [32]byte
	query                string
	expires              time.Time
	tenant, device, peer string
	used                 bool
}

func (b *clientlessBroker) portableDestinationConfirmation(device string) bool {
	return device != "" && b.ceremonyRecoveryReady() && b.rollout.featureEnabled(authrollout.RevocationReauthenticationFeature)
}

func (b *clientlessBroker) destinationConfirmationMAC(r *http.Request, browser [32]byte, expires, nonce string) string {
	mac := hmac.New(sha256.New, b.signer.key)
	query := sha256.Sum256([]byte(r.URL.RawQuery))
	_, _ = mac.Write([]byte(strings.Join([]string{"dsse destination confirmation v1", b.selfBaseURL, hex.EncodeToString(browser[:]), hex.EncodeToString(query[:]), expires, nonce}, "\x00")))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (b *clientlessBroker) recoverDestinationConfirmation(r *http.Request, browser [32]byte, token, device string, now time.Time) (time.Time, bool) {
	if !b.portableDestinationConfirmation(device) {
		return time.Time{}, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "dc1" || !validAuthResultRequestID(parts[2]) {
		return time.Time{}, false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	deadline := time.Unix(exp, 0)
	if err != nil || !now.Before(deadline) || deadline.After(now.Add(authStartTTL)) || !hmac.Equal([]byte(parts[3]), []byte(b.destinationConfirmationMAC(r, browser, parts[1], parts[2]))) {
		return time.Time{}, false
	}
	return deadline, true
}

func (b *clientlessBroker) confirmAuthenticationDestination(w http.ResponseWriter, r *http.Request, tenant, device string) bool {
	now := time.Now().UTC()
	session, err := ensureBrowserSession(w, r)
	if err != nil {
		respondCeremonyError(w, r, 503, "Authentication unavailable", "Request a fresh sign-in link.")
		return false
	}
	browser := sha256.Sum256([]byte(session))
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		origin, originErr := authportal.Origin(r.Header.Get("Origin"))
		portalOrigin, portalErr := authportal.Origin(b.selfBaseURL)
		if originErr != nil || portalErr != nil || origin != portalOrigin || r.Header.Get("Sec-Fetch-Site") == "cross-site" || r.ParseForm() != nil || len(r.PostForm) != 1 || len(r.PostForm["confirmation"]) != 1 {
			respondCeremonyError(w, r, 403, "Destination confirmation invalid", "Reload this page and confirm the destination again.")
			return false
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweepAuthLocked(now)
	for token, confirmation := range b.confirmations {
		if !now.Before(confirmation.expires) {
			delete(b.confirmations, token)
		}
	}
	if r.Method == http.MethodPost {
		// Origin is sent by standard browsers for this same-origin form POST.
		// A proof is also bound to an HttpOnly browser cookie and the full query,
		// so no destination, tenant, assurance or lifetime can be substituted.
		token := r.PostForm.Get("confirmation")
		confirmation, ok := b.confirmations[token]
		if !ok {
			deadline, verified := b.recoverDestinationConfirmation(r, browser, token, device, now)
			if verified && b.authCapacityForPeerLocked(tenant, device, authPeerIP(r), r.URL.Query().Get("request_id")) && b.allowAuthStartLocked(tenant, device, authPeerIP(r), now) {
				confirmation = authDestinationConfirmation{browser: browser, query: r.URL.RawQuery, expires: deadline, tenant: tenant, device: device, peer: authPeerIP(r)}
				ok = true
			}
		}
		if !ok || confirmation.used || confirmation.browser != browser || confirmation.query != r.URL.RawQuery || !now.Before(confirmation.expires) {
			respondCeremonyError(w, r, 403, "Destination confirmation expired", "Reload this page and confirm the destination again.")
			return false
		}
		confirmation.used = true
		if b.confirmations == nil {
			b.confirmations = make(map[string]authDestinationConfirmation)
		}
		b.confirmations[token] = confirmation
		// A peer may receive the same signed request too. The proof cannot authorize
		// any other request; deterministic grant IDs and CP atomic minting preserve
		// one issuance across Portals, as for recovered OIDC callbacks.
		return true
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return false
	}
	for token, confirmation := range b.confirmations {
		if !confirmation.used && confirmation.browser == browser && confirmation.query == r.URL.RawQuery {
			writeDestinationConfirmation(w, r, token)
			return false
		}
	}
	// Bound unattended tabs independently from pending OIDC ceremonies. No
	// provider URL, nonce, PKCE verifier or grant is created before confirmation.
	if !b.authCapacityForPeerLocked(tenant, device, authPeerIP(r), r.URL.Query().Get("request_id")) || !b.allowAuthStartLocked(tenant, device, authPeerIP(r), now) {
		w.Header().Set("Retry-After", "60")
		respondCeremonyError(w, r, 429, "Too many sign-in requests", "Complete or wait for outstanding requests to expire.")
		return false
	}
	token, err := oidcbroker.NewOpaqueToken()
	if err != nil {
		respondCeremonyError(w, r, 503, "Authentication unavailable", "Request a fresh sign-in link.")
		return false
	}
	if b.confirmations == nil {
		b.confirmations = make(map[string]authDestinationConfirmation)
	}
	expires := now.Add(authStartTTL)
	if unix, err := strconv.ParseInt(r.URL.Query().Get("expires_at"), 10, 64); err == nil && time.Unix(unix, 0).Before(expires) {
		expires = time.Unix(unix, 0)
	}
	if b.portableDestinationConfirmation(device) {
		exp := strconv.FormatInt(expires.Unix(), 10)
		token = "dc1." + exp + "." + token + "." + b.destinationConfirmationMAC(r, browser, exp, token)
	}
	b.confirmations[token] = authDestinationConfirmation{browser: browser, query: r.URL.RawQuery, expires: expires, tenant: tenant, device: device, peer: authPeerIP(r)}
	writeDestinationConfirmation(w, r, token)
	return false
}

func writeDestinationConfirmation(w http.ResponseWriter, r *http.Request, token string) {
	// no-referrer makes standard browsers send Origin: null even on this form
	// POST. same-origin preserves the CSRF Origin check and still discloses no
	// start URL or Referer to a cross-origin IdP. The following redirect resets
	// the stricter no-referrer policy in handleStart.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	body := `<p>` + ceremonyLabel("Your application requested access to:", r) + `</p><p><strong>` + html.EscapeString(federatedDestinationScope(r.URL.Query().Get("return_to"))) + `</strong></p><p>` + ceremonyLabel("Continue only if you intended to connect to this destination. Your identity provider may use an existing sign-in.", r) + `</p><form method="post" action="` + html.EscapeString(r.URL.RequestURI()) + `"><input type="hidden" name="confirmation" value="` + html.EscapeString(token) + `"><button type="submit">` + ceremonyLabel("Continue to sign in", r) + `</button></form>`
	writeCeremonyPage(w, 200, ceremonyPageShell("", "Confirm destination", body, "", r))
}

// Chromium also applies form-action 'self' to a form submission's redirects.
// Finish the same-origin POST with a document, whose refresh is a separate
// top-level navigation. Keep the restrictive form policy, script-independent navigation, and no
// Referer. target is the broker-built configured IdP URL, never a caller-supplied
// navigation target. The link handles browsers with automatic refresh disabled.
func navigateToAuthenticationProvider(w http.ResponseWriter, r *http.Request, target string) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	escaped := html.EscapeString(target)
	body := `<p>` + ceremonyLabel("Opening your identity provider.", r) + `</p><p><a href="` + escaped + `" rel="noreferrer noopener">` + ceremonyLabel("Continue to sign in", r) + `</a></p>`
	page := ceremonyPageShell("", "Continue to your identity provider", body, "", r)
	page = strings.Replace(page, "</head>", `<meta http-equiv="refresh" content="0;url=`+escaped+`"></head>`, 1)
	writeCeremonyPage(w, http.StatusOK, page)
}
