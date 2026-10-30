package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/oidcbroker"
)

const authStartTTL = 2 * time.Minute
const authPendingLimit = 256
const authDevicePendingLimit = 4
const authSessionCookie = "__Host-dsse_auth_session"

// The local copy supports same-node retry. When the fleet recovery capability is
// activated, signed requests additionally carry encrypted pending context in
// OIDC state; anonymous requests remain local. Grants live in the shared store.
type authCeremony struct {
	state, authorizeURL, csrf, startQuery string
	tenant, device                        string
	browserHash                           [32]byte
	startExpires, expires                 time.Time
	finished                              bool
	busy, succeeded, restart              bool
}

func addAuthStartLifetime(q url.Values, now time.Time) error {
	id, err := oidcbroker.NewOpaqueToken()
	if err != nil {
		return err
	}
	q.Set("request_id", id)
	q.Set("issued_at", strconv.FormatInt(now.Unix(), 10))
	q.Set("expires_at", strconv.FormatInt(now.Add(authStartTTL).Unix(), 10))
	return nil
}

func validateAuthStartLifetime(q url.Values, now time.Time) error {
	for _, key := range []string{"request_id", "issued_at", "expires_at"} {
		if len(q[key]) != 1 {
			return fmt.Errorf("missing or duplicate start lifetime")
		}
	}
	id, err := base64.RawURLEncoding.DecodeString(q.Get("request_id"))
	if err != nil || len(id) != 24 {
		return fmt.Errorf("invalid request identifier")
	}
	issued, e1 := strconv.ParseInt(q.Get("issued_at"), 10, 64)
	expires, e2 := strconv.ParseInt(q.Get("expires_at"), 10, 64)
	if e1 != nil || e2 != nil || issued <= 0 || expires <= issued || expires-issued != int64(authStartTTL/time.Second) || issued > now.Unix()+5 || now.Unix() >= expires {
		return fmt.Errorf("expired or invalid start lifetime")
	}
	return nil
}

func authResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func browserSession(r *http.Request) (string, bool) {
	cookies := r.CookiesNamed(authSessionCookie)
	if len(cookies) != 1 {
		return "", false
	}
	value := cookies[0].Value
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return value, err == nil && len(decoded) == 24
}

func ensureBrowserSession(w http.ResponseWriter, r *http.Request) (string, error) {
	if value, ok := browserSession(r); ok {
		return value, nil
	}
	value, err := oidcbroker.NewOpaqueToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{Name: authSessionCookie, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return value, nil
}

// Called under b.mu, also bounding abandoned requests without a background worker.
func (b *clientlessBroker) sweepAuthLocked(now time.Time) {
	for state, p := range b.pending {
		if !now.Before(p.createdAt.Add(pendingAuthTTL)) {
			delete(b.pending, state)
		}
	}
	for id, c := range b.ceremonies {
		if !now.Before(c.expires) {
			delete(b.pending, c.state)
			delete(b.ceremonies, id)
		}
	}
}

// Active ceremonies and replay tombstones have separate bounds. Anonymous work
// cannot spend a signed device's tenant quota; all retained objects remain bounded.
func (b *clientlessBroker) authCapacityLocked(tenant, device string) bool {
	return b.authCapacityForPeerLocked(tenant, device, "")
}
func (b *clientlessBroker) authCapacityForPeerLocked(tenant, device, ip string, replacing ...string) bool {
	total, active, perTenant, perDevice, anonymous, perIP, retainedTenant, retainedDevice := 0, 0, 0, 0, 0, 0, 0, 0
	count := func(t, d, peer string, completed bool) {
		total++
		if d == "" {
			anonymous++
			if peer == ip {
				perIP++
			}
			return
		}
		if t == tenant {
			retainedTenant++
			if d == device {
				retainedDevice++
			}
		}
		if completed {
			return
		}
		active++
		if t == tenant {
			perTenant++
			if d == device {
				perDevice++
			}
		}
	}
	for id, c := range b.ceremonies {
		if len(replacing) == 1 && id == replacing[0] {
			continue
		}
		count(c.tenant, c.device, "", c.finished || c.succeeded)
	}
	for _, p := range b.pending {
		if p.requestID != "" && b.ceremonies[p.requestID] != nil {
			continue
		}
		count(p.tenantID, p.boundDevice, p.sourceIP, false)
	}
	for _, c := range b.confirmations {
		count(c.tenant, c.device, c.peer, c.used)
	}
	// Never evict a live replay tombstone to admit more requests.
	if total >= 1024 {
		return false
	}
	if device == "" {
		return anonymous < 64 && perIP < 8
	}
	return retainedTenant < 128 && retainedDevice < 32 && active < authPendingLimit && perTenant < 64 && perDevice < authDevicePendingLimit
}

type authRateKey struct{ class, tenant, principal string }
type authRateWindow struct {
	start time.Time
	count int
}

func authPeerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	// Privacy addresses on one IPv6 LAN share an admission budget.
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// Bounded one-minute windows, under b.mu. Only validated device bindings can
// consume device quotas; anonymous clients are limited by their actual peer IP.
func (b *clientlessBroker) allowAuthStartLocked(tenant, device, ip string, now time.Time) bool {
	if b.startRates == nil {
		b.startRates = make(map[authRateKey]authRateWindow)
	}
	limits := make(map[authRateKey]int)
	if device != "" {
		limits[authRateKey{class: "edge"}] = 500
		limits[authRateKey{class: "tenant", tenant: tenant}] = 100
		limits[authRateKey{class: "device", tenant: tenant, principal: device}] = 10
	} else {
		limits[authRateKey{class: "anonymous"}] = 100
		limits[authRateKey{class: "ip", principal: ip}] = 10
	}
	for key, window := range b.startRates {
		if !now.Before(window.start.Add(time.Minute)) {
			delete(b.startRates, key)
		}
	}
	for key, limit := range limits {
		if b.startRates[key].count >= limit {
			return false
		}
	}
	// At most 600 accepted starts/minute, each introduces at most three keys.
	if len(b.startRates) > 2000 {
		return false
	}
	for key := range limits {
		window := b.startRates[key]
		if window.count == 0 {
			window.start = now
		}
		window.count++
		b.startRates[key] = window
	}
	return true
}

// A callback must come from the browser that began this attempt. A wrong browser
// must not consume the real user's state. Reserve valid callbacks before I/O.
func (b *clientlessBroker) takePending(r *http.Request, state string, now time.Time) (pendingAuth, bool) {
	session, ok := browserSession(r)
	if !ok {
		return pendingAuth{}, false
	}
	hash := sha256.Sum256([]byte(session))
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweepAuthLocked(now)
	p, ok := b.pending[state]
	if !ok || p.consuming || p.browserHash != hash {
		return pendingAuth{}, false
	}
	if p.requestID != "" {
		c := b.ceremonies[p.requestID]
		if c == nil || c.finished || c.state != state || c.browserHash != hash {
			return pendingAuth{}, false
		}
		// Keep a tombstone through the absolute ceremony deadline: callback retries
		// cannot mint another grant when a persistence response is lost.
		c.finished = true
		c.busy = true
	}
	p.consuming = true
	b.pending[state] = p
	return p, true
}

// Login requests have a strict size ceiling before parsing or retaining data.
func validAuthQuery(r *http.Request) bool {
	if len(r.URL.RawQuery) > 16384 {
		return false
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return false
	}
	for _, v := range q {
		if len(v) != 1 || len(v[0]) > 8192 || strings.ContainsAny(v[0], "\r\n\x00") {
			return false
		}
	}
	return true
}

func (b *clientlessBroker) endAuthCallback(state, id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.pending, state)
	if c := b.ceremonies[id]; c != nil {
		c.busy = false
	}
}

func (b *clientlessBroker) ceremonyError(w http.ResponseWriter, r *http.Request, p pendingAuth, status int, title, detail string) {
	if p.requestID == "" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		respondCeremonyError(w, r, status, title, detail)
		return
	}
	b.mu.Lock()
	c := b.ceremonies[p.requestID]
	csrf := ""
	if c != nil && !c.succeeded && time.Now().Before(c.startExpires) {
		csrf = c.csrf
	}
	b.mu.Unlock()
	body := "<p>" + ceremonyErrorLabel(detail, r) + "</p>"
	if csrf != "" {
		body += `<form method="post" action="/clientless/auth/retry"><input type="hidden" name="request_id" value="` + html.EscapeString(p.requestID) + `"><input type="hidden" name="csrf" value="` + html.EscapeString(csrf) + `"><button type="submit">` + ceremonyLabel("Retry authentication", r) + `</button></form>`
	}
	writeCeremonyPage(w, status, ceremonyPageShell("", html.EscapeString(title), body, "", r))
}

// Only an explicit, same-browser POST with an unguessable anti-CSRF value can
// invalidate an in-progress attempt. Refreshing GET is idempotent.
func (b *clientlessBroker) handleRetry(w http.ResponseWriter, r *http.Request) {
	authResponseHeaders(w)
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.ParseForm() != nil {
		http.Error(w, "invalid retry", 400)
		return
	}
	session, ok := browserSession(r)
	if !ok || len(r.PostForm["request_id"]) != 1 || len(r.PostForm["csrf"]) != 1 {
		http.Error(w, "invalid retry", 403)
		return
	}
	id := r.PostForm.Get("request_id")
	b.mu.Lock()
	c := b.ceremonies[id]
	if c == nil || c.browserHash != sha256.Sum256([]byte(session)) || c.csrf == "" || c.csrf != r.PostForm.Get("csrf") || c.succeeded || c.busy || !time.Now().Before(c.startExpires) {
		b.mu.Unlock()
		http.Error(w, "retry unavailable; request a fresh link", 409)
		return
	}
	delete(b.pending, c.state)
	c.restart = true
	query := c.startQuery
	b.mu.Unlock()
	next := r.Clone(r.Context())
	http.Redirect(w, next, "/clientless/auth/start?"+query, http.StatusSeeOther)
}
