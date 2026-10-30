package main

import (
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var confirmationInput = regexp.MustCompile(`name="confirmation" value="([A-Za-z0-9_.-]+)"`)
var authenticationRefresh = regexp.MustCompile(`<meta http-equiv="refresh" content="0;url=([^"]+)">`)

func TestAuthenticationPostNavigationPreservesRestrictiveFormPolicy(t *testing.T) {
	target := `https://idp.example/authorize?state=quoted%22value&client_id=example`
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request := httptest.NewRequest(method, "https://portal.example/clientless/auth/start", nil)
		response := httptest.NewRecorder()
		navigateToAuthenticationProvider(response, request, target)
		if method == http.MethodGet {
			if response.Code != http.StatusFound || response.Header().Get("Location") != target {
				t.Fatal("non-form navigation changed")
			}
			continue
		}
		if response.Code != http.StatusOK || response.Header().Get("Location") != "" || authenticationNavigationForTest(response) != target {
			t.Fatal("form POST must finish before cross-origin navigation")
		}
		if !strings.Contains(response.Header().Get("Content-Security-Policy"), "form-action 'self'") || response.Header().Get("Referrer-Policy") != "no-referrer" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("navigation weakened form, referrer or caching protection")
		}
		if strings.Contains(response.Body.String(), "location.replace") || !strings.Contains(response.Body.String(), `rel="noreferrer noopener"`) || !strings.Contains(response.Body.String(), "&amp;client_id=") {
			t.Fatal("navigation must remain independent of script, escaped, and offer a safe link fallback")
		}
	}
}

// Model the browser's automatic document navigation after the same-origin POST.
// Existing ceremony tests inspect the resulting IdP navigation, while direct
// confirmation tests below also verify the actual intermediate HTTP response.
func authenticationNavigationForTest(w *httptest.ResponseRecorder) string {
	if w.Code == http.StatusFound {
		return w.Header().Get("Location")
	}
	if w.Code == http.StatusOK {
		if match := authenticationRefresh.FindStringSubmatch(w.Body.String()); len(match) == 2 {
			return html.UnescapeString(match[1])
		}
	}
	return ""
}

// Existing ceremony tests explicitly simulate the new user confirmation too;
// no production handler has a bypass for tests or anonymous clients.
func (b *clientlessBroker) startForTest(w http.ResponseWriter, r *http.Request) {
	first := httptest.NewRecorder()
	b.handleStart(first, r)
	match := confirmationInput.FindStringSubmatch(first.Body.String())
	if first.Code != 200 || len(match) != 2 {
		for k, values := range first.Header() {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(first.Code)
		_, _ = io.Copy(w, first.Body)
		return
	}
	post := r.Clone(r.Context())
	post.Method = "POST"
	post.Body = io.NopCloser(strings.NewReader(url.Values{"confirmation": {match[1]}}.Encode()))
	post.Header = r.Header.Clone()
	post.Header.Set("Origin", b.selfBaseURL)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range first.Result().Cookies() {
		post.AddCookie(c)
		http.SetCookie(w, c)
	}
	response := httptest.NewRecorder()
	b.handleStart(response, post)
	for k, values := range response.Header() {
		for _, value := range values {
			w.Header().Add(k, value)
		}
	}
	if target := authenticationNavigationForTest(response); response.Code == http.StatusOK && target != "" {
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
		return
	}
	w.WriteHeader(response.Code)
	_, _ = io.Copy(w, response.Body)
}

func TestUnconfirmedDestinationDoesNotContactAuthority(t *testing.T) {
	var calls atomic.Int32
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
	defer cp.Close()
	b, g := ceremonyFixture(t)
	b.authorityRequired = true
	b.authority = &grantCPReporter{url: cp.URL + "/grant-report", client: cp.Client()}
	link := authTestSignedLink(g, g.stepUpURLFor("app:22", "corp", "", "device", "tenant"))
	page := httptest.NewRecorder()
	b.handleStart(page, httptest.NewRequest("GET", link, nil))
	if page.Code != 200 || calls.Load() != 0 || len(b.pending) != 0 {
		t.Fatal("opening confirmation contacted authority")
	}
	confirmed := httptest.NewRecorder()
	b.startForTest(confirmed, httptest.NewRequest("GET", link, nil))
	if confirmed.Code != 503 || calls.Load() != 1 || len(b.pending) != 0 || len(b.grants.ListAll()) != 0 {
		t.Fatal("confirmed CP outage failed open")
	}
}

func TestDestinationConfirmationCanonicalizesDefaultPortAndHostname(t *testing.T) {
	b, g := ceremonyFixture(t)
	b.selfBaseURL = "https://PORTAL.example:443"
	link := authTestSignedLink(g, g.stepUpURLFor("app:22", "corp", "", "device", "tenant"))
	get := httptest.NewRecorder()
	b.handleStart(get, httptest.NewRequest("GET", link, nil))
	match := confirmationInput.FindStringSubmatch(get.Body.String())
	if len(match) != 2 {
		t.Fatal("confirmation missing")
	}
	post := httptest.NewRequest("POST", link, strings.NewReader(url.Values{"confirmation": {match[1]}}.Encode()))
	post.Header.Set("Origin", "https://portal.example")
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range get.Result().Cookies() {
		post.AddCookie(cookie)
	}
	result := httptest.NewRecorder()
	b.handleStart(result, post)
	if result.Code != http.StatusOK || authenticationNavigationForTest(result) == "" {
		t.Fatal("standard browser default-port Origin rejected", result.Code)
	}
}

func TestDestinationConfirmationRequiresExplicitBoundSingleUsePost(t *testing.T) {
	for _, mode := range []string{"valid", "cross-origin", "other-browser", "tampered-query", "expired", "duplicate-token"} {
		t.Run(mode, func(t *testing.T) {
			b, g := ceremonyFixture(t)
			link := authTestSignedLink(g, g.stepUpURLFor("app:22", "corp", "", "device", "tenant"))
			get := httptest.NewRecorder()
			b.handleStart(get, httptest.NewRequest("GET", link, nil))
			if get.Code != 200 || get.Header().Get("Location") != "" || !strings.Contains(get.Body.String(), "app:22") || len(b.pending) != 0 || len(b.grants.ListAll()) != 0 {
				t.Fatal("browser open performed authentication")
			}
			if get.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(get.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
				t.Fatal("confirmation can be framed")
			}
			if get.Header().Get("Referrer-Policy") != "same-origin" {
				t.Fatal("form would suppress its Origin header")
			}
			token := confirmationInput.FindStringSubmatch(get.Body.String())[1]
			values := url.Values{"confirmation": {token}}
			if mode == "duplicate-token" {
				values.Add("confirmation", token)
			}
			if mode == "tampered-query" {
				link += "&login_hint=changed"
			}
			if mode == "expired" {
				c := b.confirmations[token]
				c.expires = time.Now().Add(-time.Second)
				b.confirmations[token] = c
			}
			post := httptest.NewRequest("POST", link, strings.NewReader(values.Encode()))
			post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			post.Header.Set("Origin", b.selfBaseURL)
			if mode == "cross-origin" {
				post.Header.Set("Origin", "https://elsewhere.example")
			}
			if mode != "other-browser" {
				for _, c := range get.Result().Cookies() {
					post.AddCookie(c)
				}
			}
			result := httptest.NewRecorder()
			b.handleStart(result, post)
			if mode == "valid" {
				if result.Code != http.StatusOK || authenticationNavigationForTest(result) == "" || len(b.pending) != 1 {
					t.Fatal("confirmed authentication did not start", result.Code)
				}
				replay := httptest.NewRequest("POST", link, strings.NewReader(values.Encode()))
				replay.Header = post.Header.Clone()
				denied := httptest.NewRecorder()
				b.handleStart(denied, replay)
				if denied.Code != 403 || len(b.pending) != 1 {
					t.Fatal("confirmation replay accepted")
				}
			} else if result.Code < 400 || len(b.pending) != 0 {
				t.Fatal("invalid confirmation started authentication", mode, result.Code)
			}
		})
	}
}

func TestDestinationConfirmationCanMoveBetweenFleetEdges(t *testing.T) {
	for _, mode := range []string{"valid", "different-browser", "different-query", "different-key", "inactive-recovery"} {
		t.Run(mode, func(t *testing.T) {
			first, gate := ceremonyFixture(t)
			first.recoverySharedKey = true
			link := authTestSignedLink(gate, gate.stepUpURLFor("app:22", "corp", "", "device", "tenant"))
			get := httptest.NewRecorder()
			first.handleStart(get, httptest.NewRequest("GET", link, nil))
			match := confirmationInput.FindStringSubmatch(get.Body.String())
			if len(match) != 2 || !strings.HasPrefix(match[1], "dc1.") {
				t.Fatal("fleet proof missing")
			}
			peer := newClientlessBroker(first.registry, first.grants, nil, first.selfBaseURL, first.tenantID, time.Hour, first.signer)
			peer.recoverySharedKey = true
			if mode == "different-key" {
				peer.signer = newDeviceBindingSignerFromSecret("other-deployment")
			}
			if mode == "inactive-recovery" {
				peer.recoverySharedKey = false
			}
			if mode == "different-query" {
				u, _ := url.Parse(link)
				q := u.Query()
				q.Set("return_to", "other:22")
				q.Set("requirements_sig", gate.signer.signRequirements(q))
				u.RawQuery = q.Encode()
				link = u.String()
			}
			post := httptest.NewRequest("POST", link, strings.NewReader(url.Values{"confirmation": {match[1]}}.Encode()))
			post.Header.Set("Origin", peer.selfBaseURL)
			post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if mode != "different-browser" {
				for _, cookie := range get.Result().Cookies() {
					post.AddCookie(cookie)
				}
			}
			result := httptest.NewRecorder()
			peer.handleStart(result, post)
			if mode == "valid" {
				if result.Code != http.StatusOK || len(peer.pending) != 1 {
					t.Fatal("confirmation required backend affinity", result.Code)
				}
				location, _ := url.Parse(authenticationNavigationForTest(result))
				if !strings.HasPrefix(location.Query().Get("state"), sealedAuthStatePrefix) {
					t.Fatal("confirmation lost recovery context")
				}
			} else if result.Code < 400 || len(peer.pending) != 0 {
				t.Fatal("peer accepted invalid confirmation", mode, result.Code)
			}
		})
	}
}
