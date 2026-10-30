package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func ceremonyFixture(t *testing.T) (*clientlessBroker, *federatedAuthGate) {
	t.Helper()
	reg := idpregistry.NewStore()
	_, err := reg.Upsert(idpregistry.Connection{IdPID: "corp", TenantID: "tenant", Type: "oidc", Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/auth", ClientID: "client", VerifiedDomains: []string{"example"}})
	if err != nil {
		t.Fatal(err)
	}
	authTestAssign(t, reg, "tenant", "device", "user", "corp")
	signer, _ := newDeviceBindingSigner()
	store := grantstore.NewStore()
	return newClientlessBroker(reg, store, nil, "https://portal.example", "tenant", time.Hour, signer), &federatedAuthGate{registry: reg, signer: signer, brokerBaseURL: "https://portal.example", tenantID: "tenant", grants: store}
}

func TestSignedRequestUsesOpaqueFleetStableGrantID(t *testing.T) {
	a := newDeviceBindingSignerFromSecret("test-shared-deployment-key")
	b := newDeviceBindingSignerFromSecret("test-shared-deployment-key")
	other := newDeviceBindingSignerFromSecret("other-test-deployment-key")
	requestID := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	id := a.grantIDForRequest(requestID)
	if id == "" || id == requestID || id != b.grantIDForRequest(requestID) ||
		id == other.grantIDForRequest(requestID) || id == a.grantIDForRequest("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") ||
		(*deviceBindingSigner)(nil).grantIDForRequest(requestID) != "" {
		t.Fatal("signed request grant ID must be opaque, stable only for the same fleet and request")
	}
}

func TestCeremonyLifetimeAndBrowserBinding(t *testing.T) {
	b, g := ceremonyFixture(t)
	link := authTestSignedLink(g, g.stepUpURLFor("app:22", "corp", "", "device", "tenant"))
	start := httptest.NewRecorder()
	b.startForTest(start, httptest.NewRequest("GET", link, nil))
	if start.Code != 302 {
		t.Fatal(start.Code)
	}
	cookies := start.Result().Cookies()
	auth, _ := url.Parse(start.Header().Get("Location"))
	state := auth.Query().Get("state")
	// Wrong browser must not consume the legitimate attempt.
	wrong := httptest.NewRecorder()
	b.handleCallback(wrong, httptest.NewRequest("GET", "https://portal.example/clientless/auth/callback?state="+state+"&error=access_denied", nil))
	if wrong.Code == 200 || len(b.pending) != 1 {
		t.Fatal("wrong browser consumed state")
	}
	repeat := httptest.NewRequest("GET", link, nil)
	for _, c := range cookies {
		repeat.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.startForTest(rec, repeat)
	if rec.Header().Get("Location") != start.Header().Get("Location") || len(b.pending) != 1 {
		t.Fatal("GET refresh replaced the attempt")
	}
	cancel := httptest.NewRequest("GET", "https://portal.example/clientless/auth/callback?state="+state+"&error=access_denied", nil)
	for _, c := range cookies {
		cancel.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	b.handleCallback(rec, cancel)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "Retry authentication") || len(b.pending) != 0 {
		t.Fatal("cancel must permit a safe explicit retry")
	}
	original, _ := url.Parse(link)
	id := original.Query().Get("request_id")
	c := b.ceremonies[id]
	deadline := c.expires
	form := url.Values{"request_id": {id}, "csrf": {c.csrf}}
	retry := httptest.NewRequest("POST", "https://portal.example/clientless/auth/retry", strings.NewReader(form.Encode()))
	retry.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		retry.AddCookie(cookie)
	}
	rec = httptest.NewRecorder()
	b.handleRetry(rec, retry)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body.String())
	}
	confirm := httptest.NewRequest("GET", rec.Header().Get("Location"), nil)
	for _, cookie := range cookies {
		confirm.AddCookie(cookie)
	}
	rec = httptest.NewRecorder()
	b.startForTest(rec, confirm)
	next, _ := url.Parse(rec.Header().Get("Location"))
	if next.Query().Get("state") == state || !b.ceremonies[id].expires.Equal(deadline) || !b.pending[next.Query().Get("state")].deadline.Equal(deadline) {
		t.Fatal("retry must rotate state without extending deadline")
	}
	old := httptest.NewRecorder()
	b.handleCallback(old, cancel)
	if len(b.pending) != 1 {
		t.Fatal("late old callback invalidated new attempt")
	}
	if start.Header().Get("Referrer-Policy") != "no-referrer" || start.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authentication redirects leak referrer/cache")
	}
	for _, cookie := range cookies {
		if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatal("weak browser binding cookie")
		}
	}
}

func TestCeremonyRejectsOldTamperedDuplicateAndUnboundLinks(t *testing.T) {
	b, g := ceremonyFixture(t)
	u, _ := url.Parse(authTestSignedLink(g, g.stepUpURLFor("app:22", "corp", "", "device", "tenant")))
	for _, field := range []string{"issued_at", "expires_at", "request_id", "portal_origin"} {
		for _, mode := range []string{"missing", "tamper", "duplicate"} {
			q := u.Query()
			switch mode {
			case "missing":
				q.Del(field)
			case "tamper":
				q.Set(field, "invalid")
			case "duplicate":
				q.Add(field, q.Get(field))
			}
			rec := httptest.NewRecorder()
			b.startForTest(rec, httptest.NewRequest("GET", "/clientless/auth/start?"+q.Encode(), nil))
			if rec.Code < 400 || len(b.pending) != 0 {
				t.Fatalf("accepted %s %s", mode, field)
			}
		}
	}
	q := u.Query()
	_ = addAuthStartLifetime(q, time.Now().Add(-3*time.Minute))
	q.Set("requirements_sig", g.signer.signRequirements(q))
	rec := httptest.NewRecorder()
	b.startForTest(rec, httptest.NewRequest("GET", "/clientless/auth/start?"+q.Encode(), nil))
	if rec.Code != 401 {
		t.Fatal("expired signed link admitted")
	}
}

func TestCeremonyCannotMoveToAnotherTrustedPortal(t *testing.T) {
	b, g := ceremonyFixture(t)
	link := authTestSignedLink(g, g.stepUpURLFor("app:22", "corp", "", "device", "tenant"))
	// Even with the same cluster signer, another Portal cannot start this request.
	b.selfBaseURL = "https://other-portal.example"
	rec := httptest.NewRecorder()
	b.startForTest(rec, httptest.NewRequest("GET", link, nil))
	if rec.Code < 400 || len(b.pending) != 0 || len(b.ceremonies) != 0 {
		t.Fatal("request's Portal binding was ignored")
	}
}

func TestCeremonyWrongBrowserAndConcurrentCallbackReservation(t *testing.T) {
	b, g := ceremonyFixture(t)
	start := httptest.NewRecorder()
	b.startForTest(start, httptest.NewRequest("GET", authTestSignedLink(g, g.stepUpURLFor("app:22", "corp", "", "device", "tenant")), nil))
	auth, _ := url.Parse(start.Header().Get("Location"))
	state := auth.Query().Get("state")
	r := httptest.NewRequest("GET", "https://portal.example/clientless/auth/callback", nil)
	for _, c := range start.Result().Cookies() {
		r.AddCookie(c)
	}
	if _, ok := b.takePending(r, state, time.Now()); !ok {
		t.Fatal("legitimate callback refused")
	}
	if _, ok := b.takePending(r, state, time.Now()); ok {
		t.Fatal("same callback reserved twice")
	}
	// Abandoned requests are bounded and cleaned before accepting more work.
	b.mu.Lock()
	b.sweepAuthLocked(time.Now().Add(pendingAuthTTL + time.Second))
	b.mu.Unlock()
	if len(b.pending) != 0 || len(b.ceremonies) != 0 {
		t.Fatal("expired ceremony retained")
	}
}

func TestCeremonyCapacity(t *testing.T) {
	b, _ := ceremonyFixture(t)
	for i := 0; i < authDevicePendingLimit; i++ {
		b.pending[string(rune(i+1))] = pendingAuth{tenantID: "tenant", boundDevice: "device", createdAt: time.Now(), browserHash: sha256.Sum256([]byte("binding"))}
	}
	if b.authCapacityLocked("tenant", "device") {
		t.Fatal("device can allocate unbounded pending authentication")
	}
	if !b.authCapacityLocked("other", "device") {
		t.Fatal("tenant capacity was conflated")
	}
}

func TestCeremonyAnonymousCallbackRetainsCapacityReservation(t *testing.T) {
	b, _ := ceremonyFixture(t)
	start := httptest.NewRecorder()
	b.startForTest(start, httptest.NewRequest("GET", "https://portal.example/clientless/auth/start?idp=corp&return_to=app.example%3A22", nil))
	if start.Code != http.StatusFound {
		t.Fatal(start.Code)
	}
	auth, _ := url.Parse(start.Header().Get("Location"))
	state := auth.Query().Get("state")
	r := httptest.NewRequest("GET", "https://portal.example/clientless/auth/callback", nil)
	for _, cookie := range start.Result().Cookies() {
		r.AddCookie(cookie)
	}
	if _, ok := b.takePending(r, state, time.Now()); !ok {
		t.Fatal("callback refused")
	}
	if len(b.pending) != 1 || !b.pending[state].consuming {
		t.Fatal("in-flight callback escaped capacity accounting")
	}
	if _, ok := b.takePending(r, state, time.Now()); ok {
		t.Fatal("callback reserved twice")
	}
	b.endAuthCallback(state, "")
	if len(b.pending) != 0 {
		t.Fatal("completed callback retained capacity")
	}
}

func TestAuthenticatedResumeRejectsNewDenyStrongerRequirementAndPolicyRace(t *testing.T) {
	b, g := ceremonyFixture(t)
	now := time.Now()
	_, err := b.grants.Mint(authTestBindGrant(t, g, grantstore.Grant{GrantID: "grant", TenantID: "tenant", DeviceID: "device", IdPID: "corp", UserID: "user", ACR: "2", Scope: "app:22"}), time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	generation := uint64(1)
	dec := model.AccessDecision{TenantID: "tenant", Decision: "authenticate_required", Actions: []model.DecisionAction{{Type: "prompt_reauthentication", Metadata: map[string]any{"required_idp_id": "corp", "min_acr": "2"}}}}
	check := func(change bool) bool {
		_, ok := authorizeAuthenticatedResume(g, "tenant", "device", "app:22", now, func() uint64 { return generation }, func() (model.AccessDecision, bool) {
			if change {
				generation++
			}
			return dec, true
		}, "", testAuthPrincipal, testAuthSession)
		return ok
	}
	if !check(false) {
		t.Fatal("matching current requirement denied")
	}
	dec.Decision = "deny"
	if check(false) {
		t.Fatal("old grant bypassed new deny")
	}
	dec.Decision = "authenticate_required"
	dec.Actions[0].Metadata["min_acr"] = "3"
	if check(false) {
		t.Fatal("weaker old grant bypassed stronger requirement")
	}
	dec.Decision = "allow"
	if check(true) {
		t.Fatal("policy changed during resume accepted")
	}
}

func TestCeremonyRateLimitsAndActualPeer(t *testing.T) {
	b, _ := ceremonyFixture(t)
	now := time.Now()
	for i := 0; i < 10; i++ {
		if !b.allowAuthStartLocked("tenant", "device", "127.0.0.1", now) {
			t.Fatal("early refusal")
		}
	}
	if b.allowAuthStartLocked("tenant", "device", "127.0.0.2", now) {
		t.Fatal("device quota bypassed with another IP")
	}
	if !b.allowAuthStartLocked("tenant", "other", "127.0.0.1", now) {
		t.Fatal("device quotas conflated")
	}
	if !b.allowAuthStartLocked("tenant", "device", "127.0.0.1", now.Add(time.Minute)) {
		t.Fatal("quota did not expire")
	}
	for i := 0; i < 10; i++ {
		if !b.allowAuthStartLocked("tenant", "", "192.0.2.1", now.Add(time.Minute)) {
			t.Fatal("anonymous early refusal")
		}
	}
	if b.allowAuthStartLocked("other", "", "192.0.2.1", now.Add(time.Minute)) {
		t.Fatal("anonymous IP quota bypassed")
	}
	r := httptest.NewRequest("GET", "https://portal.example", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if authPeerIP(r) != "192.0.2.1" {
		t.Fatal("trusted attacker forwarding header")
	}
}

func TestCeremonyCompletedRequestsUseSeparateReplayBudget(t *testing.T) {
	b, _ := ceremonyFixture(t)
	for i := 0; i < 32; i++ {
		if !b.authCapacityLocked("tenant", "device") {
			t.Fatalf("completed request %d blocked next destination", i)
		}
		b.ceremonies[fmt.Sprint(i)] = &authCeremony{tenant: "tenant", device: "device", succeeded: true}
	}
	if b.authCapacityLocked("tenant", "device") {
		t.Fatal("unbounded per-device replay memory")
	}
}

func TestCeremonyAnonymousCannotConsumeSignedCapacity(t *testing.T) {
	b, _ := ceremonyFixture(t)
	for i := 0; i < 64; i++ {
		b.pending[fmt.Sprint(i)] = pendingAuth{tenantID: "tenant", sourceIP: fmt.Sprint(i)}
	}
	if b.authCapacityLocked("tenant", "") {
		t.Fatal("anonymous memory not bounded")
	}
	if !b.authCapacityLocked("tenant", "device") {
		t.Fatal("anonymous work exhausted signed tenant capacity")
	}
	now := time.Now()
	for i := 0; i < 100; i++ {
		if !b.allowAuthStartLocked("tenant", "", fmt.Sprint(i), now) {
			t.Fatal(i)
		}
	}
	if b.allowAuthStartLocked("tenant", "", "other", now) {
		t.Fatal("anonymous rate not bounded")
	}
	if !b.allowAuthStartLocked("tenant", "device", "same", now) {
		t.Fatal("anonymous starts exhausted signed rate")
	}
	r := httptest.NewRequest("GET", "https://portal.example", nil)
	r.RemoteAddr = "[2001:db8:1234:5678::1]:1"
	first := authPeerIP(r)
	r.RemoteAddr = "[2001:db8:1234:5678:aaaa:bbbb:cccc:dddd]:2"
	if first != authPeerIP(r) {
		t.Fatal("IPv6 privacy address bypass")
	}
}

func TestCeremonyMisconfiguredBaseFailsBeforeRedirect(t *testing.T) {
	for _, base := range []string{"http://portal.example", "https://portal.example/subpath"} {
		b, _ := ceremonyFixture(t)
		b.selfBaseURL = base
		w := httptest.NewRecorder()
		b.startForTest(w, httptest.NewRequest("GET", "/clientless/auth/start", nil))
		if w.Code != 503 || w.Header().Get("Location") != "" || len(b.pending) != 0 {
			t.Fatal("misconfigured Portal silently started a broken ceremony")
		}
	}
}

func TestCeremonyClientClockToleranceDoesNotExtendServerLifetime(t *testing.T) {
	now := time.Now().UTC()
	q := url.Values{}
	if err := addAuthStartLifetime(q, now); err != nil {
		t.Fatal(err)
	}
	if validateAuthStartLifetime(q, now.Add(120*time.Second)) == nil {
		t.Fatal("server accepted expired start")
	}
	if validateAuthStartLifetime(q, now.Add(-6*time.Second)) == nil {
		t.Fatal("server clock validation weakened")
	}
}

func TestCeremonyRetainedRecordsIsolateTenantAndDevice(t *testing.T) {
	b, _ := ceremonyFixture(t)
	for i := 0; i < 128; i++ {
		b.ceremonies[fmt.Sprint(i)] = &authCeremony{tenant: "busy", device: fmt.Sprint(i % 4), finished: true}
	}
	if b.authCapacityLocked("busy", "new-device") {
		t.Fatal("tenant retained quota bypassed by another device")
	}
	if !b.authCapacityLocked("other", "device") {
		t.Fatal("one tenant blocked another")
	}
	for i := 128; i < 1024; i++ {
		b.ceremonies[fmt.Sprint(i)] = &authCeremony{tenant: fmt.Sprint(i), device: "d", finished: true}
	}
	if b.authCapacityLocked("new-tenant", "d") {
		t.Fatal("global memory unbounded")
	}
	b.sweepAuthLocked(time.Now())
	if !b.authCapacityLocked("busy", "device") {
		t.Fatal("expired quota not reclaimed")
	}
}
