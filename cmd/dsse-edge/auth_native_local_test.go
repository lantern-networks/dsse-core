package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/oidcbroker"
)

// Local atomic authority fixture: separate Edge stores exercise the production
// shared-store refresh/mint/revocation path. This is not a database/IdP product
// acceptance claim; the IdP below is an isolated TLS mock with real signed JWTs.
type authLocalAuthority struct {
	mu  sync.Mutex
	raw []byte
}

func (a *authLocalAuthority) Load() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.raw...), nil
}
func (a *authLocalAuthority) Save(raw []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.raw = append([]byte(nil), raw...)
	return nil
}
func (a *authLocalAuthority) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := f(a.raw)
	if err == nil {
		a.raw = append([]byte(nil), raw...)
	}
	return err
}

func authTestFrame(w io.Writer, id uint32, typ byte, data []byte) error {
	frame := make([]byte, 9+len(data))
	binary.BigEndian.PutUint32(frame[:4], id)
	frame[4] = typ
	binary.BigEndian.PutUint32(frame[5:9], uint32(len(data)))
	copy(frame[9:], data)
	_, err := w.Write(frame)
	return err
}

func TestAuthLocalNativeWaitOIDCSharedGrantAndRevocation(t *testing.T) {
	key, jwks := brokerTestKeyJWKS(t)
	var issuer string
	var mu sync.Mutex
	type codeRecord struct{ nonce, challenge, redirect string }
	codes := make(map[string]codeRecord)
	idpMux := http.NewServeMux()
	idpMux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "PKCE required", 400)
			return
		}
		code, _ := oidcbroker.NewOpaqueToken()
		mu.Lock()
		codes[code] = codeRecord{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")}
		mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), 302)
	})
	idpMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		record, ok := codes[r.Form.Get("code")]
		delete(codes, r.Form.Get("code"))
		mu.Unlock()
		if !ok || oidcbroker.CodeChallengeS256(r.Form.Get("code_verifier")) != record.challenge || r.Form.Get("redirect_uri") != record.redirect {
			http.Error(w, "code rejected", 400)
			return
		}
		claims := map[string]any{"iss": issuer, "aud": "client", "sub": "user", "email": "user@example.com", "email_verified": true, "nonce": record.nonce, "exp": time.Now().Add(time.Hour).Unix(), "auth_time": time.Now().Unix(), "acr": "2", "amr": []string{"pwd", "otp"}}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": brokerSignJWT(t, key, claims)})
	})
	idpMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(jwks) })
	idp := httptest.NewTLSServer(idpMux)
	defer idp.Close()
	issuer = idp.URL
	registry := idpregistry.NewStore()
	_, err := registry.Upsert(idpregistry.Connection{IdPID: "corp", TenantID: "tenant", Type: "oidc", Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks", ClientID: "client", VerifiedDomains: []string{"example.com"}, DomainMode: "email_domain"})
	if err != nil {
		t.Fatal(err)
	}
	authTestAssign(t, registry, "tenant", "device", "user", "corp")
	authority := &authLocalAuthority{}
	storeA, storeB := grantstore.NewStore(), grantstore.NewStore()
	for _, s := range []*grantstore.Store{storeA, storeB} {
		if err = s.SetPersister(authority); err != nil {
			t.Fatal(err)
		}
	}
	signer, _ := newDeviceBindingSigner()
	broker := newClientlessBroker(registry, storeA, idp.Client(), "https://portal.example", "tenant", time.Hour, signer)
	gate := &federatedAuthGate{registry: registry, grants: storeB, signer: signer, brokerBaseURL: "https://portal.example", tenantID: "tenant"}
	age := int64(0)
	req := federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, IdP: "corp", ACR: "2", AMR: []string{"otp"}, MaxAgeSeconds: &age, Scope: "app.internal:22"}
	link := gate.stepUpURLWithRequirements("app.internal:22", "device", "tenant", req)
	startLink, _ := url.Parse(link)
	req.RequestID = startLink.Query().Get("request_id")
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	forwarded := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		edgeplane.NewSteerMux(server).Run(func(id uint32, dst string, vc *edgeplane.MuxVirtualConn) {
			defer vc.Close()
			close(ready)
			if !waitForStepUpGrant(ctx, gate, "tenant", "device", req, vc, 8*time.Second, link) {
				forwarded <- "not authorized"
				return
			}
			dec := model.AccessDecision{TenantID: "tenant", Decision: "authenticate_required", Actions: []model.DecisionAction{{Type: "prompt_reauthentication", Metadata: map[string]any{"required_idp_id": "corp", "min_acr": "2", "required_amr": []string{"otp"}, "max_age_seconds": int64(0)}}}}
			if _, ok := authorizeAuthenticatedResume(gate, "tenant", "device", dst, time.Now(), func() uint64 { return 1 }, func() (model.AccessDecision, bool) { return dec, true }, req.RequestID, testAuthPrincipal, testAuthSession); !ok {
				forwarded <- "reevaluation denied"
				return
			}
			data := make([]byte, 5)
			if _, err := io.ReadFull(vc, data); err != nil {
				forwarded <- "read failed"
				return
			}
			forwarded <- string(data)
		})
	}()
	if err = authTestFrame(client, 1, 0, []byte("app.internal:22")); err != nil {
		t.Fatal(err)
	}
	<-ready
	header := make([]byte, 9)
	if _, err = io.ReadFull(client, header); err != nil {
		t.Fatal(err)
	}
	if header[4] != 3 {
		t.Fatal("no authentication notification")
	}
	size := binary.BigEndian.Uint32(header[5:9])
	if size > 16384 {
		t.Fatal("unbounded notification")
	}
	notification := make([]byte, size)
	if _, err = io.ReadFull(client, notification); err != nil {
		t.Fatal(err)
	}
	if string(notification) != link {
		t.Fatal("wrong request delivered")
	}
	if err = authTestFrame(client, 1, 1, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-forwarded:
		t.Fatal("data forwarded before authentication")
	default:
	}
	start := httptest.NewRecorder()
	broker.startForTest(start, httptest.NewRequest("GET", link, nil))
	if start.Code != 302 {
		t.Fatal("start rejected", start.Code)
	}
	browser := *idp.Client()
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := browser.Get(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	callbackURL, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewRequest("GET", callbackURL.String(), nil)
	for _, c := range start.Result().Cookies() {
		callback.AddCookie(c)
	}
	deadline := broker.pending[callbackURL.Query().Get("state")].deadline
	result := httptest.NewRecorder()
	broker.handleCallback(result, callback)
	if result.Code != 200 {
		t.Fatal("callback rejected", result.Code)
	}
	if err = storeB.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	// Reconnection is a new request and cannot borrow the held request's result.
	reconnect := req
	reconnect.RequestID = "different-request"
	if gate.hasLiveGrantWithRequirements("tenant", "device", reconnect) {
		t.Fatal("fresh authentication reused on reconnect")
	}
	rows := storeB.ListForAuthorization("tenant")
	if len(rows) != 1 || rows[0].ReauthenticationStartedAt == "" {
		t.Fatal("validated fresh-authentication evidence was not shared")
	}
	select {
	case data := <-forwarded:
		if data != "hello" {
			t.Fatal(data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("held flow did not resume")
	}
	rows = storeA.ListAll()
	if len(rows) != 1 {
		t.Fatal("expected exactly one grant")
	}
	expiry, parseErr := time.Parse(time.RFC3339, rows[0].ExpiresAt)
	if parseErr != nil || expiry.After(deadline) {
		t.Fatal("single-request grant outlives ceremony deadline")
	}
	// Browser callback replay cannot mint another grant.
	replay := httptest.NewRecorder()
	broker.handleCallback(replay, callback)
	if replay.Code < 400 || len(storeA.ListAll()) != 1 {
		t.Fatal("callback replay accepted")
	}
	if gate.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("peer reused a consumed single-request grant")
	}
	other := req
	other.Scope = "other.internal:22"
	if gate.hasLiveGrantWithRequirements("tenant", "device", other) || gate.hasLiveGrantWithRequirements("tenant", "other-device", req) {
		t.Fatal("scope/device isolation lost")
	}
	if _, _, err = storeA.RevokeForTenant("tenant", rows[0].GrantID); err != nil {
		t.Fatal(err)
	}
	if err = storeB.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if gate.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("peer accepted revoked grant")
	}
	_ = client.Close()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal(fmt.Errorf("mux did not stop"))
	}
}

func TestAuthWaitRetainsQuotaAndBufferDuringCurrentPolicyCheck(t *testing.T) {
	b, g := ceremonyFixture(t)
	_, err := b.grants.Mint(authTestBindGrant(t, g, grantstore.Grant{GrantID: "live", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Scope: "app:22"}), time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	entered := make(chan struct{})
	resume := make(chan struct{})
	result := make(chan bool, 1)
	go edgeplane.NewSteerMux(server).Run(func(_ uint32, _ string, vc *edgeplane.MuxVirtualConn) {
		ok := waitForStepUpGrantChecked(context.Background(), g, "tenant", "device", federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, Scope: "app:22"}, vc, 2*time.Second, "", func() bool { close(entered); <-resume; return true })
		result <- ok
	})
	if err := authTestFrame(client, 1, 0, []byte("app:22")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("did not reach real policy-check boundary")
	}
	g.waitBudget.mu.Lock()
	slots := g.waitBudget.total
	g.waitBudget.mu.Unlock()
	if slots != 1 {
		t.Error("quota released before policy check")
	}
	if err := authTestFrame(client, 1, 1, make([]byte, 16*1024+1)); err != nil {
		t.Fatal(err)
	}
	h := make([]byte, 9)
	if _, err := io.ReadFull(client, h); err != nil {
		t.Fatal(err)
	}
	if h[4] != 2 {
		t.Fatal("buffer was expanded before policy check")
	}
	close(resume)
	select {
	case ok := <-result:
		if ok {
			t.Fatal("overflowed flow resumed")
		}
	case <-time.After(time.Second):
		t.Fatal("policy check did not end")
	}
	g.waitBudget.mu.Lock()
	slots = g.waitBudget.total
	g.waitBudget.mu.Unlock()
	if slots != 0 {
		t.Fatal("quota leaked after refusal")
	}
}
