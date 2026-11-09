package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// Security review S12 (2026-11-07). The account lock stopped password guessing and handed anybody who knew an
// administrator's address a way to keep that administrator locked out. The source is now bounded as well.
func TestAFloodOfSignInAttemptsFromOneAddressIsAnswered429(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adminAuth, _ := adminRBACMatrixAuthStore(t)
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		AdminAuth: adminAuth, LocalCredentials: newLocalAdminCredentialStore("Lantern DSSE"),
	})
	codes := map[int]int{}
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodPost, "/admin/login/password", strings.NewReader(`{"email":"somebody@corp.example.com","password":"wrong"}`))
		req.RemoteAddr = "203.0.113.7:4000"
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		codes[rec.Code]++
	}
	if codes[http.StatusTooManyRequests] == 0 {
		t.Fatalf("sixty wrong passwords from one address were all judged individually: %v", codes)
	}
	if codes[http.StatusUnauthorized] == 0 {
		t.Fatalf("the first attempts from the address were not judged at all: %v", codes)
	}
	// Another address is not punished for the first one's flood.
	req := httptest.NewRequest(http.MethodPost, "/admin/login/password", strings.NewReader(`{"email":"somebody@corp.example.com","password":"wrong"}`))
	req.RemoteAddr = "198.51.100.9:4000"
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("a different address was throttled for the first address's flood")
	}
}

// Review R2: the Console proxies every administrator's sign-in from one address, so the tight bound is keyed
// on (source, account): one person's flood does not lock the next person out from the same Console.
func TestColleaguesBehindOneConsoleAreJudgedOnTheirOwnAccounts(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adminAuth, _ := adminRBACMatrixAuthStore(t)
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		AdminAuth: adminAuth, LocalCredentials: newLocalAdminCredentialStore("Lantern DSSE"),
	})
	attempt := func(email string) int {
		req := httptest.NewRequest(http.MethodPost, "/admin/login/password", strings.NewReader(`{"email":"`+email+`","password":"wrong"}`))
		req.RemoteAddr = "10.77.0.6:4000" // the Console
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 40; i++ {
		attempt("flooder@corp.example.com")
	}
	if code := attempt("flooder@corp.example.com"); code != http.StatusTooManyRequests {
		t.Fatalf("the flooded account from the Console was still judged: %d", code)
	}
	for _, colleague := range []string{"alice@corp.example.com", "bob@corp.example.com", "carol@corp.example.com"} {
		if code := attempt(colleague); code != http.StatusUnauthorized {
			t.Fatalf("%s, from the same Console, was answered %d instead of being judged on their own password", colleague, code)
		}
	}
}

// Re-review RR3: the second factor and the activation steps are keyed on their own token, so one person's
// flood on their challenge or invitation does not consume a bucket every other person behind the Console
// would then meet.
func TestTheSecondFactorAndActivationAreKeyedOnTheirOwnToken(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adminAuth, _ := adminRBACMatrixAuthStore(t)
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		AdminAuth: adminAuth, LocalCredentials: newLocalAdminCredentialStore("Lantern DSSE"),
	})
	post := func(path, body string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.RemoteAddr = "10.77.0.6:4000" // the Console
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 40; i++ {
		post("/admin/login/totp", `{"challenge_token":"the-flooders-challenge","code":"000000"}`)
	}
	if code := post("/admin/login/totp", `{"challenge_token":"the-flooders-challenge","code":"000000"}`); code != http.StatusTooManyRequests {
		t.Fatalf("the flooded challenge was still judged: %d", code)
	}
	if code := post("/admin/login/totp", `{"challenge_token":"a-colleagues-challenge","code":"000000"}`); code == http.StatusTooManyRequests {
		t.Fatal("a colleague's second factor, from the same Console, was throttled for the flooder's challenge")
	}
	for i := 0; i < 40; i++ {
		post("/admin/activate", `{"token":"the-flooders-invitation"}`)
	}
	if code := post("/admin/activate", `{"token":"the-flooders-invitation"}`); code != http.StatusTooManyRequests {
		t.Fatalf("the flooded invitation was still judged: %d", code)
	}
	if code := post("/admin/activate", `{"token":"a-colleagues-invitation"}`); code == http.StatusTooManyRequests {
		t.Fatal("a colleague's invitation, from the same Console, was throttled for the flooder's")
	}
}

// Third review RRR1: the bound and the handler read one body with one decoder. A body carrying both
// "token" and "Token" is served by the handler as the LAST case-insensitive match; the bound must key on
// exactly that, or a changing decoy buys a fresh bucket for the same invitation on every request.
func TestTheBoundReadsTheBodyExactlyAsTheHandlerDoes(t *testing.T) {
	for _, tc := range []struct{ path, body, want string }{
		{"/admin/activate", `{"token":"decoy","Token":"real"}`, "real"},
		{"/admin/activate/password", `{"Token":"real","token":"decoy"}`, "decoy"},
		{"/admin/login/totp", `{"challenge_token":"decoy","CHALLENGE_TOKEN":"real"}`, "real"},
		{"/admin/login/password", `{"email":"decoy@x","Email":"Real@X"}`, "real@x"},
	} {
		var expect string
		switch tc.path {
		case "/admin/activate":
			var v activationTokenRequest
			_ = json.Unmarshal([]byte(tc.body), &v)
			expect = v.Token
		case "/admin/activate/password":
			var v activationPasswordRequest
			_ = json.Unmarshal([]byte(tc.body), &v)
			expect = v.Token
		case "/admin/login/totp":
			var v totpLoginRequest
			_ = json.Unmarshal([]byte(tc.body), &v)
			expect = v.ChallengeToken
		case "/admin/login/password":
			var v passwordLoginRequest
			_ = json.Unmarshal([]byte(tc.body), &v)
			expect = strings.ToLower(v.Email)
		}
		if expect != tc.want {
			t.Fatalf("%s: the handler's own decoding of %s gives %q, this test expected %q", tc.path, tc.body, expect, tc.want)
		}
		_, got := signInSubject(tc.path, []byte(tc.body))
		if got != tc.want {
			t.Errorf("%s: the bound keys on %q while the handler acts on %q (body %s)", tc.path, got, tc.want, tc.body)
		}
	}

	// And end to end: a changing decoy beside one real invitation does not buy a fresh bucket.
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adminAuth, _ := adminRBACMatrixAuthStore(t)
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		AdminAuth: adminAuth, LocalCredentials: newLocalAdminCredentialStore("Lantern DSSE"),
	})
	codes := map[int]int{}
	for i := 0; i < 40; i++ {
		body := `{"token":"decoy-` + strconv.Itoa(i) + `","Token":"the-one-invitation"}`
		req := httptest.NewRequest(http.MethodPost, "/admin/activate", strings.NewReader(body))
		req.RemoteAddr = "10.77.0.6:4000"
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		codes[rec.Code]++
	}
	if codes[http.StatusTooManyRequests] != 20 {
		t.Fatalf("forty attempts on one invitation behind changing decoys: %v, want 20 refused", codes)
	}
}
