package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCeremonyLanguagePreferenceAndBrowserFallback(t *testing.T) {
	for _, tc := range []struct{ header, cookie, want string }{
		{"ja-JP,ja;q=0.9,en;q=0.8", "", "ja"},
		{"en-US,en;q=0.9,ja;q=0.5", "", "en"},
		{"fr,ja;q=0.8,en;q=0.5", "", "ja"},
		{"ja;q=0,en;q=0.7", "", "en"},
		{"ja;q=bad,en;q=0.7", "", "en"},
		{"ja-JP", "en", "en"},
		{"en-US", "ja", "ja"},
		{"ja-JP", "<script>", "ja"},
		{"fr", "", "en"},
	} {
		r := httptest.NewRequest("GET", "https://portal.example/", nil)
		r.Header.Set("Accept-Language", tc.header)
		if tc.cookie != "" {
			r.AddCookie(&http.Cookie{Name: ceremonyLanguageCookie, Value: tc.cookie})
		}
		if got := ceremonyLanguage(r); got != tc.want {
			t.Fatalf("header=%q preference=%q: got %q want %q", tc.header, tc.cookie, got, tc.want)
		}
	}
}

func TestCeremonyJapaneseSuccessAndFailureKeepEscapingAndAPI(t *testing.T) {
	r := httptest.NewRequest("GET", "https://portal.example/clientless/auth/callback", nil)
	r.Header.Set("Accept-Language", "ja-JP")
	success := httptest.NewRecorder()
	writeCeremonySuccessHTML(success, `<script>account</script>`, "phishing_resistant", `app.invalid:22<img src=x>`, r)
	for _, text := range []string{`<html lang="ja">`, `>本人確認が完了しました</h1>`, `>接続先:</span>`, `>サインインしたアカウント:</span>`, `data-dsse-language="ja"`, `&lt;script&gt;account&lt;/script&gt;`} {
		if !strings.Contains(success.Body.String(), text) {
			t.Fatalf("missing Japanese or safe dynamic content: %s", text)
		}
	}
	if strings.Contains(success.Body.String(), `<script>account`) || strings.Contains(success.Body.String(), `<img src=x>`) {
		t.Fatal("dynamic identity/destination became executable markup")
	}
	failure := httptest.NewRecorder()
	respondCeremonyError(failure, r, 401, "Sign-in link expired", "Return to your app and request a fresh sign-in link.")
	if failure.Code != 401 || !strings.Contains(failure.Body.String(), ">認証リンクの有効期限が切れました</h1>") || !strings.Contains(failure.Body.String(), "新しい認証画面を開いてください。") {
		t.Fatal("error status or Japanese explanation lost")
	}
	unknown := httptest.NewRecorder()
	respondCeremonyError(unknown, r, 400, "Uncatalogued error", "Uncatalogued detail")
	if !strings.Contains(unknown.Body.String(), ">処理を完了できません</h1>") || !strings.Contains(unknown.Body.String(), ">処理を完了できませんでした。元のアプリからもう一度お試しいただくか、管理者にお問い合わせください。</span>") {
		t.Fatal("unknown errors need a useful Japanese fallback")
	}
	api := httptest.NewRecorder()
	r.Header.Set("Accept", "application/json")
	respondCeremonyError(api, r, 401, "Sign-in link expired", "Return to your app and request a fresh sign-in link.")
	if !strings.Contains(api.Header().Get("Content-Type"), "application/json") || strings.Contains(api.Body.String(), "<html") || !strings.Contains(api.Body.String(), "Return to your app") {
		t.Fatal("presentation locale changed the machine-readable API")
	}
}

func TestCeremonyLanguageUsesOnlyHashAuthorizedPresentationScript(t *testing.T) {
	r := httptest.NewRequest("GET", "https://portal.example/", nil)
	w := httptest.NewRecorder()
	writeDestinationConfirmation(w, r, "local-test-confirmation")
	page := w.Body.String()
	start := strings.Index(page, "<script>")
	end := strings.Index(page, "</script>")
	if start < 0 || end <= start {
		t.Fatal("language controls lack their presentation script")
	}
	digest := sha256.Sum256([]byte(page[start+len("<script>") : end]))
	policy := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"'") || !strings.Contains(policy, "form-action 'self'") || strings.Contains(policy, "script-src 'unsafe-inline'") {
		t.Fatal("script hash or restrictive form policy lost")
	}
	if strings.Contains(ceremonyLanguageScript, "fetch(") || strings.Contains(ceremonyLanguageScript, "innerHTML") || strings.Contains(ceremonyLanguageScript, "location.") || strings.Contains(ceremonyLanguageScript, authSessionCookie) {
		t.Fatal("language switching must not navigate, replay callbacks or read authentication state")
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Vary") != "Accept-Language, Cookie" {
		t.Fatal("localized pages may be cached across preferences")
	}
}

func TestCeremonyLanguagePreferenceDoesNotChangeBoundConfirmation(t *testing.T) {
	b, gate := ceremonyFixture(t)
	link := authTestSignedLink(gate, gate.stepUpURLFor("app:22", "corp", "", "device", "tenant"))
	get := httptest.NewRequest("GET", link, nil)
	get.Header.Set("Accept-Language", "ja-JP")
	page := httptest.NewRecorder()
	b.handleStart(page, get)
	match := confirmationInput.FindStringSubmatch(page.Body.String())
	if page.Code != 200 || len(match) != 2 || !strings.Contains(page.Body.String(), ">接続先を確認</h1>") || len(b.pending) != 0 {
		t.Fatal("Japanese confirmation must wait for explicit user action")
	}
	post := httptest.NewRequest("POST", link, strings.NewReader(url.Values{"confirmation": {match[1]}}.Encode()))
	post.Header.Set("Origin", b.selfBaseURL)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range page.Result().Cookies() {
		post.AddCookie(cookie)
	}
	post.AddCookie(&http.Cookie{Name: ceremonyLanguageCookie, Value: "en"})
	response := httptest.NewRecorder()
	b.handleStart(response, post)
	if response.Code != 200 || authenticationNavigationForTest(response) == "" || len(b.pending) != 1 || len(b.grants.ListAll()) != 0 {
		t.Fatal("changing presentation preference changed authentication confirmation")
	}
}
