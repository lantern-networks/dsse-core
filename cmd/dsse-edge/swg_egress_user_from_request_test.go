package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func mkJWT(claims map[string]any) string {
	pl, _ := json.Marshal(claims)
	return "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(pl) + ".sig"
}

func TestSWGEgressUserFromRequest_JWT(t *testing.T) {
	// Authorization: Bearer <JWT with email> -> the email is extracted from the DECRYPTED request.
	r, _ := http.NewRequest("GET", "https://chatgpt.com/backend-api/me", nil)
	r.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"sub": "u-1", "email": "taro.yamada@example.com"}))
	if got := swgEgressUserFromRequest(r); got != "taro.yamada@example.com" {
		t.Fatalf("email from Bearer JWT: got %q want taro.yamada@example.com", got)
	}
	// preferred_username fallback (M365 style)
	r2, _ := http.NewRequest("GET", "https://x/", nil)
	r2.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"preferred_username": "alice@corp.example"}))
	if got := swgEgressUserFromRequest(r2); got != "alice@corp.example" {
		t.Fatalf("preferred_username: got %q", got)
	}
	// JWT in a cookie
	r3, _ := http.NewRequest("GET", "https://x/", nil)
	r3.AddCookie(&http.Cookie{Name: "id_token", Value: mkJWT(map[string]any{"email": "bob@corp.example"})})
	if got := swgEgressUserFromRequest(r3); got != "bob@corp.example" {
		t.Fatalf("cookie JWT: got %q", got)
	}
	// no token -> empty (falls back to other attribution downstream)
	r4, _ := http.NewRequest("GET", "https://x/", nil)
	if got := swgEgressUserFromRequest(r4); got != "" {
		t.Fatalf("no token should be empty, got %q", got)
	}
	// opaque (non-JWT) bearer -> empty
	r5, _ := http.NewRequest("GET", "https://x/", nil)
	r5.Header.Set("Authorization", "Bearer opaque-session-token-not-a-jwt")
	if got := swgEgressUserFromRequest(r5); got != "" {
		t.Fatalf("opaque token should be empty, got %q", got)
	}
}

func TestUserFromJWT_NamespacedAndNestedEmail(t *testing.T) {
	// Auth0/OpenAI-style: opaque sub at top level, real email under a URL-namespaced claim -> email wins.
	if got := userFromJWT(mkJWT(map[string]any{
		"sub":                          "google-oauth2|100000000000000000000",
		"https://api.openai.com/email": "alice@corp.example",
	})); got != "alice@corp.example" {
		t.Fatalf("namespaced email: got %q want alice@corp.example", got)
	}
	// Nested profile object.
	if got := userFromJWT(mkJWT(map[string]any{
		"sub":     "auth0|abc",
		"profile": map[string]any{"email": "bob@corp.example", "name": "Bob"},
	})); got != "bob@corp.example" {
		t.Fatalf("nested email: got %q want bob@corp.example", got)
	}
	// No email anywhere -> falls back to the opaque sub (stable per user).
	if got := userFromJWT(mkJWT(map[string]any{"sub": "auth0|xyz"})); got != "auth0|xyz" {
		t.Fatalf("opaque fallback: got %q want auth0|xyz", got)
	}
	// A non-email preferred_username with no email present -> returned as the (opaque) fallback.
	if got := userFromJWT(mkJWT(map[string]any{"preferred_username": "alice", "sub": "s"})); got != "alice" {
		t.Fatalf("username fallback: got %q want alice", got)
	}
	// A namespaced key that is NOT an email value must be ignored (don't return garbage).
	if got := userFromJWT(mkJWT(map[string]any{"sub": "s", "org_email_verified": "true"})); got != "s" {
		t.Fatalf("non-email namespaced key: got %q want s", got)
	}
}

func TestParseSteerOpenOSUser_WindowsAndMac(t *testing.T) {
	cases := map[string]string{
		`u=WIN-DEV-01\jdoe`:    `WIN-DEV-01\jdoe`,   // Windows DOMAIN\user (backslash must survive)
		"u=a.tanaka":           "a.tanaka",          // macOS local user
		"u=MACHINE\\localuser": `MACHINE\localuser`, // local Windows account
		"":                     "",                  // no metadata -> empty
		"x=other":              "",                  // unrelated key -> empty
		"u=":                   "",                  // empty value -> empty
	}
	for meta, want := range cases {
		if got := parseSteerOpenOSUser(meta); got != want {
			t.Errorf("parseSteerOpenOSUser(%q) = %q, want %q", meta, got, want)
		}
	}
	// A control char in the user is stripped (log/identity safety), backslash is kept.
	if got := parseSteerOpenOSUser("u=DOM\x07\\bob"); got != `DOM\bob` {
		t.Errorf("control-char strip: got %q want DOM\\bob", got)
	}
}

func TestIsNonInteractiveAccount(t *testing.T) {
	sys := []string{"_mdnsresponder", "_windowserver", "root", "daemon", "nobody", "NT", "SYSTEM", `NT AUTHORITY\SYSTEM`, `NT SERVICE\MSSQL`, `CORP\LOCAL SERVICE`}
	for _, s := range sys {
		if !isNonInteractiveAccount(s) {
			t.Errorf("isNonInteractiveAccount(%q) = false, want true", s)
		}
	}
	users := []string{"a.tanaka", `WIN-DEV-01\jdoe`, "alice", `CORP\jdoe`, ""}
	for _, s := range users {
		if isNonInteractiveAccount(s) {
			t.Errorf("isNonInteractiveAccount(%q) = true, want false", s)
		}
	}
}

func TestUserFromJWT_NamePreferredOverOpaqueSub(t *testing.T) {
	mk := func(claims string) string {
		b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
		return b64(`{"alg":"none"}`) + "." + b64(claims) + ".sig"
	}
	// An AI service that carries a display name and a uuid sub but no email -> the display name.
	if got := userFromJWT(mk(`{"sub":"00000000-0000-4000-8000-000000000000","name":"Taro Yamada","iss":"ai-service-routing"}`)); got != "Taro Yamada" {
		t.Errorf("name-bearing token: got %q, want \"Taro Yamada\"", got)
	}
	// Email still wins over name.
	if got := userFromJWT(mk(`{"sub":"x","name":"Taro Yamada","email":"taro.yamada@example.com"}`)); got != "taro.yamada@example.com" {
		t.Errorf("email must win over name: got %q", got)
	}
	// given/family name composite when no name claim.
	if got := userFromJWT(mk(`{"sub":"x","given_name":"Taro","family_name":"Yamada"}`)); got != "Taro Yamada" {
		t.Errorf("given+family: got %q, want \"Taro Yamada\"", got)
	}
	// Opaque sub only (no name/email) -> the sub.
	if got := userFromJWT(mk(`{"sub":"google-oauth2|123"}`)); got != "google-oauth2|123" {
		t.Errorf("opaque sub fallback: got %q", got)
	}
}

func TestSwgEgressUserFromRequest_CopilotStrongOverAnon(t *testing.T) {
	jwt := func(claims string) string {
		b := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
		return b(`{"alg":"none"}`) + "." + b(claims) + ".sig"
	}
	authBearer := jwt(`{"sub":"google-oauth2|100000000000000000000","email":"taro.yamada@example.com","name":"Taro Yamada","iss":"https://auth.copilot.microsoft.com/"}`)
	anon := jwt(`{"sub":"anonymousSession000000","iss":"https://copilot.microsoft.com"}`)

	// Request carrying BOTH the authenticated bearer (email) and the anon cookie -> email must win.
	r1, _ := http.NewRequest("POST", "https://copilot.microsoft.com/c/api/conversations", nil)
	r1.Header.Set("Authorization", "Bearer "+authBearer)
	r1.AddCookie(&http.Cookie{Name: "__Host-copilot-anon", Value: anon})
	if got := swgEgressUserFromRequest(r1); got != "taro.yamada@example.com" {
		t.Errorf("bearer+anon: got %q, want taro.yamada@example.com", got)
	}

	// Request with ONLY the anon cookie -> no identity (anon session is not a user), not the opaque uuid.
	r2, _ := http.NewRequest("GET", "https://copilot.microsoft.com/", nil)
	r2.AddCookie(&http.Cookie{Name: "__Host-copilot-anon", Value: anon})
	if got := swgEgressUserFromRequest(r2); got != "" {
		t.Errorf("anon-only: got %q, want empty (anon session skipped)", got)
	}

	// A weak (opaque-sub) NON-anon cookie is still used when nothing stronger exists.
	r3, _ := http.NewRequest("GET", "https://x.example/", nil)
	r3.AddCookie(&http.Cookie{Name: "session", Value: jwt(`{"sub":"opaque-123"}`)})
	if got := swgEgressUserFromRequest(r3); got != "opaque-123" {
		t.Errorf("weak fallback: got %q, want opaque-123", got)
	}
}

func TestShouldLogAccessDecision(t *testing.T) {
	ai := &model.SaaSContext{SaaSApplicationID: "saas_anthropic_claude"}
	nonAI := &model.SaaSContext{SaaSApplicationID: "saas_google_workspace"}
	cases := []struct {
		name string
		dec  model.AccessDecision
		want bool
	}{
		{"routine allow, no saas", model.AccessDecision{Decision: "allow"}, false},
		{"routine allow, non-AI saas", model.AccessDecision{Decision: "allow", SaaSContext: nonAI}, false},
		{"allow to AI service", model.AccessDecision{Decision: "allow", SaaSContext: ai}, true},
		{"deny", model.AccessDecision{Decision: "deny"}, true},
		{"authenticate", model.AccessDecision{Decision: "authenticate"}, true},
		// Per-rule log flag: an egress rule opting a non-AI allow INTO logging.
		{"rule log=true, non-AI allow", model.AccessDecision{Decision: "allow", SaaSContext: nonAI, Metadata: map[string]any{"log_traffic": true}}, true},
		// A rule's log=false wins over the AI default for a plain allow (admin explicitly chose not to log).
		{"rule log=false, AI allow", model.AccessDecision{Decision: "allow", SaaSContext: ai, Metadata: map[string]any{"log_traffic": false}}, false},
		// ...but a deny is always logged — a rule's log=false cannot suppress a security action.
		{"rule log=false, deny", model.AccessDecision{Decision: "deny", Metadata: map[string]any{"log_traffic": false}}, true},
	}
	for _, c := range cases {
		if got := shouldLogAccessDecision(c.dec); got != c.want {
			t.Errorf("%s: shouldLogAccessDecision = %v, want %v", c.name, got, c.want)
		}
	}
	// -access-log-all restores full logging.
	accessLogAllDecisions = true
	if !shouldLogAccessDecision(model.AccessDecision{Decision: "allow"}) {
		t.Error("with -access-log-all, a routine allow must be logged")
	}
	accessLogAllDecisions = false
}

func TestSwgEgressIdentityFromRequest(t *testing.T) {
	// ChatGPT-style: email + name in the bearer -> both fields.
	r, _ := http.NewRequest("POST", "https://chatgpt.com/x", nil)
	r.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"email": "taro.yamada@example.com", "name": "Taro Yamada"}))
	if e, n := swgEgressIdentityFromRequest(r); e != "taro.yamada@example.com" || n != "Taro Yamada" {
		t.Errorf("email+name: got (%q,%q)", e, n)
	}
	// Claude-style: name only, no email -> name filled, email BLANK.
	r2, _ := http.NewRequest("POST", "https://claude.ai/x", nil)
	r2.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"sub": "00000000-0000-4000-8000-000000000000", "name": "Taro Yamada"}))
	if e, n := swgEgressIdentityFromRequest(r2); e != "" || n != "Taro Yamada" {
		t.Errorf("name-only: got (%q,%q), want (\"\",\"Taro Yamada\")", e, n)
	}
	// Email only -> email filled, name BLANK.
	r3, _ := http.NewRequest("POST", "https://x/", nil)
	r3.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"email": "taro.yamada@example.com"}))
	if e, n := swgEgressIdentityFromRequest(r3); e != "taro.yamada@example.com" || n != "" {
		t.Errorf("email-only: got (%q,%q)", e, n)
	}
	// Compose across tokens: bearer email + a session cookie carrying the name -> both.
	r4, _ := http.NewRequest("POST", "https://x/", nil)
	r4.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"email": "taro.yamada@example.com"}))
	r4.AddCookie(&http.Cookie{Name: "session", Value: mkJWT(map[string]any{"name": "Taro Yamada"})})
	if e, n := swgEgressIdentityFromRequest(r4); e != "taro.yamada@example.com" || n != "Taro Yamada" {
		t.Errorf("compose bearer-email + cookie-name: got (%q,%q)", e, n)
	}
	// Anon cookie is skipped (its name must not fill the field).
	r5, _ := http.NewRequest("POST", "https://copilot.microsoft.com/x", nil)
	r5.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"email": "taro.yamada@example.com"}))
	r5.AddCookie(&http.Cookie{Name: "__Host-copilot-anon", Value: mkJWT(map[string]any{"sub": "anon0", "name": "Anon"})})
	if e, n := swgEgressIdentityFromRequest(r5); e != "taro.yamada@example.com" || n != "" {
		t.Errorf("bearer+anon: got (%q,%q) — anon must be skipped", e, n)
	}
	// No token -> both blank (Gemini-like -> device fallback happens downstream).
	r6, _ := http.NewRequest("GET", "https://gemini.google.com/", nil)
	if e, n := swgEgressIdentityFromRequest(r6); e != "" || n != "" {
		t.Errorf("no token: got (%q,%q)", e, n)
	}
}

func TestSwgEgressIdentityForService(t *testing.T) {
	// ChatGPT's fixed rule reads email + name from the Bearer.
	r, _ := http.NewRequest("POST", "https://chatgpt.com/x", nil)
	r.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"email": "taro.yamada@example.com", "name": "Taro Yamada"}))
	if e, n := swgEgressIdentityForService(r, nil, "saas_openai_chatgpt"); e != "taro.yamada@example.com" || n != "Taro Yamada" {
		t.Errorf("chatgpt: got (%q,%q)", e, n)
	}
	// KEY: Claude's rule has NO email source. Even if the request carries a stray email (an analytics cookie), the
	// per-service rule must NOT attribute it — only the name is read. This is the precision win over a generic scan.
	r2, _ := http.NewRequest("POST", "https://claude.ai/x", nil)
	r2.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"name": "Taro Yamada"}))
	r2.AddCookie(&http.Cookie{Name: "analytics", Value: mkJWT(map[string]any{"email": "someone.else@tracker.example"})})
	if e, n := swgEgressIdentityForService(r2, nil, "saas_anthropic_claude"); e != "" || n != "Taro Yamada" {
		t.Errorf("claude must NOT grab a stray email: got (%q,%q), want (\"\",\"Taro Yamada\")", e, n)
	}
	// Gemini reads nothing (opaque cookies) even if a token is present -> device fallback downstream.
	r3, _ := http.NewRequest("GET", "https://gemini.google.com/", nil)
	r3.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"email": "x@example.com", "name": "X"}))
	if e, n := swgEgressIdentityForService(r3, nil, "saas_google_gemini"); e != "" || n != "" {
		t.Errorf("gemini reads nothing: got (%q,%q)", e, n)
	}
	// Uncatalogued AI service -> generic best-effort rule still extracts.
	r4, _ := http.NewRequest("POST", "https://newai.example/x", nil)
	r4.Header.Set("Authorization", "Bearer "+mkJWT(map[string]any{"email": "taro.yamada@example.com"}))
	if e, _ := swgEgressIdentityForService(r4, nil, "saas_unknown_newai"); e != "taro.yamada@example.com" {
		t.Errorf("unknown service generic fallback: got %q", e)
	}
}

func TestAIServiceIdentityRuleCatalogOverride(t *testing.T) {
	// A catalog entry with a custom IdentityRule overrides the built-in default: give Claude an email source
	// (a cookie) it does not have by default.
	custom := model.SaaSIdentityRule{EmailFrom: []model.SaaSIdentitySource{{Source: "cookie", Claim: "email"}}}
	catalog := []model.SaaSCatalogEntry{{SaaSApplicationID: "saas_anthropic_claude", IdentityRule: &custom}}
	r, _ := http.NewRequest("POST", "https://claude.ai/x", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: mkJWT(map[string]any{"email": "taro.yamada@example.com"})})
	if e, _ := swgEgressIdentityForService(r, catalog, "saas_anthropic_claude"); e != "taro.yamada@example.com" {
		t.Errorf("catalog override: got email %q, want the cookie email", e)
	}
	// Without the override (built-in Claude), there is NO email source, so the same request yields no email.
	if e, _ := swgEgressIdentityForService(r, nil, "saas_anthropic_claude"); e != "" {
		t.Errorf("built-in Claude has no email source: got %q, want empty", e)
	}
}
