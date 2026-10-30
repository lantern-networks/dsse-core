package authportal

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestStartURLUsesExactSignedOriginAndLifetime(t *testing.T) {
	now := time.Now()
	q := url.Values{"portal_origin": {"https://portal.example:443"}, "request_id": {base64.RawURLEncoding.EncodeToString(make([]byte, 24))}, "issued_at": {strconv.FormatInt(now.Unix(), 10)}, "expires_at": {strconv.FormatInt(now.Add(120*time.Second).Unix(), 10)}, "requirements_sig": {"signature"}, "device_sig": {"signature"}}
	raw := "https://portal.example/clientless/auth/start?" + q.Encode()
	origins := []string{"https://portal.example:443"}
	if _, err := ValidateStart(raw, origins, now); err != nil {
		t.Fatal(err)
	}
	// The endpoint treats signed policy fields as opaque; the Portal verifies
	// their signature. New capped requests do not require an agent reinstall.
	if _, err := ValidateStart(raw+"&grant_ttl=300", origins, now); err != nil {
		t.Fatal(err)
	}
	for _, skew := range []time.Duration{-299 * time.Second, 299 * time.Second} {
		if _, err := ValidateStart(raw, origins, now.Add(skew)); err != nil {
			t.Fatalf("endpoint clock skew blocked launch: %v", err)
		}
	}
	for _, bad := range []string{
		"http://portal.example/clientless/auth/start?" + q.Encode(),
		"https://portal.example.attacker.test/clientless/auth/start?" + q.Encode(),
		"https://portal.example:444/clientless/auth/start?" + q.Encode(),
		"https://user@portal.example/clientless/auth/start?" + q.Encode(),
		"https://portal.example/clientless/auth/start/../callback?" + q.Encode(),
		raw + "#ignored", raw + "&request_id=duplicate", raw + "\n",
	} {
		if _, err := ValidateStart(bad, origins, now); err == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
	if _, err := ValidateStart(raw, nil, now); err == nil {
		t.Fatal("missing signed origins accepted")
	}
	if _, err := ValidateStart(raw, origins, now.Add(420*time.Second)); err == nil {
		t.Fatal("expired request accepted")
	}
	if _, err := ValidateStart(raw, []string{"https://*.example"}, now); err == nil {
		t.Fatal("wildcard trust accepted")
	}
	q.Set("portal_origin", "https://other.example")
	if _, err := ValidateStart("https://portal.example/clientless/auth/start?"+q.Encode(), []string{"https://portal.example", "https://other.example"}, now); err == nil {
		t.Fatal("request moved between two trusted origins")
	}
}
