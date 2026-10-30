// Package authportal validates browser launch destinations against signed deployment facts.
package authportal

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func Origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", fmt.Errorf("portal must be an HTTPS origin")
	}
	if strings.ContainsAny(u.Hostname(), "*% \\\t\r\n") {
		return "", fmt.Errorf("invalid portal host")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid portal port")
	}
	return "https://" + net.JoinHostPort(strings.ToLower(u.Hostname()), strconv.Itoa(n)), nil
}

func ValidateStart(raw string, origins []string, now time.Time) (string, error) {
	if len(raw) > 16384 || strings.ContainsAny(raw, "\"'`\\ \t\r\n") {
		return "", fmt.Errorf("invalid sign-in address")
	}
	for _, r := range raw {
		if r < 32 || r == 127 {
			return "", fmt.Errorf("invalid sign-in address")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawPath != "" || u.Path != "/clientless/auth/start" {
		return "", fmt.Errorf("invalid sign-in endpoint")
	}
	origin, err := Origin("https://" + u.Host)
	if err != nil {
		return "", err
	}
	trusted := false
	for _, candidate := range origins {
		expected, e := Origin(candidate)
		if e != nil {
			return "", e
		}
		if expected == origin {
			trusted = true
		}
	}
	if !trusted {
		return "", fmt.Errorf("sign-in endpoint is not in the signed Portal list")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", fmt.Errorf("invalid sign-in request")
	}
	if q.Get("portal_origin") != origin {
		return "", fmt.Errorf("sign-in request belongs to another Portal")
	}
	for _, v := range q {
		if len(v) != 1 {
			return "", fmt.Errorf("duplicate sign-in parameter")
		}
	}
	id, err := base64.RawURLEncoding.DecodeString(q.Get("request_id"))
	if err != nil || len(id) != 24 {
		return "", fmt.Errorf("invalid sign-in identifier")
	}
	// This is a browser-launch check, not authorization. Allow five minutes
	// of endpoint clock skew; the Portal still enforces its exact 120s lifetime.
	issued, e1 := strconv.ParseInt(q.Get("issued_at"), 10, 64)
	expires, e2 := strconv.ParseInt(q.Get("expires_at"), 10, 64)
	if e1 != nil || e2 != nil || issued <= 0 || expires <= issued || expires-issued != 120 || issued > now.Unix()+300 || now.Unix()-300 >= expires || q.Get("requirements_sig") == "" || q.Get("device_sig") == "" {
		return "", fmt.Errorf("expired or unbound sign-in request")
	}
	return raw, nil
}
