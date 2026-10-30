package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type federatedRequirements struct {
	IdP, ACR, Scope         string
	RequestID               string
	OSPrincipal, OSSession  string
	AMR                     []string
	MaxAgeSeconds           *int64
	GrantTTLSeconds         *int64
	AuthenticationStartedAt time.Time
	Invalid                 bool
}

// A HTTP grant covers an origin; a native grant covers an exact host:port.
// Empty legacy clientless scope cannot release a scoped resource.
func federatedDestinationScope(destination string) string {
	destination = strings.TrimSpace(destination)
	if u, err := url.Parse(destination); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil {
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ""
		}
		return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), strconv.Itoa(n))
	}
	host, port, err := net.SplitHostPort(destination)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || host == "" || n < 1 || n > 65535 {
		return ""
	}
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(n))
}

func authFlowRequirements(dec model.AccessDecision, destination string) federatedRequirements {
	req := federatedRequirements{Scope: federatedDestinationScope(destination)}
	if req.Scope == "" {
		req.Invalid = true
	}
	for _, a := range dec.Actions {
		if a.Type != "prompt_reauthentication" {
			continue
		}
		for key, target := range map[string]*string{"required_idp_id": &req.IdP, "min_acr": &req.ACR} {
			if raw, ok := a.Metadata[key]; ok {
				value, valid := raw.(string)
				value = strings.TrimSpace(value)
				if !valid || (*target != "" && value != "" && *target != value) {
					req.Invalid = true
				} else if value != "" {
					*target = value
				}
			}
		}
		if raw, ok := a.Metadata["required_amr"]; ok {
			var methods []string
			switch v := raw.(type) {
			case []string:
				methods = v
			case []any:
				for _, x := range v {
					s, ok := x.(string)
					if !ok {
						req.Invalid = true
					}
					methods = append(methods, s)
				}
			case string:
				methods = strings.Split(v, ",")
			default:
				req.Invalid = true
			}
			for _, method := range methods {
				method = strings.TrimSpace(method)
				if method == "" || strings.ContainsAny(method, " ,\t\r\n") {
					req.Invalid = true
					continue
				}
				req.AMR = append(req.AMR, method)
			}
		}
		if raw, ok := a.Metadata["grant_ttl_seconds"]; ok {
			encoded, err := json.Marshal(raw)
			var ttl int64
			if err != nil || json.Unmarshal(encoded, &ttl) != nil || !validAuthGrantTTLSeconds(ttl) {
				req.Invalid = true
			} else if req.GrantTTLSeconds == nil || ttl < *req.GrantTTLSeconds {
				req.GrantTTLSeconds = &ttl
			}
		}
		if raw, ok := a.Metadata["max_age_seconds"]; ok {
			encoded, err := json.Marshal(raw)
			var age int64
			if err != nil || json.Unmarshal(encoded, &age) != nil || age < 0 || age > 86400 {
				req.Invalid = true
				continue
			}
			if req.MaxAgeSeconds == nil || age < *req.MaxAgeSeconds {
				req.MaxAgeSeconds = &age
			}
		}
	}
	return req
}

func (s *deviceBindingSigner) signRequirements(q url.Values) string {
	if s == nil || len(s.key) == 0 {
		return ""
	}
	fields := url.Values{}
	for _, key := range []string{"device", "tenant", "idp", "acr", "amr", "max_age", "grant_ttl", "return_to", "request_id", "issued_at", "expires_at", "portal_origin", "os_principal", "os_session"} {
		if q.Has(key) {
			fields[key] = append([]string(nil), q[key]...)
		}
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("dsse step-up requirements v1|" + fields.Encode()))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (g *federatedAuthGate) stepUpURLWithRequirements(returnTo, deviceID, tenantID string, req federatedRequirements) string {
	if g == nil {
		return ""
	}
	return g.stepUpURLWithRequirementsAtOrigin(g.brokerBaseURL, returnTo, deviceID, tenantID, req)
}

func (g *federatedAuthGate) stepUpURLWithRequirementsAtOrigin(origin, returnTo, deviceID, tenantID string, req federatedRequirements) string {
	if req.Invalid || g == nil || (g.draining != nil && g.draining.Load()) {
		return ""
	}
	if req.MaxAgeSeconds != nil && *req.MaxAgeSeconds == 0 && !g.rollout.featureEnabled("single-request-v1") {
		return ""
	}
	base := g.stepUpURLForOrigin(origin, returnTo, req.IdP, req.ACR, deviceID, tenantID)
	u, err := url.Parse(base)
	if err != nil || base == "" {
		return ""
	}
	q := u.Query()
	identityEnabled, identityKnown := g.rollout.deviceUserBindingMode()
	if deviceID != "" && !identityKnown {
		return ""
	}
	if deviceID != "" && identityEnabled {
		if !validAuthOwner(req.OSPrincipal, req.OSSession) {
			return ""
		}
		q.Set("os_principal", req.OSPrincipal)
		q.Set("os_session", req.OSSession)
	}
	if len(req.AMR) > 0 {
		q.Set("amr", strings.Join(req.AMR, ","))
	}
	if req.GrantTTLSeconds != nil {
		if !validAuthGrantTTLSeconds(*req.GrantTTLSeconds) {
			return ""
		}
		q.Set("grant_ttl", strconv.FormatInt(*req.GrantTTLSeconds, 10))
	}
	if req.MaxAgeSeconds != nil {
		q.Set("max_age", strconv.FormatInt(*req.MaxAgeSeconds, 10))
	}
	q.Set("requirements_sig", g.signer.signRequirements(q))
	u.RawQuery = q.Encode()
	return u.String()
}

func requirementsMatchGrant(amr []string, authTime, scope string, req federatedRequirements, now time.Time) bool {
	if req.Invalid || (req.Scope != "" && scope != req.Scope) {
		return false
	}
	for _, want := range req.AMR {
		found := false
		for _, got := range amr {
			if want == got {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if req.MaxAgeSeconds != nil {
		at, err := time.Parse(time.RFC3339, authTime)
		if err != nil || at.After(now) || *req.MaxAgeSeconds < 0 || *req.MaxAgeSeconds > 86400 {
			return false
		}
		if *req.MaxAgeSeconds == 0 {
			return !req.AuthenticationStartedAt.IsZero() && !req.AuthenticationStartedAt.After(now) && at.Unix() >= req.AuthenticationStartedAt.Unix()
		}
		if now.Unix()-at.Unix() > *req.MaxAgeSeconds {
			return false
		}
	}
	return true
}
