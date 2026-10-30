package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func registerInspectionCRLListenerFlag() *string {
	return flag.String("inspection-crl-listen", "", "optional plaintext HTTP listener serving only signed interception CRL DER; expose it through an independent read-only CRL entry")
}

// A CDP is fetched by the operating system without an application bearer or
// client certificate. The bytes are public but authenticated by the issuer's
// signature. No private key, tenant metadata, or on-demand signing is exposed.
func registerTenantInspectionCRLPublicRoute(mux *http.ServeMux, a *tenantInterceptionAuthority) {
	mux.HandleFunc("GET /pki/crl/{tenant}/{file}", func(w http.ResponseWriter, r *http.Request) {
		file := r.PathValue("file")
		if r.URL.RawQuery != "" || !strings.HasSuffix(file, ".crl") || !crlFingerprintValid(strings.TrimSuffix(file, ".crl")) || a == nil {
			http.NotFound(w, r)
			return
		}
		status, err := a.crlStatus(r.Context(), r.PathValue("tenant"), strings.TrimSuffix(file, ".crl"))
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "CRL unavailable", http.StatusServiceUnavailable)
			return
		}
		issuer, parseErr := parseFirstCertificatePEM([]byte(status.IssuerPEM))
		if parseErr != nil {
			http.NotFound(w, r)
			return
		}
		matched := false
		for _, origin := range status.BaseURLs {
			base, err := url.Parse(origin)
			expected, urlErr := inspectioncrl.URL(origin, status.Tenant, issuer)
			if err == nil && urlErr == nil && sameCRLHTTPHost(r.Host, base) && r.URL.Path == strings.TrimPrefix(expected, origin) {
				matched = true
				break
			}
		}
		if !matched {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Cache-Control", "public, max-age=30")
		_, _ = w.Write(status.DER)
	})
}

func sameCRLHTTPHost(requestHost string, base *url.URL) bool {
	if base == nil || base.Scheme != "http" {
		return false
	}
	request := &url.URL{Scheme: "http", Host: requestHost}
	port := func(u *url.URL) string {
		if u.Port() == "" {
			return "80"
		}
		return u.Port()
	}
	return request.Hostname() != "" && strings.EqualFold(request.Hostname(), base.Hostname()) && port(request) == port(base)
}

func crlFingerprintValid(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, c := range fp {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func registerTenantInspectionCRLRoute(mux *http.ServeMux, a *tenantInterceptionAuthority, token string, tca *tenantca.TenantCARegistry) {
	if a == nil || strings.TrimSpace(token) == "" {
		return
	}
	authorized := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if !auditIngestBearerValid(r, token) {
			writeError(w, 401, fmt.Errorf("unauthorized"))
			return "", false
		}
		s, ok := auditIngestShipperFrom(r, tca)
		if !ok || s.CertTenant != "" || strings.TrimSpace(s.Identity) == "" {
			writeError(w, 403, fmt.Errorf("verified operator Edge identity required"))
			return "", false
		}
		return s.Identity, true
	}
	mux.HandleFunc("GET /tenant-inspection-crl", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authorized(w, r); !ok {
			return
		}
		fp := r.URL.Query().Get("issuer")
		if len(r.URL.Query()["tenant"]) != 1 || len(r.URL.Query()["issuer"]) != 1 || strings.TrimSpace(r.URL.Query().Get("tenant")) == "" || !crlFingerprintValid(fp) {
			writeError(w, 400, fmt.Errorf("invalid issuer"))
			return
		}
		status, e := a.crlStatus(trustDistributionWriteContext(r.Context()), r.URL.Query().Get("tenant"), fp)
		if e != nil {
			w.Header().Set("Retry-After", "1")
			writeError(w, 503, e)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, status)
	})
	mux.HandleFunc("POST /tenant-inspection-crl", func(w http.ResponseWriter, r *http.Request) {
		edge, ok := authorized(w, r)
		if !ok {
			return
		}
		var body struct {
			TenantID     string `json:"tenant_id"`
			IssuerSHA256 string `json:"issuer_sha256"`
			DER          []byte `json:"der"`
		}
		if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*inspectioncrl.MaxDERBytes)).Decode(&body); e != nil {
			writeError(w, 400, e)
			return
		}
		if strings.TrimSpace(body.TenantID) == "" || !crlFingerprintValid(body.IssuerSHA256) {
			writeError(w, 400, fmt.Errorf("tenant and issuer required"))
			return
		}
		if e := a.publishLeafCRL(trustDistributionWriteContext(r.Context()), body.TenantID, edge, body.IssuerSHA256, body.DER); e != nil {
			writeError(w, 409, e)
			return
		}
		w.WriteHeader(204)
	})
}

func registerTenantInspectionCRLAdminRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, a *tenantInterceptionAuthority, audit func(*http.Request, string, string, map[string]any)) {
	mux.HandleFunc("POST /admin/tenant-interception-authority/root-crl", adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if a == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("tenant interception authority is unavailable"))
			return
		}
		var b struct {
			TenantID string `json:"tenant_id"`
			DER      []byte `json:"der"`
		}
		if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*inspectioncrl.MaxDERBytes)).Decode(&b); e != nil {
			writeError(w, 400, e)
			return
		}
		tenant, e := adminTenantForWrite(r, b.TenantID)
		if e != nil {
			writeError(w, 403, e)
			return
		}
		if e = adminTenantPKITargetAllowed(r, tenant, "updating interception root revocation for"); e != nil {
			writeError(w, 403, e)
			return
		}
		if e = a.updateRootCRL(trustDistributionWriteContext(r.Context()), tenant, b.DER); e != nil {
			writeError(w, 409, e)
			return
		}
		if audit != nil {
			audit(r, tenant, "interception_root_crl", map[string]any{"at": time.Now().UTC()})
		}
		w.WriteHeader(204)
	}))
	mux.HandleFunc("POST /admin/tenant-interception-authority/revoke-delegation", adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if a == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("tenant interception authority is unavailable"))
			return
		}
		var b struct {
			TenantID     string `json:"tenant_id"`
			IssuerSHA256 string `json:"issuer_sha256"`
			Reason       string `json:"reason"`
		}
		if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b); e != nil {
			writeError(w, 400, e)
			return
		}
		tenant, e := adminTenantForWrite(r, b.TenantID)
		if e != nil {
			writeError(w, 403, e)
			return
		}
		if e = adminTenantPKITargetAllowed(r, tenant, "revoking interception delegation for"); e != nil {
			writeError(w, 403, e)
			return
		}
		if !crlFingerprintValid(b.IssuerSHA256) || strings.TrimSpace(b.Reason) == "" || len(b.Reason) > 1000 {
			writeError(w, 400, fmt.Errorf("issued delegation fingerprint and reason required"))
			return
		}
		if e = a.revokeDelegation(trustDistributionWriteContext(r.Context()), tenant, b.IssuerSHA256); e != nil {
			writeError(w, 409, e)
			return
		}
		if audit != nil {
			audit(r, tenant, "interception_revoke_delegation", map[string]any{"issuer_sha256": b.IssuerSHA256, "reason": b.Reason, "at": time.Now().UTC()})
		}
		w.WriteHeader(204)
	}))
}
