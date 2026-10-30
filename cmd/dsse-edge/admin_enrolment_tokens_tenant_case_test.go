package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

func TestEnrolmentTokenOperatorTenantComparisonIsExact(t *testing.T) {
	tokens := enrolltoken.NewStore()
	mux := http.NewServeMux()
	registerAdminEnrolmentTokenEndpoints(mux, tokens, enrolltoken.DefaultPolicy(),
		func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, nil,
		func(_, _ string) string { return "" }, "acme", nil, nil, "", "Acme")
	for _, tc := range []struct {
		tenant string
		want   int
	}{
		{"Acme", http.StatusConflict},
		{"acme", http.StatusOK},
	} {
		r := httptest.NewRequest(http.MethodPost, "/admin/enrolment-tokens",
			strings.NewReader(`{"label":"one device","count":1,"expires_in_hours":8}`))
		r = requestWithAdminIdentity(r, adminIdentity{PrincipalID: "admin", TenantID: tc.tenant})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("tenant %q: HTTP %d, want %d", tc.tenant, w.Code, tc.want)
		}
	}
}

func TestEnrolmentTenantWarningAndDisclosureKeepCaseDistinct(t *testing.T) {
	if warning := enrolmentTokenTenantWarning("Acme", "acme", true, false); warning == "" {
		t.Fatal("different exact-case tenant must not be described as this node's tenant")
	}
	r := requestWithAdminIdentity(httptest.NewRequest(http.MethodGet, "/admin/enrolment-tokens", nil),
		adminIdentity{PrincipalID: "admin", TenantID: "Acme"})
	if got := enrolmentTokenEnrolsForDisclosure(r, "acme"); got != "" {
		t.Fatalf("disclosed another case-distinct tenant %q", got)
	}
	if got := enrolmentTokenEnrolsForDisclosure(r, "Acme"); got != "Acme" {
		t.Fatalf("same-tenant disclosure = %q", got)
	}
}
