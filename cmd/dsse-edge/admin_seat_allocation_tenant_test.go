package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/seatallocation"
)

// Exercise the actual authenticated route. The operator explicitly chooses the
// organization; a customer's admin or owner role cannot allocate any seats.
func TestSeatAllocationUsesAuthenticatedOperatorAndExactBodyTenant(t *testing.T) {
	for _, tc := range []struct {
		name, home, role, target string
		want                     int
	}{
		{"customer cannot raise its quota", "customer", "admin", "customer", http.StatusForbidden},
		{"customer owner is not the operator", "customer", "owner", "customer", http.StatusForbidden},
		{"customer cannot allocate for another", "customer", "owner", "other", http.StatusForbidden},
		{"operator names a customer", "operations", "super_admin", "customer", http.StatusOK},
		{"operator must explicitly name a tenant", "operations", "super_admin", "", http.StatusBadRequest},
		{"case distinct tenant stays distinct", "operations", "super_admin", "CUSTOMER", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			declareOperatorTenantForTest(t, "operations")
			now := time.Now()
			tenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, now, "", "operations")
			for _, id := range []string{"operations", "customer", "CUSTOMER", "other"} {
				if _, err := tenants.Put(context.Background(), adminTenantModel{TenantID: id, Status: "active"}, now); err != nil {
					t.Fatal(err)
				}
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "principal", TenantID: tc.home, Roles: []string{tc.role}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "token", TenantID: tc.home, TokenHash: adminTokenHash("seat-boundary-fixture"), Roles: []string{tc.role}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "principal", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
			allocations := seatallocation.NewStore()
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, TenantModelStore: tenants, OperatorTenantID: "operations", SeatAllocations: allocations, VendorLicense: newLicenseStore(), LicenseAllowOversubscription: true})
			r := httptest.NewRequest(http.MethodPost, "/admin/seat-allocations", strings.NewReader(fmt.Sprintf(`{"tenant_id":%q,"seats":7}`, tc.target)))
			r.Header.Set("Authorization", "Bearer seat-boundary-fixture")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
			rows := allocations.List()
			if tc.want != http.StatusOK {
				if len(rows) != 0 {
					t.Fatalf("refused request changed allocations: %+v", rows)
				}
			} else if len(rows) != 1 || rows[0].TenantID != tc.target || rows[0].Seats != 7 {
				t.Fatalf("allocation target changed: %+v", rows)
			}
		})
	}
}

func mustReadSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func section(src, from, to string) string {
	i := strings.Index(src, from)
	if i < 0 {
		return ""
	}
	if to == "" {
		return src[i:]
	}
	j := strings.Index(src[i:], to)
	if j < 0 {
		return src[i:]
	}
	return src[i : i+j]
}
