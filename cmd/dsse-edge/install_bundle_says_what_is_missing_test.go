package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★★★ AN EMPTY ANSWER AND A WRONG NODE LOOKED THE SAME (2026-08-21, measured across both planes of the
// reference lab). GET /admin/tenant-install-bundle/{tenant} is assembled from the node's own data plane — the
// anchors it serves, the interception engine it runs — and a control plane has neither. The same route, same
// organization, same credential:
//
//	edge          complete=true   interception root "Lab Tenant Interception Root 2028"   1335 bytes of CA
//	control plane complete=false  ""                                                      0 bytes
//
// The second reads exactly like "this organization has nothing set up". It is the document an installer
// embeds, and a device built from the empty version trusts nothing and can verify no Edge.
func TestTheInstallBundleNamesWhatIsMissingAndWhy(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenant-install-bundle/tenant_northwind", nil)
	req.Header.Set("authorization", "Bearer "+testTenantCANorthwindBearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Complete bool     `json:"complete"`
		Missing  []string `json:"missing"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Complete {
		t.Fatal("this harness configures no interception and serves no anchors, so the bundle cannot be " +
			"complete — the control being wrong makes the rest of this test meaningless")
	}
	if len(body.Missing) == 0 {
		t.Fatal("★ the bundle is incomplete and says nothing about what is absent. A caller pointed at a " +
			"control plane gets this same answer, and cannot tell it from an organization that is genuinely " +
			"not set up yet.")
	}
	joined := strings.Join(body.Missing, " | ")
	if !strings.Contains(joined, "transport_ca_pem") {
		t.Fatalf("the absent transport anchors are not named: %s", joined)
	}
	// ★ AND IT MUST POINT AT THE LIKELY CAUSE. Naming the field alone still leaves the reader guessing which
	// node they should have asked, which is the whole failure this came from.
	if !strings.Contains(strings.ToUpper(joined), "CONTROL") {
		t.Fatalf("nothing tells a caller they may have asked the wrong plane: %s", joined)
	}
}
