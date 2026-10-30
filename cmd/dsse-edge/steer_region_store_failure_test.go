package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

func TestRegionEndpointsRefuseUnavailableTenantPlacement(t *testing.T) {
	catalog, err := parseRegionEndpoints("east=https://east.example:443;west=https://west.example:443")
	if err != nil {
		t.Fatal(err)
	}
	old := regionMap.Catalog()
	regionMap.Set(catalog)
	t.Cleanup(func() { regionMap.Set(old) })
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("placement-device", "tenant_placement", "", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerSteerAgentPolicyRoutes(mux, serverConfig{EnrolledLedger: ledger}, testEvaluator(), nil, nil, nil, nil, failedEnrollmentLifecycle{})
	response := asVerifiedDevice(t, mux, "placement-device", "/steer/region-endpoints")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable placement returned %d: %s", response.Code, response.Body.String())
	}
}
