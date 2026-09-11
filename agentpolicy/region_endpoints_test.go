package agentpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// regionEndpointsServer stands up a test Edge that signs and serves a region-endpoints envelope with signer, and
// returns the base URL + a client.
func regionEndpointsServer(t *testing.T, signer *Signer, payload map[string]any) (string, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(regionEndpointsPath, func(w http.ResponseWriter, _ *http.Request) {
		env, err := signer.Sign(payload, time.Now())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(env)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client()
}

func TestFetchVerifiedRegionEndpoints_Valid(t *testing.T) {
	signer, err := LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"schema_version":  RegionEndpointsSchema,
		"tenant_id":       "tenant-a",
		"device_identity": "win-dev-1",
		"home_region":     "jp-east",
		"allowed_region_endpoints": []map[string]string{
			{"region": "jp-east", "endpoint": "https://edge-jp.example.com:18543"},
			{"region": "ap-southeast", "endpoint": "https://edge-sg.example.com:18543"},
		},
	}
	base, client := regionEndpointsServer(t, signer, payload)

	got, err := FetchVerifiedRegionEndpoints(context.Background(), client, base, signer.PublicKeyHex())
	if err != nil {
		t.Fatalf("valid signed list must verify: %v", err)
	}
	if got.HomeRegion != "jp-east" || got.TenantID != "tenant-a" {
		t.Fatalf("payload metadata wrong: %+v", got)
	}
	if len(got.AllowedRegionEndpoints) != 2 ||
		got.AllowedRegionEndpoints[0].Region != "jp-east" ||
		got.AllowedRegionEndpoints[0].Endpoint != "https://edge-jp.example.com:18543" {
		t.Fatalf("allowed endpoints wrong: %+v", got.AllowedRegionEndpoints)
	}
}

func TestFetchVerifiedRegionEndpoints_WrongKeyRejected(t *testing.T) {
	signer, _ := LoadOrGenerateSigner("", true)
	attacker, _ := LoadOrGenerateSigner("", true) // a DIFFERENT key
	payload := map[string]any{
		"schema_version":           RegionEndpointsSchema,
		"home_region":              "jp-east",
		"allowed_region_endpoints": []map[string]string{{"region": "jp-east", "endpoint": "https://e.example.com:18543"}},
	}
	base, client := regionEndpointsServer(t, signer, payload)

	if _, err := FetchVerifiedRegionEndpoints(context.Background(), client, base, attacker.PublicKeyHex()); err == nil {
		t.Fatal("a list signed by a different key MUST be rejected (fail-closed)")
	}
}

func TestFetchVerifiedRegionEndpoints_WrongSchemaRejected(t *testing.T) {
	signer, _ := LoadOrGenerateSigner("", true)
	// A correctly-signed envelope, but the payload is a steer-exclusion body, not region endpoints.
	payload := map[string]any{
		"schema_version":           EnvelopeType,
		"excluded_app_signing_ids": []string{"com.example.vpn"},
	}
	base, client := regionEndpointsServer(t, signer, payload)

	_, err := FetchVerifiedRegionEndpoints(context.Background(), client, base, signer.PublicKeyHex())
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("a mis-schema'd (but validly signed) body MUST be rejected; got %v", err)
	}
}

func TestFetchVerifiedRegionEndpoints_NoPinRejected(t *testing.T) {
	if _, err := FetchVerifiedRegionEndpoints(context.Background(), http.DefaultClient, "https://x", ""); err == nil {
		t.Fatal("an empty pin MUST be rejected (no TOFU on every fetch)")
	}
}
