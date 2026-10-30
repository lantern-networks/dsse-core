package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

type organizationBundleRoundTripper func(*http.Request) (*http.Response, error)

func (f organizationBundleRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Exercise both real callers without opening a listener, changing services, or
// contacting a deployment. A shared-transport profile deliberately has no name.
func TestOrganizationBundleWindowsCallers(t *testing.T) {
	for _, named := range []bool{false, true} {
		for _, reread := range []bool{false, true} {
			for _, foreign := range []bool{false, true} {
				name := "shared"
				if named {
					name = "named"
				}
				if reread {
					name += "/reread"
				} else {
					name += "/recover"
				}
				if foreign {
					name += "/foreign"
				}
				t.Run(name, func(t *testing.T) {
					signer := newTestSigner(t)
					ca := newTestCA(t, "test-shared-transport")
					tenant := "test_device_organization"
					bundleTenant := tenant
					if foreign {
						bundleTenant = "test_other_organization"
					}
					env, err := signer.SignTrustBundlePayload(agentpolicy.TrustBundlePayload{
						SchemaVersion: agentpolicy.TrustBundleSchema, TenantID: bundleTenant,
						Serial: 7, TransportCAPEM: string(ca.pem), TransportServerName: "announced.example.invalid",
					}, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					body, err := json.Marshal(env)
					if err != nil {
						t.Fatal(err)
					}
					tc := &transportConfig{host: "shared.example.invalid:443"}
					if named {
						tc.configuredServerName = "organization.example.invalid"
					}
					calls := 0
					client := &http.Client{Transport: organizationBundleRoundTripper(func(r *http.Request) (*http.Response, error) {
						calls++
						if r.URL.Path != "/bootstrap/trust-bundle" || r.URL.Query().Get("tenant") != tenant ||
							r.URL.Query().Get("server_name") != tc.configuredServerName {
							t.Fatalf("caller did not select the known organization")
						}
						return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
							Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
					})}
					cfg := trustRecoveryConfig{stateDir: t.TempDir(), pinHex: signer.PublicKeyHex(),
						tenantID: tenant, bundleURL: "https://shared.example.invalid", client: client}
					if reread {
						pointer := &adoptedTrustPointer{Serial: 7}
						got := reReadAnnouncedNames(tc, cfg, time.Second, pointer)
						if foreign && got != "" {
							t.Fatal("foreign organization's name was returned")
						}
						if !foreign && got != "announced.example.invalid" {
							t.Fatal("own organization's current name was not returned")
						}
						if pointer.Serial != 7 || pointer.RenewalRecoverySNI != "" {
							t.Fatal("name-only read changed the adopted state")
						}
					} else {
						got, err := fetchVerifiedTrustBundleFor(tc, cfg, time.Second)
						if foreign && (err == nil || got.TenantID != "") {
							t.Fatal("foreign organization's payload was returned")
						}
						if !foreign && (err != nil || got.TenantID != tenant) {
							t.Fatalf("own organization's bundle was refused: %v", err)
						}
					}
					if calls != 1 {
						t.Fatalf("got %d requests; no fallback or retry is permitted", calls)
					}
				})
			}
		}
	}
}

func TestOrganizationBundleWindowsLegacySelector(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: organizationBundleRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Query().Has("tenant") || r.URL.Query().Get("server_name") != "legacy.example.invalid" {
			t.Fatal("unknown-tenant legacy configuration changed selector")
		}
		return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader("not found")), Request: r}, nil
	})}
	cfg := trustRecoveryConfig{stateDir: t.TempDir(), bundleURL: "https://shared.example.invalid", client: client}
	tc := &transportConfig{host: "shared.example.invalid:443", configuredServerName: "legacy.example.invalid"}
	if _, err := fetchVerifiedTrustBundleFor(tc, cfg, time.Second); err == nil || calls != 1 {
		t.Fatal("legacy failure was retried or ignored")
	}
}
