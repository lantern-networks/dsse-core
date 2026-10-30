package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// All requests in this file end at this in-memory transport. No listening socket,
// DNS lookup or live endpoint is involved in the tenant-selection checks.
type organizationBundleTransport func(*http.Request) (*http.Response, error)

func (f organizationBundleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func organizationBundleEnvelope(t *testing.T, signer *Signer, tenant string, serial int64) Envelope {
	t.Helper()
	payload := TrustBundlePayload{
		SchemaVersion:  TrustBundleSchema,
		TenantID:       tenant,
		Serial:         serial,
		TransportCAPEM: testCAPEM(t, "Offline organization-selection test CA"),
	}
	var env Envelope
	var err error
	if strings.TrimSpace(tenant) == "" {
		// Negative fixtures must remain correctly signed even when the production
		// signing helper refuses to issue a payload without a tenant.
		env, err = signer.Sign(payload, time.Now())
	} else {
		env, err = signer.SignTrustBundlePayload(payload, time.Now())
	}
	if err != nil {
		t.Fatalf("sign offline fixture: %v", err)
	}
	return env
}

func organizationBundleClient(t *testing.T, env Envelope, status int, inspect func(*http.Request)) *http.Client {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: organizationBundleTransport(func(r *http.Request) (*http.Response, error) {
		inspect(r)
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(raw))),
			Request:    r,
		}, nil
	})}
}

func organizationBundleAssertNoPayload(t *testing.T, got TrustBundlePayload, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("unacceptable organization bundle was accepted")
	}
	if !reflect.DeepEqual(got, TrustBundlePayload{}) {
		t.Fatal("a rejected bundle exposed a usable payload")
	}
}

func TestOrganizationBundleSelectors(t *testing.T) {
	signer := testSigner(t)
	for _, tc := range []struct {
		name       string
		tenant     string
		serverName string
		payloadID  string
		wantQuery  url.Values
	}{
		{
			name: "shared transport still sends tenant", tenant: "tenant-a", payloadID: "tenant-a",
			wantQuery: url.Values{"tenant": {"tenant-a"}},
		},
		{
			name: "named transport sends both selectors", tenant: "tenant-a", serverName: "edge.tenant-a.invalid", payloadID: "tenant-a",
			wantQuery: url.Values{"tenant": {"tenant-a"}, "server_name": {"edge.tenant-a.invalid"}},
		},
		{
			name: "selector characters cannot inject parameters", tenant: "tenant A&server_name=other+?x#fragment/組織",
			serverName: "edge name&tenant=other+?x#fragment", payloadID: "tenant A&server_name=other+?x#fragment/組織",
			wantQuery: url.Values{"tenant": {"tenant A&server_name=other+?x#fragment/組織"}, "server_name": {"edge name&tenant=other+?x#fragment"}},
		},
		{
			name: "surrounding whitespace is trimmed", tenant: " \ttenant-a\n", serverName: "\tedge.tenant-a.invalid \n", payloadID: "tenant-a",
			wantQuery: url.Values{"tenant": {"tenant-a"}, "server_name": {"edge.tenant-a.invalid"}},
		},
		{
			name: "blank optional name is omitted", tenant: "tenant-a", serverName: " \t\n", payloadID: "tenant-a",
			wantQuery: url.Values{"tenant": {"tenant-a"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			env := organizationBundleEnvelope(t, signer, tc.payloadID, 7)
			client := organizationBundleClient(t, env, http.StatusOK, func(r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.URL.Path != trustBundlePath {
					t.Fatalf("unexpected request method/path: %s %s", r.Method, r.URL.Path)
				}
				if !reflect.DeepEqual(r.URL.Query(), tc.wantQuery) || r.URL.RawQuery != tc.wantQuery.Encode() {
					t.Fatalf("selectors = %q, want %q", r.URL.RawQuery, tc.wantQuery.Encode())
				}
				if r.URL.Fragment != "" {
					t.Fatal("selector escaped into URL fragment")
				}
			})
			got, err := FetchVerifiedTrustBundleForOrganization(context.Background(), client, "https://bundle.invalid/", tc.tenant, tc.serverName, []string{signer.PublicKeyHex()}, 6)
			if err != nil {
				t.Fatalf("matching verified bundle: %v", err)
			}
			if strings.TrimSpace(got.TenantID) != strings.TrimSpace(tc.tenant) || got.Serial != 7 {
				t.Fatal("returned payload does not match the verified organization and serial")
			}
			if calls != 1 {
				t.Fatalf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestOrganizationBundleRejectsSignedTenantMismatch(t *testing.T) {
	signer := testSigner(t)
	for _, tc := range []struct{ name, payloadID string }{
		{"another tenant", "tenant-b"},
		{"empty tenant", ""},
		{"whitespace tenant", " \t\n"},
		{"case is significant", "TENANT-A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := organizationBundleClient(t, organizationBundleEnvelope(t, signer, tc.payloadID, 7), http.StatusOK, func(*http.Request) { calls++ })
			got, err := FetchVerifiedTrustBundleForOrganization(context.Background(), client, "https://bundle.invalid", "tenant-a", "", []string{signer.PublicKeyHex()}, 6)
			organizationBundleAssertNoPayload(t, got, err)
			if calls != 1 {
				t.Fatalf("requests = %d, want 1 without fallback", calls)
			}
		})
	}
}

func TestOrganizationBundleKeepsIndependentVerification(t *testing.T) {
	signer := testSigner(t)
	otherSigner := testSigner(t)
	valid := organizationBundleEnvelope(t, signer, "tenant-a", 7)
	wrongSchema, err := signer.Sign(RegionEndpointsPayload{SchemaVersion: RegionEndpointsSchema, TenantID: "tenant-a"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		env    Envelope
		pins   []string
		last   int64
		replay bool
	}{
		{"untrusted signature", valid, []string{otherSigner.PublicKeyHex()}, 6, false},
		{"missing independent pin", valid, nil, 6, false},
		{"wrong signed schema", wrongSchema, []string{signer.PublicKeyHex()}, 0, false},
		{"same serial replay", valid, []string{signer.PublicKeyHex()}, 7, true},
		{"older serial replay", valid, []string{signer.PublicKeyHex()}, 8, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := organizationBundleClient(t, tc.env, http.StatusOK, func(*http.Request) { calls++ })
			got, err := FetchVerifiedTrustBundleForOrganization(context.Background(), client, "https://bundle.invalid", "tenant-a", "", tc.pins, tc.last)
			organizationBundleAssertNoPayload(t, got, err)
			if tc.replay && !errors.Is(err, ErrTrustBundleNotNewer) {
				t.Fatalf("replay lost its existing error identity: %v", err)
			}
			if calls > 1 {
				t.Fatalf("rejected verification retried %d requests", calls)
			}
		})
	}
}

func TestOrganizationBundleUnknownTenantDoesNotFallback(t *testing.T) {
	signer := testSigner(t)
	calls := 0
	client := organizationBundleClient(t, organizationBundleEnvelope(t, signer, "unknown-tenant", 7), http.StatusNotFound, func(r *http.Request) {
		calls++
		if r.URL.Query().Get("tenant") != "unknown-tenant" {
			t.Fatal("unknown tenant request fell back to another selector")
		}
	})
	got, err := FetchVerifiedTrustBundleForOrganization(context.Background(), client, "https://bundle.invalid", "unknown-tenant", "", []string{signer.PublicKeyHex()}, 6)
	organizationBundleAssertNoPayload(t, got, err)
	if calls != 1 {
		t.Fatalf("requests = %d, want exactly one failed lookup", calls)
	}
}

func TestOrganizationBundleBlankTenantDoesNotSendHTTP(t *testing.T) {
	for _, tenant := range []string{"", " ", "\t\r\n"} {
		t.Run("blank_"+strings.ReplaceAll(strings.ReplaceAll(tenant, "\t", "tab"), "\r\n", "newline"), func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: organizationBundleTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("HTTP must not be called")
			})}
			got, err := FetchVerifiedTrustBundleForOrganization(context.Background(), client, "https://bundle.invalid", tenant, "edge.invalid", []string{"not-used"}, 0)
			organizationBundleAssertNoPayload(t, got, err)
			if calls != 0 {
				t.Fatalf("blank tenant sent %d requests", calls)
			}
		})
	}
}

func TestOrganizationBundleLegacyWrappersKeepSelectors(t *testing.T) {
	signer := testSigner(t)
	env := organizationBundleEnvelope(t, signer, "legacy-node-tenant", 7)
	for _, tc := range []struct {
		name      string
		wantQuery string
		fetch     func(*http.Client) (TrustBundlePayload, error)
	}{
		{"single key unnamed", "", func(c *http.Client) (TrustBundlePayload, error) {
			return FetchVerifiedTrustBundle(context.Background(), c, "https://bundle.invalid", signer.PublicKeyHex(), 6)
		}},
		{"key set unnamed", "", func(c *http.Client) (TrustBundlePayload, error) {
			return FetchVerifiedTrustBundleWithKeys(context.Background(), c, "https://bundle.invalid", []string{signer.PublicKeyHex()}, 6)
		}},
		{"name only", "server_name=edge.legacy.invalid", func(c *http.Client) (TrustBundlePayload, error) {
			return FetchVerifiedTrustBundleForName(context.Background(), c, "https://bundle.invalid", "edge.legacy.invalid", []string{signer.PublicKeyHex()}, 6)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := organizationBundleClient(t, env, http.StatusOK, func(r *http.Request) {
				calls++
				if r.URL.RawQuery != tc.wantQuery {
					t.Fatalf("legacy query = %q, want %q", r.URL.RawQuery, tc.wantQuery)
				}
			})
			got, err := tc.fetch(client)
			if err != nil || got.TenantID != "legacy-node-tenant" || got.Serial != 7 {
				t.Fatalf("legacy verified bundle changed: serial=%d, err=%v", got.Serial, err)
			}
			if calls != 1 {
				t.Fatalf("legacy requests = %d, want 1", calls)
			}
		})
	}
}
