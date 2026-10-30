package dnsresolver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type tenantDNSConnector struct {
	fakeConnectorDNS
	tenant string
	ctx    context.Context
}

func (c *tenantDNSConnector) ResolveViaConnectorForTenant(ctx context.Context, tenant, upstream string, raw []byte) ([]byte, error) {
	c.tenant, c.ctx = tenant, ctx
	return c.ResolveViaConnector(ctx, upstream, raw)
}

func TestDNSQueryAttributionUsesAuthenticatedTenant(t *testing.T) {
	for _, mode := range []string{"public", "sinkhole", "stub", "connector"} {
		t.Run(mode, func(t *testing.T) {
			ct := dns.NewConntrackStore()
			response := dnsAplusHTTPSEch(t, "app.example.", [4]byte{192, 0, 2, 5})
			r := NewWithUpstream("Tenant", fakeUpstream{resp: response}, ct)
			dto := PolicyDTO{}
			switch mode {
			case "sinkhole":
				dto.Sinkhole = map[string]string{"app.example": "192.0.2.5"}
			case "stub":
				dto.StubIPv4 = map[string]string{"app.example": "192.0.2.5"}
			case "connector":
				dto.ForwardZones = []ForwardZoneDTO{{Zone: "example", Upstream: "192.0.2.53:53"}}
			}
			p, err := PolicyFromDTO(dto)
			if err != nil {
				t.Fatal(err)
			}
			r.SetPolicy(p)
			connector := &tenantDNSConnector{fakeConnectorDNS: fakeConnectorDNS{resp: response}}
			r.SetConnectorDNS(connector)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := time.Now()
			if _, err := r.HandleQueryForTenant(ctx, "tenant", dnsQuery(t, "app.example.", dnsmessage.TypeA), now); err != nil {
				t.Fatal(err)
			}
			if fqdn, _, ok := ct.LookupFQDN("tenant", "192.0.2.5", now); !ok || fqdn != "app.example" {
				t.Fatal("authenticated tenant did not receive its DNS observation")
			}
			if _, _, ok := ct.LookupFQDN("Tenant", "192.0.2.5", now); ok {
				t.Fatal("DNS observation escaped into the boot tenant")
			}
			if mode == "connector" && (connector.tenant != "tenant" || connector.ctx != ctx) {
				t.Fatal("private DNS did not retain request tenant and cancellation")
			}
		})
	}
}

func TestLegacyPrivateDNSCannotRouteAnotherTenant(t *testing.T) {
	r := NewWithUpstream("Tenant", &countedUpstream{}, nil)
	c := &fakeConnectorDNS{}
	r.SetConnectorDNS(c)
	p, err := PolicyFromDTO(PolicyDTO{ForwardZones: []ForwardZoneDTO{{Zone: "example", Upstream: "192.0.2.53:53"}}})
	if err != nil {
		t.Fatal(err)
	}
	r.SetPolicy(p)
	out, err := r.HandleQueryForTenant(context.Background(), "tenant", dnsQuery(t, "app.example.", dnsmessage.TypeA), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var reply dnsmessage.Message
	if reply.Unpack(out) != nil || reply.RCode != dnsmessage.RCodeServerFailure || c.called {
		t.Fatal("legacy adapter routed another tenant's private query")
	}
}

func TestOverTunnelTenantMustBeVerifiedBeforeReadingQuery(t *testing.T) {
	for _, tc := range []struct {
		name, tenant string
		verified     bool
	}{
		{"unverified", "tenant", false}, {"missing", " ", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &countedUpstream{}
			r := NewWithUpstream("boot", u, nil)
			h := OverTunnelHandlerForTenant(r, func(*http.Request) (string, bool) { return tc.tenant, tc.verified })
			w := httptest.NewRecorder()
			h(w, httptest.NewRequest(http.MethodPost, "/steer/dns-query", bytes.NewReader(dnsQuery(t, "app.example.", dnsmessage.TypeA))))
			if w.Code != http.StatusUnauthorized || u.calls != 0 {
				t.Fatal("unverified tenant was resolved")
			}
		})
	}
}
