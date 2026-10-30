package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/internalca"
	"github.com/lantern-networks/dsse-core/model"
)

func TestSWGConnectionReuseDoesNotCrossTenantRoutes(t *testing.T) {
	servers := map[string]*httptest.Server{}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		servers[tenant] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tenant) }))
		defer servers[tenant].Close()
	}
	var dials atomic.Int32
	base := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		server := servers[edgeplane.FlowTenantFromContext(ctx)]
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer base.CloseIdleConnections()
	for _, tenant := range []string{"tenant-a", "tenant-b", "tenant-a", "tenant-b"} {
		client := swgHTTPEgressProxyClient(&http.Client{Transport: base}, true)
		// No private CA is needed for an HTTP application, or for a private
		// application whose certificate chains to public roots. Routes still differ.
		client.Transport = upstreamTransportTrustingTheOrganizationsPrivateAssets(client.Transport, nil, tenant, time.Now())
		if tr, ok := client.Transport.(*http.Transport); ok {
			defer tr.CloseIdleConnections()
		}
		req, _ := http.NewRequestWithContext(edgeplane.WithFlowTenant(context.Background(), tenant), http.MethodGet, "http://same.internal/", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != tenant {
			t.Errorf("tenant %s reached another route: body=%q err=%v", tenant, body, err)
		}
	}
	if got := dials.Load(); got != 2 {
		t.Errorf("want one reusable connection per tenant, got %d", got)
	}
}

func TestBrowserMimicConnectorPoolDoesNotCrossTenantRoutes(t *testing.T) {
	servers := map[string]*httptest.Server{}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		servers[tenant] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, tenant) }))
		defer servers[tenant].Close()
	}
	var dials atomic.Int32
	connectorTransport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, servers[edgeplane.FlowTenantFromContext(ctx)].Listener.Addr().String())
	}}
	defer connectorTransport.CloseIdleConnections()
	resolve := func(_ context.Context, _, host, _ string) (model.ConnectorRegistration, bool, error) {
		return model.ConnectorRegistration{}, host == "same.internal", nil
	}
	broker := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("broker")), Request: req}, nil
	})
	wrapped := edgeplane.NewConnectorOrBrokerRoundTripper(resolve, "operator", connectorTransport, broker)
	for _, tenant := range []string{"tenant-a", "tenant-b", "tenant-a", "tenant-b"} {
		client := &http.Client{Transport: upstreamTransportTrustingTheOrganizationsPrivateAssets(wrapped, nil, tenant, time.Now())}
		req, _ := http.NewRequestWithContext(edgeplane.WithFlowTenant(context.Background(), tenant), http.MethodGet, "http://same.internal/", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != tenant {
			t.Fatalf("tenant %s reached another route: body=%q err=%v", tenant, body, err)
		}
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("want one reusable connector connection per tenant, got %d", got)
	}
	client := &http.Client{Transport: upstreamTransportTrustingTheOrganizationsPrivateAssets(wrapped, nil, "tenant-b", time.Now())}
	resp, err := client.Get("http://public.example/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "broker" {
		t.Fatalf("public destination lost broker egress: %q", body)
	}
}

func TestBrowserMimicOpaqueConnectorTransportFailsClosed(t *testing.T) {
	resolve := func(_ context.Context, _, host, _ string) (model.ConnectorRegistration, bool, error) {
		return model.ConnectorRegistration{}, host == "same.internal", nil
	}
	connector := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("opaque connector transport was shared across tenants")
		return nil, nil
	})
	broker := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
	})
	wrapped := edgeplane.NewConnectorOrBrokerRoundTripper(resolve, "operator", connector, broker)
	client := &http.Client{Transport: upstreamTransportTrustingTheOrganizationsPrivateAssets(wrapped, nil, "tenant-b", time.Now())}
	if _, err := client.Get("http://same.internal/"); err == nil {
		t.Fatal("unsupported connector pool must refuse instead of sharing")
	}
	resp, err := client.Get("http://public.example/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("public broker path should remain usable: response=%v err=%v", resp, err)
	}
	resp.Body.Close()
}

func TestBrowserMimicPrivateCATrustRemainsTenantScoped(t *testing.T) {
	asset, authority := privateAsset(t)
	now := time.Now().UTC()
	store, err := internalca.NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert(internalca.Authority{ID: "a", TenantID: "tenant-a", CertificatePEM: authority}, now); err != nil {
		t.Fatal(err)
	}
	resolve := func(_ context.Context, _, _ string, _ string) (model.ConnectorRegistration, bool, error) {
		return model.ConnectorRegistration{}, true, nil
	}
	connector := http.DefaultTransport.(*http.Transport).Clone()
	defer connector.CloseIdleConnections()
	broker := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("private asset must not use browser broker")
		return nil, nil
	})
	wrapped := edgeplane.NewConnectorOrBrokerRoundTripper(resolve, "operator", connector, broker)
	for _, tc := range []struct {
		tenant string
		allow  bool
	}{{"tenant-a", true}, {"tenant-b", false}} {
		client := &http.Client{Transport: upstreamTransportTrustingTheOrganizationsPrivateAssets(wrapped, store, tc.tenant, now)}
		req, _ := http.NewRequestWithContext(edgeplane.WithFlowTenant(context.Background(), tc.tenant), http.MethodGet, asset.URL, nil)
		resp, err := client.Do(req)
		if tc.allow && err != nil {
			t.Fatalf("tenant with private CA could not reach asset: %v", err)
		}
		if !tc.allow && err == nil {
			resp.Body.Close()
			t.Fatal("other tenant inherited private CA trust or pooled TLS connection")
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
}
