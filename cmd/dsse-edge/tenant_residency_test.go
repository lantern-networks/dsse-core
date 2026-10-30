package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/tunnel"
)

type residencyLookupFailure struct{}

func (residencyLookupFailure) Get(context.Context, string) (adminTenantModel, error) {
	return adminTenantModel{}, errors.New("tenant store unavailable")
}

func TestTenantResidencyLookupFailureStopsConnectorEgress(t *testing.T) {
	for _, path := range []string{"bypass", "intercept"} {
		t.Run(path, func(t *testing.T) {
			manager := tunnel.NewManager()
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			session, _ := manager.Register("conn-tok", "tunnel", tunnel.NewInProcessConn(a, true))
			go session.Run()
			startFakeConnectorEcho(tunnel.NewInProcessConn(b, false))
			reg := newConnectorEgressTestRegistry(t, []string{"corp.internal"})
			residency := tenantResidencyResolver(residencyLookupFailure{})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var err error
			if path == "bypass" {
				direct := &recordingDirectDialer{}
				dialer := edgeplane.ConnectorEgressDialer{ResolveConnector: connectorDestinationResolver(reg), Tunnels: manager, TenantID: "tenant-a", Residency: residency, Direct: direct}
				conn, e := dialer.OpenTCPConnection(ctx, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "tenant-a", Host: "host.corp.internal", Port: 443})
				err = e
				if conn != nil {
					conn.Close()
				}
				if direct.called {
					t.Fatal("residency lookup failure bypassed connector policy")
				}
			} else {
				direct := func(context.Context, string, string) (net.Conn, error) {
					t.Error("must not dial directly")
					return nil, errors.New("unexpected direct")
				}
				dial := edgeplane.ConnectorEgressDialContext(direct, connectorDestinationResolver(reg), manager, "tenant-a", "", residency, nil, nil)
				conn, e := dial(ctx, "tcp", "host.corp.internal:443")
				err = e
				if conn != nil {
					conn.Close()
				}
			}
			if err == nil || !strings.Contains(err.Error(), "residency") {
				t.Fatalf("unknown residency must deny connection, got %v", err)
			}
		})
	}
}

func TestTenantResidencyLookupFailureStopsMeshDiagnostic(t *testing.T) {
	reg := meshRegistryWithConnectorInRegion(t, "region-x")
	manager := tunnel.NewManager()
	seen := probeConnector(t, manager, "conn-x", true)
	f := tunnel.Frame{Type: tunnel.FrameProbeRequest, RequestID: "probe", TenantID: "tenant-a", ProbeConnectorID: "conn-x", Host: "corp.internal", Port: 443, ProbeProtocol: tunnel.ProbeProtocolWeb}
	_, err := meshConnectorProber(reg, manager, "region-x", tenantResidencyResolver(residencyLookupFailure{}))(context.Background(), f)
	if err == nil || !strings.Contains(err.Error(), "residency") {
		t.Errorf("unknown residency must deny diagnostic, got %v", err)
	}
	select {
	case <-seen:
		t.Error("diagnostic reached connector despite unknown residency")
	default:
	}
}

type residencyLookupFunc func(context.Context, string) (adminTenantModel, error)

func (f residencyLookupFunc) Get(ctx context.Context, id string) (adminTenantModel, error) {
	return f(ctx, id)
}

func TestTenantResidencyResolverKeepsUnpinnedAndConfiguredBoundaries(t *testing.T) {
	if regions, err := tenantResidencyResolver(nil)("tenant-a"); err != nil || len(regions) != 0 {
		t.Fatalf("unconfigured resolver: %v %v", regions, err)
	}
	for _, allowed := range [][]string{nil, {"region-a", "region-b"}} {
		store := residencyLookupFunc(func(_ context.Context, id string) (adminTenantModel, error) {
			if id != "tenant-b" {
				t.Fatalf("looked up wrong tenant %q", id)
			}
			return adminTenantModel{TenantID: id, AllowedRegions: allowed}, nil
		})
		regions, err := tenantResidencyResolver(store)("tenant-b")
		if err != nil || strings.Join(regions, ",") != strings.Join(allowed, ",") {
			t.Fatalf("boundary changed: %v %v", regions, err)
		}
		if len(regions) > 0 {
			regions[0] = "other"
			if allowed[0] != "region-a" {
				t.Fatal("resolver exposed store-owned boundary slice")
			}
		}
	}
}
