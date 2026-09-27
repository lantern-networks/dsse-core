package edgeplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestInspectionDeviceScopesAreIsolatedCopiedAndCleared(t *testing.T) {
	e := NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	e.SetSNIBasedDecision(true)
	a := InspectionPatterns{Intercept: []string{"*"}, BypassByDevice: map[string][]string{"device-a": {"TARGET.invalid"}, "": {"*"}, " device-a ": {"*"}}}
	b := InspectionPatterns{Intercept: []string{}, InterceptByDevice: map[string][]string{"device-a": {"target.invalid"}}}
	defaults := InspectionPatterns{Intercept: []string{"*"}, BypassByDevice: map[string][]string{"device-a": {"*"}}}
	e.ReplaceInspectionPatterns(defaults, map[string]InspectionPatterns{"a": a, "b": b})
	a.BypassByDevice["device-a"][0] = "*"
	delete(b.InterceptByDevice, "device-a")
	for _, tc := range []struct {
		tenant, device, osuser, host string
		want                         bool
	}{
		{"a", "device-a", "", "target.invalid", false}, {"a", "device-b", "device-a", "target.invalid", true}, {"a", "", "device-a", "target.invalid", true}, {"a", "DEVICE-A", "", "target.invalid", true}, {"a", "device-a", "", "other.invalid", true},
		{"b", "device-a", "", "target.invalid", true}, {"b", "device-b", "", "target.invalid", false}, {"unknown", "device-a", "", "target.invalid", true}, {"", "device-a", "", "target.invalid", true},
	} {
		r := NetworkExtensionRuntimeCopyTCPRoute{TenantID: tc.tenant, DeviceIdentity: tc.device, OSUser: tc.osuser, Host: "192.0.2.1", SNI: tc.host, Port: 443}
		if got := e.Matches(r); got != tc.want {
			t.Fatalf("%+v got=%v", tc, got)
		}
	}
	p := e.InspectionPatternsForTenant("a")
	if len(p.BypassByDevice) != 1 || len(p.Bypass) != 0 {
		t.Fatal("invalid device keys or shared exception", p)
	}
	p.BypassByDevice["device-a"][0] = "*"
	if e.InspectionPatternsForTenant("a").BypassByDevice["device-a"][0] != "target.invalid" {
		t.Fatal("read alias")
	}
	e.ReplaceInspectionPatterns(InspectionPatterns{Intercept: []string{"*"}}, nil)
	if !e.Matches(NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", DeviceIdentity: "device-a", Host: "target.invalid", Port: 443}) {
		t.Fatal("removed device exception retained")
	}
}

func TestInspectionDeviceScopeSnapshotAtomic(t *testing.T) {
	e := NewNetworkExtensionLabTLSInterceptionMatchOnly(nil)
	one := InspectionPatterns{Intercept: []string{"*"}, Bypass: []string{}, BypassByDevice: map[string][]string{"device-a": {"one.invalid"}}}
	two := InspectionPatterns{Intercept: []string{}, Bypass: []string{}, InterceptByDevice: map[string][]string{"device-b": {"two.invalid"}}}
	e.ReplaceInspectionPatterns(InspectionPatterns{}, map[string]InspectionPatterns{"a": one})
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func(writer bool) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if writer {
					p := one
					if i%2 != 0 {
						p = two
					}
					e.ReplaceInspectionPatterns(InspectionPatterns{}, map[string]InspectionPatterns{"a": p})
				} else {
					p := e.InspectionPatternsForTenant("a")
					if !reflect.DeepEqual(p, one) && !reflect.DeepEqual(p, two) {
						t.Error("mixed device selector snapshot", p)
						return
					}
					e.Matches(NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", DeviceIdentity: "device-a", Host: "one.invalid", Port: 443})
				}
			}
		}(n == 0)
	}
	wg.Wait()
}

type deviceScopeRecordingDialer struct {
	called []NetworkExtensionRuntimeCopyTCPRoute
	err    error
}

func (d *deviceScopeRecordingDialer) OpenTCPConnection(_ context.Context, r NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	d.called = append(d.called, r)
	return nil, d.err
}
func TestInspectionDeviceScopeSelectsRealTLSInsteadOfRawForward(t *testing.T) {
	e, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	e.ReplaceInspectionPatterns(InspectionPatterns{Intercept: []string{"*"}}, map[string]InspectionPatterns{"a": {Intercept: []string{"*"}, BypassByDevice: map[string][]string{"device-a": {"target.invalid"}}}})
	sentinel := errors.New("fixture raw dial")
	base := &deviceScopeRecordingDialer{err: sentinel}
	dialer := NetworkExtensionRuntimeCopyTLSInterceptionDialer{Base: base, Intercepter: e}
	r := NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", DeviceIdentity: "device-a", Host: "target.invalid", Port: 443}
	if _, err := dialer.OpenTCPConnection(context.Background(), r); !errors.Is(err, sentinel) {
		t.Fatal("selected device was not raw forwarded", err)
	}
	r.DeviceIdentity = "device-b"
	conn, err := dialer.OpenTCPConnection(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(e.RootCertificatePEM())
	tlsConn, ok := conn.(interface{ SetDeadline(time.Time) error })
	if ok {
		tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	}
	// OpenTCPConnection returns the in-process TLS connection as a net.Conn.
	client := tls.Client(conn.(net.Conn), &tls.Config{ServerName: "target.invalid", RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if len(base.called) != 1 || base.called[0].DeviceIdentity != "device-a" {
		t.Fatal("other device raw forwarded", base.called)
	}
}
