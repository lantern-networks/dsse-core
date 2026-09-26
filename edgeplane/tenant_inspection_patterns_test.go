package edgeplane

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestTenantPinProposalUsesTheActualTLSRoute(t *testing.T) {
	e, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	proposals := make(chan string, 3)
	e.SetTenantCertPinCandidateEmitter(func(tenant, host string) { proposals <- tenant + "/" + host })
	for _, tenant := range []string{"a", "b", "a"} {
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			e.serve(server, NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: "pin.invalid", Port: 443}, &networkExtensionLabTLSConnState{})
		}()
		client.SetDeadline(time.Now().Add(2 * time.Second))
		conn := tls.Client(client, &tls.Config{ServerName: "pin.invalid", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12})
		if err := conn.Handshake(); err == nil {
			t.Fatal("untrusted fixture certificate accepted")
		}
		client.Close()
		<-done
	}
	if len(proposals) != 1 || <-proposals != "a/pin.invalid" {
		t.Fatal("TLS failure attributed across route owners")
	}
	for _, tenant := range []string{"a", "b"} {
		if !e.Matches(NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: "pin.invalid", Port: 443}) {
			t.Fatal("default detection bypassed traffic")
		}
	}
}

func TestTenantInspectionPatternsSeparateFallbackAndReplacement(t *testing.T) {
	e := NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	e.SetSNIBasedDecision(true)
	defaults := InspectionPatterns{Intercept: []string{"*"}, Bypass: []string{"system.invalid"}}
	a := InspectionPatterns{Intercept: []string{"*"}, Bypass: []string{"a.invalid"}}
	b := InspectionPatterns{Intercept: []string{"selected.invalid"}, Bypass: []string{"b.invalid"}}
	entries := map[string]InspectionPatterns{"a": a, "b": b, "": {Bypass: []string{"*"}}}
	e.ReplaceInspectionPatterns(defaults, entries)
	a.Bypass[0] = "*"
	defaults.Bypass[0] = "*"
	delete(entries, "b")
	for _, tc := range []struct {
		tenant, host string
		want         bool
	}{
		{"a", "a.invalid", false}, {"b", "a.invalid", false}, {"a", "b.invalid", true},
		{"b", "selected.invalid", true}, {"a", "selected.invalid", true}, {"unknown", "a.invalid", true},
		{"", "a.invalid", true}, {"unknown", "system.invalid", false}, {"a", "system.invalid", true},
	} {
		if got := e.Matches(NetworkExtensionRuntimeCopyTCPRoute{TenantID: tc.tenant, Host: "192.0.2.1", SNI: tc.host, Port: 443}); got != tc.want {
			t.Fatalf("%s %s = %v", tc.tenant, tc.host, got)
		}
	}
	copy := e.InspectionPatternsForTenant("a")
	copy.Bypass[0] = "*"
	if e.InspectionPatternsForTenant("a").Bypass[0] != "a.invalid" {
		t.Fatal("snapshot alias")
	}
	e.ReplaceInspectionPatterns(InspectionPatterns{Intercept: []string{"*"}}, nil)
	if !e.Matches(NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", Host: "a.invalid", Port: 443}) {
		t.Fatal("removed tenant bypass retained")
	}
}

func TestTenantInspectionPatternSnapshotIsAtomic(t *testing.T) {
	e := NewNetworkExtensionLabTLSInterceptionMatchOnly(nil)
	one := InspectionPatterns{Intercept: []string{"one.invalid"}, Bypass: []string{"two.invalid"}}
	two := InspectionPatterns{Intercept: []string{"two.invalid"}, Bypass: []string{"one.invalid"}}
	e.ReplaceInspectionPatterns(one, map[string]InspectionPatterns{"a": one})
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func(writer bool) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				if writer {
					p := one
					if i%2 == 0 {
						p = two
					}
					e.ReplaceInspectionPatterns(p, map[string]InspectionPatterns{"a": p})
				} else {
					p := e.InspectionPatternsForTenant("a")
					if !reflect.DeepEqual(p, one) && !reflect.DeepEqual(p, two) {
						t.Error("mixed pattern revision", p)
						return
					}
					e.Matches(NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", Host: "one.invalid", Port: 443})
				}
			}
		}(n == 0)
	}
	wg.Wait()
}

func TestTenantPinLearningDoesNotCrossRouteOwners(t *testing.T) {
	e, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	e.SetDynamicPinDetectionEnabled(true)
	var proposals []string
	e.SetTenantCertPinCandidateEmitter(func(tenant, host string) { proposals = append(proposals, tenant+"/"+host) })
	e.recordHandshakeOutcomeForTenant("a", "same.invalid", false)
	e.recordHandshakeOutcomeForTenant("b", "same.invalid", true)
	if !e.recordHandshakeOutcomeForTenant("a", "same.invalid", false) {
		t.Fatal("another tenant reset failures")
	}
	for _, tenant := range []string{"a", "b", ""} {
		got := e.Matches(NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: "same.invalid", Port: 443})
		if got != (tenant != "a") {
			t.Fatal("pin crossed tenant", tenant, got)
		}
	}
	if !reflect.DeepEqual(proposals, []string{"a/same.invalid"}) {
		t.Fatal("wrong proposal owner", proposals)
	}
	e.SetDynamicPinDetectionEnabled(false)
	if !e.Matches(NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", Host: "same.invalid", Port: 443}) {
		t.Fatal("disabled pin retained")
	}
	e.recordHandshakeOutcomeForTenant("c", "another.invalid", false)
	e.recordHandshakeOutcomeForTenant("c", "another.invalid", false)
	if !e.Matches(NetworkExtensionRuntimeCopyTCPRoute{TenantID: "c", Host: "another.invalid", Port: 443}) || proposals[1] != "c/another.invalid" {
		t.Fatal("proposal auto-bypassed or lost owner")
	}
}
