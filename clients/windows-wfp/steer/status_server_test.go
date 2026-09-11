package main

import (
	"net"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentstatus"
)

func TestDeriveProtection(t *testing.T) {
	cases := []struct {
		disarmed, captive, edge bool
		want                    agentstatus.Protection
	}{
		{false, false, true, agentstatus.Steering},         // armed, edge up
		{false, false, false, agentstatus.Dark},            // armed, edge down => fail-closed dark
		{true, true, false, agentstatus.CaptiveOnboarding}, // disarmed for captive window
		{true, false, false, agentstatus.Disarmed},         // disarmed via fail-open
		{true, true, true, agentstatus.CaptiveOnboarding},  // captive window (edge state irrelevant while disarmed)
	}
	for _, c := range cases {
		if got := deriveProtection(c.disarmed, c.captive, c.edge); got != c.want {
			t.Fatalf("deriveProtection(%v,%v,%v)=%s want %s", c.disarmed, c.captive, c.edge, got, c.want)
		}
	}
}

func TestServeAndFetchStatus(t *testing.T) {
	holder := agentstatus.NewHolder(agentstatus.Status{Protection: agentstatus.Stopped})
	holder.Set(func(s *agentstatus.Status) {
		s.Tenant = "acme"
		s.Group = "developers"
		s.Region = "ap-northeast-1"
		s.Posture = "fail-closed"
	})
	holder.SetProtection(agentstatus.Steering, 1_700_000_000)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { serveStatus(stop, ln, holder, nil); close(done) }()

	// give the server a beat to start serving
	var got agentstatus.Status
	for i := 0; i < 50; i++ {
		got, err = fetchStatus(addr, 2*time.Second)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got.Protection != agentstatus.Steering || got.Tenant != "acme" || got.Region != "ap-northeast-1" {
		t.Fatalf("fetched status mismatch: %+v", got)
	}

	// live update is reflected on the next fetch
	holder.SetProtection(agentstatus.Dark, 1_700_000_001)
	got, err = fetchStatus(addr, 2*time.Second)
	if err != nil || got.Protection != agentstatus.Dark {
		t.Fatalf("expected dark after update, got %+v err=%v", got, err)
	}

	close(stop)
	<-done
}
