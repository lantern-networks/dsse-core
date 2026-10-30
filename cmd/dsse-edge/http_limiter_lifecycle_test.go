package main

import (
	"fmt"
	"testing"
	"time"
)

func TestHTTPRateLimiterReclaimsOnlyFullyRefilledIdleBuckets(t *testing.T) {
	now := time.Now()
	l := newTokenBucketLimiter(1, 2)
	l.now = func() time.Time { return now }
	for i := 0; i < 100; i++ {
		l.allow(fmt.Sprintf("idle-%d", i))
	}
	if !l.allow("active") || !l.allow("active") || l.allow("active") {
		t.Fatal("rate protection absent")
	}
	now = now.Add(time.Second)
	if !l.allow("active") || l.allow("active") {
		t.Fatal("partially refilled key lost its rate history")
	}
	now = now.Add(time.Second)
	l.allow("new")
	if len(l.buckets) != 2 {
		t.Fatalf("idle keys retained forever: %d", len(l.buckets))
	}
	if _, ok := l.buckets["active"]; !ok {
		t.Fatal("active limited key was evicted")
	}
	if !l.allow("active") || l.allow("active") {
		t.Fatal("cleanup reset active rate protection")
	}
}

func TestSeatQuotaAlertsKeepExactTenantIdentity(t *testing.T) {
	e := &enrolmentLicensing{}
	e.noteOverQuota(" Acme ", 2, 1)
	e.noteOverQuota("acme", 3, 1)
	for tenant, want := range map[string]int{"Acme": 2, "acme": 3} {
		if got, ok := e.overQuotaSeen.Load(tenant); !ok || got != want {
			t.Fatalf("tenant alert merged for %s: %v", tenant, got)
		}
	}
}
