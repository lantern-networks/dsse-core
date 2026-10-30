package main

import (
	"testing"
	"time"
)

func TestConfigBundleTrafficGate(t *testing.T) {
	if !configBundleReadyForTraffic(nil, nil) {
		t.Fatal("a standalone authority must serve without a puller")
	}
	source := &configBundleSource{}
	if configBundleReadyForTraffic(source, nil) {
		t.Fatal("a configured puller without status must fail closed")
	}
	status := &configBundleSyncStatus{}
	if configBundleReadyForTraffic(source, status) {
		t.Fatal("a new Edge must not serve before its first successful bundle")
	}
	status.recordError(errInitialBundleForTest{}, time.Now())
	if configBundleReadyForTraffic(source, status) {
		t.Fatal("a failed initial pull must not open the data plane")
	}
	status.recordApplied(1, "epoch", 2, time.Now())
	if !configBundleReadyForTraffic(source, status) {
		t.Fatal("an applied bundle must open the data plane")
	}
	status.recordError(errInitialBundleForTest{}, time.Now())
	if !configBundleReadyForTraffic(source, status) {
		t.Fatal("a later transient CP error must retain last good enforcement")
	}
}

type errInitialBundleForTest struct{}

func (errInitialBundleForTest) Error() string { return "initial bundle unavailable" }
