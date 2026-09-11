package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
)

// ★★★ EVERY CONNECTOR STORE RECORDS LIVENESS, BECAUSE A GENERATED DEPLOYMENT RUNS THE OTHER ONE (2026-09-01,
// the second time in one day).
//
// The method was added to the in-memory registry. The report handler asks for it with a type assertion; the
// postgres store a generated deployment actually uses did not implement it, so the assertion quietly found
// nothing and every liveness report was dropped — while the Console went on showing a site with two live
// connectors as "Down — 0 of 2 online".
//
// It is the same shape as the enrolment-token refusal fixed this morning: a concrete store swapped in and a
// path silently off. A compile-time check is the cheapest guard that exists for it, so the next store added
// here fails to build rather than failing in a deployment.
func TestEveryConnectorRegistryImplementsTheLivenessRecorder(t *testing.T) {
	var _ connectorLivenessRecorder = postgresConnectorRegistryStore{}
	// The in-memory one is the *connector.Registry the reference Edge runs; asserted through the same
	// interface so the two cannot drift apart in either direction.
	var _ connectorLivenessRecorder = connector.NewRegistry()
}
