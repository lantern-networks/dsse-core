package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 0.4.1 final acceptance A (2026-11-09): the published single-region layout, installed exactly as -order says,
// failed -verify on "the consensus store can lose one place". The check recognised one host by its store
// speaking plain HTTP; security review S4 put that store on TLS. One machine is one place by declaration, and
// this check now asks the shape the way the doorway check does.
func TestAOneMachineDeploymentsTLSStoreIsNotAskedToSurviveLosingAPlace(t *testing.T) {
	dir := t.TempDir()
	env := strings.Join([]string{
		"DSSE_ETCD_CLIENT_SCHEME='https'",
		"DSSE_ETCD_HOSTS=\"'node-a.example.test:12379'\"",
		"DSSE_REGION_ENDPOINTS='region-a=https://agents.region-a.example.test'",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if !deploymentIsASingleMachine(dir) {
		t.Fatal("the fixture is not the single-machine shape; the test proves nothing")
	}
	got := verifyTheStoreCanLoseAPlace(dir, readDeploymentEnv(dir))
	if len(got) != 1 || !got[0].ok || got[0].name != "the consensus store spans places" {
		t.Fatalf("a one-machine deployment with a TLS store was failed for being one machine: %+v", got)
	}
}

// The exemption must not reach a deployment of several machines: with control-plane peers declared, the store is
// asked, and a store this walk cannot reach is reported as not asked rather than passed.
func TestASeveralMachineDeploymentsStoreIsStillAsked(t *testing.T) {
	dir := t.TempDir()
	env := strings.Join([]string{
		"DSSE_ETCD_CLIENT_SCHEME='https'",
		"DSSE_ETCD_HOSTS=\"'cp-a.example.test:12379,cp-b.example.test:12379,cp-c.example.test:12379'\"",
		"DSSE_CP_PEERS='https://cp-b.example.test:19543,https://cp-c.example.test:19543'",
		"DSSE_REGION_ENDPOINTS='region-a=https://agents.region-a.example.test;region-b=https://agents.region-b.example.test'",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if deploymentIsASingleMachine(dir) {
		t.Fatal("the fixture reads as one machine; the test proves nothing")
	}
	got := verifyTheStoreCanLoseAPlace(dir, readDeploymentEnv(dir))
	if len(got) != 1 || got[0].ok || got[0].name == "the consensus store spans places" {
		t.Fatalf("a several-machine deployment took the one-machine exemption: %+v", got)
	}
}
