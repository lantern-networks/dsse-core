package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ A MEMBER IN ANOTHER REGION HAD NO WAY TO EXIST (2026-08-31). The consensus store's own comment says
// there is one per deployment with a member per region, and three things in the rendered file made that
// impossible:
//
//   - the member list was three container aliases, which name nothing outside this host
//   - each member advertised a container alias as its peer URL, so anyone told about it could not dial it
//   - only the CLIENT port was published; peers gossip on 2380 and it was not published at all
//
// The third is the one that decides it: a member can be told about this one and still never reach it. A
// cluster that looks configured and cannot form is the shape this project spends its days removing.
//
// The default still renders the one-host reference exactly, because that deployment exists and is correct.
func TestTheStoreCanBeToldWhereItsMembersActuallyAre(t *testing.T) {
	dir := t.TempDir()
	if err := writeComposeFile(dir); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)

	// The peer port is published, or no member anywhere else can ever join.
	if !strings.Contains(got, ":2380\"") {
		t.Error("the peer port is not published: members gossip on 2380, so a member elsewhere could be told " +
			"about this one and never reach it")
	}

	// Every value a deployment spanning machines has to change is a variable, not a literal.
	for _, knob := range []string{
		"${DSSE_ETCD_INITIAL_CLUSTER:-",       // who the members are
		"${DSSE_ETCD_INITIAL_CLUSTER_STATE:-", // new cluster, or joining one that exists
		"${DSSE_ETCD_A_PEER_ADVERTISE:-",      // what this member tells the others to dial
		"${DSSE_ETCD_A_PEER_PUBLISH:-",        // where it actually listens for them
	} {
		if !strings.Contains(got, knob) {
			t.Errorf("%s is not a variable, so a deployment across machines cannot set it", knob)
		}
	}

	// ★ THE DEFAULT IS ONE MEMBER NOW (2026-09-03, the operator's decision — see
	// TestAOneHostDeploymentRendersOneStoreMember). It was the three container aliases, which was right while
	// a one-host deployment ran three; a default naming members the file no longer defines is a store that
	// waits for something that will never arrive.
	if !strings.Contains(got, "dsse-store-a=http://dsse-store-a:2380") {
		t.Error("the default no longer names the one local member")
	}
	if strings.Contains(got, "dsse-store-b=http://dsse-store-b:2380") {
		t.Error("the default still names members this file does not define")
	}
	if !strings.Contains(got, "ETCD_INITIAL_CLUSTER_STATE: ${DSSE_ETCD_INITIAL_CLUSTER_STATE:-new}") {
		t.Error("the one-host default no longer bootstraps a new cluster")
	}

	// ★ THE MEMBER PUBLISHES ITS OWN PORTS. When there were three, sharing a host port was a member that
	// never started; with one, this holds that the ports are still the machine's and not the container's.
	if !strings.Contains(got, "12390") {
		t.Error("the member's peer port is missing")
	}
}
