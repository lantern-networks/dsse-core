package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/revocation"
)

// ★ THE DEFECT THIS EXISTS FOR (2026-08-17, found on the lab). The fast revocation poller had been failing
// every two seconds since boot — the control plane answering 403 because the Edge's token lacked
// admin.endpoints.read — and the ONLY place that said so was the container log. /healthz answered ok, the
// security-posture check reported 24 passed / 0 failed, and the Console showed nothing. A device revoked on
// the control plane was not refused by this node, and no surface of the product disagreed.
//
// Fail-closed is what made it invisible: keeping the last synced set is right, and "never received a first
// set" looks exactly like "the control plane has nothing to revoke" from the outside. So the status has to
// distinguish them, and have_applied is the field that does.
func TestRevocationSyncStatusSeparatesNeverHeardFromNothingToRevoke(t *testing.T) {
	// A control plane that refuses this Edge, exactly as the lab's did.
	refusing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"admin api token scope admin.endpoints.read is required"}`))
	}))
	defer refusing.Close()

	status := &revocationSyncStatus{}
	src := revocationSource{
		url: refusing.URL, token: "t", interval: time.Hour, status: status,
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
	}
	overlay := revocation.NewAdmissionRevocations()
	ctx, cancel := context.WithCancel(context.Background())
	go src.run(ctx, overlay, nil)
	waitFor(t, func() bool { return status.snapshot()["consecutive_failures"].(int) > 0 })
	cancel()

	snap := status.snapshot()
	if snap["have_applied"].(bool) {
		t.Fatal("nothing was ever applied, so have_applied must be false")
	}
	if snap["last_error"].(string) == "" {
		t.Fatal("a refused pull must leave the reason behind — the lab's said which SCOPE was missing, which is what made it fixable")
	}

	// And an EMPTY-but-answered set is a different state: the control plane spoke, there is nothing to revoke.
	empty := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(revocationFeed{Generation: 1, Epoch: "e1", Revoked: map[string]string{}, Authoritative: true})
	}))
	defer empty.Close()
	status2 := &revocationSyncStatus{}
	src2 := revocationSource{
		url: empty.URL, token: "t", interval: time.Hour, status: status2,
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	go src2.run(ctx2, revocation.NewAdmissionRevocations(), nil)
	waitFor(t, func() bool { return status2.snapshot()["have_applied"].(bool) })
	cancel2()

	snap2 := status2.snapshot()
	if snap2["consecutive_failures"].(int) != 0 {
		t.Fatalf("a successful pull clears the failure run, got %v", snap2["consecutive_failures"])
	}
	if snap2["revocation_count"].(int) != 0 {
		t.Fatalf("the count is what the control plane sent, got %v", snap2["revocation_count"])
	}
	// The two states must not read the same. This is the whole point.
	if snap["have_applied"] == snap2["have_applied"] {
		t.Fatal("\"never heard from the control plane\" and \"nothing to revoke\" produce the same status — the defect is back")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached within 5s")
}
