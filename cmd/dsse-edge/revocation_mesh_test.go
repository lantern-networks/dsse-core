package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/revocation"
)

// fakePeerCP mirrors the real POST /revocation-mesh/admission handler (secret check + RevokeFromMesh) against a
// real overlay, so the test exercises the push wire contract end to end over a real socket.
func fakePeerCP(t *testing.T, overlay *revocation.AdmissionRevocations, secret string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/revocation-mesh/admission" {
			http.NotFound(w, r)
			return
		}
		if secret != "" && r.Header.Get("x-revocation-mesh-secret") != secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var item revocationMeshItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		overlay.RevokeFromMesh(item.Identity, item.Reason)
		w.WriteHeader(http.StatusOK)
	}))
}

// TestRevocationMeshPushReachesPeerOverlay proves the proprietary push side over a real HTTP round trip: an origin
// revocation on region A is pushed to region B's CP and folded into B's overlay (denied on B).
func TestRevocationMeshPushReachesPeerOverlay(t *testing.T) {
	peerOverlay := revocation.NewAdmissionRevocations()
	peer := fakePeerCP(t, peerOverlay, "s3cr3t")
	defer peer.Close()

	src := revocationMeshSource{
		originRegion: "region-a",
		peers:        []revocationMeshPeer{{region: "region-b", url: peer.URL}},
		secret:       "s3cr3t",
		client:       peer.Client(),
	}

	regionA := revocation.NewAdmissionRevocations()
	// Synchronous push in the reporter for test determinism (production fans out goroutines with retry).
	regionA.SetMeshReporter(func(identity, reason string) {
		if !src.pushOnce(src.peers[0], revocationMeshItem{Identity: identity, Reason: reason, OriginRegion: src.originRegion}) {
			t.Errorf("pushOnce to peer failed")
		}
	})

	regionA.Revoke("dev-roamer", "admin_kill")

	if _, ok := peerOverlay.IsRevoked("dev-roamer"); !ok {
		t.Fatal("region B's overlay must deny the device after region A pushed the revocation over the mesh")
	}
}

// TestRevocationMeshPushRejectedWithoutSecret proves the receive side is authenticated.
func TestRevocationMeshPushRejectedWithoutSecret(t *testing.T) {
	peerOverlay := revocation.NewAdmissionRevocations()
	peer := fakePeerCP(t, peerOverlay, "s3cr3t")
	defer peer.Close()

	src := revocationMeshSource{originRegion: "region-a", peers: []revocationMeshPeer{{region: "region-b", url: peer.URL}}, secret: "wrong", client: peer.Client()}
	if src.pushOnce(src.peers[0], revocationMeshItem{Identity: "dev1", Reason: "kill"}) {
		t.Fatal("push with the wrong secret must be rejected")
	}
	if _, ok := peerOverlay.IsRevoked("dev1"); ok {
		t.Fatal("an unauthenticated push must NOT apply")
	}
}

// TestParseRevocationMeshPeers guards the config contract.
func TestParseRevocationMeshPeers(t *testing.T) {
	peers, err := parseRevocationMeshPeers("region-b=https://cp.osaka:9443;region-c=https://cp.ishikari:9443")
	if err != nil || len(peers) != 2 {
		t.Fatalf("parse = (%v, %v), want 2 peers", peers, err)
	}
	for _, bad := range []string{"region-b", "=https://x", "region-b=https://a;region-b=https://b"} {
		if _, err := parseRevocationMeshPeers(bad); err == nil {
			t.Fatalf("parseRevocationMeshPeers(%q) = nil error, want rejection", bad)
		}
	}
	if p, err := parseRevocationMeshPeers(""); err != nil || p != nil {
		t.Fatalf("empty = (%v, %v), want (nil, nil)", p, err)
	}
}
