package main

import (
	"net/http"
	"testing"
	"time"
)

func TestMeshReplayAtExactExpiryIsRejected(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	h := http.Header{}
	body := []byte(`{"fixture":true}`)
	signMeshRequest(h, "fixture-key", body, now)
	g := newMeshReplayGuard(meshAntiReplayWindow)
	if err := verifyMeshAntiReplay(h, "fixture-key", body, g, now); err != nil {
		t.Fatal(err)
	}
	if err := verifyMeshAntiReplay(h, "fixture-key", body, g, now.Add(meshAntiReplayWindow)); err == nil {
		t.Fatal("request accepted again when its nonce expired at the freshness boundary")
	}
}
