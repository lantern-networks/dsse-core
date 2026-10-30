package edgeplane

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestRuntimeCopySessionQuotasOnlyWhenOperatorConfiguresThem(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	manager := NewNetworkExtensionRuntimeCopySessionManager(0, 0, clock)
	for i := 0; i < 2048; i++ {
		r := networkExtensionRuntimeCopySessionRequest{RequestID: fmt.Sprintf("held-%d", i), TenantID: "tenant", ApplicationID: "app"}
		if _, failure := manager.Open(r, NetworkExtensionRuntimeCopyTCPRoute{}, nil); failure.status != 0 {
			t.Fatalf("unconfigured session quota refused session %d: %s", i, failure.category)
		}
	}
	now = now.Add(48 * time.Hour)
	if _, failure := manager.Get("tenant", "", "held-0", "app"); failure.status != 0 {
		t.Fatal("unconfigured idle quota reaped a session")
	}
	if _, failure := manager.Get("tenant", "", "held-0", "other-app"); failure.status == 0 {
		t.Fatal("removing resource quotas weakened application scope")
	}
	for i := 0; i < 2048; i++ {
		if !manager.Close("tenant", "", fmt.Sprintf("held-%d", i), "app") {
			t.Fatal("session was lost before explicit close")
		}
	}
	configured := NewNetworkExtensionRuntimeCopySessionManager(time.Second, 1, clock)
	r := networkExtensionRuntimeCopySessionRequest{RequestID: "first", TenantID: "tenant", ApplicationID: "app"}
	if _, failure := configured.Open(r, NetworkExtensionRuntimeCopyTCPRoute{}, nil); failure.status != 0 {
		t.Fatal("first session rejected")
	}
	r.RequestID = "second"
	if _, failure := configured.Open(r, NetworkExtensionRuntimeCopyTCPRoute{}, nil); failure.status != http.StatusTooManyRequests {
		t.Fatal("explicit session count quota was not enforced")
	}
	now = now.Add(2 * time.Second)
	if _, failure := configured.Open(r, NetworkExtensionRuntimeCopyTCPRoute{}, nil); failure.status != 0 {
		t.Fatal("expired session did not release explicitly configured capacity")
	}
}
