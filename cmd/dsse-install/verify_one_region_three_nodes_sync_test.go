package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictSyncVerificationReadsLivePatroniConfig(t *testing.T) {
	config := `{"synchronous_mode":true,"synchronous_mode_strict":true,"synchronous_node_count":1}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(config))
	}))
	defer server.Close()
	env := map[string]string{"DSSE_PG_A_API_PUBLISH": strings.TrimPrefix(server.URL, "http://")}
	if got := verifyOneRegionThreeNodesSync(env); !got.ok {
		t.Fatalf("live strict config was refused: %+v", got)
	}
	config = `{"synchronous_mode":true,"synchronous_mode_strict":false,"synchronous_node_count":1}`
	if got := verifyOneRegionThreeNodesSync(env); got.ok {
		t.Fatalf("non-strict config passed: %+v", got)
	}
}

func TestOneRegionThreeNodesVerifiesTwoReplicasWithoutInventingASecondRegion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"database":{"replicas_streaming":2,"replica_members":["dsse-pg-node-b","dsse-pg-node-c"]}}`))
	}))
	defer server.Close()
	got := verifyAuthorityStateForProfile(server.Client(), server.URL, true)
	for _, result := range got {
		if !result.ok {
			t.Fatalf("three independent Node DBs in one DSSE Region were rejected: %+v", result)
		}
		if strings.Contains(result.name, "losing this region") {
			t.Fatalf("one-region topology was evaluated as a cross-region topology: %+v", result)
		}
	}
}
