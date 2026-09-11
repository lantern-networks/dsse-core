package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// Review #28: POST /steer/dns-query must NOT be an unauthenticated open resolver. Every sibling /steer/*
// control endpoint 401s a caller with no verified device transport identity; dns-query was registered raw
// with no gate. A request with no verified mTLS client cert (r.TLS == nil, as httptest produces) must be
// rejected with 401 before the resolver runs.
func TestSteerDNSQueryRequiresVerifiedDeviceIdentity(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_lab_001"}},
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})

	// A non-empty body so the request would otherwise reach the resolver; the gate must reject it first.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/steer/dns-query", strings.NewReader("not-a-real-dns-query"))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /steer/dns-query status = %d, want 401 (open-resolver guard)", rec.Code)
	}
}
