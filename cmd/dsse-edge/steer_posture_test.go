package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

func posturePolicyServer(t *testing.T, signer *agentpolicy.Signer, posture steerPostureConfig) http.Handler {
	t.Helper()
	return newServerWithConfig(serverConfig{
		Evaluator:         decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "t1"}},
		Registry:          connector.NewRegistry(),
		AdminAuth:         newAdminAuthStore(),
		AgentPolicySigner: signer,
		SteerPosture:      posture,
	})
}

// TestSteeringPostureEndpointSignsCPConfig asserts the edge serves the CP-configured posture as a signed
// envelope that the client library verifies against the edge's key, keyed to the cert-proven device identity.
func TestSteeringPostureEndpointSignsCPConfig(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	handler := posturePolicyServer(t, signer, steerPostureConfig{FailOpenMode: agentpolicy.FailOpenTerminal, FailOpenCooldownMS: 8000, RegionFailover: true})

	cert := leafWithCN(t, "win-dev-1")
	req := httptest.NewRequest(http.MethodGet, "/steer/agent-policy/posture", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var env agentpolicy.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	payloadBytes, err := agentpolicy.Verify(env, signer.PublicKeyHex())
	if err != nil {
		t.Fatalf("served posture must verify against the edge key: %v", err)
	}
	var p agentpolicy.SteeringPosturePayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		t.Fatal(err)
	}
	if p.SchemaVersion != agentpolicy.SteeringPostureSchema || p.DeviceIdentity != "win-dev-1" {
		t.Fatalf("posture payload wrong: %+v", p)
	}
	if !p.FailOpenPermitted() || p.FailOpenCooldownMS != 8000 || !p.RegionFailover {
		t.Fatalf("CP posture not reflected: %+v", p)
	}
}

// TestSteeringPostureEndpointRequiresDeviceIdentity: no verified transport identity => 401.
func TestSteeringPostureEndpointRequiresDeviceIdentity(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	handler := posturePolicyServer(t, signer, steerPostureConfig{})
	req := httptest.NewRequest(http.MethodGet, "/steer/agent-policy/posture", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a verified device identity", rec.Code)
	}
}

// TestSteeringPostureNormalizedFailClosed: an unknown fail-open mode must clamp to fail-CLOSED "off" so a
// misconfigured edge flag never widens the boundary.
func TestSteeringPostureNormalizedFailClosed(t *testing.T) {
	got := steerPostureConfig{FailOpenMode: "garbage", FailOpenCooldownMS: -5}.normalized()
	if got.FailOpenMode != agentpolicy.FailOpenOff || got.FailOpenCooldownMS != 0 {
		t.Fatalf("normalized() = %+v, want fail-CLOSED off + cooldown 0", got)
	}
}
