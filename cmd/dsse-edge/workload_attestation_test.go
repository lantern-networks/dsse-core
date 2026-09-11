package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	nhi "github.com/lantern-networks/dsse-core/nhi"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestRuntimeDecisionRequiresSignedWorkloadAttestationOutsideLabMode(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_nhi_tool_attested_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 90,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_soc_agent_001",
				"delegated_access_grant_id": "dag_lab_001",
				"tool_id":                   "tool_ticket_create_001",
				"application_id":            "app_dummy_https",
			},
			Action:                      model.PolicyAction{Decision: "allow"},
			RequiredWorkloadAttestation: true,
			Status:                      "active",
		},
	})
	now := time.Now().UTC()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	delegatedGrants := newDelegatedAccessGrantStore()
	if _, err := delegatedGrants.Upsert(model.DelegatedAccessGrant{
		ID:            "dag_lab_001",
		TenantID:      "tenant_lab_001",
		SubjectUserID: "user_lab_001",
		ActorNHIID:    "nhi_soc_agent_001",
		ToolIDs:       []string{"tool_ticket_create_001"},
		ApplicationID: stringPtr("app_dummy_https"),
		ExpiresAt:     now.Add(time.Hour).Format(time.RFC3339),
		Status:        "active",
		Metadata:      map[string]any{},
	}); err != nil {
		t.Fatalf("upsert grant returned error: %v", err)
	}
	nhiRegistry := nhi.NewStore()
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{
		ID:          "nhi_soc_agent_001",
		Name:        "SOC Agent",
		NHIType:     "ai_agent",
		OwnerUserID: "user_owner_001",
		Status:      "active",
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert NHI returned error: %v", err)
	}
	devMode := false
	attestationSecret := "runtime-attestation-secret"
	handler := newServerWithConfig(serverConfig{
		Evaluator:                 evaluator,
		Writer:                    writer,
		Registry:                  connector.NewRegistry(),
		ConnectorSecret:           defaultConnectorSecret,
		WorkloadAttestationSecret: attestationSecret,
		LabMode:                   &devMode,
		DelegatedGrants:           delegatedGrants,
		NonHumanIdentities:        nhiRegistry,
	})
	decisionBody := `{
		"tenant_id":"tenant_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_type":"human",
		"actor_nhi_id":"nhi_soc_agent_001",
		"delegated_access_grant_id":"dag_lab_001",
		"agent_task_session_id":"ats_lab_001",
		"tool_id":"tool_ticket_create_001",
		"application_id":"app_dummy_https",
		"service_family":"https",
		"workload_attestation_state":"verified"
	}`

	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unsigned status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode unsigned decision: %v", err)
	}
	if dec.Decision != "require_workload_attestation" || !stringSliceContains(dec.ReasonCodes, "workload_attestation_required") {
		t.Fatalf("unsigned decision = %#v, want workload attestation required", dec)
	}

	signedReq := model.DecisionRequest{
		TenantID:               "tenant_lab_001",
		ActorType:              "delegated_agent",
		ActorNHIID:             "nhi_soc_agent_001",
		DelegatedAccessGrantID: "dag_lab_001",
		AgentTaskSessionID:     "ats_lab_001",
		ToolID:                 "tool_ticket_create_001",
		ApplicationID:          "app_dummy_https",
	}
	staleTimestamp := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	req.Header.Set(workloadAttestationStateHeader, "verified")
	req.Header.Set(workloadAttestationTimestampHeader, staleTimestamp)
	req.Header.Set(workloadAttestationNonceHeader, "nonce-stale-runtime-attestation-test")
	req.Header.Set(workloadAttestationSignatureHeader, runtimeWorkloadAttestationSignature(attestationSecret, signedReq, "verified", staleTimestamp, "nonce-stale-runtime-attestation-test"))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale status = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	attestationTimestamp := time.Now().UTC().Format(time.RFC3339)
	attestationNonce := "nonce-runtime-attestation-test"
	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	req.Header.Set(workloadAttestationStateHeader, "verified")
	req.Header.Set(workloadAttestationTimestampHeader, attestationTimestamp)
	req.Header.Set(workloadAttestationNonceHeader, attestationNonce)
	req.Header.Set(workloadAttestationSignatureHeader, runtimeWorkloadAttestationSignature(attestationSecret, signedReq, "verified", attestationTimestamp, attestationNonce))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signed status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode signed decision: %v", err)
	}
	if dec.Decision != "allow" || dec.WorkloadAttestationState == nil || *dec.WorkloadAttestationState != "verified" || dec.Metadata["runtime_evidence_result"] != "valid" {
		t.Fatalf("signed decision = %#v, want allow with signed workload attestation", dec)
	}
	if dec.Metadata["workload_attestation_source"] != "runtime_signed_header" || dec.Metadata["workload_attestation_signature_alg"] != "hmac-sha256" {
		t.Fatalf("signed decision metadata = %#v, want signed workload attestation source", dec.Metadata)
	}
	if dec.Metadata["workload_attestation_nonce_hash"] != runtimeWorkloadAttestationNonceHash("tenant_lab_001", attestationNonce) {
		t.Fatalf("nonce hash = %#v, want hash metadata", dec.Metadata["workload_attestation_nonce_hash"])
	}
	if dec.Metadata["workload_attestation_timestamp"] != attestationTimestamp {
		t.Fatalf("timestamp metadata = %#v, want %s", dec.Metadata["workload_attestation_timestamp"], attestationTimestamp)
	}
	if dec.Metadata["nhi_registry_last_used_result"] != "updated" || dec.Metadata["nhi_registry_last_used_at"] == "" {
		t.Fatalf("signed decision NHI usage metadata = %#v, want last_used updated", dec.Metadata)
	}
	identities, err := nhiRegistry.List(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("list NHI registry: %v", err)
	}
	if len(identities) != 1 || identities[0].LastUsedAt == nil || *identities[0].LastUsedAt == "" {
		t.Fatalf("NHI registry identities = %#v, want last_used_at updated", identities)
	}

	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	req.Header.Set(workloadAttestationStateHeader, "verified")
	req.Header.Set(workloadAttestationTimestampHeader, attestationTimestamp)
	req.Header.Set(workloadAttestationNonceHeader, attestationNonce)
	req.Header.Set(workloadAttestationSignatureHeader, runtimeWorkloadAttestationSignature(attestationSecret, signedReq, "verified", attestationTimestamp, attestationNonce))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestRuntimeWorkloadAttestationReplayCacheIsBounded(t *testing.T) {
	now := time.Now().UTC()
	cache := newRuntimeWorkloadAttestationReplayCache()
	for i := 0; i < maxRuntimeWorkloadAttestationNonces; i++ {
		cache.seen[fmt.Sprintf("tenant_lab_001\x00nonce_%d", i)] = now.Add(time.Minute)
	}
	if err := cache.Remember("tenant_lab_001", "overflow_nonce", now, now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "replay cache is full") {
		t.Fatalf("Remember overflow error = %v, want replay cache full", err)
	}
	if got := len(cache.seen); got != maxRuntimeWorkloadAttestationNonces {
		t.Fatalf("cache size = %d, want bounded size %d", got, maxRuntimeWorkloadAttestationNonces)
	}

	cache = newRuntimeWorkloadAttestationReplayCache()
	for i := 0; i < maxRuntimeWorkloadAttestationNonces-1; i++ {
		cache.seen[fmt.Sprintf("tenant_lab_001\x00active_nonce_%d", i)] = now.Add(time.Minute)
	}
	cache.seen["tenant_lab_001\x00expired_nonce"] = now.Add(-time.Second)
	if err := cache.Remember("tenant_lab_001", "replacement_nonce", now, now.Add(time.Minute)); err != nil {
		t.Fatalf("Remember after expired sweep returned error: %v", err)
	}
	if _, ok := cache.seen["tenant_lab_001\x00expired_nonce"]; ok {
		t.Fatalf("expired nonce remained in cache")
	}
	if got := len(cache.seen); got != maxRuntimeWorkloadAttestationNonces {
		t.Fatalf("cache size after replacement = %d, want %d", got, maxRuntimeWorkloadAttestationNonces)
	}
}

func TestWorkloadAttestationSecretConfigRequiresDedicatedSecretOutsideLabMode(t *testing.T) {
	for name, tc := range map[string]struct {
		devMode                   bool
		connectorSecret           string
		workloadAttestationSecret string
		wantErr                   bool
	}{
		"lab mode allows empty":        {devMode: true, connectorSecret: defaultConnectorSecret},
		"non lab rejects empty":        {connectorSecret: "tenant-connector-secret", wantErr: true},
		"non lab rejects shared":       {connectorSecret: "shared-secret", workloadAttestationSecret: "shared-secret", wantErr: true},
		"non lab accepts split secret": {connectorSecret: "tenant-connector-secret", workloadAttestationSecret: "tenant-attestation-secret"},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateWorkloadAttestationSecretConfig(tc.devMode, tc.connectorSecret, tc.workloadAttestationSecret)
			if tc.wantErr && err == nil {
				t.Fatalf("validateWorkloadAttestationSecretConfig returned nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateWorkloadAttestationSecretConfig returned error: %v", err)
			}
		})
	}
}

func TestWorkloadAttestationNonceStoreConfigRequiresPostgresOutsideLabMode(t *testing.T) {
	for name, tc := range map[string]struct {
		devMode        bool
		mode           string
		allowEphemeral bool
		wantErr        bool
	}{
		"lab mode allows memory":              {devMode: true, mode: "memory"},
		"lab mode allows empty default":       {devMode: true},
		"non lab rejects empty default":       {wantErr: true},
		"non lab rejects memory":              {mode: "memory", wantErr: true},
		"non lab accepts postgres":            {mode: "postgres"},
		"non lab accepts trimmed postgres":    {mode: " POSTGRES "},
		"non lab memory + ephemeral opt-in":   {mode: "memory", allowEphemeral: true},          // zero-DB Edge
		"non lab ephemeral opt-in but no mem": {mode: "", allowEphemeral: true, wantErr: true}, // opt-in alone isn't enough
		"non lab postgres ignores opt-in":     {mode: "postgres", allowEphemeral: true},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateWorkloadAttestationNonceStoreConfig(tc.devMode, tc.mode, tc.allowEphemeral)
			if tc.wantErr && err == nil {
				t.Fatalf("validateWorkloadAttestationNonceStoreConfig returned nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateWorkloadAttestationNonceStoreConfig returned error: %v", err)
			}
		})
	}
}
