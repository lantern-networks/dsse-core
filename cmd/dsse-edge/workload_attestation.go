package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

const (
	workloadAttestationStateHeader          = "x-workload-attestation-state"
	workloadAttestationTimestampHeader      = "x-workload-attestation-timestamp"
	workloadAttestationNonceHeader          = "x-workload-attestation-nonce"
	workloadAttestationSignatureHeader      = "x-workload-attestation-signature"
	workloadAttestationSignaturePrefix      = "sha256="
	workloadAttestationSignatureInputPrefix = "dsse-workload-attestation-v1"

	maxRuntimeWorkloadAttestationSkew    = 5 * time.Minute
	maxRuntimeWorkloadAttestationNonces  = 10000
	runtimeWorkloadAttestationSweepEvery = 64
)

type runtimeWorkloadAttestationNonceStore interface {
	Remember(tenantID, nonce string, now, expiresAt time.Time) error
}

type runtimeWorkloadAttestationReplayCache struct {
	mu            sync.Mutex
	seen          map[string]time.Time
	rememberCalls uint64
}

type runtimeWorkloadAttestationEvidence struct {
	Source    string
	Timestamp string
	NonceHash string
	Algorithm string
}

func newRuntimeWorkloadAttestationReplayCache() *runtimeWorkloadAttestationReplayCache {
	return &runtimeWorkloadAttestationReplayCache{seen: map[string]time.Time{}}
}

func (cache *runtimeWorkloadAttestationReplayCache) Remember(tenantID, nonce string, now, expiresAt time.Time) error {
	if cache == nil {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	nonce = strings.TrimSpace(nonce)
	if tenantID == "" || nonce == "" {
		return fmt.Errorf("runtime workload attestation tenant and nonce are required")
	}
	now = now.UTC()
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now) {
		expiresAt = now.Add(time.Second)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.seen == nil {
		cache.seen = map[string]time.Time{}
	}
	cache.rememberCalls++
	key := tenantID + "\x00" + nonce
	if expiry, ok := cache.seen[key]; ok {
		if expiry.After(now) {
			return fmt.Errorf("runtime workload attestation nonce was already used")
		}
		delete(cache.seen, key)
	}
	if cache.rememberCalls%runtimeWorkloadAttestationSweepEvery == 0 || len(cache.seen) >= maxRuntimeWorkloadAttestationNonces {
		cache.sweepExpiredLocked(now)
	}
	if len(cache.seen) >= maxRuntimeWorkloadAttestationNonces {
		return fmt.Errorf("runtime workload attestation replay cache is full")
	}
	cache.seen[key] = expiresAt
	return nil
}

func (cache *runtimeWorkloadAttestationReplayCache) sweepExpiredLocked(now time.Time) {
	for key, expiry := range cache.seen {
		if !expiry.After(now) {
			delete(cache.seen, key)
		}
	}
}

func validateWorkloadAttestationSecretConfig(devMode bool, connectorSecret, workloadAttestationSecret string) error {
	if devMode {
		return nil
	}
	connectorSecret = strings.TrimSpace(connectorSecret)
	workloadAttestationSecret = strings.TrimSpace(workloadAttestationSecret)
	if workloadAttestationSecret == "" {
		return fmt.Errorf("workload-attestation-secret is required when lab-mode is disabled")
	}
	if connectorSecret != "" && workloadAttestationSecret == connectorSecret {
		return fmt.Errorf("workload-attestation-secret must differ from connector-secret when lab-mode is disabled")
	}
	return nil
}

// validateWorkloadAttestationNonceStoreConfig: in production (non-lab) the attestation-nonce replay store
// must be durable (postgres) by default. To let an ENFORCEMENT Edge run zero-DB (audit/persistence
// decoupling), an in-memory nonce store is allowed when the operator EXPLICITLY opts in
// (allowEphemeral) — this provides PER-INSTANCE replay protection only (an HA fleet wants the shared
// store / control plane), so it must be a conscious choice, never a silent downgrade.
func validateWorkloadAttestationNonceStoreConfig(devMode bool, mode string, allowEphemeral bool) error {
	if devMode {
		return nil
	}
	mode = strings.TrimSpace(strings.ToLower(mode))
	// storeBackend so "postgres+import:<path>" — the same backend, carrying its old file across — is not read
	// as "not postgres" and refused here.
	if storeBackend(mode) == "postgres" {
		return nil
	}
	if mode == "memory" && allowEphemeral {
		return nil
	}
	return fmt.Errorf("workload-attestation-nonce-store=postgres is required when lab-mode is disabled (or set -workload-attestation-nonce-store=memory with -allow-ephemeral-attestation-nonce-store for a zero-DB Edge with per-instance replay protection only)")
}

func runtimeWorkloadAttestationStateAllowed(state string) bool {
	return state == "verified" || state == "valid"
}

func runtimeWorkloadAttestationSignature(secret string, req model.DecisionRequest, state, timestamp, nonce string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(runtimeWorkloadAttestationSignatureInput(req, state, timestamp, nonce)))
	return workloadAttestationSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func runtimeWorkloadAttestationSignatureValid(secret string, req model.DecisionRequest, state, timestamp, nonce, signature string) bool {
	expected := runtimeWorkloadAttestationSignature(secret, req, state, timestamp, nonce)
	return hmac.Equal([]byte(strings.TrimSpace(signature)), []byte(expected))
}

func runtimeWorkloadAttestationNonceHash(tenantID, nonce string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(nonce)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func annotateRuntimeWorkloadAttestationMetadata(dec *model.AccessDecision, evidence runtimeWorkloadAttestationEvidence) {
	if dec == nil || evidence.Source == "" {
		return
	}
	if dec.Metadata == nil {
		dec.Metadata = map[string]any{}
	}
	dec.Metadata["workload_attestation_source"] = evidence.Source
	dec.Metadata["workload_attestation_timestamp"] = evidence.Timestamp
	dec.Metadata["workload_attestation_nonce_hash"] = evidence.NonceHash
	dec.Metadata["workload_attestation_signature_alg"] = evidence.Algorithm
}

func runtimeWorkloadAttestationSignatureInput(req model.DecisionRequest, state, timestamp, nonce string) string {
	return strings.Join([]string{
		workloadAttestationSignatureInputPrefix,
		req.TenantID,
		req.ActorType,
		req.ActorNHIID,
		req.DelegatedAccessGrantID,
		req.AgentTaskSessionID,
		req.ToolID,
		req.ToolActionType,
		req.MCPServerID,
		req.RuntimeEnvironmentID,
		req.ApplicationID,
		state,
		timestamp,
		nonce,
	}, "\n")
}
