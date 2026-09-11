package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

const (
	SessionStateScopeEdgeLocalAffinity      = "edge_local_session_affinity"
	SessionAffinityStrategyConnectorIDHash  = "connector_id_hash_session_affinity"
	SessionExternalRegistryGateNotRequired  = "not_required_current_edge_local_affinity"
	SessionMigratableWithoutReconnectNo     = "no_requires_connector_reconnect_or_external_registry"
	SessionProductionScaleClaimNotPerformed = "not_performed_no_production_scale_claim"
)

type SessionStateRecord struct {
	ConnectorID                 string `json:"connector_id"`
	TunnelID                    string `json:"tunnel_id"`
	TransportProtocol           string `json:"transport_protocol"`
	StateScope                  string `json:"state_scope"`
	AffinityStrategy            string `json:"affinity_strategy"`
	AffinityKey                 string `json:"affinity_key"`
	ExternalRegistryGate        string `json:"external_registry_gate"`
	MigratableWithoutReconnect  string `json:"migratable_without_reconnect"`
	ProductionScaleClaim        string `json:"production_scale_claim"`
	SessionAffinityRequired     bool   `json:"session_affinity_required"`
	ExternalRegistryRequired    bool   `json:"external_registry_required"`
	MultiEdgeStatelessClaimed   bool   `json:"multi_edge_stateless_claimed"`
	ProductionScaleClaimed      bool   `json:"production_scale_claimed"`
	RawConnectorIdentifierInKey bool   `json:"raw_connector_identifier_in_key"`
	NoSecretAttestation         bool   `json:"no_secret_attestation"`
}

func NewSessionStateRecord(connectorID, tunnelID, transportProtocol string) (SessionStateRecord, error) {
	if connectorID == "" {
		return SessionStateRecord{}, fmt.Errorf("connector_id is required")
	}
	if tunnelID == "" {
		return SessionStateRecord{}, fmt.Errorf("tunnel_id is required")
	}
	if transportProtocol == "" {
		transportProtocol = WebSocketTextJSONTransportProtocol
	}
	affinityKey, err := SessionAffinityKey(connectorID)
	if err != nil {
		return SessionStateRecord{}, err
	}
	return SessionStateRecord{
		ConnectorID:                 connectorID,
		TunnelID:                    tunnelID,
		TransportProtocol:           transportProtocol,
		StateScope:                  SessionStateScopeEdgeLocalAffinity,
		AffinityStrategy:            SessionAffinityStrategyConnectorIDHash,
		AffinityKey:                 affinityKey,
		ExternalRegistryGate:        SessionExternalRegistryGateNotRequired,
		MigratableWithoutReconnect:  SessionMigratableWithoutReconnectNo,
		ProductionScaleClaim:        SessionProductionScaleClaimNotPerformed,
		SessionAffinityRequired:     true,
		ExternalRegistryRequired:    false,
		MultiEdgeStatelessClaimed:   false,
		ProductionScaleClaimed:      false,
		RawConnectorIdentifierInKey: false,
		NoSecretAttestation:         true,
	}, nil
}

func SessionAffinityKey(connectorID string) (string, error) {
	if connectorID == "" {
		return "", fmt.Errorf("connector_id is required")
	}
	sum := sha256.Sum256([]byte(connectorID))
	return "sha256:" + hex.EncodeToString(sum[:16]), nil
}

func (s *Session) StateRecord() (SessionStateRecord, error) {
	if s == nil {
		return SessionStateRecord{}, fmt.Errorf("session is required")
	}
	return NewSessionStateRecord(s.ConnectorID, s.TunnelID, s.TransportProtocol)
}

func (m *Manager) SessionStateSnapshot() []SessionStateRecord {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.RUnlock()

	records := make([]SessionStateRecord, 0, len(sessions))
	for _, session := range sessions {
		record, err := session.StateRecord()
		if err == nil {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].ConnectorID == records[j].ConnectorID {
			return records[i].TunnelID < records[j].TunnelID
		}
		return records[i].ConnectorID < records[j].ConnectorID
	})
	return records
}
