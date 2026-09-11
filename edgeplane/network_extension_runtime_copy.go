package edgeplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	NetworkExtensionRuntimeCopyRoundTripPath                = "/network-extension/runtime-copy/round-trip"
	NetworkExtensionRuntimeCopySessionPath                  = "/network-extension/runtime-copy/session"
	networkExtensionRuntimeCopyRoundTripRequestSchema       = "network_extension_runtime_copy_round_trip_request.v1"
	NetworkExtensionRuntimeCopyRoundTripResponseSchema      = "network_extension_runtime_copy_round_trip_response.v1"
	NetworkExtensionRuntimeCopyRoundTripErrorResponseSchema = "network_extension_runtime_copy_round_trip_error.v1"
	NetworkExtensionRuntimeCopySessionRequestSchema         = "network_extension_runtime_copy_session_request.v1"
	NetworkExtensionRuntimeCopySessionResponseSchema        = "network_extension_runtime_copy_session_response.v1"
	networkExtensionRuntimeCopySessionErrorResponseSchema   = "network_extension_runtime_copy_session_error.v1"
	networkExtensionRuntimeCopyRoundTripMaxRequestBodyBytes = 1 << 20
	networkExtensionRuntimeCopyRoundTripDefaultTimeout      = 5 * time.Second
	networkExtensionRuntimeCopyRoundTripDefaultReadBytes    = 64 << 10
	networkExtensionRuntimeCopySessionDefaultIdleTimeout    = 2 * time.Minute
	networkExtensionRuntimeCopySessionDefaultMaxSessions    = 1024
	NetworkExtensionRuntimeCopySessionEmptyDownstreamWait   = 500 * time.Millisecond
	networkExtensionRuntimeCopySessionDownstreamSignalWait  = 1 * time.Second
	networkExtensionRuntimeCopySessionCloseSignalWait       = 100 * time.Millisecond
)

const (
	NetworkExtensionRuntimeCopySessionOperationOpen     = "open"
	NetworkExtensionRuntimeCopySessionOperationExchange = "exchange"
	networkExtensionRuntimeCopySessionOperationClose    = "close"
)

type NetworkExtensionRuntimeCopyRoundTripHandlerConfig struct {
	TenantID string
	// DeviceTenant resolves the tenant from the device's certificate. See DeviceTenantFunc.
	DeviceTenant      DeviceTenantFunc
	Dialer            NetworkExtensionRuntimeCopyTCPDialer
	Timeout           time.Duration
	TransportIdentity TransportIdentityFunc
}

type NetworkExtensionRuntimeCopySessionHandlerConfig struct {
	TenantID string
	// DeviceTenant resolves the tenant from the device's certificate. See DeviceTenantFunc.
	DeviceTenant      DeviceTenantFunc
	Dialer            NetworkExtensionRuntimeCopyTCPDialer
	Timeout           time.Duration
	SessionManager    *NetworkExtensionRuntimeCopySessionManager
	TransportIdentity TransportIdentityFunc
}

type networkExtensionRuntimeCopyRoundTripRequest struct {
	SchemaVersion         string `json:"schema_version"`
	TenantID              string `json:"tenant_id"`
	RequestID             string `json:"request_id"`
	ApplicationID         string `json:"application_id"`
	DestinationHost       string `json:"destination_host"`
	DestinationPort       int    `json:"destination_port"`
	UpstreamPayloadBase64 string `json:"upstream_payload_b64"`
}

type networkExtensionRuntimeCopySessionRequest struct {
	SchemaVersion         string `json:"schema_version"`
	TenantID              string `json:"tenant_id"`
	RequestID             string `json:"request_id"`
	Operation             string `json:"operation"`
	ApplicationID         string `json:"application_id"`
	DestinationHost       string `json:"destination_host,omitempty"`
	DestinationPort       int    `json:"destination_port,omitempty"`
	UpstreamPayloadBase64 string `json:"upstream_payload_b64,omitempty"`
	ClientEOF             bool   `json:"client_eof,omitempty"`
}

type networkExtensionRuntimeCopyRoundTripResponse struct {
	SchemaVersion                          string                                    `json:"schema_version"`
	Status                                 string                                    `json:"status"`
	Category                               string                                    `json:"category"`
	RequestID                              string                                    `json:"request_id,omitempty"`
	DownstreamPayloadBase64                string                                    `json:"downstream_payload_b64,omitempty"`
	Audit                                  networkExtensionRuntimeCopyRoundTripAudit `json:"audit"`
	AuditMetadataOnlyGate                  string                                    `json:"audit_metadata_only_gate"`
	SecretLeakGate                         string                                    `json:"secret_leak_gate"`
	RuntimeOverclaimGate                   string                                    `json:"runtime_overclaim_gate"`
	FlowCopyOverclaimGate                  string                                    `json:"flow_copy_overclaim_gate"`
	EdgeRuntimeCopyRouteGate               string                                    `json:"edge_runtime_copy_route_gate,omitempty"`
	RuntimeInstalledClaimed                bool                                      `json:"runtime_installed_claimed"`
	FlowTunneledClaimed                    bool                                      `json:"flow_tunneled_claimed"`
	FlowDeniedClaimed                      bool                                      `json:"flow_denied_claimed"`
	RealTLSInterceptionClaimed             bool                                      `json:"real_tls_interception_claimed"`
	CertificateIssuanceClaimed             bool                                      `json:"certificate_issuance_claimed"`
	ProductionPrivateAppEnforcementClaimed bool                                      `json:"production_private_app_enforcement_claimed"`
}

type networkExtensionRuntimeCopySessionResponse struct {
	SchemaVersion                          string                                    `json:"schema_version"`
	Status                                 string                                    `json:"status"`
	Category                               string                                    `json:"category"`
	RequestID                              string                                    `json:"request_id,omitempty"`
	DownstreamPayloadBase64                string                                    `json:"downstream_payload_b64,omitempty"`
	SessionClosed                          bool                                      `json:"session_closed"`
	Audit                                  networkExtensionRuntimeCopyRoundTripAudit `json:"audit"`
	AuditMetadataOnlyGate                  string                                    `json:"audit_metadata_only_gate"`
	SecretLeakGate                         string                                    `json:"secret_leak_gate"`
	RuntimeOverclaimGate                   string                                    `json:"runtime_overclaim_gate"`
	FlowCopyOverclaimGate                  string                                    `json:"flow_copy_overclaim_gate"`
	EdgeRuntimeCopyRouteGate               string                                    `json:"edge_runtime_copy_route_gate,omitempty"`
	RuntimeInstalledClaimed                bool                                      `json:"runtime_installed_claimed"`
	FlowTunneledClaimed                    bool                                      `json:"flow_tunneled_claimed"`
	FlowDeniedClaimed                      bool                                      `json:"flow_denied_claimed"`
	RealTLSInterceptionClaimed             bool                                      `json:"real_tls_interception_claimed"`
	CertificateIssuanceClaimed             bool                                      `json:"certificate_issuance_claimed"`
	ProductionPrivateAppEnforcementClaimed bool                                      `json:"production_private_app_enforcement_claimed"`
}

type networkExtensionRuntimeCopyRoundTripAudit struct {
	SchemaVersion                          string `json:"schema_version"`
	Status                                 string `json:"status"`
	Category                               string `json:"category"`
	TenantID                               string `json:"tenant_id,omitempty"`
	RequestID                              string `json:"request_id,omitempty"`
	ApplicationID                          string `json:"application_id,omitempty"`
	MetadataOnly                           bool   `json:"metadata_only"`
	RawPayloadIncluded                     bool   `json:"raw_payload_included"`
	RawNEFlowIncluded                      bool   `json:"raw_ne_flow_included"`
	RawDestinationIPIncluded               bool   `json:"raw_destination_ip_included"`
	HostUserMaterialIncluded               bool   `json:"host_user_material_included"`
	CredentialsIncluded                    bool   `json:"credentials_included"`
	TokenIncluded                          bool   `json:"token_included"`
	CookieIncluded                         bool   `json:"cookie_included"`
	SessionIDIncluded                      bool   `json:"session_id_included"`
	ClientSecretIncluded                   bool   `json:"client_secret_included"`
	TLSMaterialIncluded                    bool   `json:"tls_material_included"`
	CertificateMaterialIncluded            bool   `json:"certificate_material_included"`
	DeviceIdentifierIncluded               bool   `json:"device_identifier_included"`
	AppleIdentifierIncluded                bool   `json:"apple_identifier_included"`
	RuntimeInstalledClaimed                bool   `json:"runtime_installed_claimed"`
	FlowTunneledClaimed                    bool   `json:"flow_tunneled_claimed"`
	FlowDeniedClaimed                      bool   `json:"flow_denied_claimed"`
	RealTLSInterceptionClaimed             bool   `json:"real_tls_interception_claimed"`
	CertificateIssuanceClaimed             bool   `json:"certificate_issuance_claimed"`
	ProductionPrivateAppEnforcementClaimed bool   `json:"production_private_app_enforcement_claimed"`
}

// RemoteAddrString returns a net.Conn's peer address (guarding nil) — the mTLS tunnel's OBSERVED source, a
// trust-boundary fact used as the access log's source_ip (never the agent's self-reported address).
func RemoteAddrString(c net.Conn) string {
	if c == nil {
		return ""
	}
	if a := c.RemoteAddr(); a != nil {
		return a.String()
	}
	return ""
}

type networkExtensionRuntimeCopyEmptyDownstreamConn interface {
	AllowEmptyRuntimeCopyDownstream() bool
}

type networkExtensionRuntimeCopySessionDoneConn interface {
	RuntimeCopySessionDone() <-chan struct{}
}

type networkExtensionRuntimeCopyDrainWaitConn interface {
	RuntimeCopyDrainWait() time.Duration
}

type networkExtensionRuntimeCopyDownstreamExpectedConn interface {
	RuntimeCopyDownstreamExpected() <-chan struct{}
}

type networkExtensionRuntimeCopySessionExchangeResult struct {
	downstream    []byte
	sessionClosed bool
}

type NetworkExtensionRuntimeCopySessionManager struct {
	mu          sync.Mutex
	sessions    map[string]*NetworkExtensionRuntimeCopySession
	idleTimeout time.Duration
	maxSessions int
	now         func() time.Time
}

type NetworkExtensionRuntimeCopySession struct {
	RequestID     string
	tenantID      string
	applicationID string
	route         NetworkExtensionRuntimeCopyTCPRoute
	conn          io.ReadWriteCloser
	mu            sync.Mutex
	openedAt      time.Time
	lastUsedAt    time.Time
	bytesUp       int64
	bytesDown     int64
}

func NewNetworkExtensionRuntimeCopySessionManager(idleTimeout time.Duration, maxSessions int, now func() time.Time) *NetworkExtensionRuntimeCopySessionManager {
	if idleTimeout <= 0 {
		idleTimeout = networkExtensionRuntimeCopySessionDefaultIdleTimeout
	}
	if maxSessions <= 0 {
		maxSessions = networkExtensionRuntimeCopySessionDefaultMaxSessions
	}
	if now == nil {
		now = time.Now
	}
	return &NetworkExtensionRuntimeCopySessionManager{
		sessions:    map[string]*NetworkExtensionRuntimeCopySession{},
		idleTimeout: idleTimeout,
		maxSessions: maxSessions,
		now:         now,
	}
}

func (manager *NetworkExtensionRuntimeCopySessionManager) Open(req networkExtensionRuntimeCopySessionRequest, route NetworkExtensionRuntimeCopyTCPRoute, conn io.ReadWriteCloser) (*NetworkExtensionRuntimeCopySession, networkExtensionRuntimeCopyRoundTripFailure) {
	if manager == nil {
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "session_manager_missing", routeGate: "session_manager_missing"}
	}
	now := manager.now().UTC()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.reapExpiredLocked(now)
	if _, exists := manager.sessions[req.RequestID]; exists {
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusConflict, category: "session_already_open", routeGate: "session_request_rejected"}
	}
	if len(manager.sessions) >= manager.maxSessions {
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusTooManyRequests, category: "session_cap_exceeded", routeGate: "session_request_rejected"}
	}
	session := &NetworkExtensionRuntimeCopySession{
		RequestID:     req.RequestID,
		tenantID:      req.TenantID,
		applicationID: req.ApplicationID,
		route:         route,
		conn:          conn,
		openedAt:      now,
		lastUsedAt:    now,
	}
	manager.sessions[req.RequestID] = session
	return session, networkExtensionRuntimeCopyRoundTripFailure{}
}

func (manager *NetworkExtensionRuntimeCopySessionManager) Get(RequestID, applicationID string) (*NetworkExtensionRuntimeCopySession, networkExtensionRuntimeCopyRoundTripFailure) {
	if manager == nil {
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "session_manager_missing", routeGate: "session_manager_missing"}
	}
	now := manager.now().UTC()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.reapExpiredLocked(now)
	session, ok := manager.sessions[RequestID]
	if !ok {
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusNotFound, category: "session_not_found", routeGate: "session_not_open"}
	}
	if session.applicationID != applicationID {
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "session_scope_mismatch", routeGate: "session_request_rejected"}
	}
	return session, networkExtensionRuntimeCopyRoundTripFailure{}
}

func (manager *NetworkExtensionRuntimeCopySessionManager) Close(RequestID string) bool {
	if manager == nil {
		return false
	}
	manager.mu.Lock()
	session, ok := manager.sessions[RequestID]
	if ok {
		delete(manager.sessions, RequestID)
	}
	manager.mu.Unlock()
	if ok && session.conn != nil {
		_ = session.conn.Close()
	}
	return ok
}

func (manager *NetworkExtensionRuntimeCopySessionManager) reapExpiredLocked(now time.Time) {
	for RequestID, session := range manager.sessions {
		session.mu.Lock()
		expired := now.Sub(session.lastUsedAt) > manager.idleTimeout
		session.mu.Unlock()
		if !expired {
			continue
		}
		delete(manager.sessions, RequestID)
		if session.conn != nil {
			_ = session.conn.Close()
		}
	}
}

type networkExtensionRuntimeCopyRoundTripFailure struct {
	status    int
	category  string
	routeGate string
}

func (failure networkExtensionRuntimeCopyRoundTripFailure) Error() string {
	return failure.category
}

func NewNetworkExtensionRuntimeCopyRoundTripHandler(config NetworkExtensionRuntimeCopyRoundTripHandlerConfig) http.HandlerFunc {
	runtimeTenantID := strings.TrimSpace(config.TenantID)
	dialer := config.Dialer
	if dialer == nil {
		dialer = NetworkExtensionRuntimeCopyNetDialer{}
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = networkExtensionRuntimeCopyRoundTripDefaultTimeout
	}
	deviceTenant := config.DeviceTenant
	return func(w http.ResponseWriter, r *http.Request) {
		runtimeTenantID := tenantForRequest(deviceTenant, r, runtimeTenantID)
		if r.Method != http.MethodPost {
			writeNetworkExtensionRuntimeCopyRoundTripError(w, http.StatusMethodNotAllowed, "method_not_allowed", networkExtensionRuntimeCopyRoundTripRequest{}, runtimeTenantID, "method_rejected")
			return
		}
		if r.ContentLength > networkExtensionRuntimeCopyRoundTripMaxRequestBodyBytes {
			writeNetworkExtensionRuntimeCopyRoundTripError(w, http.StatusRequestEntityTooLarge, "request_body_too_large", networkExtensionRuntimeCopyRoundTripRequest{}, runtimeTenantID, "request_body_rejected")
			return
		}

		var req networkExtensionRuntimeCopyRoundTripRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, networkExtensionRuntimeCopyRoundTripMaxRequestBodyBytes))
		if err := decoder.Decode(&req); err != nil {
			status := http.StatusBadRequest
			category := "invalid_request_json"
			if strings.Contains(err.Error(), "request body too large") {
				status = http.StatusRequestEntityTooLarge
				category = "request_body_too_large"
			}
			writeNetworkExtensionRuntimeCopyRoundTripError(w, status, category, req, runtimeTenantID, "request_body_rejected")
			return
		}
		if req.SchemaVersion != networkExtensionRuntimeCopyRoundTripRequestSchema {
			writeNetworkExtensionRuntimeCopyRoundTripError(w, http.StatusBadRequest, "invalid_schema_version", req, runtimeTenantID, "schema_rejected")
			return
		}
		if strings.TrimSpace(req.TenantID) == "" {
			writeNetworkExtensionRuntimeCopyRoundTripError(w, http.StatusBadRequest, "invalid_tenant_id", req, runtimeTenantID, "tenant_rejected")
			return
		}
		if runtimeTenantID == "" || strings.TrimSpace(req.TenantID) != runtimeTenantID {
			writeNetworkExtensionRuntimeCopyRoundTripError(w, http.StatusBadGateway, "tenant_scope_mismatch", req, runtimeTenantID, "tenant_rejected")
			return
		}
		req.TenantID = runtimeTenantID
		req.RequestID = strings.TrimSpace(req.RequestID)
		req.ApplicationID = strings.TrimSpace(req.ApplicationID)
		if req.RequestID == "" {
			writeNetworkExtensionRuntimeCopyRoundTripError(w, http.StatusBadRequest, "invalid_request_id", req, runtimeTenantID, "request_id_rejected")
			return
		}
		upstream, err := base64.StdEncoding.DecodeString(req.UpstreamPayloadBase64)
		if err != nil {
			writeNetworkExtensionRuntimeCopyRoundTripError(w, http.StatusBadRequest, "invalid_base64_payload", req, runtimeTenantID, "payload_rejected")
			return
		}
		if len(upstream) == 0 {
			writeNetworkExtensionRuntimeCopyRoundTripError(w, http.StatusBadRequest, "empty_upstream_payload", req, runtimeTenantID, "payload_rejected")
			return
		}
		// ★★★ THE CERT-PROVEN ORGANIZATION OUTRANKS THE CLAIM, AND THE ROUTE NEEDS IT (2026-09-01). The
		// request's own tenant_id is what the endpoint SAID; runtimeTenantID is what its certificate PROVED.
		// A connector is matched within an organization, so a route built from the claim alone found no
		// connector for any customer's internal destination and was dialled directly into the SSRF guard.
		routed := req
		if proven := strings.TrimSpace(runtimeTenantID); proven != "" {
			routed.TenantID = proven
		}
		route, ok, failure := networkExtensionRuntimeCopyRouteFromRequest(routed)
		if !ok {
			writeNetworkExtensionRuntimeCopyRoundTripError(w, failure.status, failure.category, req, runtimeTenantID, failure.routeGate)
			return
		}
		if id, verified := resolveTransportIdentity(config.TransportIdentity, r); verified {
			route.DeviceIdentity = id
		}
		route.TenantID = runtimeTenantID

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		downstream, err := runNetworkExtensionRuntimeCopyRoundTrip(ctx, upstream, route, dialer)
		if err != nil {
			var typedFailure networkExtensionRuntimeCopyRoundTripFailure
			if errors.As(err, &typedFailure) {
				writeNetworkExtensionRuntimeCopyRoundTripError(w, typedFailure.status, typedFailure.category, req, runtimeTenantID, typedFailure.routeGate)
				return
			}
			writeNetworkExtensionRuntimeCopyRoundTripError(w, http.StatusBadGateway, "round_trip_failed", req, runtimeTenantID, "destination_round_trip_failed")
			return
		}

		writeJSON(w, http.StatusOK, networkExtensionRuntimeCopyRoundTripResponse{
			SchemaVersion:            NetworkExtensionRuntimeCopyRoundTripResponseSchema,
			Status:                   "ok",
			Category:                 "round_trip_completed",
			RequestID:                req.RequestID,
			DownstreamPayloadBase64:  base64.StdEncoding.EncodeToString(downstream),
			Audit:                    networkExtensionRuntimeCopyRoundTripAuditEvent("ok", "round_trip_completed", req, runtimeTenantID),
			AuditMetadataOnlyGate:    "ok",
			SecretLeakGate:           "ok",
			RuntimeOverclaimGate:     "ok",
			FlowCopyOverclaimGate:    "ok",
			EdgeRuntimeCopyRouteGate: "destination_authority_round_trip_completed",
		})
	}
}

func NewNetworkExtensionRuntimeCopySessionHandler(config NetworkExtensionRuntimeCopySessionHandlerConfig) http.HandlerFunc {
	runtimeTenantID := strings.TrimSpace(config.TenantID)
	dialer := config.Dialer
	if dialer == nil {
		dialer = NetworkExtensionRuntimeCopyNetDialer{}
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = networkExtensionRuntimeCopyRoundTripDefaultTimeout
	}
	manager := config.SessionManager
	if manager == nil {
		manager = NewNetworkExtensionRuntimeCopySessionManager(0, 0, nil)
	}
	deviceTenant := config.DeviceTenant
	return func(w http.ResponseWriter, r *http.Request) {
		runtimeTenantID := tenantForRequest(deviceTenant, r, runtimeTenantID)
		if r.Method != http.MethodPost {
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusMethodNotAllowed, "method_not_allowed", networkExtensionRuntimeCopySessionRequest{}, runtimeTenantID, "method_rejected")
			return
		}
		if r.ContentLength > networkExtensionRuntimeCopyRoundTripMaxRequestBodyBytes {
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusRequestEntityTooLarge, "request_body_too_large", networkExtensionRuntimeCopySessionRequest{}, runtimeTenantID, "request_body_rejected")
			return
		}

		var req networkExtensionRuntimeCopySessionRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, networkExtensionRuntimeCopyRoundTripMaxRequestBodyBytes))
		if err := decoder.Decode(&req); err != nil {
			status := http.StatusBadRequest
			category := "invalid_request_json"
			if strings.Contains(err.Error(), "request body too large") {
				status = http.StatusRequestEntityTooLarge
				category = "request_body_too_large"
			}
			writeNetworkExtensionRuntimeCopySessionError(w, status, category, req, runtimeTenantID, "request_body_rejected")
			return
		}
		if req.SchemaVersion != NetworkExtensionRuntimeCopySessionRequestSchema {
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadRequest, "invalid_schema_version", req, runtimeTenantID, "schema_rejected")
			return
		}
		if strings.TrimSpace(req.TenantID) == "" {
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadRequest, "invalid_tenant_id", req, runtimeTenantID, "tenant_rejected")
			return
		}
		if runtimeTenantID == "" || strings.TrimSpace(req.TenantID) != runtimeTenantID {
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadGateway, "tenant_scope_mismatch", req, runtimeTenantID, "tenant_rejected")
			return
		}
		req.TenantID = runtimeTenantID
		req.RequestID = strings.TrimSpace(req.RequestID)
		req.ApplicationID = strings.TrimSpace(req.ApplicationID)
		req.Operation = strings.TrimSpace(req.Operation)
		if req.RequestID == "" {
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadRequest, "invalid_request_id", req, runtimeTenantID, "request_id_rejected")
			return
		}
		if req.ApplicationID == "" {
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadRequest, "invalid_application_id", req, runtimeTenantID, "application_rejected")
			return
		}
		switch req.Operation {
		case NetworkExtensionRuntimeCopySessionOperationOpen, NetworkExtensionRuntimeCopySessionOperationExchange, networkExtensionRuntimeCopySessionOperationClose:
		default:
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadRequest, "invalid_session_operation", req, runtimeTenantID, "session_request_rejected")
			return
		}

		if req.Operation == networkExtensionRuntimeCopySessionOperationClose || req.ClientEOF {
			manager.Close(req.RequestID)
			writeJSON(w, http.StatusOK, networkExtensionRuntimeCopySessionResponse{
				SchemaVersion:            NetworkExtensionRuntimeCopySessionResponseSchema,
				Status:                   "ok",
				Category:                 "session_closed",
				RequestID:                req.RequestID,
				SessionClosed:            true,
				Audit:                    networkExtensionRuntimeCopySessionAuditEvent("ok", "session_closed", req, runtimeTenantID),
				AuditMetadataOnlyGate:    "ok",
				SecretLeakGate:           "ok",
				RuntimeOverclaimGate:     "ok",
				FlowCopyOverclaimGate:    "ok",
				EdgeRuntimeCopyRouteGate: "session_closed",
			})
			return
		}

		upstream, err := base64.StdEncoding.DecodeString(req.UpstreamPayloadBase64)
		if err != nil {
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadRequest, "invalid_base64_payload", req, runtimeTenantID, "payload_rejected")
			return
		}
		if len(upstream) == 0 {
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadRequest, "empty_upstream_payload", req, runtimeTenantID, "payload_rejected")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		var session *NetworkExtensionRuntimeCopySession
		if req.Operation == NetworkExtensionRuntimeCopySessionOperationOpen {
			// ★★★ AND THE ORGANIZATION, WHICH THIS DROPPED WITH THE AUTHORITATIVE VALUE IN SCOPE (2026-09-01,
			// found by making the connector lookup say whose flow it was: device="" tenant="tenant_default").
			//
			// A connector is matched WITHIN an organization. This built the route from a struct carrying only
			// a host and a port, so the egress dialer fell back to the tenant it was configured with at
			// startup — the operator's, on a deployment that serves customers. Every customer's internal
			// destination therefore found no connector on this path, was dialled directly, and was refused by
			// the SSRF guard, while the SAME flow's other dial found the connector and logged it. Two dials,
			// one flow, and only one of them knew whose it was.
			//
			// runtimeTenantID is the CERT-PROVEN organization and outranks anything the request claims; the
			// claim is used only when the proof is absent, which is the single-tenant shape.
			routeTenant := strings.TrimSpace(runtimeTenantID)
			if routeTenant == "" {
				routeTenant = strings.TrimSpace(req.TenantID)
			}
			route, ok, routeFailure := networkExtensionRuntimeCopyRouteFromRequest(networkExtensionRuntimeCopyRoundTripRequest{
				DestinationHost: req.DestinationHost,
				DestinationPort: req.DestinationPort,
				TenantID:        routeTenant,
			})
			if !ok {
				writeNetworkExtensionRuntimeCopySessionError(w, routeFailure.status, routeFailure.category, req, runtimeTenantID, routeFailure.routeGate)
				return
			}
			// Carry the verified (T) transport device identity into the route so the decrypt-all egress + the
			// federated-auth gate can bind/check a grant per-device (this runtime-copy session IS the Mac NE
			// decrypt path; without this the device is empty and grants would be tenant-wide).
			if id, verified := resolveTransportIdentity(config.TransportIdentity, r); verified {
				route.DeviceIdentity = id
			}
			route.TenantID = runtimeTenantID
			conn, err := dialer.OpenTCPConnection(ctx, route)
			if err != nil {
				if isNetworkExtensionRuntimeCopyTimeout(ctx, err) {
					writeNetworkExtensionRuntimeCopySessionError(w, http.StatusGatewayTimeout, "round_trip_timeout", req, runtimeTenantID, "destination_tcp_connect_timeout")
					return
				}
				writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadGateway, "round_trip_failed", req, runtimeTenantID, "destination_tcp_connect_failed")
				return
			}
			if conn == nil {
				writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadGateway, "round_trip_failed", req, runtimeTenantID, "destination_tcp_connect_failed")
				return
			}
			var failure networkExtensionRuntimeCopyRoundTripFailure
			session, failure = manager.Open(req, route, conn)
			if failure.category != "" {
				_ = conn.Close()
				writeNetworkExtensionRuntimeCopySessionError(w, failure.status, failure.category, req, runtimeTenantID, failure.routeGate)
				return
			}
		} else {
			var failure networkExtensionRuntimeCopyRoundTripFailure
			session, failure = manager.Get(req.RequestID, req.ApplicationID)
			if failure.category != "" {
				writeNetworkExtensionRuntimeCopySessionError(w, failure.status, failure.category, req, runtimeTenantID, failure.routeGate)
				return
			}
		}

		exchange, err := runNetworkExtensionRuntimeCopySessionExchange(ctx, session, upstream)
		if err != nil {
			manager.Close(req.RequestID)
			var typedFailure networkExtensionRuntimeCopyRoundTripFailure
			if errors.As(err, &typedFailure) {
				writeNetworkExtensionRuntimeCopySessionError(w, typedFailure.status, typedFailure.category, req, runtimeTenantID, typedFailure.routeGate)
				return
			}
			writeNetworkExtensionRuntimeCopySessionError(w, http.StatusBadGateway, "round_trip_failed", req, runtimeTenantID, "destination_round_trip_failed")
			return
		}
		if exchange.sessionClosed {
			manager.Close(req.RequestID)
		}
		writeJSON(w, http.StatusOK, networkExtensionRuntimeCopySessionResponse{
			SchemaVersion:            NetworkExtensionRuntimeCopySessionResponseSchema,
			Status:                   "ok",
			Category:                 "session_exchange_completed",
			RequestID:                req.RequestID,
			DownstreamPayloadBase64:  base64.StdEncoding.EncodeToString(exchange.downstream),
			SessionClosed:            exchange.sessionClosed,
			Audit:                    networkExtensionRuntimeCopySessionAuditEvent("ok", "session_exchange_completed", req, runtimeTenantID),
			AuditMetadataOnlyGate:    "ok",
			SecretLeakGate:           "ok",
			RuntimeOverclaimGate:     "ok",
			FlowCopyOverclaimGate:    "ok",
			EdgeRuntimeCopyRouteGate: "destination_authority_session_exchange_completed",
		})
	}
}

func networkExtensionRuntimeCopyRouteFromRequest(req networkExtensionRuntimeCopyRoundTripRequest) (NetworkExtensionRuntimeCopyTCPRoute, bool, networkExtensionRuntimeCopyRoundTripFailure) {
	host, ok := NormalizeNetworkExtensionRuntimeCopyDestinationHost(req.DestinationHost)
	if !ok {
		if strings.TrimSpace(req.DestinationHost) == "" && req.DestinationPort == 0 {
			return NetworkExtensionRuntimeCopyTCPRoute{}, false, networkExtensionRuntimeCopyRoundTripFailure{
				status:    http.StatusBadGateway,
				category:  "unknown_application_default_deny",
				routeGate: "destination_authority_not_available_in_request_v1",
			}
		}
		return NetworkExtensionRuntimeCopyTCPRoute{}, false, networkExtensionRuntimeCopyRoundTripFailure{
			status:    http.StatusBadRequest,
			category:  "invalid_destination_host",
			routeGate: "destination_authority_rejected",
		}
	}
	if req.DestinationPort < 1 || req.DestinationPort > 65535 {
		return NetworkExtensionRuntimeCopyTCPRoute{}, false, networkExtensionRuntimeCopyRoundTripFailure{
			status:    http.StatusBadRequest,
			category:  "invalid_destination_port",
			routeGate: "destination_authority_rejected",
		}
	}
	// ★★★ AND THE ORGANIZATION, WHICH THIS DROPPED (2026-09-01, found by making a not-found connector lookup
	// say which organization it had asked about).
	//
	// A destination is matched to a connector WITHIN an organization. This route is what the egress dialer
	// looks the destination up with, and it carried the host and the port and nothing else — so the dialer
	// fell back to the tenant it was configured with at startup, which on a deployment that serves customers
	// is the operator's. Every customer's internal destination therefore resolved to no connector, was dialled
	// directly, and was refused by the SSRF guard:
	//
	//	connector_route_not_found host="10.60.1.176" tenant="tenant_default"
	//
	// while the request that produced it carried the right organization all along.
	return NetworkExtensionRuntimeCopyTCPRoute{Host: host, Port: req.DestinationPort, TenantID: req.TenantID,
		BuiltBy: "runtime-copy"}, true, networkExtensionRuntimeCopyRoundTripFailure{}
}

func runNetworkExtensionRuntimeCopyRoundTrip(
	ctx context.Context,
	upstream []byte,
	route NetworkExtensionRuntimeCopyTCPRoute,
	dialer NetworkExtensionRuntimeCopyTCPDialer,
) ([]byte, error) {
	if dialer == nil {
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed", routeGate: "destination_dialer_missing"}
	}
	conn, err := dialer.OpenTCPConnection(ctx, route)
	if err != nil {
		if isNetworkExtensionRuntimeCopyTimeout(ctx, err) {
			return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusGatewayTimeout, category: "round_trip_timeout", routeGate: "destination_tcp_connect_timeout"}
		}
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed", routeGate: "destination_tcp_connect_failed"}
	}
	if conn == nil {
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed", routeGate: "destination_tcp_connect_failed"}
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if deadlineConn, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
			_ = deadlineConn.SetDeadline(deadline)
		}
	}
	if err := writeNetworkExtensionRuntimeCopyUpstream(ctx, conn, upstream); err != nil {
		if isNetworkExtensionRuntimeCopyTimeout(ctx, err) {
			return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusGatewayTimeout, category: "round_trip_timeout", routeGate: "destination_upstream_write_timeout"}
		}
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed", routeGate: "destination_upstream_write_failed"}
	}
	downstream, err := readNetworkExtensionRuntimeCopyDownstream(ctx, conn)
	if err != nil {
		if isNetworkExtensionRuntimeCopyTimeout(ctx, err) {
			return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusGatewayTimeout, category: "round_trip_timeout", routeGate: "destination_downstream_read_timeout"}
		}
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed", routeGate: "destination_downstream_read_failed"}
	}
	if len(downstream) == 0 {
		return nil, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed", routeGate: "destination_downstream_empty"}
	}
	return downstream, nil
}

func runNetworkExtensionRuntimeCopySessionExchange(
	ctx context.Context,
	session *NetworkExtensionRuntimeCopySession,
	upstream []byte,
) (networkExtensionRuntimeCopySessionExchangeResult, error) {
	if session == nil || session.conn == nil {
		return networkExtensionRuntimeCopySessionExchangeResult{}, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusNotFound, category: "session_not_found", routeGate: "session_not_open"}
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		if deadlineConn, ok := session.conn.(interface{ SetDeadline(time.Time) error }); ok {
			_ = deadlineConn.SetDeadline(deadline)
		}
	}
	if err := writeNetworkExtensionRuntimeCopyUpstream(ctx, session.conn, upstream); err != nil {
		if isNetworkExtensionRuntimeCopyTimeout(ctx, err) {
			return networkExtensionRuntimeCopySessionExchangeResult{}, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusGatewayTimeout, category: "round_trip_timeout", routeGate: "destination_upstream_write_timeout"}
		}
		return networkExtensionRuntimeCopySessionExchangeResult{}, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed", routeGate: "destination_upstream_write_failed"}
	}
	session.bytesUp += int64(len(upstream))
	downstream, sessionClosed, err := ReadNetworkExtensionRuntimeCopySessionDownstream(ctx, session.conn)
	if err != nil {
		if isNetworkExtensionRuntimeCopyTimeout(ctx, err) {
			return networkExtensionRuntimeCopySessionExchangeResult{}, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusGatewayTimeout, category: "round_trip_timeout", routeGate: "destination_downstream_read_timeout"}
		}
		return networkExtensionRuntimeCopySessionExchangeResult{}, networkExtensionRuntimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed", routeGate: "destination_downstream_read_failed"}
	}
	session.bytesDown += int64(len(downstream))
	session.lastUsedAt = time.Now().UTC()
	return networkExtensionRuntimeCopySessionExchangeResult{downstream: downstream, sessionClosed: sessionClosed}, nil
}

func writeNetworkExtensionRuntimeCopyUpstream(ctx context.Context, writer io.Writer, upstream []byte) error {
	for len(upstream) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		written, err := writer.Write(upstream)
		if written > 0 {
			upstream = upstream[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return fmt.Errorf("runtime-copy upstream write made no progress")
		}
	}
	return nil
}

func readNetworkExtensionRuntimeCopyDownstream(ctx context.Context, reader io.Reader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	buf := make([]byte, networkExtensionRuntimeCopyRoundTripDefaultReadBytes)
	n, err := reader.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("runtime-copy downstream read made no progress")
}

func ReadNetworkExtensionRuntimeCopySessionDownstream(ctx context.Context, conn io.ReadWriteCloser) ([]byte, bool, error) {
	allowEmpty := NetworkExtensionRuntimeCopyAllowsEmptyDownstream(conn)
	if !allowEmpty {
		downstream, err := readNetworkExtensionRuntimeCopyDownstream(ctx, conn)
		return downstream, false, err
	}

	var downstream []byte
	emptyDownstreamWait := networkExtensionRuntimeCopySessionDrainWait(conn)
	deadlineConn, hasDeadline := conn.(interface{ SetReadDeadline(time.Time) error })
	if hasDeadline {
		defer deadlineConn.SetReadDeadline(time.Time{})
	}
	for {
		if hasDeadline {
			_ = deadlineConn.SetReadDeadline(time.Now().Add(emptyDownstreamWait))
		}
		chunk, err := readNetworkExtensionRuntimeCopyDownstream(ctx, conn)
		if err == nil {
			downstream = append(downstream, chunk...)
			continue
		}
		if isNetworkExtensionRuntimeCopyTimeout(ctx, err) || strings.Contains(err.Error(), "runtime-copy downstream read made no progress") {
			if len(downstream) > 0 && networkExtensionRuntimeCopySessionDoneSignaled(conn, networkExtensionRuntimeCopySessionCloseSignalWait) {
				return downstream, true, nil
			}
			if networkExtensionRuntimeCopyDownstreamExpectedSignaled(conn) {
				if err := ctx.Err(); err != nil {
					return nil, false, err
				}
				continue
			}
			if len(downstream) == 0 && networkExtensionRuntimeCopyDownstreamExpectedWithin(ctx, conn, networkExtensionRuntimeCopySessionDownstreamSignalWait) {
				continue
			}
			return downstream, false, nil
		}
		if isNetworkExtensionRuntimeCopyClosedConnection(err) {
			return downstream, true, nil
		}
		return nil, false, err
	}
}

func isNetworkExtensionRuntimeCopyClosedConnection(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "closed pipe") || strings.Contains(message, "use of closed network connection")
}

func NetworkExtensionRuntimeCopyAllowsEmptyDownstream(conn io.ReadWriteCloser) bool {
	if typed, ok := conn.(networkExtensionRuntimeCopyEmptyDownstreamConn); ok {
		return typed.AllowEmptyRuntimeCopyDownstream()
	}
	return false
}

func networkExtensionRuntimeCopySessionDrainWait(conn io.ReadWriteCloser) time.Duration {
	if typed, ok := conn.(networkExtensionRuntimeCopyDrainWaitConn); ok {
		if wait := typed.RuntimeCopyDrainWait(); wait > 0 {
			return wait
		}
	}
	return NetworkExtensionRuntimeCopySessionEmptyDownstreamWait
}

func networkExtensionRuntimeCopyDownstreamExpectedSignaled(conn io.ReadWriteCloser) bool {
	typed, ok := conn.(networkExtensionRuntimeCopyDownstreamExpectedConn)
	if !ok {
		return false
	}
	expected := typed.RuntimeCopyDownstreamExpected()
	if expected == nil {
		return false
	}
	select {
	case <-expected:
		return true
	default:
		return false
	}
}

func networkExtensionRuntimeCopyDownstreamExpectedWithin(ctx context.Context, conn io.ReadWriteCloser, wait time.Duration) bool {
	typed, ok := conn.(networkExtensionRuntimeCopyDownstreamExpectedConn)
	if !ok {
		return false
	}
	expected := typed.RuntimeCopyDownstreamExpected()
	if expected == nil {
		return false
	}
	select {
	case <-expected:
		return true
	default:
	}
	if wait <= 0 {
		return false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-expected:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

func networkExtensionRuntimeCopySessionDoneSignaled(conn io.ReadWriteCloser, wait time.Duration) bool {
	typed, ok := conn.(networkExtensionRuntimeCopySessionDoneConn)
	if !ok {
		return false
	}
	done := typed.RuntimeCopySessionDone()
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
	}
	if wait <= 0 {
		return false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func isNetworkExtensionRuntimeCopyTimeout(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func writeNetworkExtensionRuntimeCopyRoundTripError(w http.ResponseWriter, status int, category string, req networkExtensionRuntimeCopyRoundTripRequest, runtimeTenantID string, routeGate string) {
	writeJSON(w, status, networkExtensionRuntimeCopyRoundTripResponse{
		SchemaVersion:            NetworkExtensionRuntimeCopyRoundTripErrorResponseSchema,
		Status:                   "error",
		Category:                 category,
		RequestID:                strings.TrimSpace(req.RequestID),
		Audit:                    networkExtensionRuntimeCopyRoundTripAuditEvent("error", category, req, runtimeTenantID),
		AuditMetadataOnlyGate:    "ok",
		SecretLeakGate:           "ok",
		RuntimeOverclaimGate:     "ok",
		FlowCopyOverclaimGate:    "ok",
		EdgeRuntimeCopyRouteGate: routeGate,
	})
}

func writeNetworkExtensionRuntimeCopySessionError(w http.ResponseWriter, status int, category string, req networkExtensionRuntimeCopySessionRequest, runtimeTenantID string, routeGate string) {
	writeJSON(w, status, networkExtensionRuntimeCopySessionResponse{
		SchemaVersion:            networkExtensionRuntimeCopySessionErrorResponseSchema,
		Status:                   "error",
		Category:                 category,
		RequestID:                strings.TrimSpace(req.RequestID),
		SessionClosed:            false,
		Audit:                    networkExtensionRuntimeCopySessionAuditEvent("error", category, req, runtimeTenantID),
		AuditMetadataOnlyGate:    "ok",
		SecretLeakGate:           "ok",
		RuntimeOverclaimGate:     "ok",
		FlowCopyOverclaimGate:    "ok",
		EdgeRuntimeCopyRouteGate: routeGate,
	})
}

func networkExtensionRuntimeCopyRoundTripAuditEvent(status, category string, req networkExtensionRuntimeCopyRoundTripRequest, runtimeTenantID string) networkExtensionRuntimeCopyRoundTripAudit {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(runtimeTenantID)
	}
	return networkExtensionRuntimeCopyRoundTripAudit{
		SchemaVersion: "network_extension_runtime_copy_round_trip_audit.v1",
		Status:        status,
		Category:      category,
		TenantID:      tenantID,
		RequestID:     strings.TrimSpace(req.RequestID),
		ApplicationID: strings.TrimSpace(req.ApplicationID),
		MetadataOnly:  true,
	}
}

func networkExtensionRuntimeCopySessionAuditEvent(status, category string, req networkExtensionRuntimeCopySessionRequest, runtimeTenantID string) networkExtensionRuntimeCopyRoundTripAudit {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(runtimeTenantID)
	}
	return networkExtensionRuntimeCopyRoundTripAudit{
		SchemaVersion: "network_extension_runtime_copy_session_audit.v1",
		Status:        status,
		Category:      category,
		TenantID:      tenantID,
		RequestID:     strings.TrimSpace(req.RequestID),
		ApplicationID: strings.TrimSpace(req.ApplicationID),
		MetadataOnly:  true,
	}
}

// TransportIdentityFunc resolves the verified (T) transport device identity of a
// request. The composition root binds it to its mTLS-leaf reader; nil means the NE
// runtime-copy path runs without a transport identity (identity stays empty).
type TransportIdentityFunc func(r *http.Request) (string, bool)

// DeviceTenantFunc answers WHOSE flow this is, from the device's own verified (T) client certificate.
//
// ★★★ THE DATA PATH ASKED THE NODE, NOT THE DEVICE (2026-08-29, measured on a real Mac). The round-trip and
// session handlers compared the device's tenant to `config.TenantID` — one value, read once at startup from
// the policy bundle this Edge process loaded, i.e. the NODE's own organization. A Mac correctly enrolled into
// a customer organization (this same Edge logged `enroll_issued tenant="tenant_j32kx…"` for it) then had
// EVERY steered flow refused with tenant_scope_mismatch. The device steered — decision=accepted,
// action=tunnel, 26 flows — and none of them could be carried, which is fail-closed by accident: no browsing,
// no explanation, on a machine whose configuration was correct in every field.
//
// The certificate is the authority, which is what steerDeviceTenant already says for the /steer routes — and
// says it by pointing AT the data path as the model. The data path was the one place not doing it.
//
// nil, or an answer of ("", false), leaves the node's own tenant in force: that is a single-tenant deployment,
// and it is the behaviour every existing caller has.
type DeviceTenantFunc func(r *http.Request) (string, bool)

// tenantForRequest is the tenant this request is allowed to act as. Named so the two handlers cannot drift.
func tenantForRequest(fn DeviceTenantFunc, r *http.Request, nodeTenant string) string {
	if fn != nil {
		if tenant, ok := fn(r); ok {
			if trimmed := strings.TrimSpace(tenant); trimmed != "" {
				return trimmed
			}
		}
	}
	return nodeTenant
}

func resolveTransportIdentity(fn TransportIdentityFunc, r *http.Request) (string, bool) {
	if fn == nil {
		return "", false
	}
	return fn(r)
}
