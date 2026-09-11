package tunnel

import (
	"fmt"
	"time"
)

// Probe protocol selectors. "web" probes DNS+TCP+TLS+HTTP; "tcp" probes DNS+TCP only.
const (
	ProbeProtocolWeb = "web"
	ProbeProtocolTCP = "tcp"
)

// Probe failure layers. These name WHICH layer first failed so the UI can show "Failure layer: DNS" etc.
// "route" is the connector's SSRF / out-of-range refusal (the destination is not within reachable_routes).
const (
	ProbeFailureLayerRoute = "route"
	ProbeFailureLayerDNS   = "dns"
	ProbeFailureLayerTCP   = "tcp"
	ProbeFailureLayerTLS   = "tls"
	ProbeFailureLayerHTTP  = "http"
)

const (
	// DefaultProbeTimeoutMillis bounds a single probe end to end; MaxProbeTimeoutMillis caps an operator
	// override so a probe can never become a long-lived connection.
	DefaultProbeTimeoutMillis = int(5 * time.Second / time.Millisecond)
	MaxProbeTimeoutMillis     = int(15 * time.Second / time.Millisecond)
)

// ProbeLayerResult is one layer's outcome. It is intentionally tiny and secret-free: a boolean, a latency,
// and a NON-secret error string (a connection/DNS/handshake message — never payload, key, or credential).
type ProbeLayerResult struct {
	Attempted     bool   `json:"attempted"`
	OK            bool   `json:"ok"`
	LatencyMillis int64  `json:"latency_ms,omitempty"`
	Error         string `json:"error,omitempty"`
}

// ProbeTLSCertInfo is the NON-secret projection of the server certificate seen during the TLS handshake.
// It carries only public certificate fields (subject/issuer/validity/SANs) — never the private key, never
// the raw certificate bytes. A probe must never leak key material.
type ProbeTLSCertInfo struct {
	Subject   string   `json:"subject,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	DNSNames  []string `json:"dns_names,omitempty"`
	Expired   bool     `json:"expired"`
}

// ProbeResult is the secret-safe, layer-by-layer reachability outcome the connector returns. Reachable is the
// overall verdict; FailureLayer names the first failing layer (empty when Reachable). ResolvedIPs/HTTPStatus
// are non-secret diagnostics. The result NEVER contains response bodies, payload bytes, or key material.
type ProbeResult struct {
	Host         string            `json:"host,omitempty"`
	Port         int               `json:"port,omitempty"`
	Protocol     string            `json:"protocol,omitempty"`
	Reachable    bool              `json:"reachable"`
	FailureLayer string            `json:"failure_layer,omitempty"`
	DNS          ProbeLayerResult  `json:"dns"`
	TCP          ProbeLayerResult  `json:"tcp"`
	TLS          ProbeLayerResult  `json:"tls"`
	HTTP         ProbeLayerResult  `json:"http"`
	ResolvedIPs  []string          `json:"resolved_ips,omitempty"`
	HTTPStatus   int               `json:"http_status,omitempty"`
	TLSCert      *ProbeTLSCertInfo `json:"tls_cert,omitempty"`
}

// ValidateProbeRequestFrame validates an edge->connector probe request. host/port are required; the timeout
// (carried on ConnectTimeoutMillis, reused) is bounded so a probe can never become a long-lived dial.
func ValidateProbeRequestFrame(frame Frame) error {
	if frame.Type != FrameProbeRequest {
		return fmt.Errorf("probe_request frame type is required")
	}
	if frame.RequestID == "" {
		return fmt.Errorf("probe_request request_id is required")
	}
	if frame.Host == "" {
		return fmt.Errorf("probe_request host is required")
	}
	if frame.Port < 1 || frame.Port > 65535 {
		return fmt.Errorf("probe_request port must be between 1 and 65535")
	}
	switch frame.ProbeProtocol {
	case ProbeProtocolWeb, ProbeProtocolTCP, "":
	default:
		return fmt.Errorf("probe_request probe_protocol %q is not allowed", frame.ProbeProtocol)
	}
	if frame.ConnectTimeoutMillis < 0 || frame.ConnectTimeoutMillis > MaxProbeTimeoutMillis {
		return fmt.Errorf("probe_request connect_timeout_ms must be between 0 and %d", MaxProbeTimeoutMillis)
	}
	return nil
}

// ProbeTimeoutMillisOrDefault clamps the requested timeout into [1, Max], defaulting when unset.
func ProbeTimeoutMillisOrDefault(requested int) int {
	if requested <= 0 {
		return DefaultProbeTimeoutMillis
	}
	if requested > MaxProbeTimeoutMillis {
		return MaxProbeTimeoutMillis
	}
	return requested
}
