package tunnel

import (
	"encoding/base64"
	"fmt"
	"time"
)

// DNS conditional-forward frames (FrameDNSQuery / FrameDNSResult): the Edge hands a RAW DNS query to the
// connector, which resolves it against the internal DNS INSIDE the private network and returns the raw
// response. See docs/dns_conditional_forwarding_design.md.

const (
	// DefaultDNSQueryTimeoutMillis bounds one internal DNS round-trip; the Max caps an override so a DNS query
	// can never become a long-lived connection.
	DefaultDNSQueryTimeoutMillis = int(4 * time.Second / time.Millisecond)
	MaxDNSQueryTimeoutMillis     = int(10 * time.Second / time.Millisecond)
	// MaxDNSMessageBytes caps a DNS message (query or response). 64 KiB is the TCP DNS ceiling; a larger frame
	// is rejected rather than forwarded.
	MaxDNSMessageBytes = 64 << 10
)

// ValidateDNSQueryFrame validates an edge->connector DNS query request: a request id, a decodable non-empty
// bounded query, and a bounded timeout. The upstream server is optional (empty = the connector's own resolver).
func ValidateDNSQueryFrame(frame Frame) error {
	if frame.Type != FrameDNSQuery {
		return fmt.Errorf("dns_query frame type is required")
	}
	if frame.RequestID == "" {
		return fmt.Errorf("dns_query request_id is required")
	}
	raw, err := DecodeDNSMessage(frame.DNSQuery)
	if err != nil {
		return fmt.Errorf("dns_query: %w", err)
	}
	if len(raw) == 0 {
		return fmt.Errorf("dns_query must carry a query")
	}
	if frame.ConnectTimeoutMillis < 0 || frame.ConnectTimeoutMillis > MaxDNSQueryTimeoutMillis {
		return fmt.Errorf("dns_query connect_timeout_ms must be between 0 and %d", MaxDNSQueryTimeoutMillis)
	}
	return nil
}

// DNSQueryTimeoutMillisOrDefault clamps the requested timeout into [1, Max], defaulting when unset.
func DNSQueryTimeoutMillisOrDefault(requested int) int {
	if requested <= 0 {
		return DefaultDNSQueryTimeoutMillis
	}
	if requested > MaxDNSQueryTimeoutMillis {
		return MaxDNSQueryTimeoutMillis
	}
	return requested
}

// EncodeDNSMessage base64-encodes raw DNS bytes for transport in a Frame.
func EncodeDNSMessage(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// DecodeDNSMessage base64-decodes DNS bytes from a Frame and enforces the size ceiling.
func DecodeDNSMessage(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("dns message is not valid base64: %w", err)
	}
	if len(raw) > MaxDNSMessageBytes {
		return nil, fmt.Errorf("dns message exceeds %d bytes", MaxDNSMessageBytes)
	}
	return raw, nil
}

// DNSResultFrame builds the connector->edge response frame. On success it carries the raw response bytes; on
// failure it carries a non-secret error string and no response (fail-closed at the resolver).
func DNSResultFrame(requestID string, response []byte, resolveErr error) Frame {
	f := Frame{Type: FrameDNSResult, RequestID: requestID}
	if resolveErr != nil {
		f.Error = resolveErr.Error()
		return f
	}
	f.DNSResponse = EncodeDNSMessage(response)
	return f
}
