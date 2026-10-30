package tunnel

import (
	"net/http"
	"strings"
)

// Negotiated on the authenticated WebSocket upgrade, independently for each
// Connector or peer Edge. An absent/unknown capability always means legacy.
const TCPQuotaCapabilityHeader = "X-Dsse-TCP-Quotas"
const TCPQuotaCapabilityV1 = "operator-v1"

func SupportsTCPQuotaV1(h http.Header) bool {
	return strings.TrimSpace(h.Get(TCPQuotaCapabilityHeader)) == TCPQuotaCapabilityV1
}

// PeerSupportsTCPQuotas is immutable for a transport's lifetime. Custom frame
// transports without this interface conservatively use the released v0.3.1 wire.
type tcpQuotaPeer interface{ PeerSupportsTCPQuotas() bool }

// PrepareTCPOpenFrame preserves old receiver limits during rolling upgrades.
// These are the old peer's own constraints, not new quotas in an upgraded peer.
// The upgraded sender still enforces any stricter explicit operator budget.
func (s *Session) PrepareTCPOpenFrame(frame Frame) Frame {
	if s != nil && s.peerTCPQuotas {
		return frame
	}
	if frame.ByteCap == 0 || frame.ByteCap > 1<<30 {
		frame.ByteCap = 1 << 30
	}
	if frame.MaxConnectionLifetimeMillis > 3_600_000 {
		frame.MaxConnectionLifetimeMillis = 3_600_000
	}
	if frame.IdleTimeoutMillis > 300_000 {
		frame.IdleTimeoutMillis = 300_000
	}
	return frame
}
