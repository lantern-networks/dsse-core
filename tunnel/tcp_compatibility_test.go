package tunnel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func compatibilityFrame() Frame {
	return Frame{Type: FrameTCPOpen, RequestID: "request", ApplicationID: "ssh", Host: "127.0.0.1", Port: 22, ConnectTimeoutMillis: 5000, ConcurrentConnectionCap: 1024}
}

// These checks are the released 0.3.1 receiver's bounds. The separate executable
// integration also runs against the actual retained release source/binaries.
func releasedTCPBounds(f Frame) error {
	if f.ByteCap < 1 || f.ByteCap > 1<<30 || f.MaxConnectionLifetimeMillis > 3600000 || f.IdleTimeoutMillis > 300000 {
		return fmt.Errorf("released receiver rejected quota frame")
	}
	return nil
}

func TestTCPQuotaNegotiationUsesTheActualUpgradeInBothDirections(t *testing.T) {
	for _, advertised := range []string{"", "unknown", TCPQuotaCapabilityV1} {
		t.Run(advertised, func(t *testing.T) {
			accepted := make(chan *Conn, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, e := UpgradeWithHeaders(w, r, http.Header{TCPQuotaCapabilityHeader: []string{advertised}})
				if e != nil {
					return
				}
				accepted <- c
			}))
			defer srv.Close()
			client, e := Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), http.Header{TCPQuotaCapabilityHeader: []string{advertised}})
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			server := <-accepted
			defer server.Close()
			for _, c := range []*Conn{client, server} {
				s, _ := NewManager().Register("peer", "tunnel", c)
				f := s.PrepareTCPOpenFrame(compatibilityFrame())
				if advertised == TCPQuotaCapabilityV1 {
					if f.ByteCap != 0 {
						t.Fatal("new peer received an invented byte budget")
					}
				} else if releasedTCPBounds(f) != nil {
					t.Fatal("absent/unknown capability broke legacy interoperability")
				}
			}
		})
	}
}

func TestLegacyQuotaProjectionPreservesReceiverBoundsAndExplicitSmallerValues(t *testing.T) {
	s := &Session{}
	f := compatibilityFrame()
	f.ByteCap = 8 << 30
	f.MaxConnectionLifetimeMillis = int((8 * time.Hour) / time.Millisecond)
	f.IdleTimeoutMillis = int(time.Hour / time.Millisecond)
	if got := s.PrepareTCPOpenFrame(f); releasedTCPBounds(got) != nil || got.ByteCap != 1<<30 || got.MaxConnectionLifetimeMillis != 3600000 || got.IdleTimeoutMillis != 300000 {
		t.Fatal("large operator settings broke the legacy wire")
	}
	f.ByteCap = 7
	f.MaxConnectionLifetimeMillis = 100
	f.IdleTimeoutMillis = 50
	if s.PrepareTCPOpenFrame(f) != f {
		t.Fatal("a stricter operator budget was changed")
	}
	s.peerTCPQuotas = true
	f = compatibilityFrame()
	if s.PrepareTCPOpenFrame(f) != f {
		t.Fatal("capable peer inherited old receiver quotas")
	}
}
