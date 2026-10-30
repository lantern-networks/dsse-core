package outboundtls

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
)

func TestCloseIdleDoesNotCreateOrReplaceAIAProfile(t *testing.T) {
	base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}
	CloseIdleConnectionsForTransport(base)
	if _, exists := wrapped.Load(base); exists {
		t.Fatal("closing idle connections constructed an unused AIA profile")
	}
	first := WrapRoundTripper(base)
	for i := 0; i < 20; i++ {
		CloseIdleConnectionsForTransport(base)
		if next := WrapRoundTripper(base); next != first {
			t.Fatal("immutable AIA profile changed on reuse")
		}
	}
}
