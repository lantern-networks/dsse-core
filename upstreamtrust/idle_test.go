package upstreamtrust

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
)

func TestCloseIdleDoesNotCreateOrReplaceVendorProfiles(t *testing.T) {
	base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}
	CloseIdleConnectionsForTransport(base)
	key := cacheKey{base, "init.ess.apple.com"}
	if _, exists := transports.Load(key); exists {
		t.Fatal("closing idle connections constructed unused vendor profile")
	}
	first := ForHost(base, key.host)
	for i := 0; i < 20; i++ {
		CloseIdleConnectionsForTransport(base)
		if next := ForHost(base, key.host); next != first {
			t.Fatal("immutable vendor profile changed on reuse")
		}
	}
}
