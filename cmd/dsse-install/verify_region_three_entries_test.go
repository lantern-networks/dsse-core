package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyComparesEdgeCatalogsEvenWithinOneRegion(t *testing.T) {
	serve := func(digest string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"role":"edge","region":"kiri","region_endpoints":["kiri"],"region_endpoints_digest":%q}`, digest)
		}))
	}
	a, b := serve("all-three"), serve("only-two")
	defer a.Close()
	defer b.Close()
	// A node is asked over TLS only (verify_asks_a_node_as_its_operator.go); httptest servers share one certificate.
	got := verifyRegionAgreement(a.Client(), []string{a.URL, b.URL})
	if len(got) == 0 || got[0].ok {
		t.Fatalf("single-region catalog mismatch was missed: %+v", got)
	}
}
