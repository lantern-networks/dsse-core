package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// An HTTP/2 server represents even an absent body with a non-nil reader.
// Relaying that reader as an outgoing request with ContentLength == 0 makes
// net/http send an unknown-length body instead of a bodyless HEADERS frame.
func TestSWGInterceptionPreservesBodyFraming(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, tc := range []struct{ method, body string }{{"GET", ""}, {"HEAD", ""}, {"POST", ""}, {"POST", "payload"}, {"GET", "payload"}} {
			name := "h1/" + tc.method + "/" + tc.body
			if h2 {
				name = "h2/" + tc.method + "/" + tc.body
			}
			t.Run(name, func(t *testing.T) {
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil || string(body) != tc.body || r.ContentLength != int64(len(tc.body)) {
						t.Errorf("origin body framing: length=%d body=%q err=%v", r.ContentLength, body, err)
						w.WriteHeader(500)
						return
					}
					w.WriteHeader(204)
				}))
				origin.EnableHTTP2 = true
				origin.StartTLS()
				defer origin.Close()
				target, _ := url.Parse(origin.URL)
				intercept := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					forward, err := edgeplane.BuildNetworkExtensionLabTLSForwardRequest(r, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "origin.example", Port: 443})
					if err != nil {
						t.Error(err)
						w.WriteHeader(502)
						return
					}
					upstream, err := newSWGHTTPEgressUpstreamRequest(forward, target)
					if err != nil {
						t.Error(err)
						w.WriteHeader(502)
						return
					}
					resp, err := origin.Client().Do(upstream)
					if err != nil {
						t.Error(err)
						w.WriteHeader(502)
						return
					}
					defer resp.Body.Close()
					w.WriteHeader(resp.StatusCode)
				}))
				intercept.EnableHTTP2 = h2
				intercept.StartTLS()
				defer intercept.Close()
				req, _ := http.NewRequest(tc.method, intercept.URL, strings.NewReader(tc.body))
				resp, err := intercept.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != 204 {
					t.Fatalf("status=%d", resp.StatusCode)
				}
				if (resp.ProtoMajor == 2) != h2 {
					t.Fatalf("wrong protocol %s", resp.Proto)
				}
			})
		}
	}
}

func TestSWGInterceptionPreservesOpenBodies(t *testing.T) {
	for _, tc := range []struct {
		method string
		length int64
	}{{"POST", -1}, {"GET", -1}, {"CONNECT", 0}} {
		t.Run(tc.method, func(t *testing.T) {
			body := io.NopCloser(strings.NewReader("stream data"))
			req := &http.Request{Method: tc.method, ProtoMajor: 2, ContentLength: tc.length, Body: body, Header: make(http.Header), URL: &url.URL{Path: "/"}}
			forward, err := edgeplane.BuildNetworkExtensionLabTLSForwardRequest(req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "origin.example", Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			if forward.Body != body || forward.ContentLength != tc.length {
				t.Fatal("open request body was changed")
			}
			got, err := io.ReadAll(forward.Body)
			if err != nil || string(got) != "stream data" {
				t.Fatalf("stream changed: %q %v", got, err)
			}
		})
	}
}
