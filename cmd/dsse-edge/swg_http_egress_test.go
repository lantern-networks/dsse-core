package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"syscall"
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

func TestSWGHTTPEgressUpstreamRequestErrorCategory(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "nil",
			err:  nil,
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryNone,
		},
		{
			name: "context canceled",
			err:  context.Canceled,
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryContextCanceled,
		},
		{
			name: "deadline",
			err:  context.DeadlineExceeded,
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTimeout,
		},
		{
			name: "dns",
			err:  &url.Error{Op: "Get", URL: "https://redacted.invalid/", Err: &net.DNSError{Err: "no such host", Name: "redacted.invalid"}},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryDNSError,
		},
		{
			name: "certificate",
			err:  &url.Error{Op: "Get", URL: "https://redacted.invalid/", Err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "redacted.invalid"}},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryCertificateError,
		},
		{
			name: "tls handshake",
			err:  &url.Error{Op: "Get", URL: "https://redacted.invalid/", Err: tls.RecordHeaderError{}},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTLSHandshakeError,
		},
		{
			name: "connection reset",
			err:  &url.Error{Op: "Get", URL: "https://redacted.invalid/", Err: syscall.ECONNRESET},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryConnectionReset,
		},
		{
			name: "connection refused",
			err:  &url.Error{Op: "Get", URL: "https://redacted.invalid/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryConnectionRefused,
		},
		{
			name: "network unreachable",
			err:  &url.Error{Op: "Get", URL: "https://redacted.invalid/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryNetworkUnreachable,
		},
		{
			name: "closed connection",
			err:  &url.Error{Op: "Get", URL: "https://redacted.invalid/", Err: net.ErrClosed},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryClosedConnection,
		},
		{
			name: "unexpected eof",
			err:  &url.Error{Op: "Get", URL: "https://redacted.invalid/", Err: errors.New("unexpected EOF")},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryClosedConnection,
		},
		{
			name: "http2 stream",
			err:  &url.Error{Op: "Post", URL: "https://redacted.invalid/", Err: errors.New("stream error: stream ID 9; INTERNAL_ERROR; received from peer")},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryHTTP2Transport,
		},
		{
			name: "malformed response",
			err:  &url.Error{Op: "Get", URL: "https://redacted.invalid/", Err: errors.New("net/http: HTTP/1.x transport connection broken: malformed HTTP response")},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryMalformedResponse,
		},
		{
			name: "tcp connect",
			err:  &url.Error{Op: "Get", URL: "https://redacted.invalid/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("redacted dial failure")}},
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTCPConnectError,
		},
		{
			name: "other",
			err:  errors.New("redacted upstream failure"),
			want: edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryOtherNonSecret,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := swgHTTPEgressUpstreamRequestErrorCategory(tt.err); got != tt.want {
				t.Fatalf("category = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSetSWGHTTPEgressUpstreamRequestErrorCategory(t *testing.T) {
	recorder := &swgHTTPEgressDiagnosticRecorder{ResponseRecorder: httptest.NewRecorder()}
	setSWGHTTPEgressUpstreamRequestErrorCategory(recorder, context.DeadlineExceeded)

	if recorder.category != edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTimeout {
		t.Fatalf("category = %q, want %q", recorder.category, edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTimeout)
	}
}

func TestSWGHTTPEgressProxyClientStabilizesDefaultTransportForNetworkExtensionRuntime(t *testing.T) {
	client := swgHTTPEgressProxyClient(&http.Client{}, true)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = false, want true so h2-only upstreams (accounts.google.com) negotiate HTTP/2 instead of returning 502")
	}
	if transport.DisableKeepAlives {
		t.Fatal("DisableKeepAlives = true, want false: the NE-runtime egress transport POOLS + REUSES origin " +
			"connections so a multi-resource page does not pay a fresh TCP+TLS handshake per request (perf fix)")
	}
	if transport.TLSNextProto != nil {
		t.Fatal("TLSNextProto != nil, want nil so Go restores automatic HTTP/2 negotiation")
	}
	if err := client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect error = %v, want http.ErrUseLastResponse", err)
	}
}

func TestSWGHTTPEgressProxyClientLeavesNonRuntimeDefaultTransportUntouched(t *testing.T) {
	client := swgHTTPEgressProxyClient(&http.Client{}, false)
	if client.Transport != nil {
		t.Fatalf("transport = %T, want nil default transport when NE runtime stabilization is disabled", client.Transport)
	}
	if err := client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect error = %v, want http.ErrUseLastResponse", err)
	}
}

func TestSWGHTTPEgressProxyClientPreservesCustomRoundTripper(t *testing.T) {
	roundTripper := swgHTTPEgressTestRoundTripper{}
	client := swgHTTPEgressProxyClient(&http.Client{Transport: roundTripper}, true)
	if client.Transport != roundTripper {
		t.Fatalf("transport = %T, want custom round tripper preserved", client.Transport)
	}
}

func TestSWGHTTPEgressForwardHeadersPreservesWebSocketUpgradeOnlyForUpgradeRequests(t *testing.T) {
	normal := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
	normal.Header.Set("Connection", "keep-alive")
	normal.Header.Set("Upgrade", "websocket")
	normal.Header.Set("Sec-WebSocket-Key", "opaque-key")
	normal.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://example.test/")
	normalForwarded := swgEgressForwardHeadersForRequest(normal)
	if normalForwarded.Get("Connection") != "" || normalForwarded.Get("Upgrade") != "" {
		t.Fatalf("normal forwarded hop-by-hop headers = Connection:%q Upgrade:%q, want stripped", normalForwarded.Get("Connection"), normalForwarded.Get("Upgrade"))
	}
	if normalForwarded.Get("Sec-WebSocket-Key") != "opaque-key" {
		t.Fatalf("normal forwarded Sec-WebSocket-Key = %q, want preserved non-control header", normalForwarded.Get("Sec-WebSocket-Key"))
	}
	if normalForwarded.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader) != "" {
		t.Fatalf("normal forwarded SWG target control header = %q, want stripped", normalForwarded.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader))
	}

	upgrade := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
	upgrade.Header.Set("Connection", "keep-alive, Upgrade")
	upgrade.Header.Set("Upgrade", "websocket")
	upgrade.Header.Set("Sec-WebSocket-Key", "opaque-key")
	upgrade.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://example.test/")
	upgradeForwarded := swgEgressForwardHeadersForRequest(upgrade)
	if upgradeForwarded.Get("Connection") != "Upgrade" || upgradeForwarded.Get("Upgrade") != "websocket" {
		t.Fatalf("websocket forwarded upgrade headers = Connection:%q Upgrade:%q, want websocket upgrade", upgradeForwarded.Get("Connection"), upgradeForwarded.Get("Upgrade"))
	}
	if upgradeForwarded.Get("Sec-WebSocket-Key") != "opaque-key" {
		t.Fatalf("websocket forwarded Sec-WebSocket-Key = %q, want preserved", upgradeForwarded.Get("Sec-WebSocket-Key"))
	}
	if upgradeForwarded.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader) != "" {
		t.Fatalf("websocket forwarded SWG target control header = %q, want stripped", upgradeForwarded.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader))
	}
}

type swgHTTPEgressDiagnosticRecorder struct {
	*httptest.ResponseRecorder
	category string
}

func (recorder *swgHTTPEgressDiagnosticRecorder) SetSWGHTTPEgressUpstreamErrorCategory(category string) {
	recorder.category = category
}

var _ http.ResponseWriter = (*swgHTTPEgressDiagnosticRecorder)(nil)

type swgHTTPEgressTestRoundTripper struct{}

func (swgHTTPEgressTestRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not used")
}
