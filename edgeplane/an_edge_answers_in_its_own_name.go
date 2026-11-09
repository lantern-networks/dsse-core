package edgeplane

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
)

// ServeLocalHTTPS answers one HTTPS request on conn from this Edge itself. It terminates TLS under the leaf this
// engine would present for the route, hands the request to handler, and closes. Nothing is dialled: there is no
// upstream connection at any point.
//
// It exists for answers the Edge gives in its own name, where forwarding is exactly what must not happen — a
// refusal page for a flow that policy has already refused. The leaf is the one the device already trusts for
// that name, because the device trusts this engine's anchor for every destination it intercepts; the caller
// decides whether the route is one this engine intercepts at all (Matches) before calling.
//
// HTTP/1.1 only and one request: an answer of this kind is a single page, and offering h2 would only add a
// second framing to get wrong. A handshake the client refuses is not recorded as certificate pinning — a refused
// flow says nothing about whether that destination pins.
func (interception *NetworkExtensionLabTLSInterception) ServeLocalHTTPS(conn net.Conn, route NetworkExtensionRuntimeCopyTCPRoute, handler http.Handler) error {
	if interception == nil || conn == nil || handler == nil {
		return errors.New("local https answer needs an interception engine, a connection and a handler")
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := interception.leafCertificate(route.TenantID, networkExtensionLabTLSLeafHost(route.Host, hello))
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}
	tlsConn := tls.Server(conn, cfg)
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	return ServeOneLocalHTTPRequest(tlsConn, handler)
}

// LocalHTTPRequestMaxHeaderBytes bounds the request line and headers ServeOneLocalHTTPRequest will read before it
// gives up on a request: 1 MiB, the Go HTTP server's default (http.DefaultMaxHeaderBytes). It is that default, not
// a promise to accept whatever any server or browser accepts: the input, request line included, stops at exactly
// this many bytes, and a request larger than that is not answered — the flow is closed.
//
// This is the protection of an HTTP message's parse, not a performance quota: without it the parser accumulated
// a request's headers without limit (a 4 MiB header was read in full through the 1 MiB flow queue, because the
// queue bounds what is unread, not what has been read — review of the fourth-walk fixes, 2026-11-08), on a path
// that is entered precisely because the flow has already been refused.
const LocalHTTPRequestMaxHeaderBytes = http.DefaultMaxHeaderBytes

// ServeOneLocalHTTPRequest reads one HTTP/1.1 request from conn, answers it with handler, and marks the exchange
// closed. Like ServeLocalHTTPS it never forwards anything: the handler's response is the whole answer. A request
// whose line and headers exceed LocalHTTPRequestMaxHeaderBytes is not answered: the read ends there and the error
// is returned, so the caller closes the flow.
func ServeOneLocalHTTPRequest(conn io.ReadWriter, handler http.Handler) error {
	if conn == nil || handler == nil {
		return errors.New("local http answer needs a connection and a handler")
	}
	// Only the head is read: the body is never consumed (the response is the whole answer and the exchange is
	// closed), so a bound on the bytes the reader may take is a bound on the request line and headers.
	req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(conn, LocalHTTPRequestMaxHeaderBytes)))
	if err != nil {
		return err
	}
	answer := &localHTTPAnswer{header: http.Header{}}
	handler.ServeHTTP(answer, req)
	status := answer.status
	if status == 0 {
		status = http.StatusOK
	}
	resp := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        answer.header,
		Body:          io.NopCloser(bytes.NewReader(answer.body.Bytes())),
		ContentLength: int64(answer.body.Len()),
		Close:         true,
		Request:       req,
	}
	return resp.Write(conn)
}

// localHTTPAnswer collects a handler's response so it can be written once, with its length, and closed.
type localHTTPAnswer struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (a *localHTTPAnswer) Header() http.Header { return a.header }

func (a *localHTTPAnswer) WriteHeader(status int) {
	if a.status == 0 {
		a.status = status
	}
}

func (a *localHTTPAnswer) Write(p []byte) (int, error) {
	if a.status == 0 {
		a.status = http.StatusOK
	}
	return a.body.Write(p)
}
