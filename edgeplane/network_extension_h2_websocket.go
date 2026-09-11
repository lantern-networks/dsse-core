package edgeplane

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// HTTP/2 WebSocket (RFC 8441 Extended CONNECT) support for the decrypt-all interception.
//
// Chrome opens a WebSocket to an intercepted origin over an h2 connection using Extended CONNECT
// (:method=CONNECT, :protocol=websocket) instead of an HTTP/1.1 Upgrade — so the Edge must advertise
// SETTINGS_ENABLE_CONNECT_PROTOCOL (enabled process-wide via GODEBUG=http2xconnect=1) AND handle it. HTTP/2
// forbids the Upgrade header, so we translate the Extended CONNECT into an HTTP/1.1 WebSocket upgrade to the
// origin (browseregress dials it over http/1.1) and tunnel the two byte streams bidirectionally over the h2
// stream. Without this, the browser's WebSocket handshake fails (close 1006) and WS apps (Copilot chat, Azure
// Web PubSub, …) break under interception.

// isNetworkExtensionLabTLSH2WebSocketConnect reports whether r is an h2 Extended-CONNECT WebSocket handshake.
func isNetworkExtensionLabTLSH2WebSocketConnect(r *http.Request) bool {
	return r != nil && r.Method == http.MethodConnect &&
		strings.EqualFold(strings.TrimSpace(r.Header.Get(":protocol")), "websocket")
}

// prepareNetworkExtensionLabTLSH2WebSocketForwardRequest rewrites the forward request (already built for the SWG
// egress handler) from an h2 Extended CONNECT into an HTTP/1.1 WebSocket upgrade GET, so the existing WS egress
// path (which re-originates over http/1.1) accepts it. The client<->edge byte stream stays on the h2 request/
// response; the forward request carries NO body (the WS payload is tunneled after the handshake).
func prepareNetworkExtensionLabTLSH2WebSocketForwardRequest(forwardReq *http.Request) error {
	forwardReq.Method = http.MethodGet
	forwardReq.Body = nil
	forwardReq.ContentLength = 0
	// Drop HTTP/2 pseudo-headers (":protocol", …) — invalid over http/1.1.
	var pseudo []string
	for name := range forwardReq.Header {
		if strings.HasPrefix(name, ":") {
			pseudo = append(pseudo, name)
		}
	}
	for _, name := range pseudo {
		forwardReq.Header.Del(name)
	}
	forwardReq.Header.Set("Connection", "Upgrade")
	forwardReq.Header.Set("Upgrade", "websocket")
	if strings.TrimSpace(forwardReq.Header.Get("Sec-WebSocket-Version")) == "" {
		forwardReq.Header.Set("Sec-WebSocket-Version", "13")
	}
	// h2 clients do NOT send Sec-WebSocket-Key (the h2 stream provides framing integrity); the h1 origin
	// requires one, so mint a fresh key for the upstream handshake.
	if strings.TrimSpace(forwardReq.Header.Get("Sec-WebSocket-Key")) == "" {
		key := make([]byte, 16)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		forwardReq.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(key))
	}
	return nil
}

// networkExtensionLabTLSHTTP2WebSocketWriter tunnels an h2 Extended-CONNECT WebSocket. It satisfies
// swgHTTPEgressWebSocketTunnelWriter, so the SWG egress handler hands it the upstream 101 response; it replies
// 200 to the client (RFC 8441) and pumps bytes between the h2 stream and the origin connection.
type networkExtensionLabTLSHTTP2WebSocketWriter struct {
	*NetworkExtensionLabTLSHTTP2StatusWriter
	clientBody io.ReadCloser   // the client->edge byte stream (the h2 request body)
	clientCtx  context.Context // the client request context — cancelled on disconnect (tunnel leak guard)
}

func (w *networkExtensionLabTLSHTTP2WebSocketWriter) TunnelSWGHTTPEgressWebSocket(resp *http.Response) error {
	if resp == nil {
		w.WriteHeader(http.StatusBadGateway)
		return fmt.Errorf("missing websocket upstream response")
	}
	upstream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		w.WriteHeader(http.StatusBadGateway)
		return fmt.Errorf("websocket upstream response body is not bidirectional")
	}
	// Carry the negotiated subprotocol / extensions back to the client. RFC 8441: a successful Extended CONNECT
	// is answered with 2xx (200) and the h2 stream becomes the tunnel — no Sec-WebSocket-Accept (unlike h1).
	for _, h := range []string{"Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	flusher, _ := w.ResponseWriter.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}
	// Ungated (once per WS connection): this is the path Chrome and the ChatGPT desktop app actually take to an
	// intercepted origin. While it was hot-path-gated the Edge looked silent for h2 WebSockets, and that silence
	// was misread as "this traffic never reaches the Edge's WS code" — see #28.
	wsHost := NetworkExtensionLabTLSLogHost(resp)
	wsID := NetworkExtensionLabTLSWebSocketSeq.Add(1)
	log.Printf("network_extension_lab_tls progress=websocket_h2_tunnel_started ws=%d host=%s", wsID, wsHost)
	dw := networkExtensionLabTLSH2FlushWriter{w: w.ResponseWriter, flusher: flusher}
	if err := CopyNetworkExtensionLabTLSWebSocketTunnel(w.clientCtx, wsHost, wsID, w.clientBody, dw, upstream); err != nil {
		return err
	}
	NetworkExtensionHotPathLog("network_extension_lab_tls progress=websocket_h2_tunnel_completed")
	return nil
}

// networkExtensionLabTLSH2FlushWriter flushes the h2 response stream after each chunk so origin->client
// WebSocket frames reach the browser as they arrive instead of buffering.
type networkExtensionLabTLSH2FlushWriter struct {
	w       io.Writer
	flusher http.Flusher
}

func (fw networkExtensionLabTLSH2FlushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if fw.flusher != nil {
		fw.flusher.Flush()
	}
	return n, err
}
