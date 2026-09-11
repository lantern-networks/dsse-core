package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

const (
	opcodeText                    = 0x1
	opcodeClose                   = 0x8
	opcodePing                    = 0x9
	opcodePong                    = 0xA
	maxWebSocketFramePayloadBytes = 16 << 20
)

type Conn struct {
	conn       net.Conn
	reader     *bufio.Reader
	maskWrites bool
	writeMu    sync.Mutex
	// ResponseHeader is what the accepting side said about itself in the 101, on a dialled connection. Nil for
	// an accepted or in-process one. It is how a client behind an L4 front door learns WHICH node it reached.
	ResponseHeader http.Header
}

var _ FrameTransport = (*Conn)(nil)

// NewInProcessConn wraps an already-connected net.Conn for local tunnel harnesses.
func NewInProcessConn(rawConn net.Conn, maskWrites bool) *Conn {
	return &Conn{conn: rawConn, reader: bufio.NewReader(rawConn), maskWrites: maskWrites}
}

// ConnectorHoldsHeader is how a dialling connector says, on the upgrade REQUEST, which Edge nodes it already
// holds a tunnel on.
//
// ★★★ THE DECISION HAS TO HAPPEN BEFORE THE REGISTRATION (2026-08-26, measured: the connector walked its
// fleet by dialling, reading the node name off the 101, and hanging up on a node it already held — and every
// one of those probes KILLED the tunnel it was probing. A manager keeps one session per connector, so the
// probe's own upgrade displaced the incumbent before the connector had read a single byte back. The walk
// produced a permanent flap instead of coverage.) So the connector declares what it holds in the request, and
// an Edge that is already one of them refuses the upgrade without registering anything.
const ConnectorHoldsHeader = "X-Dsse-Connector-Holds"

// EdgeFleetNodesHeader is how many Edge nodes this node's region is known to have, sent on the 101 beside the
// node's own name. It is the DENOMINATOR a client needs before it can say whether it covers a fleet or merely
// sits on one member of it. Absent or "0" means not known — never "none".
const EdgeFleetNodesHeader = "X-Dsse-Edge-Fleet-Nodes"

// EdgeSiblingsRelayHeader is how a node says that the OTHER Edge nodes of its region will relay to it for a
// connector it does not hold itself.
//
// ★★★ WITHOUT IT THE CONNECTOR WARNS ABOUT A HOLE THAT IS CLOSED (2026-09-02). A region's door balances by
// source address with a consistent hash, so a connector dialling from one address lands on the same node every
// time and can never spread over its region — its own log says so every thirty seconds, and then draws the
// conclusion "a flow arriving on one of the others cannot reach anything behind this connector". That
// conclusion stopped being true when the Edges learned to relay to the sibling that holds it. A connector
// cannot know that by itself; the node that does know says so here.
const EdgeSiblingsRelayHeader = "X-Dsse-Edge-Siblings-Relay"

// UpgradeRejectedError is a handshake the server answered with a non-101 status. It carries the response
// headers, so a caller can act on what the server said about itself while refusing.
type UpgradeRejectedError struct {
	StatusCode int
	Header     http.Header
}

func (e *UpgradeRejectedError) Error() string {
	return fmt.Sprintf("websocket upgrade returned status %d", e.StatusCode)
}

// EdgeNodeHeader is how an accepting Edge names ITSELF on the tunnel handshake's 101 response. A client that
// dialled an L4 front door reached the door's address, not a node's, so this is the only moment it can learn
// which member of the fleet answered — and therefore whether it is attached to all of them or just one.
const EdgeNodeHeader = "X-Dsse-Edge-Node"

// Upgrade completes the WebSocket handshake with no extra response headers.
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	return UpgradeWithHeaders(w, r, nil)
}

// UpgradeWithHeaders is Upgrade with server headers added to the 101 response, so the accepting side can tell
// the dialling side something about ITSELF at the moment the tunnel forms. A client behind an L4 front door
// cannot otherwise know which node of a fleet it reached: the address it dialled belongs to the door.
func UpgradeWithHeaders(w http.ResponseWriter, r *http.Request, extra http.Header) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("upgrade header must be websocket")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("sec-websocket-key is required")
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("response writer does not support hijack")
	}
	rawConn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}
	accept := websocketAccept(key)
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n"
	// Sorted, so the handshake a test or a capture sees does not depend on Go's map order.
	names := make([]string, 0, len(extra))
	for name := range extra {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range extra[name] {
			// A header value carrying CR or LF would end the header block early and let the caller write the
			// rest of the response itself. Nothing upstream should produce one; drop it rather than emit it.
			if strings.ContainsAny(value, "\r\n") {
				continue
			}
			response += name + ": " + value + "\r\n"
		}
	}
	response += "\r\n"
	if _, err := rw.WriteString(response); err != nil {
		rawConn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		rawConn.Close()
		return nil, err
	}
	return &Conn{conn: rawConn, reader: rw.Reader, maskWrites: false}, nil
}

func Dial(ctx context.Context, rawURL string, headers http.Header) (*Conn, error) {
	return DialTLS(ctx, rawURL, headers, nil)
}

// DialTLS is Dial with a caller-supplied TLS config for wss. When tlsConfig is non-nil it is used (cloned)
// for the wss handshake, so the caller can pin the server CA and present an mTLS client certificate
// (Connector↔Edge encrypted transport). ServerName/MinVersion are filled in when unset. A nil
// tlsConfig preserves the prior default (ServerName from the URL, TLS 1.2 minimum).
func DialTLS(ctx context.Context, rawURL string, headers http.Header, tlsConfig *tls.Config) (*Conn, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := parsed.Host
	if host == "" {
		return nil, fmt.Errorf("websocket host is required")
	}
	// ★★★ A URL WITH NO PORT IS THE NORMAL SHAPE, AND THIS DIALED IT RAW (2026-08-25, measured on a
	// generated deployment). net.Dial needs "host:port"; url.Host carries whatever was written. Everything
	// else about the connector works from a portless URL — Go's HTTP client defaults 443 for https — so a
	// connector told "https://agents.example" REGISTERED successfully, logged "connector registered", and
	// then failed every tunnel dial for ever with
	//
	//	connector tunnel ended: dial tcp: address agents.example: missing port in address
	//
	// which is the healthy-but-unreachable shape: the control plane has the connector, the Site shows it
	// enrolled, and nothing behind it can be reached. The scheme says which port a URL without one means.
	if parsed.Port() == "" {
		switch parsed.Scheme {
		case "wss":
			host = net.JoinHostPort(host, "443")
		case "ws":
			host = net.JoinHostPort(host, "80")
		}
	}
	var rawConn net.Conn
	dialer := net.Dialer{}
	switch parsed.Scheme {
	case "ws":
		rawConn, err = dialer.DialContext(ctx, "tcp", host)
	case "wss":
		cfg := tlsConfig.Clone()
		if cfg == nil {
			cfg = &tls.Config{}
		}
		if cfg.ServerName == "" {
			cfg.ServerName = parsed.Hostname()
		}
		if cfg.MinVersion == 0 {
			cfg.MinVersion = tls.VersionTLS12
		}
		// WebSocket runs over HTTP/1.1. Pin the ALPN to http/1.1 so a TLS config shared with the
		// HTTP/2-capable register/heartbeat client never negotiates h2 — which would make the server
		// answer with HTTP/2 frames and break the WebSocket upgrade.
		cfg.NextProtos = []string{"http/1.1"}
		rawConn, err = tls.DialWithDialer(&dialer, "tcp", host, cfg)
	default:
		return nil, fmt.Errorf("unsupported websocket scheme %q", parsed.Scheme)
	}
	if err != nil {
		return nil, err
	}

	key, err := randomWebSocketKey()
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: path},
		Host:   host,
		Header: make(http.Header),
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if err := req.Write(rawConn); err != nil {
		rawConn.Close()
		return nil, err
	}
	reader := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		rawConn.Close()
		return nil, &UpgradeRejectedError{StatusCode: resp.StatusCode, Header: resp.Header.Clone()}
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != websocketAccept(key) {
		rawConn.Close()
		return nil, fmt.Errorf("websocket accept header mismatch")
	}
	return &Conn{conn: rawConn, reader: reader, maskWrites: true, ResponseHeader: resp.Header.Clone()}, nil
}

func (c *Conn) ReadJSON(value any) error {
	for {
		opcode, payload, err := c.readFrame()
		if err != nil {
			return err
		}
		switch opcode {
		case opcodeText:
			return json.Unmarshal(payload, value)
		case opcodePing:
			if err := c.writeFrame(opcodePong, payload); err != nil {
				return err
			}
		case opcodeClose:
			return io.EOF
		}
	}
}

func (c *Conn) WriteJSON(value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.writeFrame(opcodeText, payload)
}

func (c *Conn) Close() error {
	_ = c.writeFrame(opcodeClose, nil)
	return c.conn.Close()
}

func (c *Conn) readFrame() (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return 0, nil, err
	}
	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		extended := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, extended); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended))
	case 127:
		extended := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, extended); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(extended)
	}
	if length > maxWebSocketFramePayloadBytes {
		return 0, nil, fmt.Errorf("websocket frame payload length %d exceeds limit %d", length, maxWebSocketFramePayloadBytes)
	}
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.reader, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return opcode, payload, nil
}

func (c *Conn) writeFrame(opcode byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	header := []byte{0x80 | opcode}
	length := len(payload)
	if length > maxWebSocketFramePayloadBytes {
		return fmt.Errorf("websocket frame payload length %d exceeds limit %d", length, maxWebSocketFramePayloadBytes)
	}
	maskBit := byte(0)
	if c.maskWrites {
		maskBit = 0x80
	}
	switch {
	case length < 126:
		header = append(header, maskBit|byte(length))
	case length <= 65535:
		header = append(header, maskBit|126, byte(length>>8), byte(length))
	default:
		header = append(header, maskBit|127)
		var extended [8]byte
		binary.BigEndian.PutUint64(extended[:], uint64(length))
		header = append(header, extended[:]...)
	}
	if c.maskWrites {
		var maskKey [4]byte
		if _, err := rand.Read(maskKey[:]); err != nil {
			return err
		}
		header = append(header, maskKey[:]...)
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ maskKey[i%4]
		}
		payload = masked
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func randomWebSocketKey() (string, error) {
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key[:]), nil
}
