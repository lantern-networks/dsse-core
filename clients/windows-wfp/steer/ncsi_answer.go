package main

import (
	"bytes"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// NCSI local responder — under steer-all, Windows' Network Connectivity Status Indicator (NlaSvc) probes get
// funneled through the active link's Edge tunnel, so they are slow/unreliable and Windows mislabels interfaces
// "No Internet" even though traffic flows — which confuses users/apps (Store/Teams/OneDrive go "offline"). We
// answer the two NCSI active probes LOCALLY and instantly so each interface is correctly detected as
// internet-connected, regardless of the tunnel:
//   - DNS probe: dns.msftncsi.com -> 131.107.255.255 (A) / fd3e:4f5a:5b81::1 (AAAA)  [answered in the DNS proxy]
//   - Web probe: GET http://www.msftconnecttest.com/connecttest.txt -> "Microsoft Connect Test" (HTTP 200)
//     [answered in the terminator before the flow is steered to the Edge]
// These are Microsoft's published, fixed probe values; answering them locally leaks nothing and changes no
// policy — it only makes the OS connectivity label truthful.

const (
	ncsiDNSName    = "dns.msftncsi.com"
	ncsiDNSReplyV4 = "131.107.255.255"
	ncsiDNSReplyV6 = "fd3e:4f5a:5b81::1"

	ncsiWebBody = "Microsoft Connect Test"
	ncsiWebResp = "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 22\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		ncsiWebBody
)

// ncsiDNSReply returns a canned DNS response for the NCSI DNS probe (dns.msftncsi.com, A or AAAA), or
// (nil,false) for any other query so the caller forwards it normally. Built with x/net/dnsmessage.
func ncsiDNSReply(query []byte) ([]byte, bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}
	if !strings.EqualFold(strings.TrimSuffix(q.Name.String(), "."), ncsiDNSName) {
		return nil, false
	}
	if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA {
		return nil, false // other qtypes (e.g. HTTPS/65) — let the real resolver handle them
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, false
	}
	if err := b.Question(q); err != nil {
		return nil, false
	}
	if err := b.StartAnswers(); err != nil {
		return nil, false
	}
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 30}
	if q.Type == dnsmessage.TypeA {
		var a4 [4]byte
		copy(a4[:], net.ParseIP(ncsiDNSReplyV4).To4())
		if err := b.AResource(rh, dnsmessage.AResource{A: a4}); err != nil {
			return nil, false
		}
	} else {
		var a16 [16]byte
		copy(a16[:], net.ParseIP(ncsiDNSReplyV6).To16())
		if err := b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a16}); err != nil {
			return nil, false
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil, false
	}
	return out, true
}

// ncsiWebHosts are the hosts Windows NCSI hits for its active HTTP connectivity probe.
var ncsiWebHosts = []string{"msftconnecttest.com", "msftncsi.com"}

// isNCSIWebProbe reports whether the buffered HTTP request bytes are an NCSI connectivity probe (a GET to one
// of the msftconnecttest/msftncsi hosts). Matches on the request line + Host header; tolerant of exact path.
func isNCSIWebProbe(reqBytes []byte) bool {
	// First line must be a GET.
	nl := bytes.IndexByte(reqBytes, '\n')
	if nl < 0 || !bytes.HasPrefix(reqBytes, []byte("GET ")) {
		return false
	}
	lower := bytes.ToLower(reqBytes)
	hostIdx := bytes.Index(lower, []byte("\nhost:"))
	if hostIdx < 0 {
		return false
	}
	host := lower[hostIdx+len("\nhost:"):]
	if end := bytes.IndexByte(host, '\n'); end >= 0 {
		host = host[:end]
	}
	for _, h := range ncsiWebHosts {
		if bytes.Contains(host, []byte(h)) {
			return true
		}
	}
	return false
}

// answerNCSIWebProbe peeks a port-80 flow's first request and, if it is an NCSI web probe, replies locally with
// "Microsoft Connect Test" (HTTP 200) and returns handled=true. Otherwise it returns the bytes it consumed so
// the caller can forward the flow to the Edge unchanged (the request was already read off the wire). It bounds
// the peek with a deadline so a non-HTTP :80 flow can't hang the steerer. Only call this for port 80.
func answerNCSIWebProbe(conn net.Conn) (handled bool, consumed []byte) {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	var buf []byte
	tmp := make([]byte, 1024)
	for len(buf) < 4096 {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if bytes.Contains(buf, []byte("\r\n\r\n")) {
			break // end of HTTP headers
		}
		if err != nil {
			break
		}
	}
	if isNCSIWebProbe(buf) {
		_, _ = conn.Write([]byte(ncsiWebResp))
		return true, nil
	}
	return false, buf
}

// prefixConn replays already-read bytes before the underlying connection — used to forward a non-NCSI :80 flow
// to the Edge after we peeked its request to check for an NCSI probe.
type prefixConn struct {
	net.Conn
	prefix []byte
}

// CloseWrite forwards the half-close to the wrapped conn. Embedding net.Conn does NOT promote CloseWrite —
// it is not part of the interface — so without this the wrapper hides a real TCP half-close from pipe().
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
