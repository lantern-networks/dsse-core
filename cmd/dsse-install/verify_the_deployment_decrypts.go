package main

// verify_the_deployment_decrypts.go — one flow, carried the way a device carries it, and the certificate that
// came back.
//
// ★★★ HOLDING AN INTERCEPTION AUTHORITY IS NOT INSPECTING (2026-08-26, measured on the release lab). The
// checks beside this one established that every Edge reports the same interception authority and that it
// chains to this deployment's anchor — and both passed on a deployment whose Edges had signed NOTHING since
// they started. `signing_counts_since_start: {}`. The tier was minted, carried to both regions, loaded by
// every node, and no byte had ever been decrypted under it.
//
// That is the same shape as every other gap this installer's verification exists to close: a step nobody can
// see reads exactly like a step that is finished. A deployment sold on inspecting traffic has to be able to
// show one intercepted flow, and until this ran, nothing in the product could.
//
// ★ IT IS THE DEVICE'S OWN PATH. The transport is the one an agent opens — mTLS with the identity this walk
// just enrolled, CONNECT /steer-mux — and the flow is an ordinary OPEN followed by a real TLS handshake. What
// comes back is whatever the Edge decided to present. Nothing here asks the Edge what it did; the certificate
// is the answer.
//
// ★ AND A DESTINATION IT CANNOT REACH IS NOT AN ANSWER. If the flow never completes, this says so and fails,
// rather than reporting "not decrypted" for a deployment whose egress is simply blocked — those are different
// findings and an operator acts on them differently.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// verifyDecryptDestination is where the one measured flow goes. A boring, stable, reserved-for-documentation
// name on purpose: this walk must not become traffic somebody has to explain, and the question it asks is
// about THIS deployment, not about the destination.
//
// ★ IT MUST BE REACHABLE FROM THE EDGE'S EGRESS, and when it is not, the check says the flow did not complete
// rather than reporting a deployment that has stopped inspecting.
const verifyDecryptDestination = "example.com:443"

// The steer mux wire frame, as edgeplane/steer_mux.go defines it:
// [flowID uint32 BE][type uint8][length uint32 BE][payload...]
const (
	muxFrameOpen  uint8 = 0
	muxFrameData  uint8 = 1
	muxFrameClose uint8 = 2
)

// muxFlowConn is one multiplexed flow as a net.Conn, so crypto/tls can be run straight through it exactly as
// the agent runs a browser's bytes through it.
type muxFlowConn struct {
	flowID uint32
	rw     net.Conn
	br     *bufio.Reader
	// pending holds bytes of this flow already read from the wire but not yet consumed by the TLS stack.
	pending  []byte
	deadline time.Time
	closed   bool
}

func (c *muxFlowConn) writeFrame(kind uint8, payload []byte) error {
	header := make([]byte, 9)
	binary.BigEndian.PutUint32(header[0:4], c.flowID)
	header[4] = kind
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))
	if _, err := c.rw.Write(append(header, payload...)); err != nil {
		return err
	}
	return nil
}

func (c *muxFlowConn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.closed {
			return 0, io.EOF
		}
		header := make([]byte, 9)
		if _, err := io.ReadFull(c.br, header); err != nil {
			return 0, err
		}
		kind := header[4]
		length := binary.BigEndian.Uint32(header[5:9])
		// A defensive bound matching the Edge's own: a length this side cannot believe is a desynchronised
		// stream, and reading it would hang rather than fail.
		if length > (1 << 20) {
			return 0, fmt.Errorf("the Edge sent a frame of %d bytes, which is larger than this protocol allows", length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return 0, err
		}
		switch kind {
		case muxFrameData:
			c.pending = payload
		case muxFrameClose:
			c.closed = true
			return 0, io.EOF
		default:
			// STEPUP and WARN are answers about this flow rather than bytes of it. Neither is an error here:
			// STEPUP means the flow was held for authentication, which is a decision, not a failure to
			// inspect — reported as such by the caller through the handshake error it produces.
			continue
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *muxFlowConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(muxFrameData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *muxFlowConn) Close() error                       { return c.writeFrame(muxFrameClose, nil) }
func (c *muxFlowConn) LocalAddr() net.Addr                { return c.rw.LocalAddr() }
func (c *muxFlowConn) RemoteAddr() net.Addr               { return c.rw.RemoteAddr() }
func (c *muxFlowConn) SetDeadline(t time.Time) error      { c.deadline = t; return c.rw.SetDeadline(t) }
func (c *muxFlowConn) SetReadDeadline(t time.Time) error  { return c.rw.SetReadDeadline(t) }
func (c *muxFlowConn) SetWriteDeadline(t time.Time) error { return c.rw.SetWriteDeadline(t) }

// verifyTheDeploymentDecryptsAFlow carries one flow to destination and reports what signed the certificate
// that came back.
// verifyTheDeploymentDecryptsAFlow returns its findings and, when it got one, the fingerprint of the
// certificate a DEVICE must hold in its trust store for the chain it is shown to close.
//
// ★★★ THAT IS NOT THE CERTIFICATE THAT SIGNS (2026-08-26, letter 112, measured on real hardware). This
// deployment's interception CA is signed by the deployment root: it is an INTERMEDIATE. A device that did the
// obvious thing — install the fingerprint the deployment announced into its Root store — still failed with
// SEC_E_UNTRUSTED_ROOT, because the chain does not close on it. What had to go into Root was the deployment
// root; the announced certificate had to go into the intermediate store instead.
//
// So the anchor is derived from the chain the Edge actually presents, and it is what the announcement is
// judged against. Reading it off the configuration would agree with itself.
func verifyTheDeploymentDecryptsAFlow(dir, door, destination string, certPEM, keyPEM []byte) ([]verifyResult, string) {
	const name = "the deployment decrypts a flow it carries"
	fail := func(format string, args ...any) ([]verifyResult, string) {
		return []verifyResult{{name: name, ok: false, note: fmt.Sprintf(format, args...)}}, ""
	}

	interceptionCA, err := interceptionAuthorityPool(dir)
	if err != nil {
		return fail("%v", err)
	}
	leaf, chain, err := oneFlowThrough(dir, door, destination, certPEM, keyPEM)
	if err != nil {
		// ★ UNREACHABLE IS NOT "NOT DECRYPTED". Said as its own outcome so nobody reads an egress problem as
		// a deployment that has stopped inspecting.
		return fail("the flow to %s did not complete, so what this deployment does to it was NOT measured: %v",
			destination, err)
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:     interceptionCA,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		// The Edge mints this leaf at the moment of the flow; checking it against its own notBefore keeps a
		// host clock a few seconds out from reading as "not inspecting".
		CurrentTime: leaf.NotBefore.Add(time.Second),
	}); verr != nil {
		// ★★★ THE MOST IMPORTANT LINE IN THIS FILE. A leaf that verifies against the PUBLIC web is the
		// destination's own certificate arriving untouched: the flow was carried and forwarded, and nothing
		// was inspected. Named that way rather than as a verification error, because "certificate does not
		// chain" is not what an operator needs to be told here.
		return fail("the certificate this deployment presented for %s was issued by %q and does NOT chain to "+
			"this deployment's interception authority — the flow was carried and forwarded without being "+
			"inspected (%v)", destination, leaf.Issuer.CommonName, verr)
	}
	out := []verifyResult{{name: name, ok: true, note: fmt.Sprintf(
		"%s came back signed by %q, valid from %s — one flow was carried, terminated and re-signed by this deployment",
		destination, leaf.Issuer.CommonName, leaf.NotBefore.UTC().Format(time.RFC3339))}}

	anchor, anchorName, presented, complete := whatADeviceMustHold(chain)
	switch {
	case anchor == "":
		out = append(out, verifyResult{name: "the chain a device is shown can be closed", ok: false,
			note: "the presented chain names no issuer this walk can identify, so what a device would have to " +
				"hold to accept it could not be determined"})
	case complete:
		out = append(out, verifyResult{name: "the chain a device is shown can be closed", ok: true,
			note: fmt.Sprintf("%d certificate(s) presented, ending in the self-signed %q (%s) — a device holding "+
				"that one accepts this chain", presented, anchorName, short(anchor))})
	default:
		// ★ NOT A FAILURE, AND THE DISTINCTION MATTERS. Presenting leaf-plus-intermediate is ordinary and
		// correct; what it means is that the device must hold the ISSUER of the topmost certificate, which is
		// not the certificate the deployment currently announces.
		out = append(out, verifyResult{name: "the chain a device is shown can be closed", ok: true,
			note: fmt.Sprintf("%d certificate(s) presented; the chain closes only on %q (%s), which is NOT "+
				"presented — that is the certificate a device must hold in its trust store, and the ones "+
				"presented belong in its intermediate store", presented, anchorName, short(anchor))})
	}
	return out, anchor
}

// whatADeviceMustHold reads the presented chain and answers the question a device asks: which certificate has
// to be in my trust store for this to verify. It is the topmost presented certificate when that one is
// self-signed, and otherwise that certificate's ISSUER, which the server did not send.
func whatADeviceMustHold(chain []*x509.Certificate) (fingerprint, name string, presented int, selfSigned bool) {
	if len(chain) == 0 {
		return "", "", 0, false
	}
	top := chain[len(chain)-1]
	if err := top.CheckSignatureFrom(top); err == nil {
		sum := sha256.Sum256(top.Raw)
		return hex.EncodeToString(sum[:]), top.Subject.CommonName, len(chain), true
	}
	// The issuer is named but not sent. Its fingerprint is not derivable from a name, so it is resolved from
	// the deployment's own anchor file by the caller when it needs a fingerprint to compare — here the name is
	// what can be said honestly.
	return interceptionAnchorPlaceholder, top.Issuer.CommonName, len(chain), false
}

// interceptionAnchorPlaceholder marks "a device must hold the issuer of what was presented, and this walk
// knows its NAME but not its fingerprint from the handshake alone".
const interceptionAnchorPlaceholder = "issuer-not-presented"

// interceptionAuthorityPool is the authority this deployment inspects under, from its own material.
func interceptionAuthorityPool(dir string) (*x509.CertPool, error) {
	path := filepath.Join(dir, interceptionRootCertFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("this deployment holds no interception authority at %s, so it can inspect "+
			"nothing: %v", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s holds no certificate", path)
	}
	return pool, nil
}

// oneFlowThrough opens the device transport, starts one flow, performs a real TLS handshake through it, and
// returns the leaf the deployment presented.
func oneFlowThrough(dir, door, destination string, certPEM, keyPEM []byte) (*x509.Certificate, []*x509.Certificate, error) {
	anchor, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("read the deployment anchor: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(anchor) {
		return nil, nil, errors.New("the deployment anchor contains no certificate")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("the issued certificate and its key do not pair: %w", err)
	}
	u, err := url.Parse(door)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %q: %w", door, err)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	transport, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", host, &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{pair},
		ServerName:   u.Hostname(),
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("open the device transport at %s: %w", host, err)
	}
	defer transport.Close()
	_ = transport.SetDeadline(time.Now().Add(25 * time.Second))

	if _, err := fmt.Fprintf(transport, "CONNECT /steer-mux HTTP/1.1\r\nHost: %s\r\n\r\n", u.Hostname()); err != nil {
		return nil, nil, fmt.Errorf("write CONNECT: %w", err)
	}
	br := bufio.NewReader(transport)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, nil, fmt.Errorf("read the answer to CONNECT: %w", err)
	}
	if !strings.Contains(line, " 200") {
		return nil, nil, fmt.Errorf("the Edge answered %q to CONNECT /steer-mux", strings.TrimSpace(line))
	}
	// Drain the rest of the response head.
	for {
		l, rerr := br.ReadString('\n')
		if rerr != nil {
			return nil, nil, fmt.Errorf("read the answer to CONNECT: %w", rerr)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}

	flow := &muxFlowConn{flowID: 1, rw: transport, br: br}
	if err := flow.writeFrame(muxFrameOpen, []byte(destination)); err != nil {
		return nil, nil, fmt.Errorf("open a flow to %s: %w", destination, err)
	}

	serverName, _, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, nil, fmt.Errorf("%q is not a host:port", destination)
	}
	var presented *x509.Certificate
	var presentedChain []*x509.Certificate
	// InsecureSkipVerify with a capture, deliberately: this is not a client deciding whether to trust the
	// answer, it is a walk asking WHO signed it. Verification against the interception authority happens at
	// the call site, where the failure can be described in the terms that matter.
	inner := tls.Client(flow, &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("the destination presented no certificate")
			}
			c, perr := x509.ParseCertificate(rawCerts[0])
			if perr != nil {
				return perr
			}
			presented = c
			for _, der := range rawCerts {
				if parsed, perr := x509.ParseCertificate(der); perr == nil {
					presentedChain = append(presentedChain, parsed)
				}
			}
			return nil
		},
	})
	defer inner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := inner.HandshakeContext(ctx); err != nil {
		return nil, nil, fmt.Errorf("the TLS handshake through the flow did not complete: %w", err)
	}
	if presented == nil {
		return nil, nil, errors.New("the handshake completed and no certificate was captured")
	}
	return presented, presentedChain, nil
}
