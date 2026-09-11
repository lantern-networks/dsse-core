package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Connector↔Edge encrypted transport. The connector dials the Edge over TLS, pinning the Edge
// transport trust anchors (fail-closed: only those anchors can verify the server chain) and presenting
// an mTLS Connector Identity certificate. This mirrors the (T) transport on the endpoint side; the same
// encrypted, mutually authenticated channel carries registration, heartbeat, the outbound tunnel, and
// identity sync.
//
// The anchor file is a SET: every certificate in the PEM is trusted, exactly like the endpoints'
// multi-CA pin (macOS pinnedCACertificates / Windows pinnedCAs). Rotation therefore never swaps —
// it overlays the new anchor next to the old one, and the old one is withdrawn only after the Edge
// presents a chain the new anchor verifies. A single-cert file (today's self-signed edge.crt) is
// just the degenerate one-anchor case.
//
// mTLS is mandatory in production: when transport TLS is configured (an Edge CA is pinned) and dev mode is
// off, a Connector Identity certificate is required. dev may pin without a client cert for bring-up.

type connectorTransportConfig struct {
	// EdgeCAFile pins the Edge transport trust anchors (PEM; every certificate in the file is an
	// anchor). When empty, TLS is not configured (plaintext, dev only).
	EdgeCAFile string
	// ClientCertFile / ClientKeyFile are the Connector Identity certificate + key (PEM) for mTLS.
	ClientCertFile string
	ClientKeyFile  string
	// DevMode relaxes the mandatory-mTLS requirement for local bring-up.
	DevMode bool
	// ServerName is the name to send in the ClientHello, when the organization has a door of its own.
	//
	// ★★★ THE EDGE PICKS AN ORGANIZATION'S TRANSPORT CERTIFICATE BY SNI — it has to, the client certificate
	// arrives after the server's — so a connector that sends the dialled host is served the deployment's
	// shared certificate however its organization is set up. Empty keeps Go's default (the dialled host),
	// which is what every connector did before this field and stays right for an organization with no door.
	ServerName string
}

// enabled reports whether transport TLS is configured (an Edge CA is pinned).
func (c connectorTransportConfig) enabled() bool {
	return strings.TrimSpace(c.EdgeCAFile) != ""
}

// buildConnectorTLSConfig builds the *tls.Config the connector uses to dial the Edge. Returns nil (no TLS)
// when no Edge CA is pinned. Fail-closed: a pinned-but-unreadable CA is an error, and outside dev mode a
// Connector Identity client certificate is REQUIRED (mTLS is a system premise, not an option).
func buildConnectorTLSConfig(cfg connectorTransportConfig) (*tls.Config, error) {
	if !cfg.enabled() {
		if !cfg.DevMode {
			return nil, fmt.Errorf("connector transport TLS is mandatory outside dev mode: set --edge-transport-ca")
		}
		return nil, nil
	}

	caPEM, err := os.ReadFile(strings.TrimSpace(cfg.EdgeCAFile))
	if err != nil {
		return nil, fmt.Errorf("read edge transport anchors %q: %w", cfg.EdgeCAFile, err)
	}
	pool, err := loadAnchorPool(cfg.EdgeCAFile, caPEM)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	if n := strings.TrimSpace(cfg.ServerName); n != "" {
		// The addresses this connector dials are unchanged: only the name it asks for changes, which is what
		// selects the certificate. Every door of the deployment serves this organization's certificate for
		// this name, so one name works at every region and failing over does not stop presenting it.
		tlsConfig.ServerName = n
		log.Printf("connector\u21c4edge transport: asking for this organization's own name %q", n)
	}

	clientCert := strings.TrimSpace(cfg.ClientCertFile)
	clientKey := strings.TrimSpace(cfg.ClientKeyFile)
	switch {
	case clientCert != "" && clientKey != "":
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("load connector identity certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	case clientCert != "" || clientKey != "":
		return nil, fmt.Errorf("connector identity requires BOTH --connector-client-cert and --connector-client-key")
	case !cfg.DevMode:
		// mTLS is mandatory in production.
		return nil, fmt.Errorf("connector identity certificate is mandatory outside dev mode (mTLS): set --connector-client-cert/--connector-client-key")
	}

	return tlsConfig, nil
}

// loadAnchorPool parses every certificate in the anchor PEM into a pool, logging each anchor's
// subject, sha256 fingerprint (the same identifier /admin/transport-ca-readiness uses, so an operator
// can correlate what this connector trusts with what the fleet reports) and expiry. An unparseable
// block is skipped with a log line rather than failing the load: during a rotation a corrupt extra
// anchor must not take down a connector that still holds a good one. Zero usable anchors is an error.
func loadAnchorPool(path string, caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	n := 0
	for rest := caPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("connector↔edge transport anchor SKIPPED (unparseable certificate in %s): %v", path, err)
			continue
		}
		pool.AddCert(cert)
		fp := sha256.Sum256(cert.Raw)
		log.Printf("connector↔edge transport anchor[%d]: subject=%q sha256=%x notAfter=%s",
			n, cert.Subject.CommonName, fp, cert.NotAfter.UTC().Format(time.RFC3339))
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("edge transport anchors %q contain no usable certificate", path)
	}
	return pool, nil
}

// newConnectorEdgeHTTPClient returns an *http.Client whose transport uses the given TLS config for the
// Edge-bound HTTP calls (registration, heartbeat, identity sync). A nil tlsConfig yields the default
// client (plaintext / dev).
// ★★★ A REQUEST WITH NO DEADLINE STOPPED THE HEARTBEAT FOR EVER, IN SILENCE (2026-09-07, measured across
// twenty connectors on a three-region lab: every site read "0 online, down" while every connector was running
// with a healthy tunnel).
//
// This client had a Transport and no Timeout. http.DefaultTransport bounds the DIAL and the TLS handshake and
// nothing after them: a request that connects, sends, and never receives a response header waits until the
// process ends. The heartbeat loop calls this synchronously —
//
//	for range ticker.C {
//		if err := sendHeartbeat(...); err != nil {
//
// — so ONE hung request is not a missed heartbeat, it is the last heartbeat. The ticker never comes round
// again, nothing returns an error, so nothing is logged, and the process stays alive with its tunnel intact.
// What an operator sees is a site reported down while traffic still flows through it, and the deployment
// cannot tell that connector from one that has actually gone.
//
// Measured shape, one connector, three nodes, all frozen while it ran: last heartbeat 06:39:37 at the region
// it registered against, 06:42:37 at the one it was attached to, 06:42:47 at the one it moved to — and then
// nothing, for as long as it was watched. The moves are what produced the hang: today every Edge in the fleet
// was restarted several times, and a request in flight to a door that goes away is exactly the request that
// never answers.
//
// ★ THE TIMEOUT IS THE WHOLE REQUEST, not the handshake, because the failure is after the handshake. 30s is
// the value connectorEnrolmentClient in this package already chose for the same kind of call, and every use
// of this client is a small JSON exchange — register, heartbeat, effective routes, identity sync, the door
// probe. The tunnel does not come through here; it dials its own connection and is meant to stay open.
//
// A ticker's channel holds one tick, so a request that takes longer than the interval costs the ticks it
// spans and then the loop resumes — which is the behaviour that was wanted all along: a heartbeat that fails
// is logged, counted, and after three in a row the connector re-registers.
const connectorEdgeRequestTimeout = 30 * time.Second

func newConnectorEdgeHTTPClient(tlsConfig *tls.Config) *http.Client {
	if tlsConfig == nil {
		// Dev mode, plaintext. It gets the deadline too: the defect is the missing bound, not the TLS.
		return &http.Client{Timeout: connectorEdgeRequestTimeout}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: transport, Timeout: connectorEdgeRequestTimeout}
}
