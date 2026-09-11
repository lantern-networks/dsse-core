package main

import (
	"crypto/x509"
	x509pem "encoding/pem"
	"sync"
	"sync/atomic"
)

// edge_client_ca_pool.go — the CAs this process will verify a CLIENT certificate against.
//
// ★ ASKING IS A PREREQUISITE FOR CHECKING (2026-08-12, eleventh review). The audit-ingest receiver derives the
// shipping Edge's tenant from its verified certificate and refuses a record naming another tenant. That check
// cannot exist unless the listener REQUESTS a certificate — and it did not, so VerifiedChains was always empty:
// first the check took its lenient branch on every real shipment, and then, once that branch was made to fail
// closed, it would have refused every shipment instead. Two opposite failures from the same missing line.
//
// Set from the tenant CA registry when one is configured, which is the same material (T) admission uses. Nil
// keeps today's behaviour exactly: no client certificate is requested and nothing that depends on one works,
// which is the honest state for a deployment that has not configured the registry.
// ★ THE SECOND CALLER USED TO REPLACE THE FIRST (2026-08-12, thirteenth review). Two things feed this — the
// operator anchors an Edge's shipping identity is issued by, and the tenant CA registry — and a control plane
// configured with BOTH kept only the later one. On a multi-tenant deployment that meant the operator-issued
// Edge certificate failed TLS verification and every audit shipment died at the handshake, which reads as a
// TLS misconfiguration rather than as the policy decision it is not.
//
// They are ADDED, because they answer different questions about different callers: "is this a device of a
// tenant I know" and "is this an Edge my operator issued". A pool that has to be one or the other is a pool
// that forces a deployment to choose which half of its clients may connect.
var (
	edgeClientCAsMu           sync.Mutex
	edgeClientCAs             atomic.Pointer[x509.CertPool]
	edgeClientAnchors         []*x509.Certificate
	edgeClientBaseAnchors     []*x509.Certificate
	edgeClientRegistryAnchors []*x509.Certificate
)

// addEdgeClientCAs ADDS anchors to what this listener will verify a client certificate against.
//
// ★ THE SECOND CALLER USED TO REPLACE THE FIRST (2026-08-12, thirteenth review). Two things feed this — the
// operator anchors an Edge's shipping identity is issued by, and the tenant CA registry — and a control plane
// configured with BOTH kept only the later one. On a multi-tenant deployment the operator-issued Edge
// certificate then failed TLS verification and every audit shipment died at the handshake, which reads as a
// TLS misconfiguration rather than the policy decision it is not.
//
// They are ADDED because they answer different questions about different callers: "is this a device of a
// tenant I know" and "is this an Edge my operator issued". A pool that has to be one or the other forces a
// deployment to choose which half of its clients may connect.
func addEdgeClientCAs(certs []*x509.Certificate) {
	if len(certs) == 0 {
		return
	}
	edgeClientCAsMu.Lock()
	defer edgeClientCAsMu.Unlock()
	edgeClientBaseAnchors = append(edgeClientBaseAnchors, certs...)
	rebuildEdgeClientCAPoolLocked()
}

// Registry anchors are replaceable; operator and peer anchors have independent ownership.
func setEdgeClientRegistryCAs(certs []*x509.Certificate) {
	edgeClientCAsMu.Lock()
	defer edgeClientCAsMu.Unlock()
	edgeClientRegistryAnchors = append([]*x509.Certificate(nil), certs...)
	rebuildEdgeClientCAPoolLocked()
}
func rebuildEdgeClientCAPoolLocked() {
	edgeClientAnchors = append(append([]*x509.Certificate(nil), edgeClientBaseAnchors...), edgeClientRegistryAnchors...)
	pool := x509.NewCertPool()
	for _, c := range edgeClientAnchors {
		pool.AddCert(c)
	}
	edgeClientCAs.Store(pool)
}

// addEdgeClientCAPEM registers anchors from PEM. Reports whether anything usable was found.
func addEdgeClientCAPEM(pem []byte) bool {
	certs := []*x509.Certificate{}
	rest := pem
	for {
		var block *x509pem.Block
		block, rest = x509pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return false
	}
	addEdgeClientCAs(certs)
	return true
}

func edgeClientCAPool() *x509.CertPool { return edgeClientCAs.Load() }
