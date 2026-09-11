package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// peer_edge_registry.go is the ORIGIN half of an inter-region mesh link (docs/multi_region_edge_architecture_design.md
//). This edge (region Y) holds an authenticated tunnel.Session to each sibling edge (region X) and, for a
// mesh-eligible flow whose connector lives in X, drives that session's OpenTCP exactly as it would a connector's —
// relaying the (already-decrypted-in-Y) flow to X, where mesh_ingress.go bridges it into X's local connector.
//
// It is the concrete edgeplane.PeerEdgeProvider that replaces the nil at the edgeplane.ConnectorAwareProxyClient call site once the
// fabric is configured (-mesh-peers). With no peers configured it is left nil, so mesh fails closed (self-gating).

// peerEdgeRegistry maps a region to its live peer-edge session. PeerEdgeFor satisfies edgeplane.PeerEdgeProvider.
type peerEdgeRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*tunnel.Session // region (lower-cased) -> live session; absent/nil = no live link
}

func newPeerEdgeRegistry() *peerEdgeRegistry {
	return &peerEdgeRegistry{sessions: map[string]*tunnel.Session{}}
}

// PeerEdgeFor returns the live session for a region's peer edge. Nil-receiver safe so a typed-nil never panics.
func (r *peerEdgeRegistry) PeerEdgeFor(region string) (*tunnel.Session, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[strings.ToLower(strings.TrimSpace(region))]
	return s, ok && s != nil
}

func (r *peerEdgeRegistry) set(region string, s *tunnel.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[strings.ToLower(strings.TrimSpace(region))] = s
}

func (r *peerEdgeRegistry) clear(region string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, strings.ToLower(strings.TrimSpace(region)))
}

// parseMeshIngressAllowedPeers parses the -mesh-ingress-allowed-peers value (comma-separated peer-edge mTLS
// identities) into a set. Empty -> nil (no allowlist; the lab fallback applies on the ingress).
func parseMeshIngressAllowedPeers(raw string) map[string]bool {
	set := map[string]bool{}
	for _, id := range strings.Split(raw, ",") {
		if id = strings.TrimSpace(id); id != "" {
			set[id] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// meshIngressAuth authenticates a peer on a mesh INGRESS — the RECEIVER half of an inter-region link: the data
// mesh (`GET /mesh/ingress/tunnel`) and the cross-region revocation mesh (`POST /revocation-mesh/admission`).
// It returns (authLabel, true) when the peer is authorized. Security model (closes the gap where ANY verified
// enrolled device cert — not just an authorized sibling edge — was accepted):
//   - allowlist configured (non-empty): require a VERIFIED peer mTLS identity that is a member of the allowlist.
//     The shared-secret fallback is DISABLED (mTLS-only — the production-correct mode).
//   - allowlist empty: lab fallback — a verified mTLS identity, OR a matching non-empty shared secret
//     (constant-time). Callers MUST first self-gate (404) when BOTH the allowlist and the secret are empty,
//     so an unconfigured edge never serves the ingress.
func meshIngressAuth(r *http.Request, allowed map[string]bool, secret, secretHeader string) (string, bool) {
	peerIdentity, peerVerified := meshPeerIdentityFromRequest(r)
	peerIdentity = strings.TrimSpace(peerIdentity)
	if len(allowed) > 0 {
		if peerVerified && peerIdentity != "" && allowed[peerIdentity] {
			return "mTLS:" + peerIdentity, true
		}
		return "", false // allowlist mode: no secret fallback, no any-cert acceptance
	}
	if peerVerified && peerIdentity != "" {
		return "mTLS:" + peerIdentity, true
	}
	if provided := r.Header.Get(secretHeader); secret != "" && len(provided) == len(secret) &&
		subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) == 1 {
		return "shared-secret", true
	}
	return "", false
}

// meshPeerConfig is one configured sibling edge.
type meshPeerConfig struct {
	region string
	url    string // ws(s)://host:port/mesh/ingress/tunnel
}

// parseMeshPeers parses the -mesh-peers value: "region=URL;region=URL". Empty -> no peers (mesh disabled).
func parseMeshPeers(raw string) ([]meshPeerConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var peers []meshPeerConfig
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		region, url, ok := strings.Cut(entry, "=")
		region = strings.ToLower(strings.TrimSpace(region))
		url = strings.TrimSpace(url)
		if !ok || region == "" || url == "" {
			return nil, fmt.Errorf("mesh peer %q must be region=URL", entry)
		}
		if !strings.HasPrefix(url, "ws://") && !strings.HasPrefix(url, "wss://") {
			return nil, fmt.Errorf("mesh peer %q URL must be ws:// or wss://", entry)
		}
		if seen[region] {
			return nil, fmt.Errorf("mesh peer region %q is configured more than once", region)
		}
		seen[region] = true
		peers = append(peers, meshPeerConfig{region: region, url: url})
	}
	return peers, nil
}

// buildMeshPeerTLSConfig builds the dial-side TLS config for the inter-region mesh link: this edge's CLIENT cert
// (mTLS identity proven to the peer edge) + the peer CA it PINS for the peer's server cert. Pinning a CA forces
// verification (no skip-verify). With neither cert nor CA, falls back to insecureSkipVerify (lab only).
func buildMeshPeerTLSConfig(certFile, keyFile, caFile string, insecureSkipVerify bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecureSkipVerify} //nolint:gosec // skip-verify is lab-only, gated by the flag and overridden by a pinned CA below
	certFile, keyFile, caFile = strings.TrimSpace(certFile), strings.TrimSpace(keyFile), strings.TrimSpace(caFile)
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("mesh client identity requires BOTH -mesh-client-cert and -mesh-client-key")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load mesh client identity: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read mesh peer CA %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("mesh peer CA %q contains no usable certificate", caFile)
		}
		cfg.RootCAs = pool
		cfg.InsecureSkipVerify = false // a pinned CA means we VERIFY the peer's server cert
		// ★ AND THE SAME AUTHORITY VERIFIES THE PEER THAT DIALS US. A mesh link is mutual: pinning the peer's
		// server certificate here and accepting the peer's CLIENT certificate on a different authority would
		// be two different answers to one question. See meshPeerIdentityFromRequest.
		// ★ THIS PINS THE PEER'S SERVER CERTIFICATE, WHICH IS A DIFFERENT QUESTION FROM WHO THE PEER IS.
		// The identity a sibling Edge proves itself WITH is the operator's tree, named separately by
		// -mesh-peer-identity-ca. Conflating them was measured: pinning the deployment anchor here and reusing
		// it as the ingress authority made every DEVICE chain root at the anchor too, and the guard that
		// refuses an operator certificate as a device then refused connectors as well.
	}
	return cfg, nil
}

// startMeshPeerLinks dials every configured peer and keeps each link up (reconnect on drop). It returns the
// peerEdgeRegistry to wire as peerEdges, or nil if no peers are configured (mesh stays fail-closed). The links run
// for the process lifetime under ctx. tlsConfig is the dial-side mTLS config (nil = plain ws only).
func startMeshPeerLinks(ctx context.Context, peers []meshPeerConfig, secret string, tlsConfig *tls.Config) *peerEdgeRegistry {
	if len(peers) == 0 {
		return nil
	}
	registry := newPeerEdgeRegistry()
	manager := tunnel.NewManager()
	for _, peer := range peers {
		go runMeshPeerLink(ctx, registry, manager, peer, secret, tlsConfig)
	}
	return registry
}

func runMeshPeerLink(ctx context.Context, registry *peerEdgeRegistry, manager *tunnel.Manager, peer meshPeerConfig, secret string, tlsConfig *tls.Config) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := connectMeshPeerOnce(ctx, registry, manager, peer, secret, tlsConfig); err != nil && ctx.Err() == nil {
			log.Printf("mesh peer %s (%s) link down: %v; retrying in 2s", peer.region, peer.url, err)
		}
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func connectMeshPeerOnce(ctx context.Context, registry *peerEdgeRegistry, manager *tunnel.Manager, peer meshPeerConfig, secret string, tlsConfig *tls.Config) error {
	headers := http.Header{}
	if strings.TrimSpace(secret) != "" {
		headers.Set("x-mesh-secret", secret)
		// Anti-replay: stamp the tunnel-upgrade request so a captured upgrade cannot be replayed to open a
		// new tunnel. The upgrade has no body; the HMAC covers ts+nonce over an empty body.
		signMeshRequest(headers, secret, nil, time.Now().UTC())
	}
	var (
		conn *tunnel.Conn
		err  error
	)
	if strings.HasPrefix(peer.url, "wss://") {
		conn, err = tunnel.DialTLS(ctx, peer.url, headers, tlsConfig)
	} else {
		conn, err = tunnel.Dial(ctx, peer.url, headers)
	}
	if err != nil {
		return err
	}
	connectorID := "peer_" + peer.region
	tunnelID := randomEdgeID("mesh_", time.Now().UTC())
	session, _ := manager.Register(connectorID, tunnelID, conn)
	registry.set(peer.region, session)
	log.Printf("mesh peer %s link up via %s", peer.region, peer.url)
	defer func() {
		registry.clear(peer.region)
		manager.Unregister(connectorID, tunnelID)
	}()
	return session.Run()
}

// enforceMeshProductionSecurity fails startup when an inter-region mesh (data-plane or revocation) is configured
// without production-grade authentication outside -lab-mode:
//   - the DATA-PLANE mesh peer link must verify the peer (a pinned CA, no insecure-skip-verify, wss://) AND
//     authenticate this edge to the peer (a client cert or the shared secret);
//   - the REVOCATION mesh must use https:// peers and a non-empty shared secret (the receive side also accepts a
//     verified mTLS peer identity, but the dial side authenticates by secret, so the secret is required).
//
// In -lab-mode the looser lab posture (ws://, skip-verify, empty secret) is allowed for local runs only.
func enforceMeshProductionSecurity(labMode bool, meshPeers, meshSecret, meshClientCert, meshPeerCA string, meshSkipVerify bool, revMeshPeers, revMeshSecret, meshIngressAllowedPeers string) error {
	if labMode {
		return nil
	}
	// Receiver-side lockdown: an edge that participates in any mesh (dials peers, or holds a mesh/revocation
	// secret = is reachable as a receiver) MUST authorize inbound peer edges by mTLS identity. Without the
	// allowlist the ingress would accept ANY verified enrolled device cert (or the shared secret) as a "peer
	// edge" and bridge it past local policy — the any-cert/secret fallback is lab-only.
	dataPeers, _ := parseMeshPeers(meshPeers)
	revPeers, _ := parseRevocationMeshPeers(revMeshPeers)
	meshParticipating := len(dataPeers) > 0 || strings.TrimSpace(meshSecret) != "" ||
		len(revPeers) > 0 || strings.TrimSpace(revMeshSecret) != ""
	if meshParticipating && strings.TrimSpace(meshIngressAllowedPeers) == "" {
		return fmt.Errorf("production: a mesh-participating edge requires -mesh-ingress-allowed-peers (authorize inbound peer-edge mTLS identities; the any-enrolled-cert/secret ingress fallback is lab-only)")
	}
	if peers, _ := parseMeshPeers(meshPeers); len(peers) > 0 {
		if meshSkipVerify {
			return fmt.Errorf("production: -mesh-peer-insecure-skip-verify is forbidden outside -lab-mode")
		}
		if strings.TrimSpace(meshPeerCA) == "" {
			return fmt.Errorf("production: -mesh-peers requires -mesh-peer-ca (pin the peer edge's server cert) outside -lab-mode")
		}
		for _, p := range peers {
			if !strings.HasPrefix(p.url, "wss://") {
				return fmt.Errorf("production: mesh peer %q must use wss:// (verified TLS) outside -lab-mode", p.region)
			}
		}
		if strings.TrimSpace(meshSecret) == "" && strings.TrimSpace(meshClientCert) == "" {
			return fmt.Errorf("production: -mesh-peers requires -mesh-secret or -mesh-client-cert to authenticate this edge outside -lab-mode")
		}
	}
	if rpeers, _ := parseRevocationMeshPeers(revMeshPeers); len(rpeers) > 0 {
		if strings.TrimSpace(revMeshSecret) == "" {
			return fmt.Errorf("production: -revocation-mesh-peers requires -revocation-mesh-secret outside -lab-mode")
		}
		for _, p := range rpeers {
			if !strings.HasPrefix(p.url, "https://") {
				return fmt.Errorf("production: revocation mesh peer %q must use https:// outside -lab-mode", p.region)
			}
		}
	}
	return nil
}

// meshEligibleFromHosts builds the meshEligible predicate from a comma-separated host/domain list. A destination
// matches if it equals a listed host or is a subdomain of a listed domain (case-insensitive). Empty -> nil (no
// host opts into mesh; every cross-region app takes the hairpin default).
func meshEligibleFromHosts(raw string) func(string) bool {
	var hosts []string
	for _, h := range strings.Split(raw, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	return func(destination string) bool {
		d := strings.ToLower(strings.TrimSpace(destination))
		if d == "" {
			return false
		}
		for _, h := range hosts {
			if d == h || strings.HasSuffix(d, "."+h) {
				return true
			}
		}
		return false
	}
}

// meshPeerCAPool is the authority a SIBLING EDGE is verified against on the mesh ingress. Set from
// -mesh-peer-ca, the same material the dial side pins the peer's server certificate with: a mesh link is
// mutual, and both ends are the same deployment naming itself.
var (
	meshPeerCAPool atomic.Pointer[x509.CertPool]
	meshPeerRoots  atomic.Pointer[[]*x509.Certificate]
)

// setMeshPeerAuthority records the authority a sibling Edge is proven by, and makes this Edge ADVERTISE it.
//
// ★★★ ADVERTISING IS NOT OPTIONAL, AND THAT IS WHY THE FIRST FIX DID NOT WORK (2026-08-25, measured).
// Verifying the peer in the handler was necessary and not sufficient: a TLS client only sends a certificate
// whose issuer the server NAMED in its CertificateRequest, and this Edge named only the device CA —
//
//	Acceptable client certificate CA names
//	O=DSSE Deployment, CN=DSSE Deployment Device CA
//
// so the peer Edge sent nothing at all and the ingress saw an anonymous connection. The link failed with the
// same 401 either way, which is why this needed measuring rather than reasoning.
//
// ★ AND ADVERTISING IT MAKES ITS CHAINS VERIFY, so the device path has to say it is not a device. See
// transportDeviceIdentityFromRequest: a certificate rooted here proves the DEPLOYMENT, never an endpoint.
func setMeshPeerAuthority(pool *x509.CertPool, roots []*x509.Certificate) {
	if pool == nil || len(roots) == 0 {
		return
	}
	meshPeerCAPool.Store(pool)
	meshPeerRoots.Store(&roots)
	addEdgeClientCAs(roots)
}

// meshPeerAuthorityRoot reports whether cert is one of the deployment authorities a peer Edge is proven by.
func meshPeerAuthorityRoot(cert *x509.Certificate) bool {
	p := meshPeerRoots.Load()
	if p == nil || cert == nil {
		return false
	}
	for _, root := range *p {
		if root.Equal(cert) {
			return true
		}
	}
	return false
}

// parsePEMCertificates reads every certificate in a PEM bundle.
func parsePEMCertificates(pemBytes []byte) ([]*x509.Certificate, error) {
	out := []*x509.Certificate{}
	rest := pemBytes
	for {
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
			return nil, err
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}
	return out, nil
}

// meshPeerIdentityFromRequest establishes WHO the peer edge is, verified against the DEPLOYMENT's own
// authority.
//
// ★★★ IT USED TO ASK transportDeviceIdentityFromRequest, WHICH IS THE WRONG TREE (2026-08-25, measured
// while bringing an inter-region mesh up, then checked against the architecture).
//
// That helper is authoritative about the device-identity tier, and the architecture says what
// that tier is for:
//
//	device-identity | proves ENDPOINTS AND CONNECTORS | endpoint/connector -> Edge
//
// A sibling Edge is neither. It belongs to no customer organization at all — it is the DEPLOYMENT, and the
// certificate a deployment presents to name ITSELF belongs to the operator, not to any customer. Worse, the device-identity trees are per-organization: verifying a
// peer Edge there means a customer's own device CA can mint something the mesh ingress will accept, which is
// exactly the one-key-speaks-for-many-organizations shape that must not exist anywhere.
//
// Measured consequence before the fix: the installer wires the fleet identity (operator CA), the receiving
// listener verifies clients against the device-CA registry, no chain verifies, and every mesh link is
// answered 401 — so step 7 could not be completed on a generated deployment at all. The wiring was right and
// this was the half that was wrong.
//
// ★ THE HANDLER VERIFIES, RATHER THAN THE LISTENER. Adding the operator CA to the listener's client pool
// would make an operator-issued certificate produce a verified chain everywhere — including where
// transportDeviceIdentityFromRequest reads one — which is the coupling this is removing, not a way to fix it.
func meshPeerIdentityFromRequest(r *http.Request) (string, bool) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	pool := meshPeerCAPool.Load()
	if pool == nil {
		// No peer authority configured: nothing can be verified as a sibling Edge. Fails closed rather than
		// falling back to whatever the listener happened to verify.
		return "", false
	}
	leaf := r.TLS.PeerCertificates[0]
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediatesFrom(r.TLS.PeerCertificates),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil || len(chains) == 0 {
		return "", false
	}
	return strings.TrimSpace(leaf.Subject.CommonName), true
}

func intermediatesFrom(chain []*x509.Certificate) *x509.CertPool {
	if len(chain) < 2 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, c := range chain[1:] {
		pool.AddCert(c)
	}
	return pool
}

// meshPeerIdentityCAFlag lives here rather than in main.go: the decomposition ratchet freezes main.go's flag
// count, and a flag belongs beside the thing it configures.
var meshPeerIdentityCAFlag = flag.String("mesh-peer-identity-ca", "",
	"PEM CA a SIBLING EDGE proves itself with on the mesh INGRESS — the operator's tree (the management CA), "+
		"not the deployment anchor and never a device CA. Empty = the ingress can identify nobody and fails "+
		"closed. The device-identity tier proves endpoints and connectors and is per organization; an Edge is "+
		"the deployment naming itself")

// egressProbeV4 / egressProbeV6 are the addresses this node dials to find out which families it can actually
// egress in. They live beside the mesh flags rather than in main.go because of the decomposition ratchet, and
// they are FLAGS because the answer must be measurable inside a network that does not allow the defaults out.
var (
	egressProbeV4Flag = flag.String("egress-probe-v4", "1.1.1.1:443",
		"address this Edge dials to establish whether it has IPv4 egress. Nothing is sent; the connection "+
			"opening is the whole test. Empty disables the IPv4 half")
	egressProbeV6Flag = flag.String("egress-probe-v6", "[2606:4700:4700::1111]:443",
		"address this Edge dials to establish whether it has IPv6 egress. An agent captures ALL outbound TCP "+
			"including IPv6; an Edge with no IPv6 leg closes every one of those flows with no bytes, and "+
			"nothing measured it. Empty disables the IPv6 half")
)

// cpDataEndpointsFlag is the DATA-plane counterpart of -config-source-endpoints: where a node WRITES, per
// region. Without it the write path holds one address and a leadership move strands everything a node has to
// tell the authority — see controlChannelCurrentDataURL.
var cpDataEndpointsFlag = flag.String("config-source-data-endpoints", "",
	"per-region DATA-plane control-plane addresses, \"region-a=https://authority.a;region-b=https://authority.b\". "+
		"The read path follows leadership through -config-source-endpoints; this is the same decision's WRITE "+
		"address, so what a node records, enrols and registers reaches the authority wherever it currently is. "+
		"Empty = the single -audit-ingest-url / machine door, which is correct for one region")

// loadMeshPeerIdentityAuthority registers the authority a sibling Edge proves itself with.
//
// ★★★ IT IS THE OPERATOR'S TREE, AND IT IS NOT THE DEPLOYMENT ANCHOR (2026-08-25, both measured).
//
// The architecture gives three tiers per organization — transport, device-identity, interception — and the
// certificate a deployment presents to name ITSELF is the operator's. A sibling Edge is the
// deployment naming itself, so it is proven by the management CA.
//
// Naming the ANCHOR instead looked equivalent and is not: the management CA and the device CA are siblings
// under it, so anchoring there makes a device chain root at the anchor as well, and nothing distinguishes an
// endpoint from the deployment. Measured as a connector that held a certificate this deployment issued and
// could no longer join it.
func loadMeshPeerIdentityAuthority(caFile string) error {
	caFile = strings.TrimSpace(caFile)
	if caFile == "" {
		return nil // no peer authority: the mesh ingress cannot identify anybody, and fails closed
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read mesh peer identity CA %q: %w", caFile, err)
	}
	roots, err := parsePEMCertificates(caPEM)
	if err != nil {
		return fmt.Errorf("mesh peer identity CA %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	for _, c := range roots {
		pool.AddCert(c)
	}
	setMeshPeerAuthority(pool, roots)
	return nil
}
