package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	certreload "github.com/lantern-networks/dsse-core/certreload"
	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/revocation"
	tenantca "github.com/lantern-networks/dsse-core/tenantca"

	"github.com/lantern-networks/dsse-core/model"
)

// transportClientCAPool is the pool device client certificates are verified against, read per handshake so
// the device-client-CA store can retire (or add) a CA with no restart.
var transportClientCAPool atomic.Pointer[x509.CertPool]
var transportClientSeedPEM atomic.Pointer[string]

// logDeviceTrustAnchors says WHICH CAs device client certificates verify against, every time the set is
// (re)built — subject and fingerprint, not a count. On 2026-08-02 the effective pool silently lost the CA
// that signs renewed device certificates and nothing named the survivors; the same lesson was already paid
// for on the device side (the mac logs its resolved anchors per handshake for exactly this reason). Contents
// are public certificates — never key material.
func logDeviceTrustAnchors(source string, serial int64, pemBytes []byte) {
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
			log.Printf("device_trust anchor source=%s serial=%d UNPARSEABLE: %v", source, serial, err)
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		log.Printf("device_trust anchor source=%s serial=%d subject=%q sha256=%s",
			source, serial, cert.Subject.String(), hex.EncodeToString(sum[:]))
	}
}

// warnUnattributedDeviceTrustAnchors names the CAs this node admits devices under that no organization
// claims.
//
// ★ THE STATE A HALF-WRITTEN WITHDRAWAL LEAVES (2026-08-16). Withdrawing a device CA used to remove only the
// attribution, so the lab ran for an afternoon admitting devices under a CA that belonged, on paper, to
// nobody — and every screen that reads the registry showed the rotation as finished. The route is fixed;
// this says so out loud when it happens anyway, because a CA can also be put into the trust set directly.
//
// Not a refusal: an anchor with no tenant is legitimate on a deployment with no tenant model at all, and the
// deployment's own transport CAs live here too. It is a fact worth having in the log rather than a rule.
func warnUnattributedDeviceTrustAnchors(anchors []*x509.Certificate, claimed func(sha256Hex string) bool) {
	if claimed == nil {
		return
	}
	for _, cert := range anchors {
		if cert == nil {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		fingerprint := hex.EncodeToString(sum[:])
		if claimed(fingerprint) {
			continue
		}
		log.Printf("device_trust ★ anchor_attributed_to_nobody subject=%q sha256=%s — this node admits devices "+
			"under it, and no organization claims it, so their traffic is admitted as belonging to nobody. "+
			"Register it to an organization (POST /admin/tenant-cas) or retire it "+
			"(DELETE /admin/device-client-cas/%s).", cert.Subject.String(), fingerprint, fingerprint)
	}
}

// enrolledInventoryFile is the stage-0 Enrolled Inventory: the set of device/connector identities
// allowed to establish the (T) transport. A static signed allowlist suffices for PoC; revocation = remove
// an identity. (Production: maintained by the control-plane from device enrollment + continuous
// revocation, refreshed/pushed to the Edge.)
type enrolledInventoryFile struct {
	EnrolledIdentities []string `json:"enrolled_identities"`
}

// loadEnrolledInventory reads the Enrolled Inventory JSON into a lowercased set. Returns an error if the
// path is set but unreadable/unparseable (fail-closed: callers must not silently run with an empty gate).
func loadEnrolledInventory(path string) (map[string]struct{}, error) {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("read enrolled inventory %q: %w", path, err)
	}
	// TWO shapes reach this file, and reading only one of them empties the admission gate silently.
	//
	// The path is shared: -transport-enrolled-inventory READS it and -enrolled-inventory-store WRITES it, in
	// its own schema (enrolled_inventory_state.v1, an `entries` map). On 2026-08-02 the store rewrote the file
	// and this parser found no `enrolled_identities` array, so it returned zero identities while the gate was
	// required — every device was refused at CONNECT, with the Edge reporting nothing worse than
	// "0 identities". Both shapes are accepted now; a file that parses to nothing while the gate is on is an
	// error rather than an empty allowlist, because "nobody is enrolled" and "I could not read the file" must
	// not look the same to a gate.
	//
	// That last promise is ENFORCED here, not just asserted: detect the recognized top-level key BEFORE
	// trusting a zero result. A file carrying NEITHER `enrolled_identities` NOR `entries` did not parse to
	// zero because nobody is enrolled — its shape drifted out from under this reader (the 2026-08-02 failure,
	// or the next one). Returning an empty set there arms a deny-all against a fleet that IS enrolled, so it
	// is refused LOUDLY. A recognized shape that is legitimately empty (`entries:{}` at bring-up, before the
	// first enrolment) is NOT an error — the store always writes the `entries` key (persistence.go), so an
	// empty managed inventory still parses as a recognized, empty allowlist.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("parse enrolled inventory %q: %w", path, err)
	}
	_, hasArray := top["enrolled_identities"]
	_, hasEntries := top["entries"]
	if !hasArray && !hasEntries {
		return nil, fmt.Errorf("enrolled inventory %q carries neither `enrolled_identities` nor `entries` — "+
			"unrecognized shape; refusing to read it as an empty allowlist that would deny every enrolled device", path)
	}

	set := map[string]struct{}{}
	if hasArray {
		var doc enrolledInventoryFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parse enrolled inventory %q: %w", path, err)
		}
		for _, id := range doc.EnrolledIdentities {
			if t := strings.ToLower(strings.TrimSpace(id)); t != "" {
				set[t] = struct{}{}
			}
		}
	}
	if len(set) == 0 && hasEntries {
		var stored struct {
			Entries map[string]struct {
				Identity string `json:"identity"`
				Enabled  bool   `json:"enabled"`
			} `json:"entries"`
		}
		// A malformed `entries` block is an error, not a silent empty: the file DECLARED the managed shape, so
		// failing to read it must not degrade to a deny-all allowlist.
		if err := json.Unmarshal(raw, &stored); err != nil {
			return nil, fmt.Errorf("parse enrolled inventory %q (entries shape): %w", path, err)
		}
		for key, e := range stored.Entries {
			if !e.Enabled {
				continue
			}
			id := strings.TrimSpace(e.Identity)
			if id == "" {
				id = key
			}
			if t := strings.ToLower(id); t != "" {
				set[t] = struct{}{}
			}
		}
	}
	return set, nil
}

// Endpoint↔Edge encrypted transport — secure transport abstraction (W1, M-series).
//
// This is the (T) TRANSPORT TUNNEL layer: it carries all steered flows (CONNECT /steer, runtime-copy,
// DNS-over-tunnel, admin) over TLS so SNI/DNS/metadata/non-TLS are hidden from the endpoint environment
// and the network path. It is DISTINCT from the (I) interception layer (Edge↔origin decrypt-all), which
// keeps its own lab CA — the two TLS layers are intentionally separate.
//
// W1 scope (this file): ADDITIVE, default OFF. When -transport-tls-listen is set, the Edge serves the
// SAME mux over TLS on that address (a second listener); the existing plaintext listener is unchanged,
// so the live Edge / lab steer path is not affected. The transport server cert can be supplied
// (-transport-tls-cert/-key) or, in lab mode, auto-generated (self-signed) for testing. mTLS device
// identity (client-cert verification + decision binding) and a multiplexed tunnel are W2+; the config
// already carries the client-CA / require-client-cert knobs so W2 only flips behavior.
//
// Pluggable transport methods (IPsec / WireGuard / mTLS-mux) and a separate tunnel-terminator topology
// are documented in ; this file is
// the co-located mTLS listener that W1 starts from.

type secureTransportConfig struct {
	ListenAddr        string // empty = disabled
	CertFile          string
	KeyFile           string
	ClientCAFile      string // mTLS: CA that signs device client certs
	RequireClientCert bool   // mTLS: require + verify a device client cert
	LabAutoCert       bool   // lab: auto self-signed transport cert when no CertFile is given
	LabMode           bool   // lab/dev: relaxes the production mTLS-mandatory guard

	// TrustedFrontDoors are the addresses allowed to state a connection's original source with a PROXY
	// protocol v1 header. An L4 front door in front of a region's Edges is the only way to honour one
	// agent-facing address per region, and it costs the source address unless the Edge reads it back. Empty
	// = no header is ever read, which is what a deployment with no front door wants; it is NOT "trust
	// anyone", because a peer that can choose its own source address chooses every per-address decision.
	TrustedFrontDoors []*net.IPNet

	// ConnRegistry, when set, tracks live (T) connections by admitted identity so a revocation can actively
	// close established sessions (active kill-switch). nil = untracked (new-handshake admission only).
	ConnRegistry *transportConnRegistry

	// stage-0 admission gate: even a CA-signed client cert is not enough — the verified mTLS
	// identity (CN/SAN) MUST be in the tenant's Enrolled Inventory, else the (T) connection is rejected at
	// the TLS handshake (before any data plane). This is what keeps an internet-facing Edge from being
	// "open to the world": only enrolled (and not-revoked) devices/connectors get in. Revocation = remove
	// the identity from the inventory. Empty inventory + RequireEnrolledIdentity = deny all (fail-closed).
	RequireEnrolledIdentity bool
	EnrolledIdentities      map[string]struct{} // set of enrolled identities (lowercased)

	// management ledger: when set, the admission membership test consults this admin-managed ledger
	// (enrolled AND enabled) live at each handshake instead of the static EnrolledIdentities snapshot, so a
	// Console enroll/disable/remove takes effect with no restart. Seeded from EnrolledIdentities. nil = use
	// the static set (back-compat).
	EnrolledLedger *enrolledinventory.Ledger

	// Admission revocations: a dynamic kill-switch overlay on the static Enrolled Inventory. An identity in
	// this set is REJECTED at the (T) handshake even if still present in EnrolledIdentities, until an explicit
	// Restore (re-enrol / re-attest). Reasons: admin kill-switch, mesh/federation. nil = overlay unchanged.
	AdmissionRevocations *revocation.AdmissionRevocations

	// /tenant identification: when set, the (T) listener trusts the per-tenant CAs in this
	// registry (ClientCAs = the registry pool) and the tenant a connection belongs to is resolved from
	// which registered Tenant CA the client cert chains to. Mutually compatible with a single ClientCAFile
	// (lab); the registry is the multi-tenant trust source.
	TenantCARegistry *tenantca.TenantCARegistry

	// tenant isolation (single-tenant Edge): when set together with TenantCARegistry, the (T)
	// handshake is rejected unless the cert's resolved tenant equals ExpectedTenantID. This binds the Edge
	// to ONE tenant — even if the registry trusts other tenants' CAs, a cross-tenant cert is denied at
	// admission (defense-in-depth for the absolute no-mixing invariant). Empty = multi-tenant Edge (tenant
	// resolved per connection and bound downstream instead).
	ExpectedTenantID string

	// ClientCAPoolManagedExternally: the runtime-mutable device-client-CA store owns transportClientCAPool,
	// and this listener must not overwrite what the store has committed. Without this, every Edge restart
	// silently reverted device trust to the seed file: on 2026-08-02 the store held the issuing CA that
	// signs renewed device certificates, the listener replaced the pool with the seed file's CAs during
	// start-up, and every device presenting a renewed certificate was refused with unknown_ca — while the
	// store file on disk plainly contained its issuer. False = this listener seeds the pool itself
	// (store-less deployments, tests).
	ClientCAPoolManagedExternally bool
}

// secureTransportEnabled reports whether a TLS transport listener should be started.
func (c secureTransportConfig) enabled() bool {
	return strings.TrimSpace(c.ListenAddr) != ""
}

// buildSecureTransportTLSConfig assembles the (T) transport tls.Config: a server certificate (loaded or
// lab-auto-generated) and, when configured, client-cert verification for mTLS device identity (W2).
func buildSecureTransportTLSConfig(cfg secureTransportConfig) (*tls.Config, error) {
	// mTLS device identity is a system premise, not optional. Outside lab/dev, enabling the (T)
	// transport REQUIRES a device client-cert CA + client-cert verification — fail to start otherwise so a
	// production Edge can never serve the tunnel without authenticating the device.
	if !cfg.LabMode && ((strings.TrimSpace(cfg.ClientCAFile) == "" && cfg.TenantCARegistry == nil) || !cfg.RequireClientCert) {
		return nil, fmt.Errorf("production transport requires mandatory mTLS: set -transport-tls-client-ca (or -transport-tenant-ca-registry) and -transport-tls-require-client-cert (mTLS is not optional)")
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: edgeTLS12CipherSuites, // forward-secret AEAD only on the 1.2 fallback (TLS 1.3 suites are fixed)
	}
	switch {
	case strings.TrimSpace(cfg.CertFile) != "" && strings.TrimSpace(cfg.KeyFile) != "":
		// Hot-reloadable, like the management listeners: the Edge identity certificate is the one every
		// device verifies, and "replaceable only by redeploy" made it the one path an operator could not
		// control from the Console. Registered under the file's derived name, so PUT /admin/certs/{name}
		// validates, writes and swaps it with no restart and no dropped connections.
		reloadable, err := certreload.NewReloadableCert(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load transport cert/key: %w", err)
		}
		certreload.RegisterReloadable(reloadable)
		transportServedCert = reloadable
		// ★ ROADMAP D, FIRST SLICE (2026-08-19): an organization's own certificate when its name is asked for,
		// the shared one otherwise. Nothing changes until somebody sends one of those names, and no device is
		// told to send one yet — see transport_tenant_certificates.go and the per-organization certificate design.
		tlsCfg.GetCertificate = transportCertificateForClientHello(reloadable.GetCertificate)
	case cfg.LabAutoCert:
		generated, _, err := generateSelfSignedTransportCert(secureTransportCertHosts(cfg.ListenAddr))
		if err != nil {
			return nil, fmt.Errorf("auto-generate lab transport cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{generated}
	default:
		return nil, fmt.Errorf("transport TLS requires -transport-tls-cert/-key (or -lab-mode for an auto self-signed cert)")
	}

	// mTLS device identity. ClientCAs come from the per-tenant CA registry (multi-tenant trust source) and/or
	// a single ClientCAFile (lab). At least one is required when RequireClientCert.
	var clientPool *x509.CertPool
	if cfg.TenantCARegistry != nil {
		clientPool = cfg.TenantCARegistry.CertPool() // clone so we don't mutate the registry's pool
	}
	var seedPEM []byte
	if strings.TrimSpace(cfg.ClientCAFile) != "" {
		caPEM, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read transport client CA: %w", err)
		}
		if clientPool == nil {
			clientPool = x509.NewCertPool()
		}
		if !clientPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("transport client CA file contained no usable certificates")
		}
		seedPEM = caPEM
	}
	seedText := string(seedPEM)
	transportClientSeedPEM.Store(&seedText)
	if clientPool != nil {
		// The pool every handshake actually uses is read from transportClientCAPool per connection, which is
		// what lets an admin retire a CA from device trust with no restart. When the device-client-CA store
		// manages the pool, it committed its set BEFORE this listener started, and that set — not the seed
		// file's — must serve from the first handshake: this Store call used to run unconditionally, so a
		// restart threw away every CA an admin had added at runtime (2026-08-02, renewed devices refused with
		// unknown_ca). Store-less deployments still seed here. ClientCAs on the base config remains as the
		// fallback for a listener without per-connection config.
		if cfg.ClientCAPoolManagedExternally {
			if p := transportClientCAPool.Load(); p != nil {
				clientPool = p
			} else {
				transportClientCAPool.Store(clientPool)
			}
		} else {
			transportClientCAPool.Store(clientPool)
			if len(seedPEM) > 0 {
				logDeviceTrustAnchors("seed_file", 0, seedPEM)
			}
		}
		tlsCfg.ClientCAs = clientPool
		if cfg.RequireClientCert {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
		// Each handshake reads the CURRENT device-trust pool, so retiring a CA takes effect on the next
		// connection rather than the next restart. Tried twice on 2026-07-31 and reverted twice, both
		// times alongside a transport-certificate change — two variables, so it was never actually
		// implicated. Restored on its own, with the known-good certificate held fixed.
		base := tlsCfg
		tlsCfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			per := base.Clone()
			per.GetConfigForClient = nil
			if p := transportClientCAPool.Load(); p != nil {
				per.ClientCAs = p
			}
			return per, nil
		}
	} else if cfg.RequireClientCert {
		return nil, fmt.Errorf("transport require-client-cert needs -transport-tls-client-ca or -transport-tenant-ca-registry")
	}

	// Admission gate at the (T) handshake (runs AFTER normal chain verification, so the cert is CA-valid).
	// Two additive checks: tenant binding (cert's tenant must equal this single-tenant Edge's tenant)
	// and enrolled identity (cert identity must be in the Enrolled Inventory). Either failing rejects
	// the handshake before any data plane — the absolute no-cross-tenant-mixing invariant is enforced here.
	tenantBindingActive := cfg.TenantCARegistry != nil && strings.TrimSpace(cfg.ExpectedTenantID) != ""
	revocations := cfg.AdmissionRevocations
	if tenantBindingActive || cfg.RequireEnrolledIdentity || revocations != nil {
		reg := cfg.TenantCARegistry
		expectedTenant := strings.TrimSpace(cfg.ExpectedTenantID)
		enrolled := cfg.EnrolledIdentities
		ledger := cfg.EnrolledLedger
		requireEnrolled := cfg.RequireEnrolledIdentity
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				log.Printf("transport_admission_denied reason=no_client_cert")
				return fmt.Errorf("transport admission: no client certificate")
			}
			// tenant binding: cert must resolve to THIS Edge's tenant (cross-tenant denied).
			if tenantBindingActive {
				tid, ok := reg.TenantForVerifiedChains(cs.VerifiedChains)
				if !ok {
					log.Printf("transport_admission_denied reason=tenant_unresolved")
					return fmt.Errorf("transport admission: certificate does not chain to a registered tenant CA")
				}
				if tid != expectedTenant {
					log.Printf("transport_admission_denied reason=tenant_mismatch resolved_tenant=%q expected=%q", tid, expectedTenant)
					return fmt.Errorf("transport admission: cross-tenant certificate (tenant %q != %q)", tid, expectedTenant)
				}
			}
			// Admission kill-switch: deny an auto-revoked identity even if it is still present in the enrolled
			// file. Runs before the enrolled check so revocation always wins; un-revoking is re-enrolment /
			// re-attestation, not a file edit. Reasons: admin kill-switch, mesh/federation, explicit re-attestation.
			if revocations != nil {
				rid := transportIdentityFromLeaf(cs.PeerCertificates[0])
				if reason, gone := revocations.IsRevoked(rid); gone {
					log.Printf("transport_admission_denied reason=revoked identity=%q revoke_reason=%q", rid, reason)
					return fmt.Errorf("transport admission: identity %q is revoked (%s)", rid, reason)
				}
			}
			// enrolled identity. The admin-managed ledger (enrolled AND enabled) is authoritative when
			// present (Console enroll/disable hot-applies); otherwise the static inventory snapshot is used.
			if requireEnrolled {
				id := transportIdentityFromLeaf(cs.PeerCertificates[0])
				if id == "" {
					log.Printf("transport_admission_denied reason=no_identity")
					return fmt.Errorf("transport admission: client certificate has no usable identity")
				}
				admitted := false
				if ledger != nil {
					admitted = ledger.IsAdmitted(id)
				} else {
					_, admitted = enrolled[strings.ToLower(strings.TrimSpace(id))]
				}
				if !admitted {
					log.Printf("transport_admission_denied reason=not_enrolled identity=%q", id)
					return fmt.Errorf("transport admission: identity %q is not enrolled", id)
				}
			}
			return nil
		}
	}

	return tlsCfg, nil
}

// attachConnRegistryTracking layers connection tracking onto tlsCfg so a live (T) connection is registered
// under its admitted identity. Registration happens DURING the handshake: GetConfigForClient hands us the raw
// net.Conn (the trackedRawConn from the registry's listener), and the per-connection VerifyConnection runs the
// original admission first, then records identity -> conn. Tracking here rather than by wrapping the *tls.Conn
// is what lets tls.NewListener hand net/http an untouched *tls.Conn — see transportConnRegistry.wrap for the
// outage that the wrapping shape caused.
//
// Returns tlsCfg unchanged when no registry is wired.
func attachConnRegistryTracking(tlsCfg *tls.Config, reg *transportConnRegistry) *tls.Config {
	if tlsCfg == nil || reg == nil {
		return tlsCfg
	}
	base := tlsCfg
	baseVerify := base.VerifyConnection
	out := base.Clone()
	out.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// ★ the enrolment fold step 3: the expired-certificate recovery path, when the handshake asks for it by name. It
		// needs RequireAnyClientCert, which the main configuration must never have — so it is a separate
		// configuration returned for that name only, and this returns BEFORE anything below runs. Nil for
		// every other connection, which then proceeds exactly as it did.
		if rec := recoveryConfigFor(base, hello); rec != nil {
			return rec, nil
		}
		// ★ the enrolment fold: the same move for a device that holds NOTHING yet. It cannot present a certificate, so the
		// enrolment name gets NoClientCert — returned for that name only, before anything below runs, and nil
		// for every other connection. See enrolment_on_transport_port.go.
		if enr := enrolmentConfigFor(base, hello); enr != nil {
			return enr, nil
		}
		raw := hello.Conn
		per := base.Clone()
		per.GetConfigForClient = nil // this per-connection config is terminal
		if p := transportClientCAPool.Load(); p != nil {
			per.ClientCAs = p
		}
		per.VerifyConnection = func(cs tls.ConnectionState) error {
			// Admission first: a rejected handshake must never be registered.
			if baseVerify != nil {
				if err := baseVerify(cs); err != nil {
					return err
				}
			}
			if raw == nil || len(cs.PeerCertificates) == 0 {
				return nil
			}
			id := transportIdentityFromLeaf(cs.PeerCertificates[0])
			if id == "" {
				return nil
			}
			reg.register(id, raw)
			// Record the certificate this device is actually presenting. Observation only — nothing reads it to
			// make a decision, and it is deliberately AFTER admission so it cannot affect one.
			deviceCertificates.observeChain(id, cs.PeerCertificates[0], cs.VerifiedChains, time.Now())
			// And which certificate WE presented on this handshake — the measurement that separates "the
			// replacement was applied" from "the fleet is actually on it" (2026-07-31).
			if len(certreload.Registered()) > 0 {
				if served, serr := servedTransportLeaf(); serr == nil {
					servedCertSightings.observe(id, served, time.Now())
				}
			}
			// Register-after-sweep TOCTOU: an ADMIN kill-switch landing between the admission check above and
			// this registration would have swept before we were visible. Re-check and refuse the handshake so
			// the block still takes effect. This denies a NEW connection (ordinary admission) — it is not an
			// out-of-band teardown of an established session.
			if reg.revoked != nil {
				if reason, gone := reg.revoked(id); gone {
					reg.unregisterConn(raw)
					log.Printf("transport_admission_denied reason=revoked_during_handshake identity=%q revoke_reason=%q", id, reason)
					return fmt.Errorf("transport admission: identity %q is revoked (%s)", id, reason)
				}
			}
			return nil
		}
		return per, nil
	}
	return out
}

// startSecureTransportListener starts an ADDITIVE TLS listener serving handler on cfg.ListenAddr. It is
// non-fatal/independent of the primary plaintext listener: a bind/config error is returned to the
// caller, which logs it without taking down the Edge. Returns the listener (close to stop) or nil when
// disabled.
func startSecureTransportListener(cfg secureTransportConfig, handler http.Handler) (net.Listener, error) {
	if !cfg.enabled() {
		return nil, nil
	}
	tlsCfg, err := buildSecureTransportTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("transport TLS listen %s: %w", cfg.ListenAddr, err)
	}
	// Track live connections by identity (active session revocation) when a registry is wired. The registry
	// wraps the RAW listener and tls.NewListener wraps THAT, so what net/http finally sees is a genuine
	// *tls.Conn — see the comment on transportConnRegistry.wrap for why the reverse order de-authenticates
	// every request. Both wrappers are transparent when ConnRegistry is nil.
	tlsCfg = attachConnRegistryTracking(tlsCfg, cfg.ConnRegistry)
	// The PROXY header is read before anything else, because it arrives before the first byte of TLS. It goes
	// INSIDE the registry wrapper so the registry — and everything downstream that asks a connection where it
	// came from — sees the device's address rather than the front door's.
	tlsLn := tls.NewListener(cfg.ConnRegistry.wrap(newProxyProtocolListener(ln, cfg.TrustedFrontDoors)), tlsCfg)
	mtls := "off"
	if tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert {
		mtls = "required"
	} else if tlsCfg.ClientAuth == tls.VerifyClientCertIfGiven {
		mtls = "optional"
	}
	log.Printf("edge secure transport (T) listening addr=%s mtls=%s (endpoint↔Edge encrypted; separate from interception)", cfg.ListenAddr, mtls)
	go func() {
		// Slowloris-safe ReadHeaderTimeout/IdleTimeout (streaming tunnel bodies unbounded).
		if serr := hardenedHTTPServer("", "transport-plane", handler).Serve(tlsLn); serr != nil {
			log.Printf("edge secure transport listener stopped: %v", serr)
		}
	}()
	return tlsLn, nil
}

// secureTransportCertHosts derives the SAN hosts for an auto-generated lab transport cert from the
// listen address, always including loopback names so local testing works.
func secureTransportCertHosts(listenAddr string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if host, _, err := net.SplitHostPort(strings.TrimSpace(listenAddr)); err == nil {
		if h := strings.TrimSpace(host); h != "" && h != "0.0.0.0" && h != "::" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// generateSelfSignedTransportCert mints a short-lived self-signed ECDSA cert for the (T) transport in
// lab mode. The returned PEM is the cert the endpoint agent pins. NOT for production: production supplies
// -transport-tls-cert/-key from the operator's own CA.
func generateSelfSignedTransportCert(hosts []string) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Lantern DSSE Transport"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return cert, certPEM, nil
}

// transportDeviceIdentityFromRequest extracts the device identity from a VERIFIED mTLS transport client
// certificate (W2). verified is true only when the TLS layer verified the client cert chain
// (RequireAndVerifyClientCert, or VerifyClientCertIfGiven with a presented + verified cert). The identity
// is the cert CommonName, else the first URI/DNS SAN. Returns ("", false) on the plaintext listener or
// when no verified client cert was presented.
func transportDeviceIdentityFromRequest(r *http.Request) (string, bool) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return "", false
	}
	// ★★★ AND A CHAIN THAT ROOTS AT THE DEPLOYMENT'S OWN AUTHORITY IS NOT A DEVICE (2026-08-25).
	//
	// The device-identity tier proves ENDPOINTS AND CONNECTORS, and every organization has its own tree. This Edge now also ADVERTISES the deployment authority as an acceptable client CA, so
	// a sibling Edge can present itself on the mesh ingress — which means certificates rooted there produce a
	// verified chain here too. Reading one as a device identity would make the deployment's own operator
	// certificate able to act as somebody's endpoint: a single key that speaks for an organization it does
	// not belong to, which the architecture says must exist nowhere.
	//
	// The peer Edge is identified by meshPeerIdentityFromRequest instead, which verifies against exactly this
	// authority and nothing else.
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) > 0 && meshPeerAuthorityRoot(chain[len(chain)-1]) {
			return "", false
		}
	}
	id := transportIdentityFromLeaf(r.TLS.PeerCertificates[0]) // verified chain → authoritative
	// Record the certificate whoever this is presented. The (T) listener already does this at its handshake,
	// but not everything arrives there: a connector authenticates with mTLS on the data listener, so its
	// certificate was invisible to a view that claimed to cover the fleet — and a connector's certificate
	// expiring takes its whole reachable network with it. Observation only; nothing here decides anything.
	deviceCertificates.observeChain(id, r.TLS.PeerCertificates[0], r.TLS.VerifiedChains, time.Now())
	return id, true
}

// transportTenantFromRequest resolves the tenant a request's mTLS connection belongs to, from which
// registered Tenant CA the verified client cert chains to (tenant identification). Returns ("",
// false) on the plaintext listener, when no verified chain, or when the cert chains to no registered
// tenant CA. AUTHORITATIVE — derived from the actual issuing CA, not a client-claimed field — so it is
// the basis for binding the flow to its tenant (cross-tenant is structurally impossible).
func transportTenantFromRequest(r *http.Request, reg *tenantca.TenantCARegistry) (string, bool) {
	if r == nil || r.TLS == nil || reg == nil || len(r.TLS.VerifiedChains) == 0 {
		return "", false
	}
	return reg.TenantForVerifiedChains(r.TLS.VerifiedChains)
}

// authoritativeTenantForRequest resolves the tenant a runtime request must be keyed to, preferring the
// AUTHORITATIVE tenant proven by the (T) mTLS client cert (resolved from WHICH registered Tenant CA it
// chains to — tenant identification) over any client-claimed value. This is the downstream half of
// the no-cross-tenant-mixing invariant: admission proves the tenant at the (T) handshake, and every
// tenant-keyed write on the data plane (decision, audit) must use the
// cert-proven tenant, not a value the client put in the request body.
//
// Returns:
//   - (certTenant, nil) when the request arrived over verified mTLS resolving to a registered tenant and
//     the claim is empty or equal to it — the cert-proven tenant is authoritative.
//   - ("", error) when a non-empty claim DISAGREES with the cert tenant — a cross-tenant claim, denied.
//   - (trimmed claim, nil) when no registry is configured or there is no verified tenant chain (plaintext /
//     lab listener) — the caller's existing client-supplied/default tenant stands (back-compat).
func authoritativeTenantForRequest(r *http.Request, claimed string, reg *tenantca.TenantCARegistry) (string, error) {
	claimed = strings.TrimSpace(claimed)
	if reg == nil {
		return claimed, nil
	}
	tid, ok := transportTenantFromRequest(r, reg)
	if !ok {
		return claimed, nil // plaintext listener / no verified tenant chain — keep client-supplied tenant
	}
	if claimed != "" && claimed != tid {
		return "", fmt.Errorf("cross-tenant request: claimed tenant %q does not match certificate tenant %q", claimed, tid)
	}
	return tid, nil // authoritative — derived from the issuing Tenant CA, not client-claimed
}

// enrichDecisionRequestWithTransportTenant binds the AUTHORITATIVE tenant (see authoritativeTenantForRequest)
// onto the decision request so policy, routing, egress and logs are keyed to the tenant the CERTIFICATE
// proves. A body that claims a different tenant than its certificate is denied (the caller rejects it). On
// the plaintext listener / without a registry it is a no-op (client-supplied TenantID kept).
//
// Phase 3 (G1, multi-tenant Admin Console design//) — production fail-closed on the residual
// primary-tenant fallback: when this Edge is a MULTI-TENANT PRODUCTION Edge (a Tenant CA registry is
// configured AND lab/devMode is OFF) and the tenant cannot be authoritatively resolved (no verified (T)
// mTLS chain AND no claimed tenant → tid==""), DENY rather than let the flow fall through to the
// evaluator's seed/primary fallback (decision.Evaluator.firstPolicyTenantID). Silently keying an
// unauthenticated flow to the seeded PolicyBundle tenant is the cross-tenant leak this closes.
//
// IMPORTANT — lab/devMode is unchanged: when labMode==true, OR when reg==nil (single-tenant lab Edge,
// e.g. the plaintext listener with no registry), the behaviour is IDENTICAL to before — the
// client-supplied/empty tenant is kept and the downstream seed fallback is allowed (back-compat).
func enrichDecisionRequestWithTransportTenant(r *http.Request, req model.DecisionRequest, reg *tenantca.TenantCARegistry, labMode bool) (model.DecisionRequest, error) {
	tid, err := authoritativeTenantForRequest(r, req.TenantID, reg)
	if err != nil {
		log.Printf("decision_tenant_denied reason=cross_tenant_claim claimed_tenant=%q", strings.TrimSpace(req.TenantID))
		return req, err
	}
	// Production multi-tenant fail-closed: an unresolved tenant must not fall back to the seed tenant.
	// Gated on (!labMode && reg != nil) so lab and single-tenant Edges keep their existing seed fallback.
	if !labMode && reg != nil && strings.TrimSpace(tid) == "" {
		log.Printf("decision_tenant_denied reason=unresolved_tenant_production_multitenant claimed_tenant=%q", strings.TrimSpace(req.TenantID))
		return req, fmt.Errorf("tenant could not be authoritatively resolved: a multi-tenant production Edge requires a verified (T) mTLS client certificate chain (no seed-tenant fallback)")
	}
	req.TenantID = tid
	return req, nil
}

// transportIdentityFromLeaf derives the transport identity from a verified client leaf cert: the CN, else
// the first URI SAN, else the first DNS SAN. Empty when the cert carries no usable identifier. Shared by
// the request path (decision binding) and the TLS handshake admission gate (enrolled inventory).
func transportIdentityFromLeaf(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	if id := strings.TrimSpace(leaf.Subject.CommonName); id != "" {
		return id
	}
	for _, uri := range leaf.URIs {
		if uri != nil && strings.TrimSpace(uri.String()) != "" {
			return uri.String()
		}
	}
	for _, dns := range leaf.DNSNames {
		if strings.TrimSpace(dns) != "" {
			return dns
		}
	}
	return ""
}

// connectorMTLSIdentityBound enforces strict per-connector authentication: when the request
// arrives over verified mTLS, the client-cert identity (CN/SAN) MUST be bound to this connectorID. A
// valid CA-signed certificate that is not THIS connector's (another connector's cert, a device cert)
// must be rejected even with a correct shared secret — being CA-signed is not enough.
//
//	present=false → no verified mTLS cert (plaintext / lab listener); the caller keeps its existing auth.
//	present=true,bound=false → mTLS cert presented but its identity does not match connectorID → REJECT.
//	present=true,bound=true → cert identity matches connectorID → bound.
func connectorMTLSIdentityBound(r *http.Request, connectorID string) (bound bool, certIdentity string, present bool) {
	id, verified := transportDeviceIdentityFromRequest(r)
	if !verified || strings.TrimSpace(id) == "" {
		return false, "", false
	}
	return strings.EqualFold(strings.TrimSpace(id), strings.TrimSpace(connectorID)), id, true
}

// enrichDecisionRequestWithTransportIdentity binds a verified mTLS device identity into the decision
// request (W2). This is AUTHORITATIVE — the transport-verified identity, not a client-claimed
// field — so a policy can require transport_client_cert_verified / transport_device_identity. No-op on
// the plaintext listener (no verified r.TLS) or when already set.
func enrichDecisionRequestWithTransportIdentity(r *http.Request, req model.DecisionRequest) model.DecisionRequest {
	if req.TransportClientCertVerified {
		return req
	}
	id, verified := transportDeviceIdentityFromRequest(r)
	if !verified {
		return req
	}
	req.TransportClientCertVerified = true
	if id != "" {
		req.TransportDeviceIdentity = id
	}
	return req
}
