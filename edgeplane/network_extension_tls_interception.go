package edgeplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/internal/posixperm"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ossintercept "github.com/lantern-networks/dsse-core/interception"
	"golang.org/x/net/http2"
)

const (
	NetworkExtensionLabTLSRootCommonName   = "Lantern DSSE Interception Root"
	NetworkExtensionLabTLSLeafOrganization = "Lantern DSSE"
	NetworkExtensionLabTLSRootCertFilename = "lantern_dsse_interception_root_ca.pem"
	NetworkExtensionLabTLSRootValidity     = 365 * 24 * time.Hour
	// Leaf validity is 30 days (was 24h). A 24h window made a leaf minted "today" expire the moment the day
	// crossed, so the first hit the next day failed net::ERR_CERT_DATE_INVALID — and passkey/WebAuthn ceremonies
	// (a tight multi-connection RP→options→get/create→verify flow) abort entirely if any one connection lands on
	// an expired/not-yet-valid leaf. 30 days removes the daily day-crossing failure. See handoff
	// docs/handoff_windows_passkey_intercept_cert_date_invalid.md.
	networkExtensionLabTLSLeafValidity = 30 * 24 * time.Hour
	// Backdate the leaf's NotBefore to absorb Edge↔client clock skew. Without it (leaf NotBefore == mint time)
	// a client clock even slightly behind the Edge saw a just-minted leaf as "not yet valid" →
	// net::ERR_CERT_DATE_INVALID (breaks passkeys). Standard practice (mitmproxy/mkcert backdate similarly).
	networkExtensionLabTLSLeafBackdate = time.Hour
	// Re-mint a cached leaf once it is within this window of NotAfter. Without it, a long-lived Edge process
	// (e.g. one frozen across macOS sleep) keeps serving a leaf from leafCache past its validity — the browser
	// then rejects the expired cert. The leaf serve path (unlike the root/intermediate) had no expiry check;
	// this margin makes it re-mint slightly before expiry.
	networkExtensionLabTLSLeafRenewBefore  = time.Hour
	NetworkExtensionLabTLSRootRotateBefore = 7 * 24 * time.Hour
	NetworkExtensionLabTLSDrainWait        = 25 * time.Millisecond
	// A decrypted response body is buffered up to this many bytes, and if it fits it is returned in one piece
	// with a definite length (Content-Length). Past the threshold, on an explicit Flush, or for SSE, it
	// switches to write-through streaming — which is what stops an unbounded buffer stalling a long-lived or
	// streaming connection into a disconnect, and stops memory growing without limit.
	NetworkExtensionLabTLSResponseStreamThreshold = 32 * 1024
)

type NetworkExtensionRuntimeCopyTLSInterceptionDialer struct {
	Base                   NetworkExtensionRuntimeCopyTCPDialer
	Intercepter            *NetworkExtensionLabTLSInterception
	ProbeOnlyDropUnmatched bool
}

// NetworkExtensionRuntimeCopySNIPeekDialer tells the tunnel handler whether it should peek at the SNI. In SNI
// mode the handler peeks at the ClientHello, sets route.SNI, and the dialer decides intercept or raw_forward
// from it — a raw forward then bridges directly rather than going through a net.Pipe, which is faster.
type NetworkExtensionRuntimeCopySNIPeekDialer interface {
	SNIBasedDecisionEnabled() bool
}

func (dialer NetworkExtensionRuntimeCopyTLSInterceptionDialer) SNIBasedDecisionEnabled() bool {
	return dialer.Intercepter.SNIBasedDecision()
}

func (dialer NetworkExtensionRuntimeCopyTLSInterceptionDialer) OpenTCPConnection(ctx context.Context, route NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	if dialer.Intercepter != nil {
		if dialer.Intercepter.Matches(route) {
			NetworkExtensionHotPathLog(
				"network_extension_lab_tls route_decision=intercept route_host_category=%s route_port_category=%s",
				NetworkExtensionLabTLSRouteHostCategory(route.Host),
				NetworkExtensionLabTLSRoutePortCategory(route.Port),
			)
			return dialer.Intercepter.OpenTCPConnection(ctx, route)
		}
		if dialer.ProbeOnlyDropUnmatched {
			NetworkExtensionHotPathLog(
				"network_extension_lab_tls route_decision=probe_only_drop route_host_category=%s route_port_category=%s",
				NetworkExtensionLabTLSRouteHostCategory(route.Host),
				NetworkExtensionLabTLSRoutePortCategory(route.Port),
			)
			return networkExtensionLabTLSProbeOnlyDroppedConn{}, nil
		}
		NetworkExtensionHotPathLog(
			"network_extension_lab_tls route_decision=raw_forward route_host_category=%s route_port_category=%s",
			NetworkExtensionLabTLSRouteHostCategory(route.Host),
			NetworkExtensionLabTLSRoutePortCategory(route.Port),
		)
	}
	base := dialer.Base
	if base == nil {
		base = NetworkExtensionRuntimeCopyNetDialer{}
	}
	return base.OpenTCPConnection(ctx, route)
}

type networkExtensionLabTLSProbeOnlyDroppedConn struct{}

func (networkExtensionLabTLSProbeOnlyDroppedConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (networkExtensionLabTLSProbeOnlyDroppedConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (networkExtensionLabTLSProbeOnlyDroppedConn) Close() error {
	return nil
}

func (networkExtensionLabTLSProbeOnlyDroppedConn) AllowEmptyRuntimeCopyDownstream() bool {
	return true
}

func (networkExtensionLabTLSProbeOnlyDroppedConn) RuntimeCopySessionDone() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

type NetworkExtensionLabTLSInterception struct {
	mu           sync.Mutex
	rootCert     *x509.Certificate               // the DEFAULT root cert (surfaced to admin / clients)
	rootRegistry *tenantInterceptionRootRegistry // resolves the signing provider per tenant (behind the HSM seam)
	// custodyChecker answers "where does the signing key live, and can it still sign?" for the admin surface.
	// Cached, because the check is a real signing operation and will cost HSM throughput once one is wired.
	custodyChecker *KeyCustodyChecker
	rootCertPEM    []byte
	// rootCACertOutPath is the file whose entire purpose is "this is the root to install on devices". It is
	// written once at construction and was then never touched again.
	//
	// ★ SO IT WENT STALE THE MOMENT THE ANCHOR CHANGED (measured 2026-08-16). The reference lab re-parented
	// its interception root to the MSSP root; the Edge served the new anchor and the distribution file kept
	// the old one — 5a74ac31… on disk while every leaf chained to 36973669…. An operator following the lab's
	// own procedure would install the wrong root onto a machine and it would fail every HTTPS site, with the
	// file that told them to do it looking perfectly valid. Retained now so the anchor and the thing handed
	// to devices cannot disagree.
	rootCACertOutPath string
	leafKey           *ecdsa.PrivateKey
	hosts             []string
	leafCache         map[string]tls.Certificate
	// Slice 3: optional rotatable intermediate between the (offline-able) root and the leaves. issuerMu guards
	// the per-(cache-tenant) issuer cache. useIntermediate off (default) => the root signs leaves directly
	// (chain [leaf, root], today's behavior); on => leaves are signed by a per-root intermediate the root issued
	// (chain [leaf, intermediate, root]), rotatable without re-trusting the root.
	issuerMu                 sync.Mutex
	useIntermediate          bool
	intermediatePermittedDNS []string
	interceptIssuers         map[string]*InterceptionIssuer
	// offlineIssuer, when set, is a FIXED intermediate loaded from an OFFLINE root: the Edge holds only the
	// intermediate's key (+ the root cert as anchor) and NO root key. issuerFor returns it directly, so every
	// leaf chains [leaf, intermediate, root] and clients pin the root — the strongest interception-CA shape
	// (the crown-jewel root key is never on the Edge). Set only via the offline-intermediate constructor.
	offlineIssuer *InterceptionIssuer
	// offlineTenantIssuers is the same shape, PER TENANT: each entry is a fixed intermediate issued by THAT
	// organization's own offline root, so the leaf a device sees chains to its own employer's anchor and to
	// nobody else's. This is what makes per-tenant interception real in the mode this product actually runs.
	//
	// ★ IT WAS UNREACHABLE BEFORE (measured 2026-08-16). Per-tenant ROOTS could be provisioned, listed and
	// distributed, and then issuerFor returned the one fixed offline intermediate for every tenant before the
	// per-tenant root was ever consulted. Two organizations on the reference lab each had a durable root on
	// disk; every leaf either would have seen was minted by the OTHER tenant's issuing CA.
	//
	// Non-empty means per-tenant offline signing is IN FORCE, and the resolution is deliberately fail-closed:
	// a tenant with no issuer of its own is refused rather than signed under somebody else's CA. Signing under
	// the wrong CA is the exact failure this whole effort exists to prevent, and it fails silently — the
	// device trusts it, the operator sees traffic, and one customer's Edge is minting certificates in another
	// customer's name. Guarded by issuerMu.
	offlineTenantIssuers map[string]*InterceptionIssuer
	// offlineTenantRoots is each of those tenants' ROOT certificate — the anchor that tenant's devices must
	// trust. Kept beside the issuer because "which anchor do I distribute to this customer" is unanswerable
	// from the issuer alone, and an anchor nobody can export is an anchor nobody deploys.
	offlineTenantRoots map[string]*x509.Certificate
	// offlineTenantRetiringRoots are roots this organization's devices are still TOLD ABOUT while they move
	// off them. They no longer sign anything.
	//
	// ★ WITHOUT THIS, REPLACING AN ORGANIZATION'S AUTHORITY IS A FLAG DAY (found 2026-08-16, the day after the
	// device-side pin shipped). A tenant announced exactly one root — whichever its current issuer chains to —
	// so loading a replacement switched the announced set instantly. Every device of that organization still
	// pinned to the previous root went from satisfied to mismatch at the same moment, and with the pin armed
	// they would all stand aside together. The agent's own rule — an overlap is a match, because a replacement
	// announces old and new together — was UNREACHABLE for a per-tenant organization: the Edge could never
	// announce two.
	//
	// So a replacement keeps the outgoing root in the announced set until it is deliberately withdrawn, which
	// is what makes "replace the authority" a move devices can be walked across rather than an event they are
	// all subjected to at once.
	offlineTenantRetiringRoots map[string][]*x509.Certificate
	// offlineTenantIncomingRoots are roots this organization's devices are told about BEFORE anything signs
	// under them.
	//
	// ★★★ THE OTHER HALF OF AN OVERLAP, AND IT WAS MISSING (2026-08-21). A replacement kept the OUTGOING root
	// announced, so a device that had not moved yet still verified — the retiring set above. Nothing announced
	// the INCOMING one, and an agent reports which of the ANNOUNCED roots it holds. So there was no way to ask
	// "do both devices have the new root yet?" before switching to it: the first evidence a root had arrived
	// was the traffic that depended on it.
	//
	// Measured what that costs: eighteen minutes of broken HTTPS on win-dev-1 when material changed under a
	// fleet that had not been asked. The transport lane has had announce-alongside-then-promote since roadmap
	// D (pendingAnchorOf); interception is the same problem and now has the same answer.
	//
	// A root here is ANNOUNCED and NOT USED. It leaves this set the moment an issuer under it is loaded — at
	// which point it is simply the current root.
	offlineTenantIncomingRoots map[string][]*x509.Certificate
	// offlineTenantRetiringFingerprints are retirements this node knows about from its DURABLE record rather
	// than from a replacement it performed. A node that came up on new material has no certificate for what it
	// was signing under before — only the fingerprint, which is all a device needs. See
	// interception_announced_roots_survive_a_restart.go.
	offlineTenantRetiringFingerprints map[string][]string
	// revokedTenantRoots are authority fingerprints this node refuses to load, with the reason. A revocation
	// that only removed the loaded issuer would be undone by the next restore from disk — and an operator who
	// has revoked a key believes it is dead.
	revokedTenantRoots map[string]string
	// revokedTenants are organizations whose authority was revoked and that therefore have NO issuer until a
	// replacement is loaded.
	//
	// ★ WITHOUT THIS, REVOKING THE LAST PER-TENANT ISSUER SILENTLY RE-SHARED THE ORGANIZATION (found by the
	// test written for the revocation itself, 2026-08-16). Removing the issuer emptied the per-tenant map,
	// which is exactly the condition issuerFor reads as "per-tenant signing is not in force" — so the node fell
	// back to the deployment's own authority and went on intercepting that organization under it. An operator
	// who has just declared a key compromised would have been told the revocation succeeded while the traffic
	// carried on being decrypted, by a different CA, with no announcement to the devices.
	revokedTenants map[string]string
	// offlinePrimaryTenant is the organization the DEFAULT offline intermediate belongs to. It keeps signing
	// under that intermediate when per-tenant issuers are added, so turning this on does not break the tenant
	// whose devices already trust the current anchor. Empty means the default intermediate serves the
	// unattributed flows only.
	offlinePrimaryTenant string
	// offlineTenantIntermediateDir persists those bundles so they survive a restart. Without it a loaded
	// intermediate is live and gone at the next deploy, and the node silently returns to refusing that
	// organization's traffic — the per-tenant ROOTS had exactly this defect and it was found only by
	// restarting. The key is written through the same at-rest sealing the root uses.
	offlineTenantIntermediateDir string
	// ★★★ AND WHETHER ANYTHING BRINGS IT BACK (2026-08-27). Not having a directory is a PROBLEM when an
	// operator placed these files here by hand and a restart would lose them — and it is the CORRECT shape
	// when the node fetches its organizations from the control plane at start-up, because what is being kept
	// off this disk is a short-lived signing key on a node that may not exist tomorrow. Without knowing
	// which, this warned on every load of every deployment the installer produces, about a state that cannot
	// happen there, in a sentence beginning "a restart returns this organization to REFUSED".
	//
	// A warning an operator is expected to ignore is worse than no warning: it is the one that teaches them
	// to ignore the next.
	offlineTenantMaterialIsFetched bool
	// reparentRestoreFailedReason is non-empty when a PERSISTED interception-root re-parent existed at boot but
	// could NOT be restored. The operator intended the MSSP-issued root; the Edge is serving the
	// self-signed one instead, and a device that has moved to the MSSP root would reject the whole chain. It is
	// surfaced in InterceptionIntermediateStatus and the PKI readiness so this shows as degraded/not-ready
	// rather than being a silent revert. Guarded by issuerMu.
	reparentRestoreFailedReason string
	// sessionTicketKeys is a process-stable TLS session-ticket key shared across every per-connection
	// tls.Config. Resumption keys live in the Config, so a fresh Config per connection would never
	// resume; sharing one key set lets a returning client skip the full handshake (asymmetric crypto) on
	// reconnect. SNI-based intercept/bypass routing is decided pre-serve at the ClientHello peek and the
	// SNI is present on resumed ClientHellos too, so resumption does not affect interception decisions.
	sessionTicketKeys [][32]byte
	now               func() time.Time
	httpHandler       http.Handler
	probeOnly         bool
	// bypassHosts are destinations that are raw-forwarded rather than intercepted even under decrypt-all
	// (`*`). The network extension steers everything and the EDGE decides what to bypass, from the SNI or the
	// host. That is what lets an operator name a destination — the control channel of the agent running on
	// the device itself, say — and have it bypassed reliably, so enabling the extension does not cut that
	// session; it removes the dependence on the extension's own hostname visibility. What is bypassed is
	// always configuration an administrator wrote, never a default.
	bypassHosts []string
	// With sniBasedDecision, intercept and bypass are decided from the TLS ClientHello's SNI rather than from
	// route.Host. Chrome resolves DNS itself and connects to an address, so route.Host is an IP and every
	// hostname match misses; the SNI is a hostname even then. This assumes everything is steered: the
	// extension sends every flow to the Edge, and the Edge intercepts what it must and raw-forwards the rest
	// — which is not decrypted, so the real certificate is presented and certificate pinning still works.
	sniBasedDecision bool
	// Dynamic certificate-pinning detection: a destination whose client REFUSED the interception certificate
	// — the intercepted handshake failed — is learned at runtime and raw-forwarded from then on. It handles
	// pinning applications (Apple's push and iCloud daemons, say) without a static bypass list, and stops the
	// cycle of a failed interception causing a client reconnect storm and tunnel connections piling up.
	// Steering is kept — the Edge stays on the path — and only decryption is given up. A destination is
	// treated as pinned after pinDetectThreshold CONSECUTIVE failures (at least 2, so a decryptable host's
	// transient failure is not mistaken for pinning), and a successful handshake resets the count.
	// pinDetectThreshold <= 0 disables it. pinnedHosts lives only as long as the Edge process; a restart
	// learns again.
	pinDetectThreshold int
	pinnedHosts        map[string]bool
	handshakeFailures  map[string]int
	// Destinations whose intercepted handshake has succeeded at least once, and are therefore known to be
	// decryptable. Used to prevent a false pin.
	everSucceededHosts map[string]bool
	// autoPinEnabled decides whether reaching the threshold turns a destination into a raw forward by itself.
	// The secure default is off. With it off, the failure learning and the candidate proposal through
	// certPinEmitter still run: DETECTING is safe, because a candidate bypasses nothing until an
	// administrator approves it.
	autoPinEnabled bool
	// certPinEmitter is called when the threshold is reached and proposes the destination as a bypass
	// candidate awaiting administrator review. Setting it does not enable auto-bypass: only approval and
	// materialisation make a candidate a bypass.
	certPinEmitter func(host string)
}

type networkExtensionLabTLSRootMaterial struct {
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// InterceptionRootProvider supplies the interception root CA used to mint per-SNI leaves: the root certificate
// (public — the chain, and what clients trust) and a crypto.Signer for signing leaves. The Signer is the SEAM
// that abstracts WHERE the root private key lives — the crown jewel of the interception design:
//   - fileInterceptionRootProvider: an in-process RSA key (generated or loaded from a PEM file) — the lab default.
//   - (future) a sealed/KMS-wrapped key, or an HSM/PKCS#11 token where the key NEVER leaves hardware.
//
// Leaf minting already signs through crypto.Signer (x509.CreateCertificate), so swapping the provider does not
// touch the live interception path. This is the foundation the per-tenant-CA and HSM-backed-key hardening build
// on (docs/pki_trust_model.md: HSM / per-tenant / name-constrained intermediate / rotation).
type InterceptionRootProvider interface {
	Certificate() *x509.Certificate
	CertPEM() []byte
	Signer() crypto.Signer
}

// fileInterceptionRootProvider is the default in-process provider: the root key is an RSA key held in memory
// (the bytes are on the host, protected only by file perms 0600 when persisted). Protecting the key AT REST is
// the job of a different provider behind this same interface (sealed/HSM), not this one — this provider just
// makes the existing file-key behavior fit the seam without any change to signing.
type fileInterceptionRootProvider struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *rsa.PrivateKey
}

func (p *fileInterceptionRootProvider) Certificate() *x509.Certificate { return p.cert }
func (p *fileInterceptionRootProvider) CertPEM() []byte                { return p.certPEM }
func (p *fileInterceptionRootProvider) Signer() crypto.Signer          { return p.key }

// NewFileInterceptionRootProvider wraps already-loaded/generated root material as the default provider.
func NewFileInterceptionRootProvider(m networkExtensionLabTLSRootMaterial) *fileInterceptionRootProvider {
	return &fileInterceptionRootProvider{cert: m.Cert, certPEM: m.CertPEM, key: m.Key}
}

func NewNetworkExtensionLabTLSInterception(hostPatterns []string, now func() time.Time) (*NetworkExtensionLabTLSInterception, error) {
	return NewNetworkExtensionLabTLSInterceptionWithPersistentRoot(hostPatterns, now, "")
}

func NewNetworkExtensionLabTLSInterceptionWithPersistentRoot(hostPatterns []string, now func() time.Time, rootCACertOut string) (*NetworkExtensionLabTLSInterception, error) {
	// Short-circuit with no side effects when there is nothing to intercept (do NOT touch/persist root material).
	if len(NormalizedNetworkExtensionLabTLSHostPatterns(hostPatterns)) == 0 {
		return nil, nil
	}
	if now == nil {
		now = time.Now
	}
	rootCACertOut, err := normalizeNetworkExtensionLabTLSRootCACertOutPath(rootCACertOut)
	if err != nil {
		return nil, err
	}
	material, reused, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(rootCACertOut, now)
	if err != nil {
		return nil, err
	}
	if material.Cert == nil {
		material, err = GenerateNetworkExtensionLabTLSRootMaterial(now)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(rootCACertOut) != "" {
			if err := WriteNetworkExtensionLabTLSPersistentRootMaterial(rootCACertOut, material); err != nil {
				return nil, err
			}
			log.Printf("network_extension_lab_tls progress=root_ca_persistence_created")
		}
	} else if reused {
		log.Printf("network_extension_lab_tls progress=root_ca_persistence_reused")
		// At-rest seal migration: if a KEK is configured, re-persist so a previously-plaintext key is SEALED in
		// place. No new root is minted (the cert/key are unchanged), so device trust is unaffected.
		if len(GetInterceptionRootKEK()) > 0 && strings.TrimSpace(rootCACertOut) != "" {
			if err := WriteNetworkExtensionLabTLSPersistentRootMaterial(rootCACertOut, material); err != nil {
				return nil, err
			}
			log.Printf("network_extension_lab_tls progress=root_ca_key_sealed_at_rest")
		}
	}
	// Default provider: the in-process file key. The seam lets production inject a sealed/HSM provider instead.
	return NewNetworkExtensionLabTLSInterceptionWithProvider(hostPatterns, now, NewFileInterceptionRootProvider(material))
}

// NewNetworkExtensionLabTLSInterceptionWithProvider builds an interception engine whose per-SNI leaves are signed
// by the given root provider — the INJECTION POINT for the HSM/sealed-key seam. The lab path supplies a
// fileInterceptionRootProvider (in-process RSA key); production can supply an HSM/PKCS#11- or KMS-backed provider
// so the crown-jewel root key never leaves hardware, with no change to the leaf-minting or serving path.
func NewNetworkExtensionLabTLSInterceptionWithProvider(hostPatterns []string, now func() time.Time, provider InterceptionRootProvider) (*NetworkExtensionLabTLSInterception, error) {
	hosts := NormalizedNetworkExtensionLabTLSHostPatterns(hostPatterns)
	if len(hosts) == 0 {
		return nil, nil
	}
	if now == nil {
		now = time.Now
	}
	if provider == nil || provider.Certificate() == nil || provider.Signer() == nil {
		return nil, fmt.Errorf("interception root provider is incomplete (cert/signer missing)")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate lab TLS leaf key: %w", err)
	}
	// Session-ticket keys let a returning client resume and skip the full handshake.
	//
	// FLEET-WIDE when a shared secret is configured: every Edge derives the same key, so a client that the
	// load balancer moves to another node still resumes. Without it the key is per-PROCESS random — correct
	// for a single Edge, but behind an LB every rebalance costs a full handshake (the PKI design).
	var sessionTicketKeys [][32]byte
	if keys, ok := fleetSessionTicketKeys(interceptionSessionTicketSecret(), now()); ok {
		sessionTicketKeys = keys
		log.Printf("interception: session-ticket keys are FLEET-WIDE (derived, rotating every %s) — a client the load balancer moves to another Edge can still resume", sessionTicketRotationPeriod)
	} else {
		var ticketKey [32]byte
		if _, err := rand.Read(ticketKey[:]); err == nil {
			sessionTicketKeys = [][32]byte{ticketKey}
		}
		// Say so. Running several Edges behind a balancer without the shared secret silently costs a full
		// handshake on every rebalance, and nothing else in the system would reveal it.
		log.Printf("interception: session-ticket keys are PER-PROCESS (no DSSE_INTERCEPTION_SESSION_TICKET_SECRET) — fine for a single Edge; behind a load balancer every rebalance costs a FULL handshake")
	}
	// The registry resolves the signing provider per tenant. It defaults to the single given provider for every
	// tenant (today's behavior) until per-tenant isolation is explicitly enabled (EnablePerTenant).
	return &NetworkExtensionLabTLSInterception{
		rootCert:          provider.Certificate(),
		rootRegistry:      NewTenantInterceptionRootRegistry(provider, now),
		rootCertPEM:       provider.CertPEM(),
		leafKey:           leafKey,
		sessionTicketKeys: sessionTicketKeys,
		hosts:             hosts,
		leafCache:         map[string]tls.Certificate{},
		interceptIssuers:  map[string]*InterceptionIssuer{},
		now:               now,
		// Default: two consecutive intercepted-handshake failures mark a destination as pinned, and it is
		// raw-forwarded from then on.
		pinDetectThreshold: 2,
		pinnedHosts:        map[string]bool{},
		handshakeFailures:  map[string]int{},
		everSucceededHosts: map[string]bool{},
		// FAIL-SAFE DEFAULT: auto-pin — turning a detection straight into a raw forward — is OFF. Enabling it
		// is an explicit opt-in through SetDynamicPinDetectionEnabled(true). Defaulting it to true would mean
		// any path that forgot to call Set has auto-bypass silently on, and an attacker who deliberately
		// fails a handshake could then take their destination out of interception. A test that exercises
		// auto-pin enables it explicitly.
		autoPinEnabled: false,
	}, nil
}

func GenerateNetworkExtensionLabTLSRootMaterial(now func() time.Time) (networkExtensionLabTLSRootMaterial, error) {
	return GenerateNetworkExtensionLabTLSRootMaterialScoped("", now)
}

// GenerateNetworkExtensionLabTLSRootMaterialScoped generates a root whose subject CN is suffixed with `scope`
// (e.g. a region id like "eu-fra") when non-empty, so a per-tenant-per-region root is identifiable AS that
// region's key — the residency property "the key that reads EU traffic is the EU key" is visible in the cert.
// scope "" is the unlabeled root (today's behavior).
func GenerateNetworkExtensionLabTLSRootMaterialScoped(scope string, now func() time.Time) (networkExtensionLabTLSRootMaterial, error) {
	if now == nil {
		now = time.Now
	}
	cn := NetworkExtensionLabTLSRootCommonName
	if scope != "" {
		cn = cn + " " + scope
	}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("generate lab TLS root key: %w", err)
	}
	createdAt := now().UTC()
	serialNumber, err := RandomNetworkExtensionLabTLSSerial()
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, err
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{NetworkExtensionLabTLSLeafOrganization},
		},
		NotBefore:             createdAt.Add(-time.Minute),
		NotAfter:              createdAt.Add(NetworkExtensionLabTLSRootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("create lab TLS root certificate: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("parse lab TLS root certificate: %w", err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	if len(rootPEM) == 0 {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("encode lab TLS root certificate PEM")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey)})
	if len(keyPEM) == 0 {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("encode lab TLS root key PEM")
	}
	return networkExtensionLabTLSRootMaterial{Cert: rootCert, Key: rootKey, CertPEM: rootPEM, KeyPEM: keyPEM}, nil
}

func (interception *NetworkExtensionLabTLSInterception) Matches(route NetworkExtensionRuntimeCopyTCPRoute) bool {
	if interception == nil || route.Port != 443 {
		return false
	}
	host, ok := interception.decisionHost(route)
	if !ok {
		return false
	}
	// Edge-side bypass takes precedence: bypass hosts are never intercepted
	// (fall through to raw_forward) — e.g. the AI dev-agent control plane and
	// cert-pinned apps. In SNI mode this matches on the SNI too.
	if networkExtensionLabTLSHostMatchesAnyPattern(host, interception.bypassHosts) {
		return false
	}
	// A destination learned to be certificate-pinning is raw-forwarded rather than intercepted; it stays
	// steered.
	if interception.isPinnedHost(host) {
		return false
	}
	return networkExtensionLabTLSHostMatchesAnyPattern(host, interception.hosts)
}

// decisionHost returns the normalised host the intercept/bypass decision is made on. In SNI mode the peeked
// SNI wins, so a connect-by-IP flow is still decided by hostname even though route.Host is an address. Shared
// so that Matches and the dynamic pin learning key on exactly the same thing.
func (interception *NetworkExtensionLabTLSInterception) decisionHost(route NetworkExtensionRuntimeCopyTCPRoute) (string, bool) {
	candidate := route.Host
	if interception.sniBasedDecision && strings.TrimSpace(route.SNI) != "" {
		candidate = route.SNI
	}
	host, ok := NormalizeNetworkExtensionRuntimeCopyDestinationHost(candidate)
	if !ok {
		return "", false
	}
	return strings.TrimSuffix(strings.ToLower(host), "."), true
}

// isPinnedHost reports whether host is in the set learned to be certificate-pinning.
func (interception *NetworkExtensionLabTLSInterception) isPinnedHost(host string) bool {
	if interception == nil || interception.pinDetectThreshold <= 0 || host == "" {
		return false
	}
	interception.mu.Lock()
	defer interception.mu.Unlock()
	return interception.pinnedHosts[host]
}

// recordIntoHandshakeOutcome records whether an intercepted TLS handshake succeeded and learns certificate
// pinning from consecutive failures. Success resets the failure count. A destination whose consecutive
// failures reach the threshold is added to pinnedHosts, and Matches() chooses a raw forward for it from then
// on. It returns true only when a destination becomes pinned for the first time.
func (interception *NetworkExtensionLabTLSInterception) recordHandshakeOutcome(host string, success bool) bool {
	if interception == nil || interception.pinDetectThreshold <= 0 || host == "" {
		return false
	}
	interception.mu.Lock()
	if success {
		// A destination whose intercepted handshake has succeeded once is settled as decryptable and is never
		// pinned afterwards. Without this, a handshake EOF from Chrome abandoning a preconnect, or from the
		// churn of a steering restart, is mistaken for certificate pinning and a perfectly decryptable host
		// — accounts.google.com, say — starts being raw-forwarded. A destination that really does pin, such
		// as an Apple daemon, never succeeds even once.
		interception.everSucceededHosts[host] = true
		delete(interception.handshakeFailures, host)
		interception.mu.Unlock()
		return false
	}
	if interception.pinnedHosts[host] {
		interception.mu.Unlock()
		return false
	}
	// A destination with a successful handshake behind it is never falsely pinned.
	if interception.everSucceededHosts[host] {
		delete(interception.handshakeFailures, host)
		interception.mu.Unlock()
		return false
	}
	interception.handshakeFailures[host]++
	reached := interception.handshakeFailures[host] >= interception.pinDetectThreshold
	var emitter func(string)
	newlyPinned := false
	if reached {
		delete(interception.handshakeFailures, host)
		// Detected: the threshold was reached. Whether or not auto-pin is on, an emitter is told about the
		// bypass candidate.
		emitter = interception.certPinEmitter
		// Auto-bypass only when it has been enabled explicitly; the default is off. A proposal on its own
		// bypasses no traffic.
		if interception.autoPinEnabled {
			interception.pinnedHosts[host] = true
			newlyPinned = true
		}
	}
	interception.mu.Unlock()
	if emitter != nil {
		// The proposal is emitted outside the lock: the candidate store has its own locking and file
		// persistence. A candidate becomes a bypass only when an administrator approves and materialises it.
		emitter(host)
	}
	return newlyPinned
}

// SetSNIBasedDecision selects the mode in which intercept and bypass are decided from route.SNI rather than
// route.Host. The tunnel handler sets the SNI by peeking at the ClientHello.
func (interception *NetworkExtensionLabTLSInterception) SetSNIBasedDecision(enabled bool) {
	if interception == nil {
		return
	}
	interception.sniBasedDecision = enabled
}

// SetDynamicPinDetectionEnabled turns dynamic certificate-pinning detection on or off — the behaviour that
// learns a destination from consecutive handshake failures and raw-forwards it. The default is OFF, because
// it is a hole: an attacker who fails handshakes deliberately can take their own destination out of
// interception, and out of any tenant restriction that rides on it. With it off, handshake failures are not
// learned and bypass comes from the static list alone, which an attacker cannot add to — and OS
// infrastructure that really does pin, such as an Apple daemon, has to be excluded there explicitly.
func (interception *NetworkExtensionLabTLSInterception) SetDynamicPinDetectionEnabled(enabled bool) {
	if interception == nil {
		return
	}
	interception.mu.Lock()
	defer interception.mu.Unlock()
	// enabled controls auto-pin — becoming a raw forward by itself — and nothing else. The DETECTION (learning
	// from handshake failures and proposing a bypass candidate through certPinEmitter) runs whenever the
	// threshold is above zero. So with the default off, a pinning host is still proposed for administrator
	// review, and an attacker failing handshakes still cannot get themselves bypassed.
	interception.autoPinEnabled = enabled
	if !enabled {
		// Disabling auto-bypass releases every automatically learned pin. The candidate proposals stay.
		interception.pinnedHosts = map[string]bool{}
	}
	if interception.pinDetectThreshold <= 0 {
		interception.pinDetectThreshold = 2
	}
}

// SetCertPinCandidateEmitter sets the callback called when certificate pinning is detected — consecutive
// handshake failures reaching the threshold. The emitter's job is to record the destination as a bypass
// candidate awaiting administrator review; it does not bypass anything. nil disables it.
func (interception *NetworkExtensionLabTLSInterception) SetCertPinCandidateEmitter(emit func(host string)) {
	if interception == nil {
		return
	}
	interception.mu.Lock()
	defer interception.mu.Unlock()
	interception.certPinEmitter = emit
}

func (interception *NetworkExtensionLabTLSInterception) SNIBasedDecision() bool {
	return interception != nil && interception.sniBasedDecision
}

// NetworkExtensionLabTLSPrefixedConn replays the ClientHello bytes read during the peek before reading the
// underlying conn, so the ClientHello reaches whatever comes next — a tls.Server that intercepts, or a raw
// forward upstream.
type NetworkExtensionLabTLSPrefixedConn struct {
	net.Conn
	Prefix []byte
}

func (conn *NetworkExtensionLabTLSPrefixedConn) Read(p []byte) (int, error) {
	if len(conn.Prefix) > 0 {
		n := copy(p, conn.Prefix)
		conn.Prefix = conn.Prefix[n:]
		return n, nil
	}
	return conn.Conn.Read(p)
}

// CloseWrite delegates the embedded conn's write half-close (TCP FIN). Without it, embedding behind the
// net.Conn interface does not promote CloseWrite, the tunnel bridge's halfCloseWriteSide fails its type
// assertion and falls back to closing BOTH directions — which RSTs a flow in the middle of delivering its
// response, and is why an intercepted POST's "next" did nothing. Delegating the half-close sends EOF one way
// while the other direction stays alive.
func (conn *NetworkExtensionLabTLSPrefixedConn) CloseWrite() error {
	if writeCloser, ok := conn.Conn.(interface{ CloseWrite() error }); ok {
		return writeCloser.CloseWrite()
	}
	return nil
}

// CloseRead is delegated for the same reason. The bridge does not use a read half-close today; this errs
// toward safety for anything later that expects net.TCPConn's behaviour.
func (conn *NetworkExtensionLabTLSPrefixedConn) CloseRead() error {
	if readCloser, ok := conn.Conn.(interface{ CloseRead() error }); ok {
		return readCloser.CloseRead()
	}
	return nil
}

// networkExtensionLabTLSHostMatchesAnyPattern reports whether host matches any of patterns — `*`,
// `*.suffix`, or an exact name. host must already be normalised: lower-cased, with any trailing dot removed.
func networkExtensionLabTLSHostMatchesAnyPattern(host string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(host, suffix) && len(host) > len(strings.TrimPrefix(suffix, ".")) {
				return true
			}
			continue
		}
		if host == pattern {
			return true
		}
	}
	return false
}

// SetBypassHosts sets the destination patterns the Edge raw-forwards instead of intercepting.
func (interception *NetworkExtensionLabTLSInterception) SetBypassHosts(patterns []string) {
	if interception == nil {
		return
	}
	interception.bypassHosts = NormalizedNetworkExtensionLabTLSHostPatterns(patterns)
}

// SetInterceptHosts sets the intercept (decrypt) host pattern set at runtime: ["*"] is decrypt-all, a narrower
// set is a decrypt allowlist (bypass-default — only these hosts are decrypted, everything else is raw-forwarded
// while still steered + policy-gated). This is what the deployment-mode switch flips
// (docs/invisible_effective_configuration.md). Mirrors SetBypassHosts; bypass hosts always win in Matches.
func (interception *NetworkExtensionLabTLSInterception) SetInterceptHosts(patterns []string) {
	if interception == nil {
		return
	}
	interception.hosts = NormalizedNetworkExtensionLabTLSHostPatterns(patterns)
}

// BypassHosts returns the live raw-forward (never-decrypted) host pattern set the interception engine uses —
// the shipped known-bypass compatibility list (Apple/iCloud/GitHub/OS-update/OCSP …) plus any materialized
// cert-pinning recommendations. Observability only (a copy; the GUI shows "what is NOT being decrypted").
func (interception *NetworkExtensionLabTLSInterception) BypassHosts() []string {
	if interception == nil {
		return []string{}
	}
	out := make([]string, len(interception.bypassHosts))
	copy(out, interception.bypassHosts)
	return out
}

// InterceptHosts returns the live intercept (decrypt) host pattern set. A set containing "*" means the default
// posture is decrypt-all (everything is decrypted except the bypass set); a narrower set means selective
// decryption. Observability only (a copy) — surfaced so the Console can SHOW the otherwise-invisible default
// inspection posture (docs/invisible_effective_configuration.md).
func (interception *NetworkExtensionLabTLSInterception) InterceptHosts() []string {
	if interception == nil {
		return []string{}
	}
	out := make([]string, len(interception.hosts))
	copy(out, interception.hosts)
	return out
}

func (interception *NetworkExtensionLabTLSInterception) SetHTTPHandler(handler http.Handler) {
	if interception == nil {
		return
	}
	interception.httpHandler = handler
}

func (interception *NetworkExtensionLabTLSInterception) SetProbeOnly(enabled bool) {
	if interception == nil {
		return
	}
	interception.probeOnly = enabled
}

func (interception *NetworkExtensionLabTLSInterception) OpenTCPConnection(ctx context.Context, route NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	if interception == nil || !interception.Matches(route) {
		return nil, fmt.Errorf("lab TLS interception route is not matched")
	}
	// Buffered (not net.Pipe) so the interception serve()'s writes (ServerHello, response data) do not block
	// synchronously on the endpoint's async read pump — which deadlocked the decrypt-all TLS handshake under a
	// browser's concurrent-flow burst on the CONNECT /steer path. See buffered_interception_pipe.go.
	clientSide, serverSide := NewBufferedInterceptionPipe(1 << 20)
	done := make(chan struct{})
	state := newNetworkExtensionLabTLSConnState()
	go func() {
		defer close(done)
		interception.serve(serverSide, route, state)
	}()
	return networkExtensionLabTLSConn{Conn: clientSide, done: done, state: state}, nil
}

type networkExtensionLabTLSConn struct {
	net.Conn
	done  <-chan struct{}
	state *networkExtensionLabTLSConnState
}

type networkExtensionLabTLSConnState struct {
	downstreamExpected     chan struct{}
	downstreamExpectedOnce sync.Once
}

func newNetworkExtensionLabTLSConnState() *networkExtensionLabTLSConnState {
	return &networkExtensionLabTLSConnState{downstreamExpected: make(chan struct{})}
}

func (state *networkExtensionLabTLSConnState) markDownstreamExpected() {
	if state == nil {
		return
	}
	state.downstreamExpectedOnce.Do(func() {
		close(state.downstreamExpected)
	})
}

func (networkExtensionLabTLSConn) AllowEmptyRuntimeCopyDownstream() bool {
	return true
}

func (conn networkExtensionLabTLSConn) RuntimeCopySessionDone() <-chan struct{} {
	return conn.done
}

func (conn networkExtensionLabTLSConn) RuntimeCopyDownstreamExpected() <-chan struct{} {
	if conn.state == nil {
		return nil
	}
	return conn.state.downstreamExpected
}

func (networkExtensionLabTLSConn) RuntimeCopyDrainWait() time.Duration {
	return NetworkExtensionLabTLSDrainWait
}

// CloseWrite delegates to the wrapped conn (the buffered interception pipe) so the tunnel bridge's
// halfCloseWriteSide sees a real CloseWrite instead of falling back to closing BOTH directions. Without this,
// the embedded net.Conn interface hides bufferedPipeConn.CloseWrite and a request-direction EOF tore down the
// response direction. (fidelity #15)
func (conn networkExtensionLabTLSConn) CloseWrite() error {
	if writeCloser, ok := conn.Conn.(interface{ CloseWrite() error }); ok {
		return writeCloser.CloseWrite()
	}
	return nil
}

// EnablePerTenantInterceptionRoots turns on per-tenant interception roots (Slice 2, docs/pki_trust_model.md):
// primaryTenant keeps the existing default root (so already-trusting devices are unaffected) while every other
// tenant's per-SNI leaves are signed by that tenant's own root — bounding blast radius. OPT-IN and deliberately
// NOT wired to a production flag yet: each tenant's root must first be distributed to its devices' trust stores
// (MDM) or TLS trust breaks for those tenants. This is the engine hook the distribution work will turn on.
func (interception *NetworkExtensionLabTLSInterception) EnablePerTenantInterceptionRoots(primaryTenant string) {
	if interception == nil || interception.rootRegistry == nil {
		return
	}
	interception.rootRegistry.EnablePerTenant(primaryTenant)
}

// EnablePerTenantPerRegionInterceptionRoots is per-tenant roots scoped to THIS edge's region (Slice 4,
// docs/multi_region_edge_architecture_design.md): the same tenant on edges in different regions gets
// DISTINCT, region-identifiable roots, so a leaked regional key MITMs only that region and "the EU key reads EU
// traffic" (residency). region "" is region-agnostic per-tenant. Same opt-in caveat as per-tenant (needs the
// region's root distributed to that region's devices).
func (interception *NetworkExtensionLabTLSInterception) EnablePerTenantPerRegionInterceptionRoots(primaryTenant, region string) {
	if interception == nil || interception.rootRegistry == nil {
		return
	}
	interception.rootRegistry.EnablePerTenantInRegion(primaryTenant, region)
}

// InterceptionSigningScope answers "whose CA will a device actually see", which is NOT the same question as
// "does this tenant have a root". Both are reported, because on this deployment they have had different
// answers: per-tenant roots can be provisioned, listed, distributed to a customer's devices — and then every
// leaf is minted by one shared intermediate anyway. A screen that shows only the roots teaches an operator
// that interception is separated per tenant when it is not.
type InterceptionSigningScope struct {
	// Configured is how the ROOT REGISTRY resolves: shared | per-tenant | per-region.
	Configured string `json:"configured"`
	// Effective is what actually signs a leaf, which the issuer above the root decides.
	Effective string `json:"effective"`
	// PerTenantSigning is the single fact worth acting on: false means a tenant's own root signs nothing.
	PerTenantSigning bool   `json:"per_tenant_signing"`
	Note             string `json:"note"`
}

// InterceptionRootScope reports both halves of that question for the admin surface.
func (interception *NetworkExtensionLabTLSInterception) InterceptionRootScope() InterceptionSigningScope {
	if interception == nil {
		return InterceptionSigningScope{Configured: "none", Effective: "none", Note: "interception is not enabled on this node"}
	}
	configured := interception.rootRegistry.Scope()
	interception.issuerMu.Lock()
	offline := interception.offlineIssuer != nil
	useIntermediate := interception.useIntermediate
	perTenantOffline := len(interception.offlineTenantIssuers)
	primary := interception.offlinePrimaryTenant
	// Whether the primary organization has an offline issuer of its OWN. Read under the same lock as the
	// count, so the sentence built from it cannot describe a state that never existed.
	primaryHasOwn := false
	if key := normalizeInterceptionTenantKey(primary); key != "" {
		_, primaryHasOwn = interception.offlineTenantIssuers[key]
	}
	interception.issuerMu.Unlock()

	switch {
	case perTenantOffline > 0:
		// Each organization's leaves are signed by an intermediate issued by ITS OWN offline root, and an
		// organization without one is refused rather than signed under somebody else's. Reported as its own
		// mode because it is neither of the two that existed before: the registry may still say "shared" —
		// those Edge-generated roots are not what signs here — and an operator reading `configured` alone
		// would conclude the opposite of the truth.
		note := fmt.Sprintf("%d organization(s) sign under their own offline root; any other organization is REFUSED rather than signed under another's CA", perTenantOffline)
		// ★ THIS SENTENCE USED TO BE UNCONDITIONAL (2026-08-19, seen the moment the lab tenant was moved). It
		// named the node's own organization as the one still on the node-wide intermediate whenever a primary
		// tenant was configured — including after that organization had been given its own root, which is the
		// whole point of configuring it. The screen went on saying the deployment had not reached the state it
		// had just reached, and the operator who did the work would have been the one told it had not happened.
		if strings.TrimSpace(primary) != "" {
			if primaryHasOwn {
				note += "; every organization on this node, including the node's own, signs under its own root, " +
					"so the node-wide intermediate now signs nothing and can be retired"
			} else {
				note += fmt.Sprintf("; %q keeps the node-wide intermediate its devices already trust", primary)
			}
		}
		return InterceptionSigningScope{
			Configured: configured, Effective: "per_tenant_offline_intermediate", PerTenantSigning: true, Note: note,
		}
	case offline:
		// The offline lane holds ONE fixed intermediate, issued out-of-band by an offline root, and issuerFor
		// returns it for every tenant before the per-tenant root is ever consulted.
		return InterceptionSigningScope{
			Configured: configured, Effective: "shared_offline_intermediate", PerTenantSigning: false,
			Note: "one fixed intermediate signs every tenant's leaves; per-tenant roots may exist and are not used to sign",
		}
	case configured == "shared":
		effective := "shared_root_direct"
		if useIntermediate {
			effective = "shared_root_intermediate"
		}
		return InterceptionSigningScope{
			Configured: configured, Effective: effective, PerTenantSigning: false,
			Note: "one root for every tenant; provisioned per-tenant roots are not used to sign",
		}
	default:
		effective := "per_tenant_root_direct"
		if useIntermediate {
			effective = "per_tenant_intermediate"
		}
		return InterceptionSigningScope{
			Configured: configured, Effective: effective, PerTenantSigning: true,
			Note: "each tenant's leaves are signed under that tenant's own root; its devices must trust it",
		}
	}
}

// SetPerTenantInterceptionRootDir makes per-tenant interception roots durable (survive restart) under dir.
func (interception *NetworkExtensionLabTLSInterception) SetPerTenantInterceptionRootDir(dir string) {
	if interception == nil || interception.rootRegistry == nil {
		return
	}
	interception.rootRegistry.SetStateDir(dir)
}

// ProvisionTenantInterceptionRoot creates (and persists, when a root dir is set) a tenant's interception root and
// returns its cert PEM, so an operator can distribute that root to the tenant's devices BEFORE enabling
// per-tenant scope. Returns the default root for the primary/empty tenant.
func (interception *NetworkExtensionLabTLSInterception) ProvisionTenantInterceptionRoot(tenantID string) (PerTenantRootInfo, error) {
	if interception == nil || interception.rootRegistry == nil {
		return PerTenantRootInfo{}, fmt.Errorf("interception is not enabled")
	}
	return interception.rootRegistry.Provision(tenantID)
}

// ListTenantInterceptionRoots returns the per-tenant roots known this run (resolved/provisioned/loaded).
func (interception *NetworkExtensionLabTLSInterception) ListTenantInterceptionRoots() []PerTenantRootInfo {
	if interception == nil || interception.rootRegistry == nil {
		return nil
	}
	return interception.rootRegistry.List()
}

// issuerFor returns the leaf issuer for a (cache-tenant, root provider): the root itself when the intermediate
// is off (today's chain [leaf, root]), otherwise a per-root rotatable intermediate (chain [leaf, intermediate,
// root]). Intermediates are cached per cache-tenant and regenerated after a rotate.
// issuerFor returns the issuer that signs this tenant's leaves, and the CACHE SCOPE that issuer implies.
//
// ★ THE SCOPE IS NOT COSMETIC. The leaf cache is keyed by (cacheTenant, host), and cacheTenant comes from the
// ROOT REGISTRY — which is "" for every tenant while the registry is in shared scope. Per-tenant offline
// issuers select a signer the registry knows nothing about, so without a scope of their own, tenant A's leaf
// for example.com — signed by A's CA — would be served straight out of the cache to tenant B's device. The
// separation would exist at the signing step and be undone one line later by a map lookup.
func (interception *NetworkExtensionLabTLSInterception) issuerFor(tenantID, cacheTenant string, provider InterceptionRootProvider) (*InterceptionIssuer, string, error) {
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	// Offline-root mode: a fixed intermediate signs the leaf; the root key is not on the Edge at all.
	//
	// With PER-TENANT offline issuers loaded, which one is not a detail — it is the whole separation. The order
	// is: this tenant's own issuer; else the default intermediate, but ONLY for the organization that
	// intermediate belongs to (or for a flow whose tenant did not resolve at all, which is what happens today
	// and which the device's own trust store refuses anyway if it is somebody else's); else REFUSED.
	//
	// The refusal is the point. Falling back to another tenant's intermediate would mint, under customer A's
	// name, the certificate customer B's browser is shown — and it would succeed, so nothing would look wrong
	// until somebody read a certificate. An operator who has enabled per-tenant signing and not yet given an
	// organization its intermediate gets no interception for that organization, loudly, instead.
	// A revoked organization has NO authority until a replacement is loaded, whatever else this node holds.
	// Checked before every fallback below, because each of those fallbacks is a different way of quietly
	// signing for somebody whose key was just declared compromised.
	if reason, dead := interception.revokedTenants[normalizeInterceptionTenantKey(tenantID)]; dead {
		return nil, "", fmt.Errorf("the interception authority of %q was REVOKED on this node (%s), so its traffic "+
			"is NOT intercepted until a replacement issuer is loaded — it is deliberately not signed under any "+
			"other authority", tenantID, reason)
	}
	if len(interception.offlineTenantIssuers) > 0 {
		key := normalizeInterceptionTenantKey(tenantID)
		if issuer, ok := interception.offlineTenantIssuers[key]; ok {
			interception.countSigning("own_offline_root")
			return issuer, "offline_tenant:" + key, nil
		}
		if interception.offlineIssuer != nil &&
			(key == "" || key == normalizeInterceptionTenantKey(interception.offlinePrimaryTenant)) {
			// ★★ A FLOW WHOSE TENANT DID NOT RESOLVE IS SIGNED UNDER A NAMED CUSTOMER'S AUTHORITY (2026-08-18).
			// The comment above says the device's own trust store refuses it — that is true of somebody ELSE's
			// device, and false of the primary organization's own devices, which trust this anchor and accept
			// the certificate without complaint. So the one case where it matters is the one case it succeeds.
			//
			// It is recorded before it is refused, because refusing first would have taken interception away
			// from whatever traffic is arriving unattributed today without anyone being able to say how much
			// that is. countSigning is the measurement; the refusal is a separate decision that needs it.
			// ★ MEASURED BEFORE IT WAS CLOSED (2026-08-18, reference lab). With the counter in place the node
			// signed 33 leaves and unattributed_under_primary stayed at 0: every flow resolved to an
			// organization. So refusing this case costs nothing observable here, and the counter remains so
			// that it is visible on the day it does.
			if key == "" {
				interception.countSigning("refused_unattributed")
				return nil, "", fmt.Errorf("per-tenant interception signing is in force and this flow's organization "+
					"did not resolve, so it is NOT intercepted; it is deliberately not signed under %q's authority, "+
					"whose own devices would accept the certificate without complaint", interception.offlinePrimaryTenant)
			}
			interception.countSigning("primary_own")
			return interception.offlineIssuer, "offline_primary:" + normalizeInterceptionTenantKey(interception.offlinePrimaryTenant), nil
		}
		// ★★★ AND AN ORGANIZATION WITH NO CA OF ITS OWN IS NOT AN ORGANIZATION WITH NO AUTHORITY (2026-08-28,
		// measured on the two-region lab: one organization was given its own interception root at 01:02 and the
		// deployment stopped decrypting everything else, invisibly).
		//
		// This used to refuse here, and the refusal named the right hazard for the wrong case. Falling back to
		// the node-wide intermediate ABOVE is dangerous because that intermediate belongs to one NAMED customer,
		// and minting customer B's certificate under customer A's name is a cross-customer act. The deployment's
		// OWN interception root is not that. It is what this deployment tells a customer it inspects them under
		// until they bring their own — /admin/tenant-interception-authority answers exactly that sentence — and
		// it is the anchor every device of this deployment already trusts.
		//
		// So giving ONE organization its own authority must not take inspection away from all the others. It did:
		// the sentence below was handed to the TLS stack, which turned it into an `internal error` alert, and the
		// only other trace was a counter nobody had reason to open.
		if iss, scope, ok := interception.deploymentOwnIssuerLocked(cacheTenant, provider); ok {
			interception.countSigningFor("deployment_root_no_own_authority", tenantID)
			return iss, scope, nil
		}
		interception.countSigningFor("refused_no_authority", tenantID)
		return nil, "", fmt.Errorf("per-tenant interception signing is in force, organization %q has no interception "+
			"intermediate on this node, and this node holds no interception authority of its own to fall back to, so "+
			"its traffic is NOT intercepted; load one (POST /admin/interception-intermediate/%s) "+
			"rather than signing it under another organization's CA", tenantID, tenantID)
	}
	// ★★★ EVERY BRANCH THAT SIGNS IS COUNTED, AND THREE OF THEM WERE NOT (2026-08-26, measured on the
	// release lab). countSigning was reached only when PER-TENANT offline issuers were loaded. The mode the
	// installer actually generates — the deployment's own root signing leaves directly — returned an issuer
	// from the line below and counted nothing, so /admin/interception-intermediate reported
	// `signing_counts_since_start: {}` for ever.
	//
	// That is not a cosmetic gap. It is the number an operator looks at to answer "is this deployment
	// inspecting", and on a generated deployment it answered "no" while the Edge was minting leaves under
	// the deployment's interception CA. Measured the same day: a flow to example.com came back signed by
	// "DSSE Deployment Interception CA" and the counter stayed empty. A reported field written on one branch
	// out of four is worse than no field, because the zero is believed.
	if interception.offlineIssuer != nil {
		interception.countSigning("offline_root")
		return interception.offlineIssuer, "", nil
	}
	if !interception.useIntermediate {
		// The deployment's own root signs leaves directly. This is what dsse-install generates.
		interception.countSigning("direct_root")
		return directInterceptionIssuer(provider), "", nil
	}
	if iss, ok := interception.interceptIssuers[cacheTenant]; ok {
		interception.countSigning("node_intermediate")
		return iss, "", nil
	}
	iss, err := newIntermediateInterceptionIssuer(provider, interception.intermediatePermittedDNS, interception.now)
	if err != nil {
		return nil, "", err
	}
	interception.interceptIssuers[cacheTenant] = iss
	interception.countSigning("node_intermediate")
	return iss, "", nil
}

// deploymentOwnIssuerLocked returns THIS DEPLOYMENT's own interception issuer — the root signing directly, or
// the node's own intermediate under it. Never the node-wide offline issuer, which belongs to one named
// organization and is the one thing that must not sign for another.
//
// Called with issuerMu held.
func (interception *NetworkExtensionLabTLSInterception) deploymentOwnIssuerLocked(cacheTenant string,
	provider InterceptionRootProvider) (*InterceptionIssuer, string, bool) {
	if provider == nil || provider.Certificate() == nil {
		return nil, "", false
	}
	if !interception.useIntermediate {
		return directInterceptionIssuer(provider), "", true
	}
	if iss, ok := interception.interceptIssuers[cacheTenant]; ok {
		return iss, "", true
	}
	iss, err := newIntermediateInterceptionIssuer(provider, interception.intermediatePermittedDNS, interception.now)
	if err != nil {
		return nil, "", false
	}
	interception.interceptIssuers[cacheTenant] = iss
	return iss, "", true
}

// normalizeInterceptionTenantKey is how a tenant id becomes a map key here: trimmed and lower-cased, the same
// way every other tenant boundary in this tree compares them, so a stray space or a capital letter cannot give
// an organization a second, empty PKI.
func normalizeInterceptionTenantKey(tenantID string) string {
	return strings.ToLower(strings.TrimSpace(tenantID))
}

// EnableInterceptionIntermediate turns on the rotatable intermediate (Slice 3): the root signs an intermediate
// (and can then stay offline/HSM), the intermediate signs leaves, and clients still anchor on the same root —
// so this is SAFE to enable without re-distributing trust (unlike per-tenant roots). permittedDNS, if non-empty,
// name-constrains what the intermediate can mint (leave empty under decrypt-all). Resets the issuer + leaf caches.
func (interception *NetworkExtensionLabTLSInterception) EnableInterceptionIntermediate(permittedDNS []string) {
	if interception == nil {
		return
	}
	interception.issuerMu.Lock()
	interception.useIntermediate = true
	interception.intermediatePermittedDNS = append([]string(nil), permittedDNS...)
	interception.interceptIssuers = map[string]*InterceptionIssuer{}
	interception.issuerMu.Unlock()
	interception.mu.Lock()
	interception.leafCache = map[string]tls.Certificate{}
	interception.mu.Unlock()
}

// RotateInterceptionIntermediate issues a FRESH intermediate (root unchanged), so the exposed online signing key
// rotates with NO flag day — devices keep trusting the same root; subsequent leaves chain through the new
// intermediate. No-op when the intermediate is off. Resets the issuer + leaf caches so new leaves are re-minted.
func (interception *NetworkExtensionLabTLSInterception) RotateInterceptionIntermediate() {
	if interception == nil {
		return
	}
	interception.issuerMu.Lock()
	interception.interceptIssuers = map[string]*InterceptionIssuer{}
	interception.issuerMu.Unlock()
	interception.mu.Lock()
	interception.leafCache = map[string]tls.Certificate{}
	interception.mu.Unlock()
}

func (interception *NetworkExtensionLabTLSInterception) RootCertificatePEM() []byte {
	if interception == nil {
		return nil
	}
	return append([]byte(nil), interception.rootCertPEM...)
}

func (interception *NetworkExtensionLabTLSInterception) serve(conn net.Conn, route NetworkExtensionRuntimeCopyTCPRoute, connState *networkExtensionLabTLSConnState) {
	defer conn.Close()
	// In SNI mode the tunnel handler does the peek, so only what is to be intercepted reaches serve(); the
	// rest is bridged directly by the dialer's raw forward, without a net.Pipe in the way.
	//
	// Fingerprint-transparency: peek the browser's REAL ClientHello here (this path ALWAYS runs for
	// interception, unlike the opt-in SNI peek) so the browser-mimic egress can replay the endpoint's exact
	// TLS fingerprint. The peeked bytes are replayed into tls.Server via a prefixed conn so the handshake is
	// byte-identical. No-op cost beyond one record read; never blocks the handshake.
	// The peeked bytes are replayed to the local TLS terminator via the prefixed conn. They used to ALSO be captured
	// for replay as the egress ClientHello (browseregress mimicked the endpoint's own fingerprint); the broker
	// generates its own Chrome ClientHello, so there is nothing left to replay them into.
	if _, helloBytes, _ := ossintercept.PeekClientHelloSNI(conn); len(helloBytes) > 0 {
		conn = &NetworkExtensionLabTLSPrefixedConn{Conn: conn, Prefix: helloBytes}
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Offer h2 first. If the browser takes it, one host multiplexes onto one connection, so a heavy
		// many-host page under decrypt-all does not spray connections and tunnels until something runs out.
		NextProtos: []string{"h2", "http/1.1"},
		// Session resumption is on: SessionTicketsDisabled's zero value is false. The shared ticket keys set
		// below let a ticket issued by a different per-connection Config still be decrypted, so a reconnect
		// skips the full handshake and its asymmetric work.
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			leafHost := networkExtensionLabTLSLeafHost(route.Host, hello)
			cert, err := interception.leafCertificate(route.TenantID, leafHost)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}
	if len(interception.sessionTicketKeys) > 0 {
		cfg.SetSessionTicketKeys(interception.sessionTicketKeys)
	}
	tlsConn := tls.Server(conn, cfg)
	defer tlsConn.Close()
	decisionHost, _ := interception.decisionHost(route)
	if err := tlsConn.Handshake(); err != nil {
		// The client refused the interception certificate, which may mean it pins. Learn it, and once the
		// threshold is reached raw-forward that destination from then on — still steered, only undecrypted.
		// That is what stops a pinning application's reconnect storm without a static list.
		newlyPinned := interception.recordHandshakeOutcome(decisionHost, false)
		if newlyPinned {
			// Actionable: the edge just learned this destination is cert-pinned and will now bypass decryption
			// for it — a real state change worth an INFO breadcrumb.
			Infof("network_extension_lab_tls progress=handshake_failed category=%s pin_learned=true",
				NetworkExtensionLabTLSErrorCategory(err))
		} else {
			// A plain per-connection handshake failure (client reset / probe / EOF) — benign hot-path noise.
			NetworkExtensionHotPathLog("network_extension_lab_tls progress=handshake_failed category=%s pin_learned=false",
				NetworkExtensionLabTLSErrorCategory(err))
		}
		return
	}
	interception.recordHandshakeOutcome(decisionHost, true)
	state := tlsConn.ConnectionState()
	NetworkExtensionHotPathLog(
		"network_extension_lab_tls progress=handshake_completed alpn_category=%s sni_match_category=%s",
		NetworkExtensionLabTLSALPNCategory(state.NegotiatedProtocol),
		NetworkExtensionLabTLSSNIMatchCategory(state.ServerName, route.Host),
	)
	// An ALPN of h2 is handed to the multiplexing HTTP/2 server; only on the path that forwards to SWG egress.
	if state.NegotiatedProtocol == "h2" && interception.httpHandler != nil {
		interception.serveHTTP2(tlsConn, route, connState)
		return
	}
	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			// Per-connection request-read failure (keep-alive close / client EOF) — benign hot-path noise.
			NetworkExtensionHotPathLog("network_extension_lab_tls progress=http_request_read_failed category=%s", NetworkExtensionLabTLSErrorCategory(err))
			return
		}
		NetworkExtensionHotPathLog("network_extension_lab_tls progress=http_request_read_completed")
		if connState != nil {
			connState.markDownstreamExpected()
		}
		if interception.httpHandler != nil {
			keepAlive, ferr := interception.serveForwardedHTTPWithReader(tlsConn, reader, req, route)
			if ferr != nil {
				log.Printf("network_extension_lab_tls progress=http_forward_failed category=%s", NetworkExtensionLabTLSErrorCategory(ferr))
				return
			}
			// To read the next request on a keep-alive connection, this request's body has to be consumed
			// completely, which is what moves the reader to the next request boundary.
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			// If the response is framed for keep-alive (a Content-Length and no Connection: close) and the
			// client did not ask to close, carry on over the same connection. That is what avoids a tunnel
			// per connection under decrypt-all, and Chrome running out of sockets.
			if !keepAlive || req.Close {
				return
			}
			continue
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		body := "dsse lab tls interception ok\n"
		if req.Method == http.MethodHead {
			body = ""
		}
		if _, err := fmt.Fprintf(
			tlsConn,
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\nX-Dsse-Lab-TLS-Interception: observed\r\nX-Dsse-Lab-TLS-Target-Host: %s\r\n\r\n%s",
			len(body),
			safeNetworkExtensionLabTLSHeaderValue(networkExtensionLabTLSResponseHost(req, route)),
			body,
		); err != nil {
			log.Printf("network_extension_lab_tls progress=http_response_write_failed category=%s", NetworkExtensionLabTLSErrorCategory(err))
			return
		}
		NetworkExtensionHotPathLog("network_extension_lab_tls progress=http_response_written bytes=%d", len(body))
		return
	}
}

func networkExtensionLabTLSLeafHost(routeHost string, hello *tls.ClientHelloInfo) string {
	if hello != nil {
		if _, ok := NormalizeNetworkExtensionRuntimeCopyDestinationHost(hello.ServerName); ok {
			return hello.ServerName
		}
	}
	return routeHost
}

func (interception *NetworkExtensionLabTLSInterception) ServeForwardedHTTP(conn io.Writer, req *http.Request, route NetworkExtensionRuntimeCopyTCPRoute) error {
	_, err := interception.serveForwardedHTTPWithReader(conn, nil, req, route)
	return err
}

// serveForwardedHTTPWithReader forwards one intercepted request and returns (keepAlive, err). keepAlive is
// true when the response was framed with a definite length and no Connection: close, so the next request can
// be taken on the same connection. Streaming (framed by EOF) and a WebSocket takeover return false: the
// connection is closed.
func (interception *NetworkExtensionLabTLSInterception) serveForwardedHTTPWithReader(conn io.Writer, downstreamReader io.Reader, req *http.Request, route NetworkExtensionRuntimeCopyTCPRoute) (bool, error) {
	probeDecision := networkExtensionLabTLSProbeDecision(req)
	// Explicit gate so the 4 sha256 fingerprints + category functions in the args are SKIPPED when quiet
	// (probeDecision itself is needed by the logic below, so it stays computed).
	if NetworkExtensionHotPathLogsOn() {
		log.Printf(
			"network_extension_lab_tls request_observed probe_decision=%s request_target_category=%s request_path_category=%s request_method_category=%s request_fetch_dest_category=%s request_accept_category=%s request_path_fingerprint=%s request_uri_fingerprint=%s request_host_category=%s request_host_fingerprint=%s route_host_fingerprint=%s",
			probeDecision,
			networkExtensionLabTLSRequestTargetCategory(req),
			networkExtensionLabTLSRequestPathCategory(req),
			NetworkExtensionLabTLSRequestMethodCategory(req),
			NetworkExtensionLabTLSFetchDestCategory(req),
			NetworkExtensionLabTLSAcceptCategory(req),
			NetworkExtensionLabTLSFingerprint(req.URL.Path),
			NetworkExtensionLabTLSFingerprint(req.RequestURI),
			NetworkExtensionLabTLSRouteHostCategory(req.Host),
			NetworkExtensionLabTLSFingerprint(req.Host),
			NetworkExtensionLabTLSFingerprint(route.Host),
		)
	}
	if networkExtensionLabTLSProbeDecisionMatches(probeDecision) {
		if err := writeNetworkExtensionLabTLSProbeResponse(conn, req.Method, networkExtensionLabTLSResponseHost(req, route)); err != nil {
			return false, err
		}
		NetworkExtensionHotPathLog("network_extension_lab_tls progress=synthetic_probe_response_written")
		return true, nil
	}
	if interception.probeOnly {
		if err := writeNetworkExtensionLabTLSProbeOnlyNonProbeResponse(conn, req.Method, networkExtensionLabTLSResponseHost(req, route)); err != nil {
			return false, err
		}
		NetworkExtensionHotPathLog("network_extension_lab_tls progress=synthetic_non_probe_response_written")
		return true, nil
	}
	forwardReq, err := BuildNetworkExtensionLabTLSForwardRequest(req, route)
	if err != nil {
		return false, err
	}

	recorder := newNetworkExtensionLabTLSResponseRecorderWithTunnel(conn, downstreamReader)
	recorder.clientWebSocketKey = req.Header.Get("Sec-WebSocket-Key")
	NetworkExtensionHotPathLog("network_extension_lab_tls progress=http_forward_started")
	interception.httpHandler.ServeHTTP(recorder, forwardReq)
	statusCode := recorder.StatusCode()
	outcomeCategory := NetworkExtensionLabTLSForwardOutcomeCategory(recorder)
	upstreamErrorCategory := NetworkExtensionLabTLSForwardUpstreamErrorCategory(recorder, outcomeCategory)
	if recorder.directResponseHandled() {
		if err := recorder.directResponseError(); err != nil {
			logNetworkExtensionLabTLSForwardAborted(statusCode, outcomeCategory, upstreamErrorCategory, err, recorder.writtenByteCount(), recorder.streaming)
			return false, err
		}
		logNetworkExtensionLabTLSForwardCompleted(statusCode, outcomeCategory, upstreamErrorCategory)
		// A directResponse takes the connection over — a WebSocket, for instance — so keep-alive is not
		// possible.
		return false, nil
	}
	if err := recorder.finishStreamedResponse(); err != nil {
		logNetworkExtensionLabTLSForwardAborted(statusCode, outcomeCategory, upstreamErrorCategory, err, recorder.writtenByteCount(), recorder.streaming)
		return false, err
	}
	logNetworkExtensionLabTLSForwardCompleted(statusCode, outcomeCategory, upstreamErrorCategory)
	NetworkExtensionHotPathLog("network_extension_lab_tls progress=http_response_written bytes=%d", recorder.writtenByteCount())
	// Both the buffered form (a Content-Length) and the streaming form (chunked, already terminated) are
	// definitely framed, so keep-alive is possible. On an error finishStreamedResponse above returns err and
	// takes the false path.
	return true, nil
}

// BuildNetworkExtensionLabTLSForwardRequest rebuilds a decrypted request as the forward request handed to SWG
// egress, carrying the real destination URL in a header. Shared by the HTTP/1.1 and HTTP/2 paths.
func BuildNetworkExtensionLabTLSForwardRequest(req *http.Request, route NetworkExtensionRuntimeCopyTCPRoute) (*http.Request, error) {
	target, err := NetworkExtensionLabTLSTargetURL(req, route)
	if err != nil {
		return nil, err
	}
	// source_ip audit: use the mTLS tunnel's OBSERVED peer address (trust-boundary fact) rather than the
	// synthetic placeholder, so the access log records the real network origin, not an agent-claimed value.
	sourceAddr := "network-extension-runtime-copy:0"
	if route.TunnelSourceIP != "" {
		sourceAddr = route.TunnelSourceIP
	}
	forwardReq := &http.Request{
		Method:        req.Method,
		URL:           &url.URL{Scheme: "http", Host: "network-extension-runtime-copy.local", Path: EdgeSWGHTTPEgressPath},
		Header:        req.Header.Clone(),
		Body:          req.Body,
		ContentLength: req.ContentLength,
		Host:          "network-extension-runtime-copy.local",
		RemoteAddr:    sourceAddr,
		RequestURI:    EdgeSWGHTTPEgressPath,
	}
	// An HTTP/2 server supplies a non-nil Body even when the request has no
	// body. For an outgoing request, however, a non-nil Body with length zero
	// means unknown length. Preserve the server's known-empty body so the
	// upstream HEADERS can carry END_STREAM, just as for an HTTP/1.1 GET.
	// Extended CONNECT keeps its body: it is the bidirectional WebSocket stream.
	if req.ProtoMajor == 2 && req.ContentLength == 0 && req.Method != http.MethodConnect {
		forwardReq.Body = http.NoBody
	}
	// DETACH the egress from the client's request-context CANCELLATION (#28). Go's http.Server cancels
	// req.Context() as soon as the client's send side reaches EOF — a half-close (FIN on h1, END-of-request on
	// the connection) — which a client does the instant it finishes sending and starts waiting for the reply.
	// The ChatGPT desktop app does exactly that; browsers (and the macOS NE, which never half-closes at the
	// tunnel) do not, which is why they were unaffected. When req.Context() is canceled, the egress round-trip
	// that fetches the streamed reply is canceled too (the broker logs "context canceled" for chat.openai.com),
	// so the Edge sends the response HEADERS and then nothing — "send works, receive never arrives".
	//
	// WithoutCancel keeps the request's VALUES (the metadata below and the egress markers) but drops the
	// cancellation, so a half-close no longer aborts the reply. A FULL client disconnect still stops the
	// response: writing it back fails once the client connection is gone, and the flow tears down normally. The
	// deadline is dropped too, which is correct — a streamed reply (SSE) is long-lived by design.
	forwardCtx := WithSWGNERuntimeUsed(context.WithoutCancel(req.Context()))
	if route.DeviceIdentity != "" {
		forwardCtx = WithTransportDevice(forwardCtx, route.DeviceIdentity)
	}
	if route.OSUser != "" {
		forwardCtx = WithOSUser(forwardCtx, route.OSUser)
	}
	if route.SourceApp != "" {
		forwardCtx = WithSourceApp(forwardCtx, route.SourceApp)
	}
	// ★★★ AND WHOSE FLOW IT IS, WHICH DECRYPTION WAS LOSING (2026-09-01, measured on a private HTTPS asset).
	//
	// The device identity, the OS user and the source app all ride across this boundary already. The
	// ORGANIZATION did not — so the handler on the far side built its decision request from the policy
	// bundle's tenant, which on a deployment that serves customers is the operator's, and its upstream then
	// looked for a connector in the wrong organization, found none, and dialled a private address directly:
	//
	//	swg egress: upstream request failed … dial tcp 10.60.1.176:443: i/o timeout
	//
	// The flow was decrypted correctly — the device was shown a certificate minted by its own organization's
	// interception authority — and then could not be delivered. Interception without the organization is a
	// flow this deployment can read and cannot route.
	if route.TenantID != "" {
		forwardCtx = WithFlowTenant(forwardCtx, route.TenantID)
	}
	forwardReq = forwardReq.WithContext(forwardCtx)
	forwardReq.Header.Set(EdgeSWGHTTPEgressTargetURLHeader, target.String())
	forwardReq.Header.Set(EdgeSWGHTTPEgressNERuntimeHeader, "runtime_copy_lab_tls")
	return forwardReq, nil
}

// serveHTTP2 runs an HTTP/2 server over the decrypted TLS connection when the ALPN is h2. HTTP/2 multiplexes
// every stream onto one connection, so a browser needs one connection and one tunnel per host, and a heavy
// many-host page under decrypt-all does not spray sockets and tunnels until something runs out. Framing,
// keep-alive and multiplexing are http2.Server's, so nothing here frames by hand.
func (interception *NetworkExtensionLabTLSInterception) serveHTTP2(tlsConn net.Conn, route NetworkExtensionRuntimeCopyTCPRoute, connState *networkExtensionLabTLSConnState) {
	// High MaxConcurrentStreams: the default (250) REFUSES the browser's 251st concurrent stream on one origin's
	// connection with REFUSED_STREAM -> the request fails with net::ERR_FAILED before any response (no cancel).
	// Under a heavy infinite-scroll page the browser opens many concurrent requests, and the browser-faithful
	// egress broker holds each stream slightly longer (the extra edge->broker->origin hop) so more are in flight at
	// once -> the cap is hit and a request like Amazon's getAsins gets refused -> stuck skeleton. Raise the cap so
	// the browser's concurrency is never refused.
	server := &http2.Server{MaxConcurrentStreams: 10000}
	server.ServeConn(tlsConn, &http2.ServeConnOpts{
		Handler: interception.networkExtensionLabTLSHTTP2Handler(route, connState),
	})
}

func (interception *NetworkExtensionLabTLSInterception) networkExtensionLabTLSHTTP2Handler(route NetworkExtensionRuntimeCopyTCPRoute, connState *networkExtensionLabTLSConnState) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if connState != nil {
			connState.markDownstreamExpected()
		}
		probeDecision := networkExtensionLabTLSProbeDecision(r)
		// h2 is the common path (most sites), so this is the real per-request hot log: gate the 4 sha256
		// fingerprints + category functions when quiet (probeDecision stays computed for the logic below).
		if NetworkExtensionHotPathLogsOn() {
			log.Printf(
				"network_extension_lab_tls request_observed probe_decision=%s request_target_category=%s request_path_category=%s request_method_category=%s request_fetch_dest_category=%s request_accept_category=%s request_path_fingerprint=%s request_uri_fingerprint=%s request_host_category=%s request_host_fingerprint=%s route_host_fingerprint=%s alpn_category=h2",
				probeDecision,
				networkExtensionLabTLSRequestTargetCategory(r),
				networkExtensionLabTLSRequestPathCategory(r),
				NetworkExtensionLabTLSRequestMethodCategory(r),
				NetworkExtensionLabTLSFetchDestCategory(r),
				NetworkExtensionLabTLSAcceptCategory(r),
				NetworkExtensionLabTLSFingerprint(r.URL.Path),
				NetworkExtensionLabTLSFingerprint(r.RequestURI),
				NetworkExtensionLabTLSRouteHostCategory(r.Host),
				NetworkExtensionLabTLSFingerprint(r.Host),
				NetworkExtensionLabTLSFingerprint(route.Host),
			)
		}
		if networkExtensionLabTLSProbeDecisionMatches(probeDecision) {
			networkExtensionLabTLSWriteProbeResponseToResponseWriter(w, r.Method, networkExtensionLabTLSResponseHost(r, route))
			return
		}
		if interception.probeOnly {
			w.Header().Set("X-Dsse-Lab-TLS-Interception", "probe-only")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		forwardReq, err := BuildNetworkExtensionLabTLSForwardRequest(r, route)
		if err != nil {
			log.Printf("network_extension_lab_tls progress=http2_forward_target_invalid category=%s", NetworkExtensionLabTLSErrorCategory(err))
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		NetworkExtensionHotPathLog("network_extension_lab_tls progress=http2_forward_started")
		// h2 Extended-CONNECT WebSocket (RFC 8441): translate to an h1 WS upgrade for the origin and tunnel the
		// two streams over this h2 stream. Without this, WS over h2 (Chrome's default to an intercepted origin)
		// fails with close 1006.
		if isNetworkExtensionLabTLSH2WebSocketConnect(r) {
			if perr := prepareNetworkExtensionLabTLSH2WebSocketForwardRequest(forwardReq); perr != nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			wsWriter := &networkExtensionLabTLSHTTP2WebSocketWriter{
				NetworkExtensionLabTLSHTTP2StatusWriter: &NetworkExtensionLabTLSHTTP2StatusWriter{ResponseWriter: w},
				clientBody:                              r.Body,
				clientCtx:                               r.Context(),
			}
			interception.httpHandler.ServeHTTP(wsWriter, forwardReq)
			return
		}
		sw := &NetworkExtensionLabTLSHTTP2StatusWriter{ResponseWriter: w}
		interception.httpHandler.ServeHTTP(sw, forwardReq)
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		if NetworkExtensionHotPathLogsOn() {
			log.Printf(
				"network_extension_lab_tls progress=http2_forward_completed status_code=%d request_method_category=%s request_fetch_dest_category=%s swg_outcome_category=%s upstream_error_category=%s set_cookie_count=%d content_type_category=%s content_encoding_category=%s response_body_bytes=%d",
				status,
				NetworkExtensionLabTLSRequestMethodCategory(r),
				NetworkExtensionLabTLSFetchDestCategory(r),
				networkExtensionLabTLSNonEmptyCategory(sw.swgOutcome),
				networkExtensionLabTLSNonEmptyCategory(sw.swgUpstreamErr),
				sw.setCookieCount,
				networkExtensionLabTLSContentTypeCategory(sw.contentType),
				networkExtensionLabTLSNonEmptyCategory(sw.contentEncoding),
				sw.bodyBytes,
			)
		}
	})
}

// networkExtensionLabTLSContentTypeCategory reduces a Content-Type to a coarse, non-sensitive enum.
func networkExtensionLabTLSContentTypeCategory(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch {
	case v == "":
		return "none"
	case strings.Contains(v, "json"):
		return "json"
	case strings.Contains(v, "javascript"):
		return "javascript"
	case strings.Contains(v, "html"):
		return "html"
	case strings.Contains(v, "css"):
		return "css"
	case strings.HasPrefix(v, "image/"):
		return "image"
	case strings.HasPrefix(v, "font/") || strings.Contains(v, "font"):
		return "font"
	case strings.Contains(v, "protobuf") || strings.Contains(v, "x-protobuffer"):
		return "protobuf"
	case strings.HasPrefix(v, "text/"):
		return "text"
	default:
		return "other"
	}
}

// NetworkExtensionLabTLSHTTP2StatusWriter wraps a ResponseWriter to observe an h2 forward's response status,
// the SWG outcome and any upstream error. It satisfies the type assertions SWG egress makes for outcome and
// upstream-error, so the h2 path can log its result as the same non-sensitive enums.
type NetworkExtensionLabTLSHTTP2StatusWriter struct {
	http.ResponseWriter
	status          int
	swgOutcome      string
	swgUpstreamErr  string
	setCookieCount  int
	contentType     string
	contentEncoding string
	bodyBytes       int
}

func (w *NetworkExtensionLabTLSHTTP2StatusWriter) captureResponseHeaders() {
	h := w.Header()
	w.setCookieCount = len(h.Values("Set-Cookie"))
	w.contentType = h.Get("Content-Type")
	w.contentEncoding = h.Get("Content-Encoding")
}

func (w *NetworkExtensionLabTLSHTTP2StatusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.captureResponseHeaders()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *NetworkExtensionLabTLSHTTP2StatusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
		w.captureResponseHeaders()
	}
	n, err := w.ResponseWriter.Write(p)
	w.bodyBytes += n
	return n, err
}

func (w *NetworkExtensionLabTLSHTTP2StatusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *NetworkExtensionLabTLSHTTP2StatusWriter) SetSWGHTTPEgressOutcome(outcome string) {
	w.swgOutcome = strings.TrimSpace(outcome)
}

func (w *NetworkExtensionLabTLSHTTP2StatusWriter) SetSWGHTTPEgressUpstreamErrorCategory(category string) {
	w.swgUpstreamErr = strings.TrimSpace(category)
}

func networkExtensionLabTLSNonEmptyCategory(value string) string {
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	return value
}

// networkExtensionLabTLSWriteProbeResponseToResponseWriter returns a synthesised probe response through an
// http.ResponseWriter, for the HTTP/2 path where the server does the framing.
func networkExtensionLabTLSWriteProbeResponseToResponseWriter(w http.ResponseWriter, method string, host string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Dsse-Lab-TLS-Interception", "observed")
	w.Header().Set("X-Dsse-Lab-TLS-Target-Host", safeNetworkExtensionLabTLSHeaderValue(host))
	w.WriteHeader(http.StatusOK)
	if method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, "dsse lab tls interception probe ok\n")
}

func logNetworkExtensionLabTLSForwardCompleted(statusCode int, outcomeCategory string, upstreamErrorCategory string) {
	NetworkExtensionHotPathLog(
		"network_extension_lab_tls progress=http_forward_completed status_code=%d egress_outcome_category=%s status_category=%s upstream_error_category=%s",
		statusCode,
		outcomeCategory,
		NetworkExtensionLabTLSForwardStatusCategory(statusCode, outcomeCategory),
		upstreamErrorCategory,
	)
}

func logNetworkExtensionLabTLSForwardAborted(statusCode int, outcomeCategory string, upstreamErrorCategory string, err error, streamedBytes int, streaming bool) {
	log.Printf(
		"network_extension_lab_tls progress=http_forward_aborted status_code=%d egress_outcome_category=%s status_category=%s upstream_error_category=%s downstream_write_category=%s streamed_bytes=%d response_framing=%s",
		statusCode,
		outcomeCategory,
		NetworkExtensionLabTLSForwardStatusCategory(statusCode, outcomeCategory),
		upstreamErrorCategory,
		NetworkExtensionLabTLSErrorCategory(err),
		streamedBytes,
		networkExtensionLabTLSResponseFramingCategory(streaming),
	)
}

// networkExtensionLabTLSResponseFramingCategory returns how a response was framed, as a non-sensitive enum:
// streaming means framed by EOF (Connection: close, a large response of unknown length), buffered means a
// Content-Length, which is everything that fits under the threshold.
func networkExtensionLabTLSResponseFramingCategory(streaming bool) string {
	if streaming {
		return "streaming_eof"
	}
	return "buffered_content_length"
}

func (interception *NetworkExtensionLabTLSInterception) leafCertificate(tenantID, host string) (tls.Certificate, error) {
	normalizedHost, ok := NormalizeNetworkExtensionRuntimeCopyDestinationHost(host)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("invalid lab TLS leaf host")
	}
	normalizedHost = strings.TrimSuffix(strings.ToLower(normalizedHost), ".")
	// Resolve the signing root for this tenant. With per-tenant isolation off (default) this is the single
	// default provider and cacheTenant is "" — so the cache key and the minted leaf are exactly as before.
	provider, cacheTenant, err := interception.rootRegistry.resolve(tenantID)
	if err != nil {
		return tls.Certificate{}, err
	}
	// The issuer is the root itself (chain [leaf, root], default) or a per-root rotatable intermediate
	// (chain [leaf, intermediate, root]) when Slice 3 is enabled. The leaf is signed by issuer.signingCert.
	issuer, issuerScope, err := interception.issuerFor(tenantID, cacheTenant, provider)
	if err != nil {
		return tls.Certificate{}, err
	}
	// The signer is part of the cache identity, not just the host. See issuerFor: with per-tenant offline
	// issuers the root registry contributes nothing to cacheTenant, so without this the cache would hand one
	// organization a certificate minted under another's CA.
	cacheKey := cacheTenant + "\x00" + issuerScope + "\x00" + normalizedHost
	interception.mu.Lock()
	now := interception.now
	if cert, ok := interception.leafCache[cacheKey]; ok && networkExtensionLabTLSLeafFresh(cert, now, issuer) {
		interception.mu.Unlock()
		return cert, nil
	}
	leafKey := interception.leafKey
	interception.mu.Unlock()
	// ★★★ REFUSING THE CACHE IS NOT REFUSING TO SIGN (2026-09-08, found by review).
	//
	// The freshness check above rejected the cached leaf when its issuer was no longer usable — and then this
	// function went on to hand that same issuer to x509.CreateCertificate, which signed happily and returned
	// err=nil. Reproduced: a six-minute intermediate, the clock moved seven minutes, and a NEW leaf with a
	// fresh serial came back as a success; the same DER handed to Go's own verifier is refused with
	// "certificate has expired". The test beside the cache said the node would "re-mint and fail loudly" —
	// it re-minted, and the loud half was not written.
	//
	// So the check belongs on the signing path too, and it must refuse rather than fall back: signing under
	// another organization's authority, or under the deployment's shared one, is the defect this file spent
	// 2026-08-18 closing. A refusal here means this organization's traffic is not intercepted until its
	// material is refreshed, which is visible and correct; a signature means every device is handed a
	// certificate it rejects while this node reports itself healthy.
	createdAt := now().UTC()
	if err := issuer.usableAt(createdAt); err != nil {
		return tls.Certificate{}, fmt.Errorf("the interception authority in force for %q cannot sign right now, "+
			"so this flow is NOT intercepted rather than served a certificate every device refuses: %w",
			tenantID, err)
	}
	serialNumber, err := RandomNetworkExtensionLabTLSSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	notBefore := createdAt.Add(-networkExtensionLabTLSLeafBackdate)
	notAfter := createdAt.Add(networkExtensionLabTLSLeafValidity)
	if issuer.pathFrom.After(notBefore) {
		notBefore = issuer.pathFrom
	}
	if issuer.pathUntil.Before(notAfter) {
		notAfter = issuer.pathUntil
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   normalizedHost,
			Organization: []string{NetworkExtensionLabTLSLeafOrganization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// ★★ NO CRL DISTRIBUTION POINT AND NO AIA, AND THAT IS A DECISION (2026-08-19, measured on win-dev-1).
	//
	// A client that treats "cannot check revocation" as fatal refuses this certificate, and the clients that do
	// are the strict ones — so the failure selects for the most careful software on the endpoint:
	//
	//   curl (schannel, default)  -> 000, CRYPT_E_NO_REVOCATION_CHECK
	//   curl --ssl-no-revoke      -> 200
	//
	// Publishing revocation information for THIS certificate would mean answering for one minted moments ago,
	// for one flow, valid for days — a responder that can only ever say "good" about certificates it just
	// created is not a revocation service, it is a formality that satisfies a check. The formality is still
	// worth serving (an empty, signed CRL satisfies a strict client without pretending to more), but it needs a
	// URL an endpoint can reach — and every such URL is another agent-facing address, which is what the enrolment fold of
	// docs/pki_who_owns_which_certificate.ja.md is reducing to one. So it is served on that one port, with the
	// fold, rather than opening a fourth address to close this.
	//
	// The revocation that carries meaning here is elsewhere and does exist: an endpoint removing the
	// interception root (a local act), and this deployment revoking an organization's interception authority
	// (POST /admin/interception-intermediate/{tenant}/revoke, which refuses the revoked fingerprints for good).
	//
	// Until the fold lands, this is an exception a strict client needs, and it is declared in the readiness
	// view rather than left for an operator to discover as a broken tool.
	if ip := net.ParseIP(normalizedHost); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{normalizedHost}
	}
	// when the interception key lives in the hsm-agent, mint the leaf through the agent's PURPOSE-BOUND
	// /sign-cert rather than building the certificate here and handing the agent only a digest. The agent sets
	// IsCA/KeyUsage/ExtKeyUsage from the interception-leaf purpose and bounds the validity, so a compromised Edge
	// cannot turn the interception key into a CA or a client-auth minter. Any non-HSM signer (lab self-signed)
	// keeps building locally — and if the assertion ever fails, this falls back safely to the same local path.
	var leafDER []byte
	if minter, ok := issuer.signer.(InterceptionCertMinter); ok {
		leafDER, err = minter.SignCert(template, issuer.signingCert, &leafKey.PublicKey, "interception-leaf")
	} else {
		log.Printf("network_extension_lab_tls interception_leaf signer_type=%T — /sign-cert unavailable, building the certificate locally", issuer.signer)
		leafDER, err = x509.CreateCertificate(rand.Reader, template, issuer.signingCert, &leafKey.PublicKey, issuer.signer)
	}
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create lab TLS leaf certificate: %w", err)
	}
	cert := tls.Certificate{
		Certificate: append([][]byte{leafDER}, issuer.chain...),
		PrivateKey:  leafKey,
		Leaf:        template,
	}
	interception.mu.Lock()
	defer interception.mu.Unlock()
	if cached, ok := interception.leafCache[cacheKey]; ok && networkExtensionLabTLSLeafFresh(cached, now, issuer) {
		return cached, nil
	}
	interception.leafCache[cacheKey] = cert
	return cert, nil
}

// networkExtensionLabTLSLeafFresh reports whether a cached leaf is still safely usable. cert.Leaf is always
// set at mint time (the template carries the dates).
//
// ★★★ A LEAF'S OWN DATES ARE NOT WHETHER THE CHAIN IT CARRIES STILL WORKS (2026-09-08, found by win-dev-1
// while reading for the cause of the overnight outage, confirmed here).
//
// This asked the leaf about its NotAfter and nothing else. Leaves are minted for THIRTY DAYS; the issuing CA
// under them lives TWELVE HOURS and is replaced on every material refresh. So from twelve hours after a
// leaf was minted, the cache went on answering "fresh" and the Edge went on serving a certificate whose
// chain was dead — to every client, for the remaining twenty-nine days.
//
// ★ AND THE CACHE KEY DOES NOT SAVE IT. cacheKey is cacheTenant + issuerScope + host, and issuerScope for a
// per-organization issuer is "offline_tenant:<organization>" — the ORGANIZATION, which is exactly what does
// not change when that organization's issuing certificate is replaced. A rotation therefore leaves every
// cached leaf in place under its own key.
//
// This is the same shape as the two defects fixed today: a true question that was not the question. The
// leaf really was inside its own dates. Nobody was asking whether it could still be verified.
//
// The issuer is compared by BYTES, not by name or by scope, because the whole point is a replacement that
// keeps every name it had. A leaf minted under a superseded issuing certificate is not fresh, whatever its
// own dates say.
func networkExtensionLabTLSLeafFresh(cert tls.Certificate, now func() time.Time, issuer *InterceptionIssuer) bool {
	if cert.Leaf == nil {
		return false
	}
	at := now().UTC()
	// Short-lived issuing paths also produce short-lived leaves. A fixed one-hour
	// margin would otherwise bypass the cache on every handshake in such a fleet.
	renewBefore := networkExtensionLabTLSLeafRenewBefore
	if fraction := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore) / 10; fraction < renewBefore {
		renewBefore = fraction
	}
	if at.Before(cert.Leaf.NotBefore) || !at.Add(renewBefore).Before(cert.Leaf.NotAfter) {
		return false
	}
	if issuer == nil || issuer.signingCert == nil {
		// Nothing to compare against: fall back to the leaf's own dates, which is what this did before.
		return true
	}
	// ★★★ THE WHOLE PRESENTED CHAIN, NOT ITS FIRST ENTRY (2026-09-08, found by review). Comparing
	// Certificate[1] catches a replaced signing certificate and misses a replaced TIER ABOVE it — and a
	// per-Edge issuing CA sits under an operator issuing CA under the organization's root. A client verifies
	// all of them.
	if len(cert.Certificate) != len(issuer.chain)+1 {
		return false
	}
	for n, der := range issuer.chain {
		if !bytes.Equal(cert.Certificate[n+1], der) {
			return false
		}
	}
	// And every certificate in that chain must still be inside its own validity. usableAt intersects the
	// whole path, so an expired tier above the signer is seen here rather than by the client.
	return issuer.usableAt(at) == nil
}

type networkExtensionLabTLSResponseRecorder struct {
	header                    http.Header
	body                      bytes.Buffer
	status                    int
	swgEgressOutcome          string
	swgEgressUpstreamErrorCat string
	downstreamWriter          io.Writer
	downstreamReader          io.Reader
	directHandled             bool
	directErr                 error
	// clientWebSocketKey is the intercepted client's Sec-WebSocket-Key, kept so the Edge can mint the 101
	// Sec-WebSocket-Accept for THIS client (the re-originated upstream 101 carries none the client can use).
	clientWebSocketKey string
	// Write-through streaming state; only on the forwarding path, which has a downstreamWriter.
	streaming      bool  // has it switched to write-through
	headersFlushed bool  // has the streaming preamble been sent
	explicitFlush  bool  // did the handler call Flush()
	streamedBytes  int64 // body bytes sent downstream write-through
	streamErr      error // an error seen writing downstream
}

func NewNetworkExtensionLabTLSResponseRecorder() *networkExtensionLabTLSResponseRecorder {
	return &networkExtensionLabTLSResponseRecorder{header: http.Header{}}
}

func newNetworkExtensionLabTLSResponseRecorderWithTunnel(downstreamWriter io.Writer, downstreamReader io.Reader) *networkExtensionLabTLSResponseRecorder {
	recorder := NewNetworkExtensionLabTLSResponseRecorder()
	recorder.downstreamWriter = downstreamWriter
	recorder.downstreamReader = downstreamReader
	return recorder
}

func (recorder *networkExtensionLabTLSResponseRecorder) Header() http.Header {
	return recorder.header
}

func (recorder *networkExtensionLabTLSResponseRecorder) WriteHeader(status int) {
	if recorder.status != 0 {
		return
	}
	recorder.status = status
}

func (recorder *networkExtensionLabTLSResponseRecorder) Write(p []byte) (int, error) {
	if recorder.status == 0 {
		recorder.status = http.StatusOK
	}
	if !recorder.streamingEnabled() {
		return recorder.body.Write(p)
	}
	if recorder.streamErr != nil {
		return 0, recorder.streamErr
	}
	if !recorder.streaming {
		// Still buffering. Passing the threshold, an explicit Flush, or SSE switches to streaming.
		if !recorder.shouldStartStreaming(len(p)) {
			return recorder.body.Write(p)
		}
		if err := recorder.beginStreaming(); err != nil {
			return 0, err
		}
	}
	n, err := writeNetworkExtensionLabTLSChunk(recorder.downstreamWriter, p)
	recorder.streamedBytes += int64(n)
	if err != nil {
		recorder.streamErr = err
	}
	return n, err
}

// writeNetworkExtensionLabTLSChunk writes one chunk of a chunked transfer-encoding (the length line, the
// body, and CRLF) and returns the body's byte count. The terminating "0\r\n\r\n" is written separately by
// finishStreamedResponse.
func writeNetworkExtensionLabTLSChunk(w io.Writer, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := fmt.Fprintf(w, "%x\r\n", len(p)); err != nil {
		return 0, err
	}
	n, err := w.Write(p)
	if err != nil {
		return n, err
	}
	if _, err := io.WriteString(w, "\r\n"); err != nil {
		return n, err
	}
	return n, nil
}

// Flush satisfies http.Flusher. When a handler calls it — SSE, for instance — this switches to streaming at
// once rather than waiting to return a definite length, and everything after that is written through.
func (recorder *networkExtensionLabTLSResponseRecorder) Flush() {
	recorder.explicitFlush = true
	if !recorder.streamingEnabled() || recorder.streamErr != nil {
		return
	}
	if recorder.status == 0 {
		recorder.status = http.StatusOK
	}
	if !recorder.streaming {
		_ = recorder.beginStreaming()
	}
	if flusher, ok := recorder.downstreamWriter.(interface{ Flush() error }); ok {
		_ = flusher.Flush()
	}
}

func (recorder *networkExtensionLabTLSResponseRecorder) streamingEnabled() bool {
	return recorder.downstreamWriter != nil
}

// shouldStartStreaming reports whether to switch to streaming: adding the len(incoming) bytes about to be
// written would pass the threshold, or a Flush was called explicitly, or the response is SSE.
func (recorder *networkExtensionLabTLSResponseRecorder) shouldStartStreaming(incoming int) bool {
	if recorder.explicitFlush || recorder.responseIsServerSentEvents() {
		return true
	}
	return recorder.body.Len()+incoming > NetworkExtensionLabTLSResponseStreamThreshold
}

func (recorder *networkExtensionLabTLSResponseRecorder) responseIsServerSentEvents() bool {
	contentType := strings.ToLower(strings.TrimSpace(recorder.header.Get("Content-Type")))
	return strings.HasPrefix(contentType, "text/event-stream")
}

// beginStreaming sends the streaming preamble, drains whatever body is already buffered, and then enters
// write-through.
func (recorder *networkExtensionLabTLSResponseRecorder) beginStreaming() error {
	recorder.streaming = true
	if err := recorder.flushStreamingHeaders(); err != nil {
		return err
	}
	if recorder.body.Len() > 0 {
		n, err := writeNetworkExtensionLabTLSChunk(recorder.downstreamWriter, recorder.body.Bytes())
		recorder.streamedBytes += int64(n)
		if err != nil {
			recorder.streamErr = err
			return err
		}
		recorder.body.Reset()
	}
	return nil
}

// flushStreamingHeaders sends the status line and headers exactly once when streaming. The length is not
// known, so there is no Content-Length: the response is framed by Connection: close and EOF.
func (recorder *networkExtensionLabTLSResponseRecorder) flushStreamingHeaders() error {
	if recorder.headersFlushed {
		return recorder.streamErr
	}
	recorder.headersFlushed = true
	status := recorder.StatusCode()
	text := http.StatusText(status)
	if text == "" {
		text = "Status"
	}
	headers := recorder.header.Clone()
	headers.Del("Content-Length")
	headers.Del("Transfer-Encoding")
	// A large response of unknown length is framed with chunked transfer. Unlike framing by EOF (Connection:
	// close) the connection can be reused, so a heavy page under decrypt-all does not spray connections until
	// sockets run out.
	headers.Set("Transfer-Encoding", "chunked")
	if _, err := fmt.Fprintf(recorder.downstreamWriter, "HTTP/1.1 %d %s\r\n", status, text); err != nil {
		recorder.streamErr = err
		return err
	}
	if err := headers.Write(recorder.downstreamWriter); err != nil {
		recorder.streamErr = err
		return err
	}
	if _, err := io.WriteString(recorder.downstreamWriter, "\r\n"); err != nil {
		recorder.streamErr = err
		return err
	}
	return nil
}

// finishStreamedResponse settles the response after ServeHTTP returns. One that fit under the threshold is
// returned in a single piece with a Content-Length; one that had already switched to streaming — an empty
// body, say — only has its headers guaranteed to have been sent, and any error seen is returned.
func (recorder *networkExtensionLabTLSResponseRecorder) finishStreamedResponse() error {
	if !recorder.streamingEnabled() {
		return nil
	}
	if recorder.streaming {
		if err := recorder.flushStreamingHeaders(); err != nil {
			return err
		}
		if recorder.streamErr != nil {
			return recorder.streamErr
		}
		// Writing the chunked terminator completes the response, which is what makes the connection reusable.
		if _, err := io.WriteString(recorder.downstreamWriter, "0\r\n\r\n"); err != nil {
			recorder.streamErr = err
			return err
		}
		return nil
	}
	// Take the byte count before returning it in one piece: WriteTo empties the buffer.
	recorder.streamedBytes = int64(recorder.body.Len())
	return WriteNetworkExtensionLabTLSRecordedResponse(recorder.downstreamWriter, recorder)
}

// writtenByteCount is the body bytes actually returned downstream, for the log.
func (recorder *networkExtensionLabTLSResponseRecorder) writtenByteCount() int {
	return int(recorder.streamedBytes)
}

func (recorder *networkExtensionLabTLSResponseRecorder) SetSWGHTTPEgressOutcome(outcome string) {
	recorder.swgEgressOutcome = strings.TrimSpace(outcome)
}

func (recorder *networkExtensionLabTLSResponseRecorder) SetSWGHTTPEgressUpstreamErrorCategory(category string) {
	recorder.swgEgressUpstreamErrorCat = strings.TrimSpace(category)
}

func (recorder *networkExtensionLabTLSResponseRecorder) StatusCode() int {
	if recorder.status == 0 {
		return http.StatusOK
	}
	return recorder.status
}

func (recorder *networkExtensionLabTLSResponseRecorder) directResponseHandled() bool {
	return recorder != nil && recorder.directHandled
}

func (recorder *networkExtensionLabTLSResponseRecorder) directResponseError() error {
	if recorder == nil {
		return nil
	}
	return recorder.directErr
}

func (recorder *networkExtensionLabTLSResponseRecorder) TunnelSWGHTTPEgressWebSocket(resp *http.Response) error {
	recorder.directHandled = true
	if resp == nil {
		recorder.status = http.StatusBadGateway
		recorder.directErr = fmt.Errorf("missing websocket upstream response")
		return recorder.directErr
	}
	recorder.status = resp.StatusCode
	for name, values := range resp.Header {
		for _, value := range values {
			recorder.header.Add(name, value)
		}
	}
	if recorder.downstreamWriter == nil || recorder.downstreamReader == nil {
		recorder.directErr = fmt.Errorf("websocket downstream tunnel is not configured")
		return recorder.directErr
	}
	upstream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		recorder.directErr = fmt.Errorf("websocket upstream response body is not bidirectional")
		return recorder.directErr
	}
	// Mint the client-facing Sec-WebSocket-Accept. The re-originated upstream 101 carries the accept for the
	// EDGE's key to the origin (meaningless to the client), and the raw broker tunnel 101 carries none at all —
	// so without this the client sees an empty/absent Sec-WebSocket-Accept and rejects the handshake, and the
	// WS never opens (#28; reproduced with wss://ws.postman-echo.com/raw through the Edge). Compute it from the
	// client's own key per RFC 6455.
	if resp.StatusCode == http.StatusSwitchingProtocols && strings.TrimSpace(recorder.clientWebSocketKey) != "" {
		accept := NetworkExtensionLabTLSWebSocketAccept(recorder.clientWebSocketKey)
		resp.Header.Set("Sec-WebSocket-Accept", accept)
		recorder.header.Set("Sec-WebSocket-Accept", accept)
	}
	// Ungated for the same reason as ws_tunnel_closed below: once per WS connection, and an operator needs the
	// open/close pair to tell "the WS never opened" from "it opened and carried nothing".
	wsHost := NetworkExtensionLabTLSLogHost(resp)
	wsID := NetworkExtensionLabTLSWebSocketSeq.Add(1)
	log.Printf("network_extension_lab_tls progress=websocket_tunnel_started ws=%d status_code=%d host=%s", wsID, resp.StatusCode, wsHost)
	if err := writeNetworkExtensionLabTLSWebSocketSwitchingProtocolResponse(recorder.downstreamWriter, resp); err != nil {
		recorder.directErr = err
		return err
	}
	// h1 client leg (the recorder path) has no request context here; the client-disconnect leak guard is a no-op
	// (nil ctx). The h2 Extended-CONNECT path — Chrome's default to an intercepted origin — passes the real
	// client context. TODO: thread the h1 client conn's context if h1 WS clients become common.
	if err := CopyNetworkExtensionLabTLSWebSocketTunnel(nil, wsHost, wsID, recorder.downstreamReader, recorder.downstreamWriter, upstream); err != nil {
		recorder.directErr = err
		log.Printf("network_extension_lab_tls progress=websocket_tunnel_aborted category=%s", NetworkExtensionLabTLSErrorCategory(err))
		return err
	}
	NetworkExtensionHotPathLog("network_extension_lab_tls progress=websocket_tunnel_completed")
	return nil
}

func NetworkExtensionLabTLSForwardOutcomeCategory(recorder *networkExtensionLabTLSResponseRecorder) string {
	if recorder == nil {
		return "unclassified"
	}
	switch strings.TrimSpace(recorder.swgEgressOutcome) {
	case EdgeSWGHTTPEgressOutcomeBadRequest,
		EdgeSWGHTTPEgressOutcomeUnauthorized,
		EdgeSWGHTTPEgressOutcomeInternalError,
		EdgeSWGHTTPEgressOutcomePolicyDenied,
		EdgeSWGHTTPEgressOutcomeRewriteFailed,
		EdgeSWGHTTPEgressOutcomeReadinessDependency,
		EdgeSWGHTTPEgressOutcomeUpstreamRequestFailed,
		EdgeSWGHTTPEgressOutcomeUpstreamResponse:
		return strings.TrimSpace(recorder.swgEgressOutcome)
	default:
		return "unclassified"
	}
}

func NetworkExtensionLabTLSForwardUpstreamErrorCategory(recorder *networkExtensionLabTLSResponseRecorder, outcomeCategory string) string {
	if outcomeCategory != EdgeSWGHTTPEgressOutcomeUpstreamRequestFailed {
		return EdgeSWGHTTPEgressUpstreamErrorCategoryNone
	}
	if recorder == nil {
		return "unclassified"
	}
	switch strings.TrimSpace(recorder.swgEgressUpstreamErrorCat) {
	case EdgeSWGHTTPEgressUpstreamErrorCategoryContextCanceled,
		EdgeSWGHTTPEgressUpstreamErrorCategoryTimeout,
		EdgeSWGHTTPEgressUpstreamErrorCategoryDNSError,
		EdgeSWGHTTPEgressUpstreamErrorCategoryTCPConnectError,
		EdgeSWGHTTPEgressUpstreamErrorCategoryTLSHandshakeError,
		EdgeSWGHTTPEgressUpstreamErrorCategoryCertificateError,
		EdgeSWGHTTPEgressUpstreamErrorCategoryConnectionReset,
		EdgeSWGHTTPEgressUpstreamErrorCategoryConnectionRefused,
		EdgeSWGHTTPEgressUpstreamErrorCategoryNetworkUnreachable,
		EdgeSWGHTTPEgressUpstreamErrorCategoryClosedConnection,
		EdgeSWGHTTPEgressUpstreamErrorCategoryHTTP2Transport,
		EdgeSWGHTTPEgressUpstreamErrorCategoryMalformedResponse,
		EdgeSWGHTTPEgressUpstreamErrorCategoryOtherNonSecret:
		return strings.TrimSpace(recorder.swgEgressUpstreamErrorCat)
	default:
		return "unclassified"
	}
}

func NetworkExtensionLabTLSForwardStatusCategory(status int, outcomeCategory string) string {
	switch {
	case status >= 200 && status <= 299:
		return "success"
	case status >= 300 && status <= 399:
		if outcomeCategory == EdgeSWGHTTPEgressOutcomeUpstreamResponse {
			return "upstream_redirect"
		}
		return "edge_redirect"
	case status >= 400 && status <= 499:
		switch outcomeCategory {
		case EdgeSWGHTTPEgressOutcomePolicyDenied:
			return "policy_denied"
		case EdgeSWGHTTPEgressOutcomeReadinessDependency:
			return "readiness_dependency"
		case EdgeSWGHTTPEgressOutcomeUpstreamResponse:
			return "upstream_client_error"
		default:
			return "edge_client_error"
		}
	case status >= 500 && status <= 599:
		switch outcomeCategory {
		case EdgeSWGHTTPEgressOutcomeUpstreamResponse:
			return "upstream_server_error"
		case EdgeSWGHTTPEgressOutcomeUpstreamRequestFailed:
			return "egress_upstream_request_failed"
		case EdgeSWGHTTPEgressOutcomeRewriteFailed:
			return "egress_rewrite_failed"
		case EdgeSWGHTTPEgressOutcomeInternalError:
			return "edge_internal_error"
		default:
			return "edge_server_error"
		}
	default:
		return "other_status"
	}
}

func WriteNetworkExtensionLabTLSRecordedResponse(w io.Writer, recorder *networkExtensionLabTLSResponseRecorder) error {
	status := recorder.StatusCode()
	text := http.StatusText(status)
	if text == "" {
		text = "Status"
	}
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", status, text); err != nil {
		return err
	}
	headers := recorder.Header().Clone()
	headers.Del("Transfer-Encoding")
	headers.Set("Content-Length", strconv.Itoa(recorder.body.Len()))
	// Framed with a Content-Length, so keep-alive is possible. Leaving Connection: close off lets the next
	// request arrive on the same intercepted connection, which is what prevents a new tunnel per connection
	// under decrypt-all and Chrome failing with ERR_INSUFFICIENT_RESOURCES.
	headers.Del("Connection")
	if err := headers.Write(w); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "\r\n"); err != nil {
		return err
	}
	_, err := recorder.body.WriteTo(w)
	return err
}

// NetworkExtensionLabTLSWebSocketAccept computes the RFC 6455 Sec-WebSocket-Accept for a client's
// Sec-WebSocket-Key: base64(SHA1(key + GUID)). The Edge is the WS server to the intercepted client, so it must
// mint this itself.
func NetworkExtensionLabTLSWebSocketAccept(clientKey string) string {
	const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	sum := sha1.Sum([]byte(strings.TrimSpace(clientKey) + magicGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeNetworkExtensionLabTLSWebSocketSwitchingProtocolResponse(w io.Writer, resp *http.Response) error {
	// Serialize the complete upgrade header before writing to TLS. Header.Write
	// emits small fragments which otherwise become separate TLS records and can
	// trigger WebSocket clients' defenses against excessive small handshake reads.
	var handshake bytes.Buffer
	status := resp.StatusCode
	text := resp.Status
	if fields := strings.Fields(text); len(fields) > 1 && fields[0] == strconv.Itoa(status) {
		text = strings.Join(fields[1:], " ")
	}
	if strings.TrimSpace(text) == "" {
		text = http.StatusText(status)
	}
	if strings.TrimSpace(text) == "" {
		text = "Switching Protocols"
	}
	if _, err := fmt.Fprintf(&handshake, "HTTP/1.1 %d %s\r\n", status, text); err != nil {
		return err
	}
	headers := resp.Header.Clone()
	headers.Del("Content-Length")
	headers.Del("Transfer-Encoding")
	if strings.TrimSpace(headers.Get("Connection")) == "" {
		headers.Set("Connection", "Upgrade")
	}
	if strings.TrimSpace(headers.Get("Upgrade")) == "" {
		headers.Set("Upgrade", "websocket")
	}
	if err := headers.Write(&handshake); err != nil {
		return err
	}
	handshake.WriteString("\r\n")
	_, err := handshake.WriteTo(w)
	return err
}

// CopyNetworkExtensionLabTLSWebSocketTunnel relays a decrypt-all WebSocket bidirectionally between the client
// (downstreamReader/Writer) and the origin (upstream). A WebSocket is FULL-DUPLEX: the two directions close
// independently. The teardown rule matters — the origin->client direction carries the WS response and ends only
// when the ORIGIN closes the socket (= response complete), so it is what authorizes teardown. A clean EOF on
// client->origin means the browser finished/half-closed ITS send side; it does NOT mean the origin is done
// answering, so it must NOT close the origin connection. Closing upstream on that first clean EOF truncated the
// origin's still-streaming response (Copilot chat showing "something went wrong, try sending a new message":
// the client's frames EOF'd after ~1.3 KB, upstream was closed, and the streamed answer was cut off at ~99 bytes;
// every wss:// origin, incl. Azure Web PubSub, hit it). Only a real client error, or the origin->client direction
// ending, tears the tunnel down.
// NetworkExtensionLabTLSLogHost returns just the origin HOST for a WS lifecycle log line. Host only, never the
// path or query: WS URLs carry credentials in the query (e.g. ChatGPT's `?verify=<token>`), which must not reach
// a log. Empty when unknown, so the log site stays cheap and never panics on a synthesized response.
func NetworkExtensionLabTLSLogHost(resp *http.Response) string {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return ""
	}
	return resp.Request.URL.Hostname()
}

// networkExtensionLabTLSCountingReader counts bytes as they are READ out of a direction's source, i.e. the
// moment the tunnel takes them to relay onward. Two earlier shapes were both wrong:
//   - taking io.Copy's return value records nothing until that copy RETURNS, and the direction still blocked on
//     a read when the tunnel tears down never returns — so it always reported 0;
//   - counting after the onward Write completes lags delivery by a scheduling quantum, so a peer that closes
//     the instant it receives the data can still observe a stale 0.
//
// Counting at read time is ordered strictly BEFORE the write that lets the far side observe those bytes, so by
// the time anyone can react to them the count is already recorded. It implements only Read, so an io.Copy that
// takes a ReadFrom shortcut on the destination still pulls through this counter.
type networkExtensionLabTLSCountingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c networkExtensionLabTLSCountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

// NetworkExtensionLabTLSWebSocketSeq numbers WebSocket tunnels so the started and closed lines of ONE tunnel can
// be paired even when several are open at once. Without it an operator reading a busy window can only guess
// which close belongs to which host — and #28 was twice mis-attributed exactly that way: a client_to_origin=0
// close was read as ChatGPT's when correlating by timestamp, and turned out to belong to a browser extension.
var NetworkExtensionLabTLSWebSocketSeq atomic.Int64

func CopyNetworkExtensionLabTLSWebSocketTunnel(ctx context.Context, host string, wsID int64, downstreamReader io.Reader, downstreamWriter io.Writer, upstream io.ReadWriteCloser) error {
	clientToOriginBytes, originToClientBytes, reason, err := CopyNetworkExtensionLabTLSWebSocketTunnelCounted(ctx, downstreamReader, downstreamWriter, upstream)
	// host is carried on the CLOSE line too, not just on the open: attribution must never depend on correlating
	// two log lines by time. reason says WHICH SIDE ended it — the ChatGPT desktop app reports its own
	// "pubsub transport closed" 30 times against 22 opens, and only a per-close reason here can say whether the
	// Edge is the one tearing those down.
	log.Printf("network_extension_lab_tls progress=ws_tunnel_closed ws=%d host=%s reason=%s client_to_origin_bytes=%d origin_to_client_bytes=%d",
		wsID, host, reason, clientToOriginBytes, originToClientBytes)
	return err
}

// CopyNetworkExtensionLabTLSWebSocketTunnelCounted is the tunnel proper, returning how many bytes each
// direction carried so the counts can be asserted in a test rather than only read out of a log line.
func CopyNetworkExtensionLabTLSWebSocketTunnelCounted(ctx context.Context, downstreamReader io.Reader, downstreamWriter io.Writer, upstream io.ReadWriteCloser) (clientToOriginBytes int64, originToClientBytes int64, reason string, err error) {
	// LEAK GUARD: if the client half-closes its send side (clientToOrigin EOFs, handled below) and then goes
	// away while the origin keeps the WS open but IDLE, the origin->client io.Copy blocks forever on
	// upstream.Read — leaking this goroutine AND the origin connection. Under repeat WS use (e.g. many Copilot
	// chat sessions) these accumulate and exhaust the Edge. Closing upstream when the client's context ends
	// (h2 stream reset / disconnect) unblocks that read. AfterFunc self-cleans; stop() cancels it on normal exit.
	if ctx != nil {
		stop := context.AfterFunc(ctx, func() { _ = upstream.Close() })
		defer stop()
	}
	clientToOrigin := make(chan error, 1)
	originToClient := make(chan error, 1)
	// #28 diagnostic: count each direction so an operator can tell WHERE a WS breaks. The count must be LIVE.
	// Recording io.Copy's return value instead reported client_to_origin_bytes=0 for a WS that demonstrably
	// carried 600 bytes upstream: when the origin closes first the tunnel returns immediately while the
	// client->origin copy is still blocked reading the client, so its total was never stored. That false zero
	// was then read as "the Edge relays nothing upstream" and became the basis for localising #28 — a
	// conclusion drawn from a broken instrument. Counting as bytes pass makes the number true at any instant.
	var c2oBytes, o2cBytes atomic.Int64
	defer func() {
		clientToOriginBytes, originToClientBytes = c2oBytes.Load(), o2cBytes.Load()
	}()
	go func() {
		_, err := io.Copy(upstream, networkExtensionLabTLSCountingReader{r: downstreamReader, n: &c2oBytes})
		clientToOrigin <- err
	}()
	go func() {
		_, err := io.Copy(downstreamWriter, networkExtensionLabTLSCountingReader{r: upstream, n: &o2cBytes})
		originToClient <- err
	}()
	for {
		select {
		case copyErr := <-originToClient:
			// The origin closed (or errored) the WS: the response is complete. Close the tunnel and return.
			_ = upstream.Close()
			if !NetworkExtensionLabTLSBenignTunnelCopyError(copyErr) {
				return 0, 0, "origin_error:" + NetworkExtensionLabTLSErrorCategory(copyErr), copyErr
			}
			// Deliberately NOT distinguishing "the client had already half-closed": whether that EOF has reached
			// the select by now is a scheduling race, so the label would be flaky and mean nothing. The question
			// a close reason must answer is WHICH SIDE ended it, and that is never ambiguous.
			return 0, 0, "origin_closed", nil
		case copyErr := <-clientToOrigin:
			if !NetworkExtensionLabTLSBenignTunnelCopyError(copyErr) {
				// The browser really disconnected/reset — nothing left to relay; tear down. This is the ONE exit
				// where the EDGE ends a WebSocket the origin was still streaming on, so its category is the
				// thing to read when a client reports transports closing under it.
				_ = upstream.Close()
				return 0, 0, "client_error:" + NetworkExtensionLabTLSErrorCategory(copyErr), copyErr
			}

			// Clean half-close of the client's send side. Do NOT close or half-close the origin: many WS servers
			// treat a TLS close_notify as connection-close and stop streaming. Just stop draining this direction
			// and keep the origin->client response flowing until the origin itself finishes.
			clientToOrigin = nil
		}
	}
}

func NetworkExtensionLabTLSBenignTunnelCopyError(err error) bool {
	return err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrClosed)
}

func writeNetworkExtensionLabTLSRedirectResponse(w io.Writer, status int, text string, location string) error {
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n", status, text); err != nil {
		return err
	}
	if location = safeNetworkExtensionLabTLSRedirectLocationHeaderValue(location); location != "" {
		if _, err := fmt.Fprintf(w, "Location: %s\r\n", location); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func safeNetworkExtensionLabTLSRedirectLocationHeaderValue(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, char := range value {
		if char == '\r' || char == '\n' || char == 0x7f || char < 0x20 || char > 0x7e {
			continue
		}
		b.WriteRune(char)
	}
	return b.String()
}

func networkExtensionLabTLSProbeRequested(req *http.Request) bool {
	return networkExtensionLabTLSProbeDecisionMatches(networkExtensionLabTLSProbeDecision(req))
}

func networkExtensionLabTLSProbeDecisionMatches(decision string) bool {
	return strings.HasPrefix(decision, "matched_")
}

func networkExtensionLabTLSProbeDecision(req *http.Request) string {
	if req == nil || req.URL == nil {
		return "missing_url"
	}
	if networkExtensionLabTLSProbePathMatches(req.URL.Path) || networkExtensionLabTLSProbePathMatches(req.URL.EscapedPath()) {
		return "matched_path"
	}
	if networkExtensionLabTLSProbeTextContainsPath(req.RequestURI) {
		return "matched_request_uri_path"
	}
	query := req.URL.Query()
	for _, key := range []string{"dsse_lab_tls_probe", "dsse_probe"} {
		if values, ok := query[key]; ok {
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					return "matched_query"
				}
			}
			return "matched_query_flag"
		}
	}
	for _, values := range query {
		for _, value := range values {
			if networkExtensionLabTLSProbeTextContainsPath(value) {
				return "matched_query_value_path"
			}
		}
	}
	return "not_matched"
}

func networkExtensionLabTLSProbePathMatches(raw string) bool {
	path := strings.Trim(strings.TrimSpace(raw), "/")
	if path == "dsse-lab-tls-probe" {
		return true
	}
	if decoded, err := url.PathUnescape(raw); err == nil && decoded != raw {
		return networkExtensionLabTLSProbePathMatches(decoded)
	}
	return false
}

func networkExtensionLabTLSProbeTextContainsPath(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	for i := 0; i < 4; i++ {
		text := strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(text, "/dsse-lab-tls-probe") {
			return true
		}
		if decoded, err := url.QueryUnescape(raw); err == nil && decoded != raw {
			raw = decoded
			continue
		}
		if decoded, err := url.PathUnescape(raw); err == nil && decoded != raw {
			raw = decoded
			continue
		}
		return false
	}
	return false
}

func networkExtensionLabTLSRequestTargetCategory(req *http.Request) string {
	if req == nil || req.URL == nil {
		return "missing_url"
	}
	if req.URL.IsAbs() {
		return "absolute_form"
	}
	if req.Method == http.MethodConnect {
		return "authority_form"
	}
	if strings.TrimSpace(req.RequestURI) == "*" {
		return "asterisk_form"
	}
	return "origin_form"
}

func networkExtensionLabTLSRequestPathCategory(req *http.Request) string {
	if req == nil || req.URL == nil {
		return "missing_url"
	}
	path := strings.TrimSpace(req.URL.Path)
	switch {
	case path == "":
		return "empty_path"
	case networkExtensionLabTLSProbePathMatches(path):
		return "probe_path"
	case path == "/":
		return "root_path"
	default:
		return "other_path"
	}
}

func NetworkExtensionLabTLSRequestMethodCategory(req *http.Request) string {
	if req == nil {
		return "missing_request"
	}
	switch strings.ToUpper(strings.TrimSpace(req.Method)) {
	case http.MethodGet:
		return "GET"
	case http.MethodHead:
		return "HEAD"
	case http.MethodPost:
		return "POST"
	case http.MethodOptions:
		return "OPTIONS"
	case http.MethodConnect:
		return "CONNECT"
	case "":
		return "empty"
	default:
		return "other"
	}
}

func NetworkExtensionLabTLSFetchDestCategory(req *http.Request) string {
	if req == nil {
		return "missing_request"
	}
	value := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Dest")))
	switch value {
	case "":
		return "missing"
	case "document", "empty", "script", "style", "image", "font", "iframe":
		return value
	default:
		return "other"
	}
}

func NetworkExtensionLabTLSAcceptCategory(req *http.Request) string {
	if req == nil {
		return "missing_request"
	}
	value := strings.ToLower(strings.TrimSpace(req.Header.Get("Accept")))
	switch {
	case value == "":
		return "missing"
	case strings.Contains(value, "text/html"):
		return "document"
	case strings.Contains(value, "text/css"):
		return "style"
	case strings.Contains(value, "javascript"):
		return "script"
	case strings.Contains(value, "image/"):
		return "image"
	case strings.Contains(value, "*/*"):
		return "any"
	default:
		return "other"
	}
}

func NetworkExtensionLabTLSFingerprint(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "empty"
	}
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("len_%d_sha256_%x", len(value), sum[:4])
}

func writeNetworkExtensionLabTLSProbeResponse(w io.Writer, method string, host string) error {
	body := "dsse lab tls interception probe ok\n"
	if method == http.MethodHead {
		body = ""
	}
	if _, err := fmt.Fprintf(
		w,
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nCache-Control: no-store\r\nX-Dsse-Lab-TLS-Interception: observed\r\nX-Dsse-Lab-TLS-Target-Host: %s\r\n\r\n%s",
		len(body),
		safeNetworkExtensionLabTLSHeaderValue(host),
		body,
	); err != nil {
		return err
	}
	return nil
}

func writeNetworkExtensionLabTLSProbeOnlyNonProbeResponse(w io.Writer, method string, host string) error {
	return writeNetworkExtensionLabTLSEmptyResponse(w, http.StatusNoContent, "No Content", "probe-only", host)
}

func writeNetworkExtensionLabTLSEmptyResponse(w io.Writer, statusCode int, statusText string, mode string, host string) error {
	_, err := fmt.Fprintf(
		w,
		"HTTP/1.1 %d %s\r\nContent-Length: 0\r\nX-Dsse-Lab-TLS-Interception: %s\r\nX-Dsse-Lab-TLS-Target-Host: %s\r\n\r\n",
		statusCode,
		statusText,
		safeNetworkExtensionLabTLSHeaderValue(mode),
		safeNetworkExtensionLabTLSHeaderValue(host),
	)
	return err
}

func NetworkExtensionLabTLSTargetURL(req *http.Request, route NetworkExtensionRuntimeCopyTCPRoute) (*url.URL, error) {
	host, ok := NormalizeNetworkExtensionRuntimeCopyDestinationHost(route.Host)
	if !ok {
		return nil, fmt.Errorf("invalid lab TLS target host")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if net.ParseIP(host) != nil {
		if requestHost, ok := networkExtensionLabTLSRequestHost(req); ok && net.ParseIP(requestHost) == nil {
			host = requestHost
		}
	}
	if route.Port > 0 && route.Port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(route.Port))
	} else {
		host = networkExtensionLabTLSURLAuthorityHost(host)
	}
	path := "/"
	if req != nil && req.URL != nil {
		if uri := strings.TrimSpace(req.URL.RequestURI()); uri != "" {
			path = uri
		}
	}
	target, err := url.Parse("https://" + host + path)
	if err != nil {
		return nil, fmt.Errorf("build lab TLS target URL: %w", err)
	}
	return target, nil
}

func networkExtensionLabTLSURLAuthorityHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func networkExtensionLabTLSResponseHost(req *http.Request, route NetworkExtensionRuntimeCopyTCPRoute) string {
	host, ok := NormalizeNetworkExtensionRuntimeCopyDestinationHost(route.Host)
	if !ok {
		return route.Host
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if net.ParseIP(host) != nil {
		if requestHost, ok := networkExtensionLabTLSRequestHost(req); ok && net.ParseIP(requestHost) == nil {
			return requestHost
		}
	}
	return host
}

func networkExtensionLabTLSRequestHost(req *http.Request) (string, bool) {
	if req == nil {
		return "", false
	}
	raw := strings.TrimSpace(req.Host)
	if raw == "" && req.URL != nil {
		raw = strings.TrimSpace(req.URL.Host)
	}
	if raw == "" {
		return "", false
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	host, ok := NormalizeNetworkExtensionRuntimeCopyDestinationHost(raw)
	if !ok {
		return "", false
	}
	return strings.TrimSuffix(strings.ToLower(host), "."), true
}

func WriteNetworkExtensionLabTLSRootCertificatePEM(path string, pemBytes []byte) error {
	path, err := normalizeNetworkExtensionLabTLSRootCACertOutPath(path)
	if err != nil {
		return err
	}
	if path == "" || len(pemBytes) == 0 {
		return nil
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create lab TLS root certificate directory: %w", err)
		}
	}
	return os.WriteFile(path, pemBytes, 0600)
}

// networkExtensionLabTLSRootCertLegacyFilenames are names this root has been stored under before. The file
// on disk IS the trust every device pinned; if a rename makes the Edge look past it, the material reads as
// absent and a brand-new root is minted — every device silently stops trusting what is served (review C9).
// The lab escaped this because it passes a file path, so only a deployment naming the directory was exposed.
var networkExtensionLabTLSRootCertLegacyFilenames = []string{"domestic_sse_lab_tls_root_ca.pem"}

func normalizeNetworkExtensionLabTLSRootCACertOutPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		current := filepath.Join(path, NetworkExtensionLabTLSRootCertFilename)
		if _, err := os.Stat(current); err == nil {
			return current, nil
		}
		for _, legacy := range networkExtensionLabTLSRootCertLegacyFilenames {
			candidate := filepath.Join(path, legacy)
			if _, err := os.Stat(candidate); err != nil {
				continue
			}
			if _, err := os.Stat(NetworkExtensionLabTLSRootKeyPath(candidate)); err != nil {
				continue
			}
			log.Printf("network_extension_lab_tls progress=root_ca_persistence_found_under_previous_name")
			return candidate, nil
		}
		return current, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat lab TLS root CA output path: %w", err)
	}
	return path, nil
}

func NetworkExtensionLabTLSRootKeyPath(certPath string) string {
	certPath = strings.TrimSpace(certPath)
	if certPath == "" {
		return ""
	}
	ext := filepath.Ext(certPath)
	if ext == "" {
		return certPath + ".key.pem"
	}
	return strings.TrimSuffix(certPath, ext) + ".key.pem"
}

func LoadNetworkExtensionLabTLSPersistentRootMaterial(rootCACertOut string, now func() time.Time) (networkExtensionLabTLSRootMaterial, bool, error) {
	rootCACertOut, err := normalizeNetworkExtensionLabTLSRootCACertOutPath(rootCACertOut)
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, false, err
	}
	if rootCACertOut == "" {
		return networkExtensionLabTLSRootMaterial{}, false, nil
	}
	keyPath := NetworkExtensionLabTLSRootKeyPath(rootCACertOut)
	certPEM, certErr := os.ReadFile(rootCACertOut)
	keyPEM, keyErr := os.ReadFile(keyPath)
	certMissing := errors.Is(certErr, os.ErrNotExist)
	keyMissing := errors.Is(keyErr, os.ErrNotExist)
	if certMissing && keyMissing {
		return networkExtensionLabTLSRootMaterial{}, false, nil
	}
	if certErr != nil && !certMissing {
		return networkExtensionLabTLSRootMaterial{}, false, fmt.Errorf("read lab TLS persistent root certificate: %w", certErr)
	}
	if keyErr != nil && !keyMissing {
		return networkExtensionLabTLSRootMaterial{}, false, fmt.Errorf("read lab TLS persistent root key: %w", keyErr)
	}
	if certMissing || keyMissing {
		log.Printf("network_extension_lab_tls progress=root_ca_persistence_rotated reason=incomplete_material")
		return networkExtensionLabTLSRootMaterial{}, false, nil
	}
	if err := validateNetworkExtensionLabTLSSecretFileMode(keyPath); err != nil {
		return networkExtensionLabTLSRootMaterial{}, false, err
	}
	// When the key is sealed at rest, decrypt it with the configured KEK before parsing (fail-closed if absent).
	keyPEM, err = maybeUnsealInterceptionKeyFromDisk(keyPEM)
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, false, err
	}
	material, err := parseNetworkExtensionLabTLSPersistentRootMaterial(certPEM, keyPEM)
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, false, err
	}
	current := time.Now
	if now != nil {
		current = now
	}
	expiresAt := material.Cert.NotAfter
	if !current().UTC().Before(expiresAt.Add(-NetworkExtensionLabTLSRootRotateBefore)) {
		log.Printf("network_extension_lab_tls progress=root_ca_persistence_rotated reason=expires_soon")
		return networkExtensionLabTLSRootMaterial{}, false, nil
	}
	if current().UTC().Before(material.Cert.NotBefore) {
		return networkExtensionLabTLSRootMaterial{}, false, fmt.Errorf("lab TLS persistent root certificate is not valid yet")
	}
	return material, true, nil
}

func parseNetworkExtensionLabTLSPersistentRootMaterial(certPEM []byte, keyPEM []byte) (networkExtensionLabTLSRootMaterial, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("parse lab TLS persistent root certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("parse lab TLS persistent root certificate: %w", err)
	}
	if !cert.IsCA {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("lab TLS persistent root certificate is not a CA")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("parse lab TLS persistent root key PEM")
	}
	key, err := parseNetworkExtensionLabTLSRootPrivateKey(keyBlock.Bytes)
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, err
	}
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("lab TLS persistent root certificate public key is not RSA")
	}
	if publicKey.E != key.PublicKey.E || publicKey.N.Cmp(key.PublicKey.N) != 0 {
		return networkExtensionLabTLSRootMaterial{}, fmt.Errorf("lab TLS persistent root certificate and key do not match")
	}
	return networkExtensionLabTLSRootMaterial{
		Cert:    cert,
		Key:     key,
		CertPEM: append([]byte(nil), certPEM...),
		KeyPEM:  append([]byte(nil), keyPEM...),
	}, nil
}

func parseNetworkExtensionLabTLSRootPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse lab TLS persistent root key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("lab TLS persistent root key is not RSA")
	}
	return key, nil
}

func validateNetworkExtensionLabTLSSecretFileMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat lab TLS secret file: %w", err)
	}
	// Windows has no POSIX permission bits; Go reports 0666 for every file there, including one just written
	// 0600. The comparison below would therefore reject every key on that platform — not because the key is
	// exposed, but because the question cannot be asked. The Edge runs on Linux, which is where this guard has
	// to hold and does; on Windows (developer machines running the test suite) it is not a check that failed,
	// it is a check that does not apply. Same reasoning as the signing-key mode tests skipped in agentpolicy.
	// ★ ONE DEFINITION OF "the mode bits mean nothing here", not a second hand-written copy (2026-08-31).
	// The same platform test was written out longhand in two guards; when the signing-key one turned out to
	// be refusing on noise and had to be fixed, nothing pointed here. posixperm.Meaningful is the family's
	// definition, so a third guard inherits the answer instead of restating it.
	if !posixperm.Meaningful() {
		return nil
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("lab TLS secret file %q must not be group/world readable or writable", path)
	}
	return nil
}

func WriteNetworkExtensionLabTLSPersistentRootMaterial(rootCACertOut string, material networkExtensionLabTLSRootMaterial) error {
	rootCACertOut, err := normalizeNetworkExtensionLabTLSRootCACertOutPath(rootCACertOut)
	if err != nil {
		return err
	}
	if rootCACertOut == "" {
		return nil
	}
	keyPath := NetworkExtensionLabTLSRootKeyPath(rootCACertOut)
	if material.Cert == nil || material.Key == nil || len(material.CertPEM) == 0 || len(material.KeyPEM) == 0 {
		return fmt.Errorf("lab TLS persistent root material is incomplete")
	}
	if dir := filepath.Dir(rootCACertOut); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create lab TLS root directory: %w", err)
		}
	}
	keyBytes, err := maybeSealInterceptionKeyForDisk(material.KeyPEM)
	if err != nil {
		return fmt.Errorf("seal lab TLS root key: %w", err)
	}
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		return fmt.Errorf("write lab TLS root key: %w", err)
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("chmod lab TLS root key: %w", err)
	}
	if err := os.WriteFile(rootCACertOut, material.CertPEM, 0600); err != nil {
		return fmt.Errorf("write lab TLS root certificate: %w", err)
	}
	if err := os.Chmod(rootCACertOut, 0600); err != nil {
		return fmt.Errorf("chmod lab TLS root certificate: %w", err)
	}
	return nil
}

func NormalizedNetworkExtensionLabTLSHostPatterns(rawPatterns []string) []string {
	var patterns []string
	seen := map[string]bool{}
	for _, raw := range rawPatterns {
		pattern := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if pattern == "" || strings.ContainsAny(pattern, "/\\@:") || strings.Contains(pattern, "..") {
			continue
		}
		if pattern == "*" {
			if !seen[pattern] {
				patterns = append(patterns, pattern)
				seen[pattern] = true
			}
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*.")
			if suffix == "" || strings.Contains(suffix, "*") {
				continue
			}
		} else if strings.Contains(pattern, "*") {
			continue
		}
		if !seen[pattern] {
			patterns = append(patterns, pattern)
			seen[pattern] = true
		}
	}
	return patterns
}

func RandomNetworkExtensionLabTLSSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate lab TLS certificate serial: %w", err)
	}
	return serial, nil
}

func NetworkExtensionLabTLSRouteHostCategory(raw string) string {
	host, ok := NormalizeNetworkExtensionRuntimeCopyDestinationHost(raw)
	if !ok {
		return "invalid"
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return "empty"
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return "ipv4"
		}
		return "ipv6"
	}
	return "domain"
}

func NetworkExtensionLabTLSRoutePortCategory(port int) string {
	switch {
	case port == 443:
		return "port_443"
	case port <= 0:
		return "invalid"
	default:
		return "other_port"
	}
}

func NetworkExtensionLabTLSALPNCategory(protocol string) string {
	switch strings.TrimSpace(strings.ToLower(protocol)) {
	case "":
		return "empty"
	case "http/1.1":
		return "http_1_1"
	case "h2":
		return "h2"
	default:
		return "other"
	}
}

func NetworkExtensionLabTLSSNIMatchCategory(rawServerName string, rawRouteHost string) string {
	serverName, serverOK := NormalizeNetworkExtensionRuntimeCopyDestinationHost(rawServerName)
	if !serverOK {
		if strings.TrimSpace(rawServerName) == "" {
			return "empty"
		}
		return "invalid"
	}
	routeHost, routeOK := NormalizeNetworkExtensionRuntimeCopyDestinationHost(rawRouteHost)
	if !routeOK {
		return "route_host_invalid"
	}
	serverName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(serverName)), ".")
	routeHost = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(routeHost)), ".")
	if serverName == "" {
		return "empty"
	}
	if routeHost == "" {
		return "route_host_empty"
	}
	if serverName == routeHost {
		return "exact"
	}
	serverIP := net.ParseIP(serverName)
	routeIP := net.ParseIP(routeHost)
	if routeIP != nil && serverIP == nil {
		return "route_ip_sni_domain"
	}
	if routeIP == nil && serverIP != nil {
		return "route_domain_sni_ip"
	}
	if routeIP != nil && serverIP != nil {
		return "ip_mismatch"
	}
	return "mismatch"
}

func safeNetworkExtensionLabTLSHeaderValue(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, char := range value {
		if char <= 0x20 || char == 0x7f || char > 0x7e {
			continue
		}
		switch char {
		case '\r', '\n', ':':
			continue
		default:
			b.WriteRune(char)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func NetworkExtensionLabTLSErrorCategory(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return "closed"
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "closed"):
		return "closed"
	case strings.Contains(message, "malformed") || strings.Contains(message, "invalid"):
		return "invalid_http_request"
	default:
		return "unknown_nonsecret"
	}
}

// InterceptionCertMinter is implemented by a signer that can mint a purpose-bound leaf through the hsm-agent's
// /sign-cert. *hsmAgentSigner satisfies it; a plain crypto.Signer (lab self-signed) does not, and the
// leaf is then built locally. Using an interface, not the concrete type, keeps the call site working if the
// signer is ever wrapped, as long as the wrapper forwards SignCert.
type InterceptionCertMinter interface {
	SignCert(template, issuer *x509.Certificate, leafPub crypto.PublicKey, purpose string) ([]byte, error)
}

// DefaultRootProvider exposes the anchor (default) interception-root signing
// provider for the composition root's PKI surfaces.
func (interception *NetworkExtensionLabTLSInterception) DefaultRootProvider() InterceptionRootProvider {
	return interception.rootRegistry.DefaultProvider()
}

// ProbeOnlyDropUnmatched reports whether the engine runs in probe-only mode.
func (interception *NetworkExtensionLabTLSInterception) ProbeOnlyDropUnmatched() bool {
	return interception.probeOnly
}

// KeyCustody exposes the engine's key-custody self-check for the health surfaces.
func (interception *NetworkExtensionLabTLSInterception) KeyCustody() map[string]any {
	return interception.keyCustody()
}

// RootCertificate exposes the engine's interception root certificate (nil until
// enabled) — the anchor a client must trust to verify minted leaves.
func (interception *NetworkExtensionLabTLSInterception) RootCertificate() *x509.Certificate {
	return interception.rootCert
}

// NewNetworkExtensionLabTLSInterceptionForwardOnly builds an engine wired only with an
// HTTP handler for the forwarded-request path — no root material. Exported so the
// composition root's forward-path tests stay black-box (they cannot set the unexported
// httpHandler field directly).
func NewNetworkExtensionLabTLSInterceptionForwardOnly(handler http.Handler) *NetworkExtensionLabTLSInterception {
	return &NetworkExtensionLabTLSInterception{httpHandler: handler}
}

// NewNetworkExtensionLabTLSInterceptionMatchOnly builds an engine with just its host
// match set (for Matches/bypass tests); no root material or handler.
func NewNetworkExtensionLabTLSInterceptionMatchOnly(hostPatterns []string) *NetworkExtensionLabTLSInterception {
	return &NetworkExtensionLabTLSInterception{hosts: NormalizedNetworkExtensionLabTLSHostPatterns(hostPatterns)}
}

// RetireTenantInterceptionRoot removes a provisioned per-tenant root — see the registry's Retire for the
// refusals, which are the point of the operation.
func (interception *NetworkExtensionLabTLSInterception) RetireTenantInterceptionRoot(tenantID string) (bool, error) {
	if interception == nil || interception.rootRegistry == nil {
		return false, fmt.Errorf("interception is not enabled")
	}
	return interception.rootRegistry.Retire(tenantID)
}
