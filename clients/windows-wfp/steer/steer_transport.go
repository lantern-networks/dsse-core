package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/installprofile"
)

// transportConfig is the (T) secure transport. The steer<->Edge tunnel is TLS (mTLS): the agent pins the Edge *transport* CA
// (a SEPARATE CA from the (I) interception CA) and presents a device client cert, so every steered flow
// (CONNECT /steer, and later DNS-over-tunnel) rides INSIDE this encrypted channel -- SNI/DNS/destination
// metadata never appear in plaintext on the endpoint or the local network. Mirrors the macOS NE side
// (). Opt-in and additive: a zero value (enabled=false) keeps the legacy plaintext --edge-url path.
type transportConfig struct {
	enabled    bool
	host       string         // host:port of the Edge TLS transport listener (e.g. 203.0.113.10:18543 or edge.example.com:18543)
	serverName string         // SNI / name verified against the pinned cert (the hostname when host is a name)
	rootCAs    *x509.CertPool // pinned Edge transport CA -- the ONLY trusted root (fail-closed)
	// pinnedCAs are the SAME certificates as rootCAs, kept parsed because x509.CertPool cannot be read back.
	// Their fingerprints are reported to the Edge so an operator can see which devices already hold the CA
	// they are about to rotate to — without that, cutting over is a guess, and a device that missed it cannot
	// recover on its own.
	pinnedCAs  []*x509.Certificate
	clientCert *tls.Certificate // device client cert for mTLS device identity (nil = none)
	// sessionCache lets the (T) tunnel RESUME TLS sessions across dials of THIS transport instead of paying a
	// full mTLS handshake (TCP RTT + TLS 2-RTT + client-cert sign/verify) every time — what makes a many-flow
	// page fast (the macOS NE resumes for free; the Windows Go client did not until ca8cd9da). It is scoped PER
	// CONFIG, not process-global: a global cache is keyed by ServerName only, so a dial with a DIFFERENT pinned
	// CA but the same ServerName could RESUME a session established under another pin — and a resumed handshake
	// skips the RootCAs chain check, silently bypassing the pin (fail-OPEN). Per-config keeps resumption for the
	// real case (one agent, one pin, many dials) while a different pin gets its own empty cache and must do a
	// full, pin-verified handshake. Set by buildTransportConfig; shared via the interface value across copies.
	//
	// It is an ATOMIC POINTER because adopting a renewed identity must be able to REPLACE it. TLS 1.3
	// resumption skips the client-certificate exchange entirely and Go's server keeps showing the certificate
	// from the ORIGINAL session (tickets live up to 7 days), so a device that renews while resumption is in
	// force goes on presenting its OLD certificate to the Edge — the endpoint believes it renewed, the Edge
	// observes the old certificate, and both are right about what they can see. That is exactly how a device
	// blocks a CA retirement it has already moved off (2026-08-02).
	sessionCache *atomic.Pointer[tls.ClientSessionCache]
	// pins holds resolved "ip:port" endpoints for a HOSTNAME Edge. dial() connects to a pin instead of resolving
	// `host` via the system resolver -- which under DNS-takeover is the loopback proxy that needs the very tunnel
	// this dial is establishing (chicken-and-egg). TLS still uses serverName, so the cert/CA pin is unchanged
	// (we dial by IP but verify the hostname). nil/empty => `host` is an IP literal (or pins not yet resolved),
	// so dial uses `host` directly. Shared via pointer across transportConfig copies; refreshed for availability.
	pins *atomic.Pointer[[]string]
	// active, when non-nil, is the region-failover-controlled LIVE endpoint (host:port + SNI + out-of-band-resolved
	// pins) shared by pointer across every transportConfig value-copy (per-flow CONNECT dial, DNS-over-tunnel
	// proxy, list-fetch HTTP client). A region switch is one atomic Store here and EVERY consumer's next dial
	// follows it -- no rebuilding goroutines. When set it OVERRIDES host/serverName/pins; nil = single-endpoint
	// mode (the legacy pins/host path). The pinned CA + device client cert are shared across regions (one
	// --transport-pinned-ca), so only the dial target + SNI change per region; the fail-closed pin is unchanged.
	active *atomic.Pointer[activeEndpoint]
	// liveClientCert, when non-nil, is the device client certificate CURRENTLY in force, shared by pointer
	// across every transportConfig value-copy so an automated renewal takes effect on the next dial without
	// restarting the agent or rebuilding anything. It OVERRIDES clientCert when set. Same idiom as `active`
	// above and for the same reason: one atomic Store and every consumer's next dial follows it.
	//
	// Established tunnels keep the certificate they handshaked with. Renewal is housekeeping and must not be
	// able to interrupt steering — a credential-maintenance path that can drop live flows would recreate the
	// outage this whole area exists to prevent.
	liveClientCert *atomic.Pointer[tls.Certificate]
	// liveTrust, when non-nil, is the pinned TRUST material currently in force — the anchor-side twin of
	// liveClientCert, and the same idiom for the same reason. Trust-anchor recovery stores adopted anchors here
	// so the next dial verifies the Edge against them without a restart; when unset, rootCAs/pinnedCAs (loaded
	// at startup) apply unchanged.
	liveTrust *atomic.Pointer[trustMaterial]
	// startupAdoptedSerial is the trust-bundle serial of the anchors buildTransportConfig loaded from the
	// adopted store at startup (0 when the provisioned pin was used, or nothing was adopted yet). It is the
	// serial-twin of pinnedCAs, used ONLY while liveTrust is unset — once trust-anchor recovery adopts at
	// runtime, the serial comes from liveTrust instead. Keeping the serial and the anchor set derived from the
	// SAME source (never one from a live set and the other from a startup snapshot) is the whole point: the
	// Edge's CA-withdrawal gate opens on the reported serial+fingerprints, so a report that pairs a set the
	// device does NOT verify with a serial it does could open the gate on unheld trust — a fleet-wide outage.
	startupAdoptedSerial int64
	// refusals, when non-nil, is the journal a failed (T) verification writes to — the served certificate and
	// the verifier's words — so a device that cannot connect can still explain why on the next connection that
	// works. Shared by pointer across every transportConfig copy. nil = not recording.
	refusals *trustRefusalJournal
	// onCertificateRequest, when non-nil, is called with the server's client-certificate request and the
	// certificate this config would present. Diagnostic only — it cannot change the outcome. Client-certificate
	// SELECTION happens inside crypto/tls, so without this the three ways a renewal can fail ("wrong issuer",
	// "cannot sign", "sent nothing") all surface as one server-side "certificate required".
	onCertificateRequest func(*tls.CertificateRequestInfo, *tls.Certificate)
	// announcedServerName, when non-nil, carries the name THIS ORGANIZATION's agents are told to send — the
	// trust bundle's transport_server_name — shared by pointer across every copy so an adoption takes effect on
	// the next dial. Empty/unset means what it has always meant: this organization is served the deployment's
	// shared certificate and the provisioned serverName applies unchanged.
	//
	// ★★★ ROADMAP D, S3 (2026-08-19, Edge half landed in fec75f5f). Every organization verifies this Edge with
	// ONE shared anchor today, so whoever holds it can impersonate the Edge to all of them. A certificate per
	// organization needs a selector the server can read BEFORE the client certificate arrives, and the only one
	// there is is the SNI. No DNS is involved: the agent dials the address it already has and sends this name.
	// The name is ANNOUNCED rather than configured here precisely so it cannot drift from the certificate the
	// Edge actually serves — an agent must never invent one.
	announcedServerName *atomic.Pointer[string]
	// fleetServerName, when non-nil, carries the transport name the SIGNED REGION LIST states this
	// organization's agents present at EVERY region (agentpolicy.RegionEndpointsPayload.TransportServerName).
	// Empty/unset means the list did not state one, which is how every list issued before the field existed
	// reads — and that absence is load-bearing; see activeServerName.
	fleetServerName *atomic.Pointer[string]
	// configuredServerName is the name the signed INSTALL PROFILE stated (installprofile.OrganizationSpec).
	// Unlike the two above it is not a live pointer: it is fixed when the profile is applied, and it is the
	// only one of the three that exists before this device has ever been told anything.
	configuredServerName string
	// announcedRecoverySNI, when non-nil, carries the trust bundle's renewal_recovery_sni — the name to SEND
	// when dialing the expired-certificate recovery path. Only recoveryTransport reads it.
	announcedRecoverySNI *atomic.Pointer[string]
	// sendSNI, when set on a COPY, is the name that copy puts in the ClientHello INSTEAD of the name it
	// verifies against. Sending and verifying are the same string everywhere else, and separating them here is
	// the whole mechanism by which the expired-certificate recovery path folds onto the main port: the Edge
	// selects the relaxed configuration by SNI, before any certificate is exchanged.
	//
	// ★ THE RECOVERY NAME IS A SELECTOR, NOT AN IDENTITY, AND THAT IS PERMANENT (measured on the live Edge,
	// 2026-08-19, with the recovery path already serving on the transport port). Under that name the Edge
	// presents its ORDINARY transport certificate — the SAN carries the Edge's own names and never the
	// recovery name. So a client that set ServerName and let the TLS stack verify would refuse the recovery
	// path outright, and would go on refusing it after every remaining step of the fold. The name must be sent
	// and NOT verified until the day that certificate is reissued carrying it.
	//
	// It is NOT a relaxation: the served chain is still verified against the pinned anchors and against the
	// name this device has always verified. Only the label in the ClientHello changes.
	sendSNI string
}

// trustMaterial pairs the verification pool with its parsed certificates (x509.CertPool cannot be read back)
// and the serial of the trust bundle they came from, so the reported serial and fingerprints always come from
// one atomic value rather than two sources that can disagree.
type trustMaterial struct {
	pool   *x509.CertPool
	cas    []*x509.Certificate
	serial int64
}

// currentTrustAnchors returns the anchors a dial would verify against right now: the adopted set when
// trust-anchor recovery has installed one, otherwise the anchors loaded at startup.
func (tc transportConfig) currentTrustAnchors() []*x509.Certificate {
	if tc.liveTrust != nil {
		if m := tc.liveTrust.Load(); m != nil {
			return m.cas
		}
	}
	return tc.pinnedCAs
}

// currentTrustSerial returns the trust-bundle serial of the anchors CURRENTLY IN FORCE — the same decision
// currentTrustAnchors makes (live adopted set vs the startup set), so the serial and the fingerprints reported
// to the Edge can never come from different realities. 0 means "no adopted bundle" (fingerprint-only, as before).
func (tc transportConfig) currentTrustSerial() int64 {
	if tc.liveTrust != nil {
		if m := tc.liveTrust.Load(); m != nil {
			return m.serial
		}
	}
	return tc.startupAdoptedSerial
}

// setTrustAnchors puts an adopted anchor set (and its serial) in force for every copy of this config. The set
// REPLACES the provisioned one — replacement is what makes a withdrawal possible; a union could only ever widen
// what the device accepts, so a compromised CA would stay trusted forever. Safe to be authoritative because
// nothing reaches this call unverified (pinned signature + advancing serial).
func (tc transportConfig) setTrustAnchors(pemBytes []byte, serial int64) {
	if tc.liveTrust == nil {
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return // an unusable set must never replace a usable one
	}
	// ★ THE SESSION CACHE OUTLIVES THE ANCHORS UNLESS IT IS DROPPED (2026-08-12, eighteenth review).
	// setClientCert has flushed for this reason since it was written; replacing the ROOTS needs it for the
	// mirror-image reason. A resumed TLS session restores the peer certificate cached with the ticket, and
	// VerifyConnection runs on resumption too — so the first dial after a withdrawal verifies the OLD
	// certificate against the NEW roots and fails. Go discards the ticket after that failure, so it is one
	// connection rather than an outage; but it is the first user flow after a CA rotation, which is precisely
	// the moment somebody is watching to see whether the rotation worked.
	//
	// ★ AND THE ORDER IS STORE-THEN-FLUSH (2026-08-12, nineteenth review). Flushing first looked safer and is
	// the one order that can leave a stale ticket behind AFTER this returns: a dial landing in the gap uses the
	// OLD roots with the NEW cache, completes a full handshake against the withdrawn CA, and SAVES that session
	// into the cache everything will go on using. Storing first bounds the damage to the gap itself — a dial
	// there uses the new roots and may resume one old ticket, which fails once and is discarded — and the flush
	// then clears whatever was in flight.
	//
	// The window is not closed, it is made survivable: closing it needs the roots and the cache swapped as one
	// value, which is a larger change to a struct copied by value into every dialer.
	tc.liveTrust.Store(&trustMaterial{pool: pool, cas: parsePinnedCAs(pemBytes), serial: serial})
	tc.flushSessionCache()
}

// currentClientCert returns the device certificate a dial would present right now: the renewed one when
// automated renewal has installed one, otherwise the certificate loaded at startup.
func (tc transportConfig) currentClientCert() *tls.Certificate {
	if tc.liveClientCert != nil {
		if live := tc.liveClientCert.Load(); live != nil {
			return live
		}
	}
	return tc.clientCert
}

// setClientCert puts a renewed certificate in force for every copy of this config, and FLUSHES the session
// cache so the next dial is a full handshake.
//
// The flush is not housekeeping — it is what makes the renewal reach the wire. Under TLS 1.3 a resumed
// handshake does not re-present the client certificate, and Go's server restores the ORIGINAL session's
// certificate from the ticket, so without this the Edge would keep observing the superseded certificate for as
// long as tickets last (up to 7 days) while this device reported itself renewed. Dropping the cache costs one
// full handshake per adoption and nothing after.
func (tc transportConfig) setClientCert(cert *tls.Certificate) {
	if tc.liveClientCert != nil {
		tc.liveClientCert.Store(cert)
	}
	tc.flushSessionCache()
}

// flushSessionCache replaces the shared cache with an empty one, so every consumer's next dial performs a full
// handshake (and therefore presents whatever identity is in force NOW).
func (tc transportConfig) flushSessionCache() {
	if tc.sessionCache == nil {
		return
	}
	fresh := tls.ClientSessionCache(tls.NewLRUClientSessionCache(256))
	tc.sessionCache.Store(&fresh)
}

// trustSnapshot is what a dial uses: the session cache it may store into, and the roots it verifies against.
//
// ★ THE ORDER OF THESE TWO READS IS A SAFETY PROPERTY (2026-08-12, twentieth review). One pairing outlives a
// CA withdrawal: a dial holding the NEW cache and the OLD roots completes a handshake against the CA being
// withdrawn and SAVES that session into the cache everything afterwards uses. The reverse pairing costs one
// resumed ticket, which fails and is discarded.
//
// setTrustAnchors stores the roots and THEN flushes the cache. So if a reader observes the new cache, the
// flush has already happened, and the flush happened after the roots were stored — therefore a read of the
// roots that comes AFTER the cache read must see the new roots. Cache first, then roots, makes the surviving
// pairing unreachable.
//
// It is one helper because the previous attempt had the production path reading roots→cache and the test
// reading cache→roots: the test asserted an interleaving the product does not perform, and passed while the
// one that matters stayed open. Anything that needs both values calls this.
func (tc transportConfig) trustSnapshot() (tls.ClientSessionCache, *x509.CertPool) {
	cache := tc.currentSessionCache()
	roots := tc.rootCAs
	if tc.liveTrust != nil {
		if m := tc.liveTrust.Load(); m != nil {
			roots = m.pool
		}
	}
	return cache, roots
}

// currentSessionCache is the cache a dial should use right now (nil-safe for zero-value configs in tests).
func (tc transportConfig) currentSessionCache() tls.ClientSessionCache {
	if tc.sessionCache == nil {
		return nil
	}
	if c := tc.sessionCache.Load(); c != nil {
		return *c
	}
	return nil
}

// newSessionCachePointer builds the shared, replaceable cache holder used by every transportConfig.
func newSessionCachePointer(size int) *atomic.Pointer[tls.ClientSessionCache] {
	p := &atomic.Pointer[tls.ClientSessionCache]{}
	c := tls.ClientSessionCache(tls.NewLRUClientSessionCache(size))
	p.Store(&c)
	return p
}

// activeEndpoint is one region's live transport target, swapped in atomically by the region-failover loop.
type activeEndpoint struct {
	host       string   // host:port to dial when dialAddrs is empty (IP literal, or pre-resolution fallback)
	serverName string   // SNI verified against the pinned transport CA for THIS region's Edge
	dialAddrs  []string // out-of-band-resolved "ip:port" pins (round-robined); empty => dial host directly
}

// edgeDialCounter spreads successive dials across multiple pinned Edge IPs (hostname-based Edge HA).
var edgeDialCounter atomic.Uint64

// dialTarget returns the address dial() should connect to: a pinned IP:port when a hostname Edge has been
// resolved (round-robined across pins), else `host` verbatim (IP literal, or pre-resolution fallback).
func (tc transportConfig) dialTarget() string {
	// Region failover (when active) overrides the single-endpoint host/pins entirely.
	if tc.active != nil {
		if ae := tc.active.Load(); ae != nil {
			if len(ae.dialAddrs) > 0 {
				return ae.dialAddrs[int(edgeDialCounter.Add(1))%len(ae.dialAddrs)]
			}
			if ae.host != "" {
				return ae.host
			}
		}
	}
	if tc.pins != nil {
		if p := tc.pins.Load(); p != nil && len(*p) > 0 {
			addrs := *p
			return addrs[int(edgeDialCounter.Add(1))%len(addrs)]
		}
	}
	return tc.host
}

// activeServerName returns the name to VERIFY the Edge's certificate against for the current dial.
//
// ★ THE ONE SUBTLE RULE IS WHAT HAPPENS UNDER REGION FAILOVER, and it turns on whether the signed region list
// STATES a fleet-wide name.
//
// It used to be unconditional: the active region's own host name outranked everything. That was the safe order
// rather than the tidy one. A region's endpoint names the certificate THAT region serves; the announcement
// comes from whichever Edge issued the bundle. A region with no certificate for this organization serves the
// shared one, and a device verifying that against the organization's name refuses it — locking itself out of
// the region it just failed over to, which is the one moment it cannot afford that.
//
// The deployment answered that on 2026-08-22 by putting the names IN the signed region list, backed by a fleet
// rule: a node that cannot keep what the fleet announces refuses to join it, so failing over never changes
// which name to send. When the list states a name, that promise exists and the name is sent everywhere. When it
// does not — every list issued before the field, and any fleet that has not adopted it — the old rule stands
// unchanged. Absence is not permission; it is the same silence it always was.
func (tc transportConfig) activeServerName() string {
	fleet := tc.currentFleetServerName()
	if tc.active != nil {
		if ae := tc.active.Load(); ae != nil && ae.serverName != "" {
			if fleet == "" {
				return ae.serverName
			}
			// The list promised this name at every region, so failing over is no longer a reason to stop
			// presenting the organization.
			return fleet
		}
	}
	if n := tc.currentAnnouncedServerName(); n != "" {
		return n
	}
	if fleet != "" {
		return fleet
	}
	// What the install stated, which is all a device has before its first trust bundle — and the whole reason
	// enrolment can select an organization-scoped route at all.
	if n := strings.TrimSpace(tc.configuredServerName); n != "" {
		return n
	}
	return tc.serverName
}

// trustBundleServerName is WHICH ORGANIZATION'S bundle this device should ask for.
//
// ★★★ A NEW DEVICE ASKED FOR NOBODY'S AND WAS GIVEN THE NODE'S (2026-08-29, measured on a Windows machine by
// the session that walked it). The first fetch passed currentAnnouncedServerName(), which is the name an
// ADOPTED bundle announced — empty on a device that has never adopted one. The Edge answers a nameless request
// with its own organization, as it must, so a brand-new device of one organization adopted the DEPLOYMENT's
// interception root and logged "ADOPTED serial=3 anchors=1". Every screen went green with the wrong authority
// in place: "each organization is inspected under its own" became false while nothing said so.
//
// The name was in the signed install profile the whole time, and the agent prints it at start-up. One query
// parameter short.
//
// ★ IT DOES NOT FALL BACK TO THE DEPLOYMENT HOST. Asking for that is the same as asking for nothing — it is
// how this device got somebody else's authority in the first place.
func (tc transportConfig) trustBundleServerName() string {
	if n := tc.currentAnnouncedServerName(); n != "" {
		return n
	}
	// What the install stated. The only thing a device has before its first bundle, and the one moment the
	// answer matters most, because what it adopts here decides what it trusts afterwards.
	return strings.TrimSpace(tc.configuredServerName)
}

// currentFleetServerName is the transport name the signed region list states, or "".
func (tc transportConfig) currentFleetServerName() string {
	if tc.fleetServerName == nil {
		return ""
	}
	if n := tc.fleetServerName.Load(); n != nil {
		return strings.TrimSpace(*n)
	}
	return ""
}

// setFleetServerName puts the signed region list's fleet-wide name in force for every copy of this config.
// Empty clears, for the same reason setAnnouncedNames' empty clears: a deployment that stops stating a name
// means "the shared certificate", and a device that kept the old one would keep asking for a certificate
// nobody serves.
func (tc transportConfig) setFleetServerName(name string) {
	if tc.fleetServerName == nil {
		return
	}
	v := strings.TrimSpace(name)
	tc.fleetServerName.Store(&v)
}

// currentAnnouncedServerName is the organization's announced transport name in force right now, or "".
func (tc transportConfig) currentAnnouncedServerName() string {
	if tc.announcedServerName == nil {
		return ""
	}
	if n := tc.announcedServerName.Load(); n != nil {
		return strings.TrimSpace(*n)
	}
	return ""
}

// currentRecoverySNI is the announced name for the expired-certificate recovery dial, or "".
func (tc transportConfig) currentRecoverySNI() string {
	if tc.announcedRecoverySNI == nil {
		return ""
	}
	if n := tc.announcedRecoverySNI.Load(); n != nil {
		return strings.TrimSpace(*n)
	}
	return ""
}

// sniToSend is the name that goes in the ClientHello. It equals the verified name unless a copy was built to
// send a different one (see sendSNI) — so a probe and the real dial always select the same certificate.
func (tc transportConfig) sniToSend() string {
	if n := strings.TrimSpace(tc.sendSNI); n != "" {
		return n
	}
	return tc.activeServerName()
}

// setAnnouncedNames puts an adopted bundle's names in force for every copy of this config. Empty clears:
// a deployment that stops announcing a name means "the shared certificate", and a device that kept the old
// name would keep asking for a certificate nobody serves any more.
func (tc transportConfig) setAnnouncedNames(serverName, recoverySNI string) {
	if tc.announcedServerName != nil {
		v := strings.TrimSpace(serverName)
		tc.announcedServerName.Store(&v)
	}
	if tc.announcedRecoverySNI != nil {
		v := strings.TrimSpace(recoverySNI)
		tc.announcedRecoverySNI.Store(&v)
	}
}

// buildTransportConfig parses the transport URL and loads the pinned CA + optional device client cert.
// Empty transportURL => disabled (legacy plaintext edge). A non-empty URL REQUIRES a pinned CA: we never
// fall back to the system trust store for the tunnel (fail-closed pinning is the whole point).
// buildTransportConfigFromPEM builds the (T) transport from in-memory PEM material instead of file paths — used
// by the --config-store service path, which loads the enrolled device identity (device.crt / device-ca.pem /
// DPAPI-unwrapped key) and MUST NOT write the unwrapped private key back to disk. Same fail-closed rules as
// buildTransportConfig: a URL with no pinned CA errors; client cert+key must come as a pair.
func buildTransportConfigFromPEM(transportURL string, pinnedCAPEM, clientCertPEM, clientKeyPEM []byte) (transportConfig, error) {
	if strings.TrimSpace(transportURL) == "" {
		return transportConfig{}, nil
	}
	u := strings.TrimSpace(transportURL)
	if !strings.HasPrefix(u, "https://") {
		return transportConfig{}, fmt.Errorf("transport url must be https:// (got %q)", transportURL)
	}
	hostport := strings.TrimRight(strings.TrimPrefix(u, "https://"), "/")
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		hostport = net.JoinHostPort(hostport, "443")
	}
	if len(pinnedCAPEM) == 0 {
		// NOT "the enrolled device-ca.pem", which is what this said and what the caller used to pass: that CA
		// signs THIS DEVICE's certificate, not the Edge's. See transport_anchors_windows.go.
		return transportConfig{}, fmt.Errorf("transport %q requires the transport anchors to verify the Edge with", transportURL)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pinnedCAPEM) {
		return transportConfig{}, fmt.Errorf("pinned transport CA has no usable certificate")
	}
	tc := transportConfig{enabled: true, host: hostport, serverName: host, rootCAs: pool,
		pinnedCAs:    parsePinnedCAs(pinnedCAPEM),
		sessionCache: newSessionCachePointer(256), liveClientCert: &atomic.Pointer[tls.Certificate]{},
		liveTrust:            &atomic.Pointer[trustMaterial]{},
		announcedServerName:  &atomic.Pointer[string]{},
		fleetServerName:      &atomic.Pointer[string]{},
		announcedRecoverySNI: &atomic.Pointer[string]{}}
	if len(clientCertPEM) > 0 || len(clientKeyPEM) > 0 {
		if len(clientCertPEM) == 0 || len(clientKeyPEM) == 0 {
			return transportConfig{}, fmt.Errorf("device client identity needs BOTH cert and key PEM")
		}
		cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		if err != nil {
			return transportConfig{}, fmt.Errorf("load device client identity: %w", err)
		}
		tc.clientCert = &cert
	}
	return tc, nil
}

// transportTrustAnchors is THE anchor set this device verifies the Edge with, and the serial it belongs to.
//
// ★ ADOPTED REPLACES PROVISIONED; IT MUST NEVER BE A UNION (2026-08-12, seventeenth review). setTrustAnchors
// says exactly this for the LIVE path and I broke it on the startup path for enrolled devices: a helper that
// returned "the pin plus whatever was adopted" looks conservative and is the opposite. A union can only ever
// WIDEN what a device accepts, so a CA withdrawn for being compromised stays trusted — and worse, silently,
// because the device reports the new anchors as adopted while still accepting the old ones.
//
// The failure was not only theoretical width. The union carried NO serial, so a device that had adopted at
// serial 3 came back from a restart reporting 0, the Edge saw an anchor set it was happy with, and nothing
// re-adopted — leaving the withdrawn CA trusted until some later serial happened to arrive.
//
// "Nothing usable adopted" falls back to the provisioned file, which is the state the device was working in.
// A missing or unusable pin file is an error for the caller to decide about: the device-issuing CA is NOT a
// substitute, and an empty set that fails every handshake is safer than a set from another trust domain.
func transportTrustAnchors(pinnedCAFile string, requiredAnchors []string) (*x509.CertPool, []*x509.Certificate, int64, string, error) {
	pinnedCAFile = strings.TrimSpace(pinnedCAFile)
	if pinnedCAFile == "" {
		return nil, nil, 0, "", fmt.Errorf("a transport CA pin is required (fail-closed)")
	}
	// ★ THE ADOPTED SET IS CONSULTED FIRST, AND THE ORDER IS THE POINT (2026-08-12, eighteenth review). The
	// first version read the provisioned file and RETURNED ITS ERROR before ever looking at the adopted store,
	// which contradicts the rule the rest of this function implements: adopted SUPERSEDES provisioned. A
	// device that has rotated past its birth anchor no longer needs that file — and on the day somebody
	// removes or truncates it, a restart took the box off the network entirely (empty pool on the enrolled
	// path, a refusal to start on the other) while a perfectly good adopted bundle sat in the same directory.
	//
	// Only the PATH is needed to find it: the adopted store lives beside the pin, so the lookup is keyed on
	// the directory rather than on the file's contents.
	if adoptedPEM, adoptedCAs, serial, ok := adoptedTrustAnchors(filepath.Dir(pinnedCAFile)); ok {
		adoptedPool := x509.NewCertPool()
		if adoptedPool.AppendCertsFromPEM(adoptedPEM) {
			// ★★★ AN ADOPTED SET THAT DOES NOT COVER THE PROFILE'S DOORS IS NOT A SUPERSESSION (2026-08-29,
			// measured on win-dev-1 against hikari.lab).
			//
			// "Adopted supersedes provisioned" is right for a ROTATION — the operator retires an anchor by
			// issuing a distribution without it, and a device that kept the old one forever could never be
			// rotated off a compromised authority. It is wrong for the case measured here: this device's
			// first trust-bundle fetch names no organization, so an Edge answers with ITS OWN
			// organization's distribution, and the device adopted anchors belonging to a different tenant.
			// They superseded the correct provisioned ones, every dial to this organization's own door
			// failed from then on, and the log line said ADOPTED.
			//
			// So supersession is conditional on COVERAGE: an adopted set may replace the provisioned one
			// only while it still verifies the doors the CURRENT signed profile tells this device to knock
			// on. When it does not, both sets are in force and the gap is stated. Rotation is unaffected —
			// a rotation is issued as a profile and a distribution together, and the profile names what it
			// still expects. The precedent is bypass_dests, merged rather than replaced for the same
			// reason: both inputs are signed by the same organization, and the measured cost of the
			// alternative is a site fact vanishing in silence.
			missing := installprofile.MissingAnchors(installprofile.Fingerprints(adoptedCAs), requiredAnchors)
			if len(missing) == 0 {
				log.Printf("transport trust anchors source=adopted serial=%d anchors=%d (the provisioned pin file is superseded)",
					serial, len(adoptedCAs))
				return adoptedPool, adoptedCAs, serial,
					fmt.Sprintf("anchors adopted from a signed trust bundle (serial %d), which SUPERSEDE the provisioned pin", serial),
					nil
			}
			provisionedPEM, readErr := os.ReadFile(pinnedCAFile)
			if readErr == nil && adoptedPool.AppendCertsFromPEM(provisionedPEM) {
				union := append(append([]*x509.Certificate{}, adoptedCAs...), parsePinnedCAs(provisionedPEM)...)
				log.Printf("transport trust anchors source=adopted+provisioned serial=%d adopted=%d union=%d "+
					"— the adopted distribution does NOT carry %d authority(ies) this profile names (%v), so it does "+
					"not supersede them; both sets are in force",
					serial, len(adoptedCAs), len(union), len(missing), missing)
				return adoptedPool, union, serial,
					fmt.Sprintf("anchors adopted from a signed trust bundle (serial %d) UNIONED with the provisioned "+
						"pin, because the adopted set does not carry %d authority the profile names", serial, len(missing)),
					nil
			}
			log.Printf("transport trust anchors source=adopted serial=%d anchors=%d — the adopted distribution does "+
				"NOT carry %d authority(ies) this profile names (%v) and the provisioned pin could not be read (%v); "+
				"dials to this organization's own door will fail",
				serial, len(adoptedCAs), len(missing), missing, readErr)
			return adoptedPool, adoptedCAs, serial,
				fmt.Sprintf("anchors adopted from a signed trust bundle (serial %d), which do NOT cover %d authority "+
					"the profile names", serial, len(missing)),
				nil
		}
	}
	// Nothing usable adopted: the provisioned anchor is what this device was born with and is still the answer.
	pemBytes, err := os.ReadFile(pinnedCAFile)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("read pinned transport CA %q: %w", pinnedCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, nil, 0, "", fmt.Errorf("pinned transport CA %q has no usable certificate", pinnedCAFile)
	}
	return pool, parsePinnedCAs(pemBytes), 0, "the provisioned transport pin", nil
}

// buildTransportConfigFromAnchors builds the (T) transport from an already-selected anchor set and an
// in-memory client identity — the enrolled path, where the certificate and key come from DPAPI rather than
// from files and must never touch disk.
//
// The pool may be EMPTY, deliberately. A device with no usable anchor has nothing to verify the Edge with, and
// the honest expression of that is a root set that accepts nothing: every handshake fails closed, the service
// still runs, and the refusal journal records what was served. Substituting a CA from another trust domain —
// the device-issuing CA, which signs client certificates — would instead GRANT it server authority.
// identityDir, when non-empty, is where an automated renewal keeps the identity it issued. It is consulted
// FIRST for the same reason the file path prefers a renewed identity over the one on the command line: once a
// device has renewed even once, the material it was provisioned with is the older credential heading for
// expiry. On an enrolled device that material is the enrolment's own certificate, which nothing rewrites.
func buildTransportConfigFromAnchors(transportURL string, pool *x509.CertPool, pinned []*x509.Certificate,
	startupSerial int64, identityDir string, clientCertPEM, clientKeyPEM []byte) (transportConfig, error) {
	if strings.TrimSpace(transportURL) == "" {
		return transportConfig{}, nil
	}
	u := strings.TrimSpace(transportURL)
	if !strings.HasPrefix(u, "https://") {
		return transportConfig{}, fmt.Errorf("transport url must be https:// (got %q)", transportURL)
	}
	hostport := strings.TrimRight(strings.TrimPrefix(u, "https://"), "/")
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		hostport = net.JoinHostPort(hostport, "443")
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	tc := transportConfig{enabled: true, host: hostport, serverName: host, rootCAs: pool,
		pinnedCAs: pinned, startupAdoptedSerial: startupSerial,
		sessionCache: newSessionCachePointer(256), liveClientCert: &atomic.Pointer[tls.Certificate]{},
		liveTrust:            &atomic.Pointer[trustMaterial]{},
		announcedServerName:  &atomic.Pointer[string]{},
		fleetServerName:      &atomic.Pointer[string]{},
		announcedRecoverySNI: &atomic.Pointer[string]{}}
	if strings.TrimSpace(identityDir) != "" {
		if pointer, perr := readIdentityPointer(identityDir); perr == nil {
			if cert, lerr := loadIdentityFromPointer(pointer); lerr == nil {
				if renewedIdentityBelongsToEnrollment(&cert, clientCertPEM) {
					log.Printf("transport device identity source=renewed (an automated renewal is in force; storage=%s)",
						pointerStorageLabel(pointer))
					tc.clientCert = &cert
					return tc, nil
				}
				log.Printf("transport device identity: ignoring a renewal from another organization; using the enrolled identity and preserving the previous key")
			} else {
				// Say it and fall through to the provisioned material, which is still a working identity until
				// it expires. Silence here would look identical to "this device has never renewed".
				log.Printf("transport device identity: a renewed identity is recorded but will not load (%v) — "+
					"using the provisioned one", lerr)
			}
		}
	}
	if len(clientCertPEM) > 0 || len(clientKeyPEM) > 0 {
		if len(clientCertPEM) == 0 || len(clientKeyPEM) == 0 {
			return transportConfig{}, fmt.Errorf("device client identity needs BOTH cert and key PEM")
		}
		cert, cerr := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		if cerr != nil {
			return transportConfig{}, fmt.Errorf("load device client identity: %w", cerr)
		}
		tc.clientCert = &cert
	}
	return tc, nil
}

func buildTransportConfig(transportURL, pinnedCAFile, clientCertFile, clientKeyFile string) (transportConfig, error) {
	if strings.TrimSpace(transportURL) == "" {
		return transportConfig{}, nil
	}
	u := strings.TrimSpace(transportURL)
	if !strings.HasPrefix(u, "https://") {
		return transportConfig{}, fmt.Errorf("transport url must be https:// (got %q)", transportURL)
	}
	hostport := strings.TrimRight(strings.TrimPrefix(u, "https://"), "/")
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		hostport = net.JoinHostPort(hostport, "443")
	}
	if strings.TrimSpace(pinnedCAFile) == "" {
		return transportConfig{}, fmt.Errorf("transport %q requires --transport-pinned-ca (fail-closed CA pin)", transportURL)
	}
	// nil: this is the FILE-based identity path (--transport-pinned-ca with a cert and key on disk), where the
	// caller has named the anchor file explicitly and no signed profile is deciding for it. The coverage rule
	// applies where a profile names the doors — the --config-store path — and main_windows.go passes the
	// profile's anchors to transportTrustAnchors directly there.
	pool, pinned, startupSerial, _, err := transportTrustAnchors(pinnedCAFile, nil)
	if err != nil {
		return transportConfig{}, err
	}
	tc := transportConfig{enabled: true, host: hostport, serverName: host, rootCAs: pool,
		pinnedCAs: pinned, startupAdoptedSerial: startupSerial,
		sessionCache: newSessionCachePointer(256), liveClientCert: &atomic.Pointer[tls.Certificate]{},
		liveTrust:            &atomic.Pointer[trustMaterial]{},
		announcedServerName:  &atomic.Pointer[string]{},
		fleetServerName:      &atomic.Pointer[string]{},
		announcedRecoverySNI: &atomic.Pointer[string]{}}
	if strings.TrimSpace(clientCertFile) != "" || strings.TrimSpace(clientKeyFile) != "" {
		if strings.TrimSpace(clientCertFile) == "" || strings.TrimSpace(clientKeyFile) == "" {
			return transportConfig{}, fmt.Errorf("device client cert needs BOTH --transport-client-cert and --transport-client-key")
		}
		// Prefer a RENEWED identity over the configured one. Once a device has renewed even once, the files on
		// the command line are the older credential heading for expiry.
		cert, source, err := loadDeviceIdentity(clientCertFile, clientKeyFile)
		if err != nil {
			return transportConfig{}, fmt.Errorf("load device client cert: %w", err)
		}
		if source == "renewed" {
			log.Printf("transport device identity source=renewed (an automated renewal is in force)")
		}
		tc.clientCert = &cert
	}
	return tc, nil
}

// tlsConfig builds the fail-closed client TLS config: the server cert MUST chain to the pinned transport
// CA (no system roots), and we present the device client cert for mTLS when configured.
func (tc transportConfig) tlsConfig() *tls.Config {
	cache, roots := tc.trustSnapshot()
	// Two names, and they are the same string except on the recovery dial: what goes on the wire selects the
	// certificate, what VerifyConnection checks below is what this device has to be able to trust. See sendSNI.
	serverName := tc.activeServerName()
	refusals := tc.refusals
	cfg := &tls.Config{
		ServerName:         tc.sniToSend(),
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: cache,
		// Verify in VerifyConnection rather than via the stdlib default so a REFUSAL can name the certificate
		// the Edge actually served: the stdlib aborts a failed verification WITHOUT exposing the served chain,
		// and a refusal a device cannot describe is the outage that hid for 47 minutes. This is a fail-CLOSED
		// REPLACEMENT, not a relaxation — InsecureSkipVerify only turns off the default check, and the check
		// below is the SAME pin (chain to the live `roots`, name == ServerName) run so its input is visible. The
		// two MUST stay paired here: InsecureSkipVerify without this callback would be fail-OPEN. A resumed
		// handshake runs this too (cs.PeerCertificates is the resumed peer), so resumption is pin-checked now
		// as well — strictly safer than the old RootCAs path, which skipped the chain check on resume.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if roots == nil {
				return fmt.Errorf("(T) transport has no pinned CA to verify the Edge against")
			}
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("the Edge presented no certificate")
			}
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         roots,
				DNSName:       serverName,
				Intermediates: intermediates,
			})
			if err != nil {
				// Write the refusal down — the served leaf and the verifier's own words — to be shipped on the
				// next working connection. Best-effort; it NEVER changes the fail-closed outcome (err is
				// returned regardless). nil journal => no-op.
				refusals.record(cs.PeerCertificates[0].Raw, err.Error(), time.Now())
			}
			return err
		},
	}
	if cert := tc.currentClientCert(); cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
		// GetClientCertificate takes precedence over Certificates and lets the decision be OBSERVED. The
		// behaviour is deliberately identical to the default: present this certificate. Returning it even when
		// SupportsCertificate objects matches what Go does with Certificates (it sends the first one rather than
		// nothing), so this hook diagnoses without changing what goes on the wire.
		if hook := tc.onCertificateRequest; hook != nil {
			chosen := *cert
			cfg.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				hook(cri, &chosen)
				return &chosen, nil
			}
		}
	}
	return cfg
}

// dial opens the (T) TLS tunnel to the Edge and returns the established (handshaked) connection. The caller
// then writes the normal CONNECT /steer (or POST /steer/dns-query) inside it.
func (tc transportConfig) dial(timeout time.Duration) (net.Conn, error) {
	target := tc.dialTarget()
	raw, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return nil, err
	}
	cfg := tc.tlsConfig()
	tconn := tls.Client(raw, cfg)
	_ = tconn.SetDeadline(time.Now().Add(timeout))
	if err := tconn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("(T) transport TLS handshake to %s (%s): %w", cfg.ServerName, target, err)
	}
	_ = tconn.SetDeadline(time.Time{})
	return tconn, nil
}

// parsePinnedCAs decodes every certificate in a PEM bundle. A bundle is the normal state during a CA
// rotation: the outgoing CA and the incoming one are both trusted until the changeover completes.
func parsePinnedCAs(pemBytes []byte) []*x509.Certificate {
	var out []*x509.Certificate
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
		// A malformed entry is skipped rather than aborting the file: losing the remainder is how an overlap
		// silently becomes a single pin again.
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, cert)
		}
	}
	return out
}

// pinnedCAFingerprints returns the SHA-256 of each pinned CA, lower-case hex — what an operator compares
// against the CA they are deploying. Reports the anchors actually in force, so an operator watching a rotation
// sees a device flip to the adopted set the moment it self-heals.
func (tc transportConfig) pinnedCAFingerprints() []string {
	cas := tc.currentTrustAnchors()
	out := make([]string, 0, len(cas))
	for _, cert := range cas {
		sum := sha256.Sum256(cert.Raw)
		out = append(out, hex.EncodeToString(sum[:]))
	}
	return out
}

// encodeCertsPEM renders parsed anchors back to PEM, for the callers that hand a CA set to something taking
// bytes. It exists so the SELECTION is made once (transportTrustAnchors) even where the consumer wants PEM.
func encodeCertsPEM(certs []*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		if c == nil {
			continue
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}
