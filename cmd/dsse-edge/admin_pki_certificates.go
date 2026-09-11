package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// The certificate MAP: every certificate and trust material this node is configured with, as one list of
// objects — each saying where it is used (what presents it, what verifies against it), what is in it, and
// which operations exist for it. GET /admin/pki/certificates.
//
// This exists because the Console's certificate screens each covered one API's slice of the PKI, and the
// operator's question — "where is what certificate used, what is in it, and how do I replace, disable or
// install it" — cuts across all of them. /admin/certs listed exactly ONE certificate (the hot-reloadable
// listener cert); the transport chain, the anchors devices pin, the device CAs and the interception CA were
// each somewhere else or nowhere. docs/pki_console_certificate_map_redesign.ja.md.
//
// FACTS ONLY, no prose: roles, addresses and relations are semantic identifiers the Console translates.
// Everything here is stated from this node's own configuration — nothing is guessed about other components,
// which is why the Console fetches this per node and shows the nodes side by side. PEM fields carry PUBLIC
// certificate material only (that is what "install" distributes); private keys never appear.

type pkiCertificateItem struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	// TenantID names the organization this material belongs to, when it belongs to one. Empty means the
	// DEPLOYMENT's own: the interception root every steered endpoint must trust, the transport anchor, this
	// node's server certificate. Those are shown to everybody, because every organization's devices depend on
	// them; per-tenant material is shown only to that organization and to the operator.
	TenantID string `json:"tenant_id,omitempty"`
	// TenantDisplayName is that organization's name as the deployment records it, so the screen can say whose
	// certificate this is without the reader having to know an id.
	//
	// ★★ THE SCREEN USED TO READ THIS OUT OF THE CERTIFICATE (2026-08-19). The Console labelled a row "Tenant"
	// and filled it from the subject's O= field, which is a string whoever minted the certificate typed. On
	// this deployment that produced both errors at once: Lab Tenant Interception Root 2028 — attributed to
	// tenant_reference_lab in the registry, and carrying no O= — showed NO organization, while the device
	// issuing CA the registry does not attribute at all showed "Lantern DSSE" because that is what its subject
	// says. An organization boundary read from a field inside the material it is supposed to bound is not a
	// boundary; it is whatever the issuer wrote. Attribution is the registry's answer or it is absent.
	TenantDisplayName string `json:"tenant_display_name,omitempty"`
	// OwnerUnknown marks a device-trust CA the registry cannot place. Shown to the operator only; a tenant's
	// view withholds these entirely, because "no owner" must never read as "everybody's" for a CA that always
	// belongs to somebody.
	OwnerUnknown bool `json:"owner_unknown,omitempty"`
	// StartupProblem is what the admission guard said about this certificate when the node started. A node
	// can be redeployed with a certificate the fleet will refuse, and until 2026-08-01 nothing said so — the
	// guard ran only on changes made through the Console. A log line alone would repeat the mistake this
	// whole screen exists to correct, so it is on the certificate itself.
	StartupProblem string `json:"startup_problem,omitempty"`
	// TrustedBy / NotReporting: devices that reported holding this certificate in their trust store, and
	// devices that said nothing. Silence is not absence — a device that has not reported may well hold it —
	// so the two are separate and a gate reads the second as "unknown", never as "no".
	// CanRetire and its reason: the same shape the transport anchor uses, so both answer "may I remove this"
	// in one way rather than two.
	CanRetire           bool     `json:"can_retire,omitempty"`
	RetireBlockedReason string   `json:"retire_blocked_reason,omitempty"`
	RetireBlockedCode   string   `json:"retire_blocked_code,omitempty"`
	RetireBlockedParams []string `json:"retire_blocked_params,omitempty"`

	// NotHolding are devices that REPORTED and do not hold this certificate — the state that decides a
	// withdrawal, and the one that used to be invisible because it was neither "trusted" nor "silent".
	NotHolding   []string `json:"not_holding,omitempty"`
	TrustedBy    []string `json:"trusted_by,omitempty"`
	NotReporting []string `json:"not_reporting,omitempty"`
	// PresentedAt: the listener addresses on THIS node that serve this certificate. Empty for material that
	// is not served (anchors, CAs, signing keys).
	PresentedAt []string `json:"presented_at,omitempty"`
	// VerifiedBy / Verifies: the trust relation in semantic ids ("device_transport_anchors",
	// "edge_transport_client_auth", …). The Console renders these; the server only asserts relations its own
	// configuration establishes.
	VerifiedBy []string `json:"verified_by,omitempty"`
	Verifies   []string `json:"verifies,omitempty"`

	Subject     string   `json:"subject,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	DNSNames    []string `json:"dns_names,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	// SelfSigned is worth stating because it changes what a replacement means: a self-signed cert IS its own
	// anchor, so replacing it re-anchors every peer that pins it.
	SelfSigned bool `json:"self_signed,omitempty"`
	// NameConstrained says the certificate limits what names its holder may issue for. The target hierarchy
	// (pki_ideal_lifecycle_design.ja.md) requires it on every per-tenant intermediate — one tenant's
	// intermediate leaking must not be able to mint certificates for another tenant's domains. Measured
	// rather than assumed: on 2026-08-01 the deployment had five self-signed CAs and no constraint at all,
	// and none of that was visible anywhere.
	NameConstrained bool `json:"name_constrained,omitempty"`

	// PEM is the public certificate, present when downloading it is how an operator installs trust in a peer
	// (an anchor into an agent config, the interception root into an endpoint trust store).
	PEM string `json:"pem,omitempty"`

	// Capabilities name the operations the Console may offer for this item: "replace" (hot-reload via
	// PUT /admin/certs/{name}), "history", "download", "rotate_signer", "renew_all", "acknowledge".
	// An operation not listed here must not be offered — a button that cannot work is worse than none.
	Capabilities []string `json:"capabilities,omitempty"`

	// CertName is the hot-reload registry name PUT /admin/certs/{name} expects, present when replace is a
	// capability of this item.
	CertName string `json:"cert_name,omitempty"`
	// Active states whether anything currently USES this material — presented on a listener, verifying what a
	// device presents today, signing what is issued today. Inactive material is real (still configured, still
	// trusted somewhere) but residual: the certificate a rotation left behind, a CA no observed device chains
	// to any more. Decided here so the Console can show the working set by default and never has to guess.
	Active bool `json:"active"`
	// ChainLength > 1 when the served material is a chain (leaf + cross-signed CA during a rotation).
	ChainLength int `json:"chain_length,omitempty"`
	// Count of observed devices, carried on the issuing CA (the fleet's certificates come from it; their
	// per-device rows live on the Devices page).
	Count int `json:"count,omitempty"`
	// Serial of the trust bundle distributing an anchor, so the operator can correlate with device logs.
	BundleSerial int64 `json:"bundle_serial,omitempty"`
	// Adoption answers "has this replacement actually reached the fleet?" for material devices verify:
	// a hot reload changes only NEW connections, so applied and adopted are different facts (2026-07-31).
	Adoption *serverCertAdoptionReport `json:"adoption,omitempty"`
}

type pkiCertificateInventory struct {
	SchemaVersion string `json:"schema_version"`
	// MeasuredOn names the machine that produced this inventory. A certificate map is assembled from more
	// than one node, and a row labelled with a plane the answer did not come from is worse than a row
	// missing: it tells an operator that the fingerprint their devices see is one they have never been shown.
	MeasuredOn string               `json:"measured_on,omitempty"`
	Items      []pkiCertificateItem `json:"items"`
}

// pkiCertInventoryInput carries the node's own configuration into the builder. Passed in rather than read
// from globals so the assembly is testable without standing up an Edge.
// interceptionRootTrust is who reported holding a given certificate, who reported NOT holding it, and who said
// nothing at all.
//
// ★★ THE MIDDLE ONE WAS MISSING, AND IT IS THE ONE A WITHDRAWAL TURNS ON (2026-08-19, found on live data
// within the hour). A device that reported and does not hold the certificate landed in neither list: not
// trusted, not silent, simply absent from the screen. Measured on the lab organization's own transport anchor
// — mac-dev-1 held it, conn_lab_001 was silent, and win-dev-1, which had answered and does NOT have it,
// appeared nowhere at all.
//
// The three states are not collapsible. Silence is "unknown, keep waiting". A definite no is "this device is
// cut off the moment you withdraw the other one". Folding no into silence makes the gate wait forever on a
// device that has already answered; folding it into trusted strands that device.
type interceptionRootTrust struct {
	Trusted []string
	NotHeld []string
	Silent  []string
}

type pkiCertInventoryInput struct {
	// InterceptionRootTrust is keyed by the root's fingerprint.
	InterceptionRootTrust map[string]interceptionRootTrust
	// TransportAnchorTrust is the same question for the anchors devices verify THE EDGE with, keyed the same
	// way. Separate from the interception map because the two are different certificates answering different
	// questions, and folding them would make a device's silence about one read as silence about both.
	TransportAnchorTrust map[string]interceptionRootTrust
	// PerTenantTransportAnchors is each organization's own anchor, keyed by organization (roadmap D). They are
	// served in that organization's bundle and must appear on the map for the same reason every other
	// certificate does: what is not drawn cannot be measured, and the last step of D is a withdrawal gated on
	// a measurement.
	PerTenantTransportAnchors map[string]string
	// PerTenantPendingTransportAnchors is the far end of an overlap: announced to that organization's devices
	// so they can adopt it, not yet served by this node. Drawn as INACTIVE, which is what it is — nothing is
	// presented under it today — and drawn at all, because "have my machines picked up the new one" is the
	// question the overlap exists to answer and it cannot be asked about a row that is not there.
	PerTenantPendingTransportAnchors map[string]string
	// InterceptionPendingRootPEM is a root being distributed but not yet signed under.
	InterceptionPendingRootPEM string
	// DeviceCARetireGate is the retire verdict per device-trust CA, keyed by fingerprint.
	DeviceCARetireGate map[string]gateVerdictResult

	Now time.Time

	// TenantName resolves an organization id to the name the deployment records for it, so the screen can say
	// whose certificate this is in the reader's words. Nil (or an unknown id) means the item carries no
	// organization name — never a guess, and never the O= field of the certificate itself.
	TenantName func(string) string

	// AttributeOwner answers whose certificate this is FROM THE SIGNATURE: the organization whose registered
	// CA issued it, or that registered it as their own. Nil means the deployment has no per-organization CA
	// registry, and then material is attributed only when something else states it outright.
	AttributeOwner func(*x509.Certificate) string

	// The hot-reloadable server certs (PUT /admin/certs) and the listeners they front.
	ComponentCerts []certInventoryEntry
	MainListen     string
	AdminListen    string

	// The (T) transport: what devices verify with the certificates they trust.
	TransportCertPEM []byte // leaf + any chain, as served
	TransportListen  string
	RecoveryListen   string
	// TransportCertName is the hot-reload registry name when the transport certificate is replaceable at
	// runtime ("" = startup-fixed). With it set, the transport item carries replace/history capabilities and
	// the component loop skips the duplicate registry entry for the same file.
	TransportCertName string
	// TransportAdoption is how far the fleet has re-handshaked onto the certificate now being served.
	TransportAdoption *serverCertAdoptionReport

	// What verifies device client certificates at (T), and what signs new ones at /enroll.
	TransportClientCAPEM []byte
	// DeviceCAOwners maps a device-trust CA's fingerprint to the organization that REGISTERED it. The registry
	// is the authority for that — a certificate is admitted as the tenant whose CA issued it — and this carries
	// the same fact onto the screen.
	//
	// ★ WITHOUT IT THE SCREEN GUESSED FROM THE NAME (2026-08-18, measured as Northwind's administrator). The
	// owner was read by looking for the literal "tenant_" inside the Subject or Issuer, so a customer CA named
	// "CN=Probe3 Device CA, O=Bootstrap Probe 3" had no owner, counted as DEPLOYMENT material, and was listed
	// to every organization on the node. The customer picks that name, so whether their own CA leaked to the
	// others depended on how they had chosen to write it.
	DeviceCAOwners map[string]string
	// DeviceClientCARetirable marks the set as runtime-mutable (the retire capability may be offered).
	DeviceClientCARetirable bool
	DeviceIssuingCAPEM      []byte

	// What devices pin, distributed by the signed trust bundle.
	TrustBundleCAPEM  string
	TrustBundleSerial int64

	// Interception: what steered endpoints trust, and what is signing right now.
	InterceptionRootPEM []byte
	IntermediateStatus  map[string]any
	InterceptionEnabled bool
	// ★★ EVERY TENANT WAS SHOWN THE DEPLOYMENT'S ROOT AS THE AUTHORITY INTERCEPTING IT (2026-08-18, measured
	// signed in as an operator inside Northwind, which HAS its own root). InterceptionRootPEM is one node-wide
	// certificate with no owner, so it rendered for everybody — and unowned items are shown to every tenant.
	// Northwind's certificates page therefore said "Lantern DSSE MSSP Root CA v2" and did NOT list "Northwind
	// Traders Interception Root 2028", which is the thing actually signing its traffic.
	//
	// That is the opposite of what this product promises the tenant: the provider's PKI and the tenant's are
	// independent, and the tenant's own root is what decrypts its people. A customer reading this screen was
	// told the provider holds that power, on the one screen built to answer exactly that question.
	//
	// PerTenantInterceptionRoots carries each tenant's own, so the row can be attributed rather than shared.
	PerTenantInterceptionRoots []perTenantInterceptionRoot
	// InterceptionPrimaryTenant is the tenant the node-wide root/intermediate actually belongs to. Naming it
	// is what stops that certificate from being everybody's.
	InterceptionPrimaryTenant string

	// The Ed25519 key devices verify signed agent policy / trust bundles / region endpoints with.
	AgentPolicySigningPubHex string

	// Fleet summary — the certificates devices hold live on /admin/device-certificates.
	DeviceCertCount int
	// The issuer CNs of the certificates devices are OBSERVED presenting right now. A client CA no observed
	// device chains to is configured-but-residual, which is the difference between the working set and the
	// leftovers of a rotation.
	ObservedDeviceIssuerCNs []string
}

// perTenantInterceptionRoot is one tenant's own interception anchor, as reported by the interception engine.
type perTenantInterceptionRoot struct {
	Tenant  string
	RootPEM string
}

// parseAllCerts returns every certificate in a PEM block, in order. Unparseable blocks are skipped: this is
// an inventory, and one corrupt entry must not hide the rest.
func parseAllCerts(pemBytes []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

func pkiItemFromCert(c *x509.Certificate) pkiCertificateItem {
	sum := sha256.Sum256(c.Raw)
	ips := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}
	return pkiCertificateItem{
		Subject:     c.Subject.String(),
		Issuer:      c.Issuer.String(),
		DNSNames:    c.DNSNames,
		IPAddresses: ips,
		NotBefore:   c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
		SHA256:      hex.EncodeToString(sum[:]),
		SelfSigned:  c.Subject.String() == c.Issuer.String(),
		NameConstrained: len(c.PermittedDNSDomains) > 0 || len(c.ExcludedDNSDomains) > 0 ||
			len(c.PermittedIPRanges) > 0 || len(c.ExcludedIPRanges) > 0,
		PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
	}
}

// verifiesCurrentChain reports whether the presented chain validates with ONLY this certificate as a root
// (the rest of the chain supplied as intermediates). With nothing presented there is no evidence either way,
// and configured material is not called residue on no evidence.
func verifiesCurrentChain(root *x509.Certificate, chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return true
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
	return err == nil
}

func buildPKICertificateInventory(in pkiCertInventoryInput) pkiCertificateInventory {
	items := []pkiCertificateItem{}

	// Component server certificates (hot-reloadable, replace + history + rollback). The transport
	// certificate registers in the same reload registry under its own name; it is the transport_server item
	// below, not a second component row.
	for _, e := range in.ComponentCerts {
		if in.TransportCertName != "" && e.Name == in.TransportCertName {
			continue
		}
		item := pkiCertificateItem{
			ID:           "component_server:" + e.Name,
			CertName:     e.Name,
			Role:         "component_server",
			Subject:      e.Subject,
			DNSNames:     e.DNSNames,
			IPAddresses:  e.IPAddresses,
			NotBefore:    e.NotBefore,
			NotAfter:     e.NotAfter,
			SHA256:       e.FingerprintSHA256,
			Active:       true, // it is being presented right now
			Capabilities: []string{"replace", "history", "download"},
		}
		addrs := []string{}
		if a := strings.TrimSpace(in.MainListen); a != "" {
			addrs = append(addrs, a)
		}
		if a := strings.TrimSpace(in.AdminListen); a != "" {
			addrs = append(addrs, a)
		}
		item.PresentedAt = addrs
		if raw, err := os.ReadFile(e.CertFile); err == nil {
			if certs := parseAllCerts(raw); len(certs) > 0 {
				parsed := pkiItemFromCert(certs[0])
				item.PEM = parsed.PEM
				item.Issuer = parsed.Issuer
				item.SelfSigned = parsed.SelfSigned
			}
		}
		items = append(items, item)
	}

	// The (T) transport chain: what the certificates devices trust verify. Not hot-reloadable — it is startup
	// configuration — so no "replace" here; offering one that needs a redeploy would be a lying button.
	transportChain := parseAllCerts(in.TransportCertPEM)
	if certs := transportChain; len(certs) > 0 {
		item := pkiItemFromCert(certs[0])
		item.ID = "transport_server"
		item.Role = "transport_server"
		for _, f := range servedCertificateStartupFindings {
			if f.Problem != "" && f.Name == deriveCertName(in.TransportCertName) {
				item.StartupProblem = f.Problem
			}
		}
		item.Active = true // presented on every device handshake
		item.ChainLength = len(certs)
		if in.TransportCertName != "" {
			item.CertName = in.TransportCertName
		}
		item.Adoption = in.TransportAdoption
		addrs := []string{}
		if a := strings.TrimSpace(in.TransportListen); a != "" {
			addrs = append(addrs, a)
		}
		if a := strings.TrimSpace(in.RecoveryListen); a != "" {
			addrs = append(addrs, a)
		}
		item.PresentedAt = addrs
		item.VerifiedBy = []string{"device_transport_anchors"}
		item.Capabilities = []string{"download"}
		if in.TransportCertName != "" {
			item.Capabilities = []string{"replace", "history", "download"}
		}
		items = append(items, item)
	}

	// The certificates devices trust, exactly as distributed. Withdrawing one is the gated operation on the
	// Device-trust surface; here each is inventory + install material. Active when it can still verify the
	// chain being presented TODAY — during a rotation's overlap both are active, which is the point of the
	// overlap; one that no longer verifies anything is residue.
	if strings.TrimSpace(in.TrustBundleCAPEM) != "" {
		if anchors, err := (agentpolicy.TrustBundlePayload{TransportCAPEM: in.TrustBundleCAPEM}).Anchors(); err == nil {
			for _, a := range anchors {
				item := pkiItemFromCert(a)
				item.ID = "transport_anchor:" + item.SHA256[:16]
				item.Role = "transport_anchor"
				item.Verifies = []string{"transport_server"}
				item.BundleSerial = in.TrustBundleSerial
				item.Active = verifiesCurrentChain(a, transportChain)
				item.Capabilities = []string{"download", "acknowledge"}
				// ★★★ WHO HOLDS IT, MEASURED (2026-08-19, roadmap D S4's precondition). Devices have been
				// reporting the transport CAs they hold (pinned_transport_ca_sha256) all along and this row
				// never asked, so the certificate map showed an anchor with no audience at all — the same
				// defect corrected for interception roots this morning, one certificate class over.
				//
				// It is not cosmetic: withdrawing an anchor from an organization's bundle is gated on every one
				// of its devices holding the replacement, and a gate with no denominator cannot fail. Roadmap D
				// ends with exactly that withdrawal, so the measurement has to exist before the step does.
				if t, ok := in.TransportAnchorTrust[item.SHA256]; ok {
					item.TrustedBy, item.NotHolding, item.NotReporting = t.Trusted, t.NotHeld, t.Silent
				}
				items = append(items, item)
			}
		}
	}

	// Each organization's OWN transport anchor (roadmap D). Drawn beside the shared ones, attributed, and
	// measured over that organization's devices — the withdrawal that ends D is gated on every one of them
	// holding it, and a certificate that is not on the map has no denominator.
	for tenant, anchorPEM := range in.PerTenantTransportAnchors {
		for _, a := range parseAllCerts([]byte(anchorPEM)) {
			item := pkiItemFromCert(a)
			item.ID = "transport_anchor:" + item.SHA256[:16]
			item.Role = "transport_anchor"
			item.TenantID = strings.TrimSpace(tenant)
			item.Verifies = []string{"transport_server"}
			item.Active = true // it is what this node serves that organization
			item.Capabilities = []string{"download"}
			if t, ok := in.TransportAnchorTrust[item.SHA256]; ok {
				item.TrustedBy, item.NotHolding, item.NotReporting = t.Trusted, t.NotHeld, t.Silent
			}
			items = append(items, item)
		}
	}

	for tenant, anchorPEM := range in.PerTenantPendingTransportAnchors {
		for _, a := range parseAllCerts([]byte(anchorPEM)) {
			item := pkiItemFromCert(a)
			item.ID = "transport_anchor:" + item.SHA256[:16]
			item.Role = "transport_anchor"
			item.TenantID = strings.TrimSpace(tenant)
			item.Verifies = []string{"transport_server"}
			item.Active = false // announced so devices can adopt it; this node still serves the other end
			item.Capabilities = []string{"download"}
			if t, ok := in.TransportAnchorTrust[item.SHA256]; ok {
				item.TrustedBy, item.NotHolding, item.NotReporting = t.Trusted, t.NotHeld, t.Silent
			}
			items = append(items, item)
		}
	}

	// What signs the certificates /enroll and /enroll/renew issue. Indexed by fingerprint so the client-CA
	// pass below can fold a duplicate into ONE row — the same certificate doing both jobs is one fact, and
	// showing it twice is how a list starts looking like leftovers.
	issuingBySHA := map[string]int{}
	for _, c := range parseAllCerts(in.DeviceIssuingCAPEM) {
		item := pkiItemFromCert(c)
		item.ID = "device_issuing_ca:" + item.SHA256[:16]
		item.Role = "device_issuing_ca"
		item.Active = true // it signs what is issued today
		// The fleet-wide renew operation and the observed-device count live HERE: this is where device
		// certificates come from, and the per-device rows live on the Devices page. (A separate "fleet"
		// aggregate used to hold them — an item with no visible contents, which the operator rightly called
		// meaningless.)
		item.Count = in.DeviceCertCount
		item.Capabilities = []string{"download", "renew_all"}
		issuingBySHA[item.SHA256] = len(items)
		items = append(items, item)
	}

	// What verifies a device's client certificate at the transport handshake. Active only while some observed
	// device still presents a certificate chaining to it — a CA the whole fleet has renewed away from is the
	// working set's leftovers, however long its own expiry runs.
	observedIssuers := map[string]bool{}
	for _, cn := range in.ObservedDeviceIssuerCNs {
		observedIssuers[strings.TrimSpace(cn)] = true
	}
	for _, c := range parseAllCerts(in.TransportClientCAPEM) {
		item := pkiItemFromCert(c)
		if idx, dup := issuingBySHA[item.SHA256]; dup {
			items[idx].Verifies = append(items[idx].Verifies, "device_certificates")
			continue
		}
		item.ID = "device_client_ca:" + item.SHA256[:16]
		item.Role = "device_client_ca"
		// The registry's answer, not the certificate's name.
		if owner := strings.TrimSpace(in.DeviceCAOwners[item.SHA256]); owner != "" {
			item.TenantID = owner
		} else {
			// ★ NAMED, NOT QUIETLY DROPPED (2026-08-18). The route that could create one of these is retired,
			// but the ones already registered are still admitting devices — and a device admitted through a CA
			// that belongs to nobody resolves to no tenant. The operator is the only caller who sees this (a
			// tenant's view withholds it) and the only one who can place it or withdraw it, so the answer says
			// so rather than leaving them to notice a blank column.
			//
			// Withdrawal is NOT automatic: a machine may hold a certificate from this CA, and removing it locks
			// that machine out. Placing it with its tenant is the other way out, and which one applies is not
			// something this code can know.
			item.OwnerUnknown = true
		}
		// Whether it can actually be retired, and if not what is holding it. The card states the rule — retire
		// once no device presents a certificate from it — and until now gave no way to see whether it held,
		// so the only way to learn the answer was to attempt the retirement.
		if v, ok := in.DeviceCARetireGate[item.SHA256]; ok {
			item.CanRetire = v.OK
			item.RetireBlockedReason = v.Text
			item.RetireBlockedCode = v.Code
			item.RetireBlockedParams = v.Params
		}
		item.Verifies = []string{"device_certificates"}
		item.Active = observedIssuers[c.Subject.CommonName]
		item.Capabilities = []string{"download"}
		if in.DeviceClientCARetirable {
			item.Capabilities = append(item.Capabilities, "retire")
		}
		// ★★ THE BADGE SAID "place or withdraw" AND ONLY ONE OF THEM WAS OFFERED (2026-08-19). An unattributed
		// device-trust CA is marked on the card with exactly that sentence, and the item carried `retire` and
		// `download` — nothing that places it. The way out existed (POST /admin/tenant-cas registers a CA to an
		// organization) and the screen holding the problem did not lead there, so the reader was told what to
		// do and left to find it. That is the shape this project keeps finding: a screen promising what it does
		// not offer.
		//
		// Placing is the SAFE half of the sentence — withdrawal locks out whatever machines hold certificates
		// from this CA — so it is the one that must be reachable from here.
		if item.OwnerUnknown {
			item.Capabilities = append(item.Capabilities, "place")
		}
		items = append(items, item)
	}

	// Interception: the root steered endpoints trust (install material), and what is signing right now.
	if in.InterceptionEnabled {
		// Each tenant's OWN anchor first, attributed. These are what its devices must trust and what actually
		// signs for it; without them a tenant with its own PKI saw only the provider's certificate.
		for _, own := range in.PerTenantInterceptionRoots {
			for _, c := range parseAllCerts([]byte(own.RootPEM)) {
				item := pkiItemFromCert(c)
				item.ID = "interception_root:" + item.SHA256[:16]
				item.Role = "interception_root"
				item.TenantID = own.Tenant
				item.Active = true
				item.VerifiedBy = []string{"steered_endpoint_trust_stores"}
				item.Capabilities = []string{"download"}
				if in.InterceptionRootTrust != nil {
					if r, ok := in.InterceptionRootTrust[item.SHA256]; ok {
						item.TrustedBy, item.NotHolding, item.NotReporting = r.Trusted, r.NotHeld, r.Silent
					}
				}
				items = append(items, item)
				break // the anchor, not whatever else the PEM carries
			}
		}
		if certs := parseAllCerts(in.InterceptionRootPEM); len(certs) > 0 {
			item := pkiItemFromCert(certs[0])
			item.ID = "interception_root"
			item.Role = "interception_root"
			// ★ The node-wide root belongs to the tenant whose devices trust it — the primary — and to nobody
			// else. Left unowned it was shown to every tenant as theirs. When no tenant owns it (no per-tenant
			// signing configured at all) it stays unowned, which is correct: then it genuinely is everyone's.
			//
			// ★★ AND ONCE THE PRIMARY HAS ITS OWN ROOT, THIS ONE BELONGS TO NOBODY (2026-08-19). Attributing it
			// to the primary regardless outlived its reason: after tenant_reference_lab was moved onto its own
			// root, this screen went on naming the provider's root as that organization's interception anchor
			// while the trust bundle it actually serves that organization announces only their own. The screen
			// built to answer "whose certificate is this" was answering it with a certificate nobody trusts and
			// nothing signs under. Unowned is the truthful answer and the operator's cue that it can be retired.
			if len(in.PerTenantInterceptionRoots) > 0 {
				primary := strings.TrimSpace(in.InterceptionPrimaryTenant)
				if primary == "" || interceptionPrimaryHasItsOwnRoot(in) {
					item.OwnerUnknown = true
				} else {
					item.TenantID = primary
				}
			}
			// Who is known to trust it. The certificate is useless — worse, invisible — unless endpoints have
			// it, and until now nothing on this screen said whether they did.
			if in.InterceptionRootTrust != nil {
				if r, ok := in.InterceptionRootTrust[item.SHA256]; ok {
					item.TrustedBy = r.Trusted
					item.NotHolding = r.NotHeld
					item.NotReporting = r.Silent
				}
			}
			item.Active = true
			item.VerifiedBy = []string{"steered_endpoint_trust_stores"}
			item.Capabilities = []string{"download"}
			items = append(items, item)
		}
		// The signer(s), WITH their contents — name and validity — one item each. The status map reported the
		// runtime intermediates as a list and the first cut here read only the offline-mode fields, so the
		// card for the signer rendered empty, which the operator rightly called meaningless.
		if in.IntermediateStatus != nil {
			mode, _ := in.IntermediateStatus["mode"].(string)
			emitSigner := func(id, cn, nb, na string, rotatable bool, tenant string) {
				item := pkiCertificateItem{
					ID: id, Role: "interception_intermediate", Active: true, TenantID: tenant,
					Subject: cn, NotBefore: nb, NotAfter: na,
					VerifiedBy: []string{"interception_root"},
				}
				if rotatable {
					item.Capabilities = []string{"rotate_signer"}
				}
				items = append(items, item)
			}
			switch mode {
			case "offline":
				cn, _ := in.IntermediateStatus["intermediate_cn"].(string)
				na, _ := in.IntermediateStatus["not_after"].(string)
				emitSigner("interception_intermediate", cn, "", na, false, "")
			case "runtime":
				if list, ok := in.IntermediateStatus["intermediates"].([]map[string]any); ok {
					for _, m := range list {
						cn, _ := m["common_name"].(string)
						nb, _ := m["not_before"].(string)
						na, _ := m["not_after"].(string)
						tenant, _ := m["cache_tenant"].(string)
						emitSigner("interception_intermediate:"+tenant, cn, nb, na, true, tenant)
					}
				}
			}
		}
	}

	// The signing key devices verify signed agent policy, region endpoints and the trust bundle with. Not a
	// certificate; listed because "what does a device trust" is incomplete without it.
	if k := strings.TrimSpace(in.AgentPolicySigningPubHex); k != "" {
		items = append(items, pkiCertificateItem{
			ID:         "agent_policy_signing_key",
			Role:       "agent_policy_signing_key",
			Active:     true,
			SHA256:     k, // the public key itself, hex — the value agents pin
			VerifiedBy: []string{"agent_pinned_signing_key"},
		})
	}

	items = appendPendingInterceptionRoot(items, in)
	items = attributeOwnersBySignature(items, in)
	items = nameOwningOrganizations(items, in.TenantName)
	return pkiCertificateInventory{SchemaVersion: "admin_pki_certificates.v1", Items: items}
}

// ownedAnchor is a CA certificate and the organization that registered it.
type ownedAnchor struct {
	tenant string
	cert   *x509.Certificate
}

// attributeOwnersBySignature fills in whose material this is, for anything the deployment has not already
// stated outright, by asking WHO SIGNED IT.
//
// ★★ THE FALLBACK USED TO READ AN ID OUT OF THE SUBJECT (2026-08-19). pkiItemTenant scanned the subject and
// issuer for the text "tenant_" and took whatever followed. Measured on the lab, that is wrong in both
// directions at once:
//
//   - The CA issuing this deployment's own device certificates is registered to tenant_reference_lab, in the
//     registry, by its exact certificate. Its subject still says "(tenant_track_a_uc03a_lab)" — the name it was
//     minted with, on a track that no longer exists. The scan therefore attributed an organization's own device
//     CA to an organization that is not theirs, and the fact needed to say otherwise was already on file.
//   - A subject is not evidence. Anyone who can mint a certificate can type another organization's id into it,
//     and attribution built on that is attribution anyone can claim.
//
// The signature is the evidence, and it is the same rule (T) admission already runs on: the organization a
// certificate belongs to is the one whose registered CA issued it, never one it names. A certificate no
// registered authority signed is left unattributed, which is a different thing from belonging to nobody and is
// treated as such everywhere downstream.
func attributeOwnersBySignature(items []pkiCertificateItem, in pkiCertInventoryInput) []pkiCertificateItem {
	// The organizations' own interception roots are an attribution basis too: they are registered per tenant
	// in exactly the same sense, in a different place.
	anchors := []ownedAnchor{}
	for _, own := range in.PerTenantInterceptionRoots {
		tenant := strings.TrimSpace(own.Tenant)
		if tenant == "" {
			continue
		}
		for _, c := range parseAllCerts([]byte(own.RootPEM)) {
			anchors = append(anchors, ownedAnchor{tenant: tenant, cert: c})
		}
	}
	if in.AttributeOwner == nil && len(anchors) == 0 {
		return items
	}
	for i := range items {
		if strings.TrimSpace(items[i].TenantID) != "" || items[i].PEM == "" {
			continue
		}
		certs := parseAllCerts([]byte(items[i].PEM))
		if len(certs) == 0 {
			continue
		}
		c := certs[0]
		owner := ""
		if in.AttributeOwner != nil {
			owner = strings.TrimSpace(in.AttributeOwner(c))
		}
		if owner == "" {
			owner = ownerFromAnchors(c, anchors)
		}
		if owner != "" {
			items[i].TenantID = owner
		}
	}
	return items
}

// ownerFromAnchors reports the organization whose anchor IS this certificate or SIGNED it. Signature only: a
// matching name proves nothing, which is the whole point of doing it this way.
func ownerFromAnchors(c *x509.Certificate, anchors []ownedAnchor) string {
	for _, a := range anchors {
		if a.cert == nil {
			continue
		}
		if bytes.Equal(a.cert.Raw, c.Raw) {
			return a.tenant
		}
		if c.CheckSignatureFrom(a.cert) == nil {
			return a.tenant
		}
	}
	return ""
}

// nameOwningOrganizations fills in each item's organization NAME from the deployment's own record of it.
//
// Only the registry's attribution is named. An item the registry does not attribute gets no name — which is
// what the Console then shows: nothing. That is the truthful answer and it is deliberately not the same as
// asking the certificate, because the certificate's O= field is a string typed by whoever minted it.
func nameOwningOrganizations(items []pkiCertificateItem, name func(string) string) []pkiCertificateItem {
	if name == nil {
		return items
	}
	for i := range items {
		id := strings.TrimSpace(items[i].TenantID)
		if id == "" {
			continue
		}
		items[i].TenantDisplayName = strings.TrimSpace(name(id))
	}
	return items
}

// pkiItemTenant answers whose material this is: the attribution, and nothing else.
//
// ★★ IT USED TO READ AN ID OUT OF THE SUBJECT (2026-08-19). This scanned the subject and issuer for the text
// "tenant_" and took whatever followed, on the reasoning that a per-tenant CA in this deployment carries the
// organization in its own name. Two things are wrong with that, and the lab had both:
//
//   - A NAME IS NOT EVIDENCE. Anyone who can mint a certificate can type any organization's id into it. An
//     attribution anyone can claim is not an attribution, and it decides who may SEE this material.
//   - IT WAS ALSO JUST WRONG. This deployment's own device CA is registered to tenant_reference_lab, by its
//     exact certificate, and its subject says "(tenant_track_a_uc03a_lab)" — the name it was minted with on a
//     track that no longer exists. The scan therefore placed an organization's device CA in an organization
//     that is not theirs, while the registry held the answer.
//
// Attribution is now resolved from the SIGNATURE before this is called (attributeOwnersBySignature): the
// organization whose registered CA issued the certificate, or that registered it as their own. That is the
// same rule (T) admission runs on, and it cannot be claimed by anybody who is not that organization.
//
// A certificate no registered authority signed is the DEPLOYMENT's, and is shown to everybody: the transport
// anchor, this node's server certificate. Withholding those would take from a customer the one thing this
// screen exists to give them. The two roles where "unattributed" must NOT read as "everybody's" — a device
// client CA and an interception root — say so themselves, and are withheld.
func pkiItemTenant(item pkiCertificateItem) string {
	return strings.TrimSpace(item.TenantID)
}

// pkiCertificateItemsForTenant keeps the deployment's own material and this organization's, and drops another
// organization's.
func pkiCertificateItemsForTenant(items []pkiCertificateItem, callerTenant string, visibleDevice func(string) bool) []pkiCertificateItem {
	// ★★ MATERIAL THAT SIGNS FOR SOMEBODY IS NOT "EVERYBODY'S" WHEN NOBODY CAN PLACE IT (2026-08-19).
	//
	// Attribution moved from reading an id out of the subject to following the signature, which is right — and
	// it took a side effect with it that had been doing real work: the name scan was what kept the interception
	// SIGNER off other organizations' screens. Measured immediately, as Northwind's administrator: their
	// certificates page listed "Lantern DSSE Interception Issuing CA (tenant_reference_lab)". That is another
	// organization's id, on a customer's screen, put there by a change that was making attribution stricter.
	//
	// So the fail-closed rule the device client CA and the interception root already carry is extended to the
	// other two roles that exist ON BEHALF of one organization: the CA that issues devices' certificates, and
	// the authority that signs the certificates for their intercepted traffic. Unattributed means "not
	// established", and a customer is not shown material this node cannot place.
	//
	// perTenant, not always: a deployment with one organization attributes nothing, and there this material
	// genuinely IS that customer's to see — withholding it everywhere would empty the screen this exists for.
	perTenant := false
	for i := range items {
		if strings.TrimSpace(items[i].TenantID) != "" {
			perTenant = true
			break
		}
	}
	signsForSomebody := map[string]bool{"device_issuing_ca": true, "interception_intermediate": true}
	out := make([]pkiCertificateItem, 0, len(items))
	for _, item := range items {
		if perTenant && signsForSomebody[item.Role] && strings.TrimSpace(item.TenantID) == "" {
			continue
		}
		owner := pkiItemTenant(item)
		if owner != "" && !strings.EqualFold(owner, callerTenant) {
			continue
		}
		// ★★ A DEVICE-TRUST CA ALWAYS BELONGS TO SOMEBODY, SO "NO OWNER" IS NOT "EVERYBODY'S" (2026-08-18).
		// An unowned item is treated as deployment material and shown to every organization, which is right for
		// this node's own certificates and wrong for a CA a customer registered. Measured as Northwind's
		// administrator: "CN=Probe3 Device CA, O=Bootstrap Probe 3" — another organization's, listed because its
		// name happened not to contain "tenant_".
		//
		// So this one fails CLOSED: a device_client_ca whose owner the registry cannot name is withheld from a
		// customer rather than shown to all of them. The operator still sees it — answering for the deployment
		// skips this whole filter — which is also who can do something about it.
		if owner == "" && item.Role == "device_client_ca" {
			continue
		}
		// ★★ AND AN INTERCEPTION ROOT NOBODY OWNS IS NOT EVERY TENANT'S EITHER (2026-08-18). Same rule, found
		// the same way: measured inside Northwind, whose certificates page named "Lantern DSSE MSSP Root CA v2"
		// as the authority intercepting it while its own root went unlisted. On a node that signs per tenant,
		// a root with no owner is the primary tenant's or it is a leftover — in neither case is it the reader's,
		// and telling a customer the provider decrypts them when their own PKI does is the exact claim this
		// product makes the opposite of.
		//
		// item.OwnerUnknown rather than owner == "": a single-tenant deployment has no per-tenant roots at all,
		// where the node's root genuinely IS everybody's and must keep showing.
		if item.OwnerUnknown && item.Role == "interception_root" {
			continue
		}
		// ★ The material can be everybody's while the machines holding it are not. These two lists name
		// DEVICES, and on the deployment's own anchors they named another organization's — measured as a
		// customer administrator: mac-dev-1, win-dev-1, conn-lab-1.
		if visibleDevice != nil {
			item.TrustedBy = keepVisibleDevices(item.TrustedBy, visibleDevice)
			item.NotReporting = keepVisibleDevices(item.NotReporting, visibleDevice)
			// The adoption report and the retire gate name machines too. The gate's PARAMS are what the Console
			// renders into its refusal sentence, so leaving them would print another organization's device in a
			// message about this one's certificate.
			if item.Adoption != nil {
				adoption := *item.Adoption
				adoption.OnCurrent = keepVisibleDevices(adoption.OnCurrent, visibleDevice)
				adoption.OnPrevious = keepVisibleDevices(adoption.OnPrevious, visibleDevice)
				adoption.NotSeen = keepVisibleDevices(adoption.NotSeen, visibleDevice)
				item.Adoption = &adoption
			}
			// The retire gate is about removing DEPLOYMENT material, which needs admin.platform.write — an
			// operator's permission. Its refusal names the machines still holding the certificate, and that
			// sentence is prose built from those names, so filtering the params alone left the names in the
			// text. A caller who cannot perform the retirement is not shown the gate at all.
			item.CanRetire = false
			item.RetireBlockedReason = ""
			item.RetireBlockedCode = ""
			item.RetireBlockedParams = nil
		}
		out = append(out, item)
	}
	return out
}

func keepVisibleDevices(ids []string, visible func(string) bool) []string {
	if len(ids) == 0 {
		return ids
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if visible(id) {
			out = append(out, id)
		}
	}
	return out
}

func registerAdminPKICertificates(mux *http.ServeMux, build func() pkiCertificateInventory,
	ledger *enrolledinventory.Ledger, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /admin/pki/certificates", adminEndpoint("admin.certs.read", func(w http.ResponseWriter, r *http.Request) {
		inv := build()
		// ★ admin.certs.read IS AN ORDINARY TENANT ADMINISTRATOR'S PERMISSION (2026-08-16, found by signing in
		// as one). The inventory is this NODE's, and a node serves every organization on it, so the customer's
		// certificate screen listed other organizations' device issuing CAs and interception intermediates —
		// by name, with their public material. Measured as Northwind's administrator: two other organizations.
		if tenant, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			inv.Items = pkiCertificateItemsForTenant(inv.Items, tenant, func(identity string) bool {
				kept, _ := deviceIdentitiesForCaller([]string{identity}, ledger, r)
				return len(kept) == 1
			})
			// ★★ AND WHAT THE ANSWER SAYS THEY MAY DO HAS TO BE TRUE OF THEM (2026-08-18, measured as
			// Northwind's administrator: the response carried "retire", and DELETE /admin/device-client-cas
			// answers 403 for that same session).
			//
			// Capabilities were built from facts about the CERTIFICATE — is it retirable, is a signer
			// rotatable — and never from the caller. So the server told a customer they could do four things
			// they cannot, and the console dutifully drew the buttons. Telling somebody they may act and then
			// refusing is worse than not offering: it reads as a fault in their account.
			//
			// Keep read-only actions. Renewal orders use admin.endpoints.write but
			// are additionally operator-only because their cutoff affects the node's fleet.
			inv.Items = pkiCapabilitiesForCaller(inv.Items)
		}
		writeJSON(w, http.StatusOK, inv)
	}))
}

// nodeWideInterceptionRootFingerprints is the NODE's answer: what this deployment signs under when an
// organization has no interception issuer of its own.
//
// ★★★ IT IS NOT THE ANSWER FOR AN ORGANIZATION THAT HAS ONE, AND THE NAME NOW SAYS SO (2026-08-19). It was
// called "current…", which reads as "the right one", and the document every agent fetches each minute asked it
// — so devices of an organization signing under its own root were told to look for the deployment's root
// instead. On win-dev-1 that meant every HTTPS request failed the moment steering was armed, while the signal
// built to prevent that reported green. Agent-facing answers come from interceptionRootFingerprintsForTenant;
// ops/checks/agent_facing_interception_root_is_per_tenant.sh refuses a commit that reaches for this one from a
// route that serves an agent. Advertised in
// the signed trust bundle so an agent knows which roots to look for in its own trust store — the signal that
// has to exist before switching that root can be anything other than blind.
func nodeWideInterceptionRootFingerprints(config serverConfig) []string {
	// A root being DISTRIBUTED but not yet signed under is advertised too, so agents report on it and an
	// operator can watch it reach the fleet BEFORE switching. Without this the interception switch is the one
	// operation with no way to see the overlap — and an interception root that has not reached a machine
	// breaks every site on it at once, not one tunnel.
	out := []string{}
	for _, c := range parseAllCerts([]byte(config.InterceptionPendingRootPEM)) {
		out = append(out, certFingerprint(c))
	}
	if config.NetworkExtensionLabTLS == nil {
		return out
	}
	// ★★★ WHAT A DEVICE MUST HOLD, NOT WHAT SIGNS. See interception_announced_anchor.go: this used to
	// announce the signing certificate, and on a deployment whose interception authority is signed by the
	// deployment root — which is what dsse-install generates — that is an INTERMEDIATE. A real machine
	// installed exactly what it was told and every HTTPS request still failed.
	rootPEM := config.NetworkExtensionLabTLS.RootCertificatePEM()
	for _, c := range parseAllCerts(rootPEM) {
		out = append(out, announcedInterceptionAnchor(c, config.InterceptionAnchorPEM)...)
	}
	return out
}

// interceptionRootSwitchGate decides whether this deployment may start signing intercepted traffic under a
// new root. It is the gate docs/interception_root_switch_design.ja.md names as the precondition for the
// operation existing at all: an interception root that has not reached a machine breaks EVERY site on it at
// once, not one tunnel, and the switch was reachable through POST /admin/interception-intermediate with
// nothing checking who holds the new root.
//
// Same shape and same escape hatch as the transport-anchor withdrawal: every enrolled device must have
// REPORTED holding the new root, silence blocks (a device that has not said is unknown, never "fine"), and
// an operator may account for one by name through the acknowledgement store — a connector has no trust store
// to report from, and a safeguard that cannot be satisfied is an instruction to work around it.
//
// Switching to the root already in force is not a switch and is always allowed (idempotent re-load).
func interceptionRootSwitchGate(config serverConfig, newRootPEM string) (bool, gateVerdict) {
	incoming := parseAllCerts([]byte(newRootPEM))
	if len(incoming) == 0 {
		return false, gateRefuse("unreadable_root", "the root certificate could not be read")
	}
	target := certFingerprint(incoming[0])
	for _, fp := range nodeWideInterceptionRootFingerprints(config) {
		if strings.EqualFold(fp, target) && !isPendingInterceptionRoot(config, target) {
			return true, gateVerdict{} // already the root in force: re-loading it changes nothing
		}
	}
	known := enabledEnrolledIdentities(config)
	if len(known) == 0 {
		return false, gateRefuse("no_enrolled_device", "no enrolled device to measure against, so the switch cannot be judged")
	}
	vouched := map[string]bool{}
	for _, ack := range transportAnchorAcks.For(strings.ToLower(target)) {
		vouched[strings.ToLower(strings.TrimSpace(ack.Identity))] = true
	}
	var missing []string
	for _, id := range known {
		if vouched[strings.ToLower(strings.TrimSpace(id))] {
			continue
		}
		// This gate measures over enabledEnrolledIdentities, which is already the node's own organization, so
		// the node's tenant is the right subject here. (That the gate has no denominator at all when the
		// devices belong to another organization is the defect one level out, noted at devicesOf in main.go.)
		if holds, _ := deviceReportedInterceptionRoot(config, config.TenantIDForTrust, id, target); !holds {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return false, gateRefuse("root_not_held_by",
			"these devices have not reported holding the new interception root: "+strings.Join(missing, ", ")+
				" — every HTTPS site breaks at once on a device that does not trust it; distribute it first, or confirm each device by name",
			missing...)
	}
	return true, gateVerdict{}
}

// isPendingInterceptionRoot reports whether a fingerprint is the DISTRIBUTED-but-not-yet-signing root. It is
// advertised alongside the live one so devices report on it, so "advertised" alone must not be read as "in
// force" — that reading would let the gate wave through the very switch it exists to hold.
func isPendingInterceptionRoot(config serverConfig, fingerprint string) bool {
	for _, c := range parseAllCerts([]byte(config.InterceptionPendingRootPEM)) {
		if strings.EqualFold(certFingerprint(c), fingerprint) {
			return true
		}
	}
	return false
}

// deviceReportedInterceptionRoot answers two questions at once, because collapsing them is the mistake: did
// this device SAY anything about interception roots, and if so did it name this one. A device that has not
// reported is unknown, never "does not trust it".
// ★★★ THE REPORT IS FILED UNDER THE DEVICE'S ORGANIZATION AND THIS READ IT UNDER THE NODE'S (2026-09-05,
// read off the Console once the certificate map could reach the Edge at all). tenant is the organization that
// OWNS this device, not config.TenantIDForTrust.
//
// The screen said, of a Mac that was steering under interception at that moment and reporting
// pinned_interception_root_sha256: 664dd13e… and pinned_transport_ca_sha256: bbef8ba4…,
//
//	Intercept Root CA   0% trusted   0 of 1 confirmed   not reported: shinnomac-mini
//	Device Trust CA     0% trusted   0 of 1 confirmed   not reported: shinnomac-mini
//
// because the device belongs to Kaede Foods and the query asked for tenant_default's reports. It is the
// failure written up eleven lines below registerAdminTrustRefusals in main.go, in those words — "the
// measurement exists, is collected correctly, and is read for the wrong subject" — surviving in the two
// places that decide whether a certificate may be withdrawn. A withdrawal gate whose denominator is always
// silent never opens, and roadmap D ends with exactly that withdrawal.
//
// deviceReportedInterceptionRootPin (interception_root_withdrawal_gate.go) already took a tenant. This is the
// same correction applied to the inventory the operator reads.
func deviceReportedInterceptionRoot(config serverConfig, tenant, identity, fingerprint string) (holds bool, said bool) {
	if config.ObservedExclusions == nil {
		return false, false
	}
	if strings.TrimSpace(tenant) == "" {
		tenant = config.TenantIDForTrust
	}
	for _, e := range config.ObservedExclusions.Query(tenant,
		observedQueryFilter{Device: identity, Limit: 1}).Entries {
		if !strings.EqualFold(strings.TrimSpace(e.DeviceIdentity), strings.TrimSpace(identity)) {
			continue
		}
		if len(e.PinnedInterceptionRootSHA256) == 0 {
			return false, false
		}
		for _, fp := range e.PinnedInterceptionRootSHA256 {
			if strings.EqualFold(fp, fingerprint) {
				return true, true
			}
		}
		return false, true
	}
	return false, false
}

// appendPendingInterceptionRoot puts a root that is being DISTRIBUTED on the screen. Without a row of its
// own an operator can be told to distribute it and then has nowhere to watch it arrive — which is the
// difference between a gated switch and a hopeful one.
func appendPendingInterceptionRoot(items []pkiCertificateItem, in pkiCertInventoryInput) []pkiCertificateItem {
	for _, c := range parseAllCerts([]byte(in.InterceptionPendingRootPEM)) {
		item := pkiItemFromCert(c)
		item.ID = "interception_root_pending-" + item.SHA256[:12]
		item.Role = "interception_root_pending"
		item.Capabilities = []string{"download"}
		if in.InterceptionRootTrust != nil {
			if r, ok := in.InterceptionRootTrust[item.SHA256]; ok {
				item.TrustedBy = r.Trusted
				item.NotHolding = r.NotHeld
				item.NotReporting = r.Silent
			}
		}
		items = append(items, item)
	}
	return items
}

// readFileOrEmpty returns a file's contents, or "" when it is absent or unreadable. Used for optional PEM
// inputs where "not configured" and "not readable" lead to the same behaviour: nothing is advertised.
func readFileOrEmpty(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// gateVerdictResult carries a gate's answer into the inventory without the inventory depending on the gate's
// internals.
type gateVerdictResult struct {
	OK     bool
	Code   string
	Text   string
	Params []string
}

// looksLikeDeviceIdentity is deliberately narrow: it answers "could this string be a machine this deployment
// enrolled", so that a refusal reason carrying a date or a count is never silently emptied.
func looksLikeDeviceIdentity(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, " ,:/") {
		return false
	}
	return strings.Contains(v, "-") || strings.Contains(v, "_")
}

// pkiCapabilitiesForCaller strips the capabilities a customer cannot exercise. Called only on the
// tenant-scoped branch: an operator answering for the deployment keeps all of them.
//
// The set is derived from the routes each capability leads to, and every one of these is gated on a
// permission no tenant role holds:
//
//	replace        PUT    /admin/certs/{name}                                admin.certs.write
//	retire         DELETE /admin/device-client-cas/{sha256}                   admin.platform.write
//	rotate_signer  POST   /admin/interception-intermediate/rotate             admin.platform.write
//	acknowledge    POST   /admin/transport-trust-anchors/{sha256}/acknowledge admin.platform.write
//
// renew_all also requires the operator-only organization gate despite its
// admin.endpoints.write permission. Only the read-only actions stay.
func pkiCapabilitiesForCaller(items []pkiCertificateItem) []pkiCertificateItem {
	operatorOnly := map[string]bool{"replace": true, "retire": true, "rotate_signer": true, "acknowledge": true, "renew_all": true}
	out := make([]pkiCertificateItem, 0, len(items))
	for _, item := range items {
		kept := make([]string, 0, len(item.Capabilities))
		for _, c := range item.Capabilities {
			if !operatorOnly[c] {
				kept = append(kept, c)
			}
		}
		item.Capabilities = kept
		out = append(out, item)
	}
	return out
}

// interceptionPrimaryHasItsOwnRoot reports whether the node's primary organization has an interception root of
// its own. When it does, the node-wide root is not that organization's anchor either — nothing signs under it
// and no organization's devices are told to trust it.
func interceptionPrimaryHasItsOwnRoot(in pkiCertInventoryInput) bool {
	primary := strings.TrimSpace(in.InterceptionPrimaryTenant)
	if primary == "" {
		return false
	}
	for _, own := range in.PerTenantInterceptionRoots {
		if strings.EqualFold(strings.TrimSpace(own.Tenant), primary) {
			return true
		}
	}
	return false
}
