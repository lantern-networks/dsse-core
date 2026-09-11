package main

import (
	"net/http"
	"strings"
	"time"
)

// The PATHS view's registry: every trust-carrying connection this node is an endpoint of, as one list.
// GET /admin/pki/paths.
//
// A path references the certificate objects of /admin/pki/certificates by ID, so the two views cannot
// disagree: the paths view says which connection uses which material, the certificates view says what the
// material is and what can be done to it. The server asserts only paths its own configuration establishes —
// the Console fetches per node and composes, and adds the entries only it can know (its own origin).
//
// Semantic ids throughout ("agents", "connectors", "console"); the Console translates. No prose.

type pkiPath struct {
	ID   string `json:"id"`
	From string `json:"from"`
	To   string `json:"to"`
	// Addresses this node serves the path on (real listener addresses), or dials for outbound paths.
	Addresses []string `json:"addresses,omitempty"`
	// ServerCertID names the /admin/pki/certificates item presented on this path ("" = not TLS-served here).
	ServerCertID      string `json:"server_cert_id,omitempty"`
	ServerCertSubject string `json:"server_cert_subject,omitempty"`
	// ★★ WHOSE CERTIFICATE THIS IS, ACCORDING TO THE INVENTORY — not according to its name (2026-08-18).
	// The tenant filter below used to infer ownership by looking for "tenant_" inside the subject string, and
	// "CN=Northwind Traders Interception Root 2028,O=Northwind Traders" contains no such substring. So it was
	// shown to Acme, as the certificate on ACME's own interception path: another customer of the same provider
	// named on this customer's screen, and factually wrong besides — Acme has no interception authority, so
	// its traffic is refused rather than signed by anybody's root.
	//
	// Same lesson the device-trust CAs taught two days earlier: ask the registry, not the certificate's name.
	// Not serialised — it exists to be filtered on, and publishing it would put the id back on the screen.
	ServerCertTenantID     string `json:"-"`
	ClientAuthTenantID     string `json:"-"`
	ServerCertOwnerUnknown bool   `json:"-"`
	ServerCertDays         *int   `json:"server_cert_days,omitempty"`
	// ClientAuthVerifiedBy names the certificate this node checks the far end's credential against. "requires a
	// device certificate" says what to bring; it does not say what decides whether it is accepted, and those
	// are different questions — the second is the one an operator changes when retiring a CA (review C8/D6).
	ClientAuthVerifiedBy string `json:"client_auth_verified_by,omitempty"`
	// ClientAuth is what the far end must present: "device_certificate", "connector_identity",
	// "enrolment_token", "admin_session", "bearer_token", "none".
	ClientAuth string `json:"client_auth,omitempty"`
	// TrustSerial is the distribution serial for the trust-distribution path.
	TrustSerial int64 `json:"trust_serial,omitempty"`
	// Count of far-end parties this node has observed (devices, …). 0 = not counted, not "none".
	Count int `json:"count,omitempty"`
	// Status is decided HERE (never recomputed in the browser): "ok" | "attention".
	Status string `json:"status"`
	// Extra carries one short deployment value (a source URL, a socket path).
	Extra string `json:"extra,omitempty"`
	// RecoveryWindowHours: how long past expiry the recovery address still renews a device.
	RecoveryWindowHours int `json:"recovery_window_hours,omitempty"`
	// External marks a path whose server certificate is issued and rotated outside this product. The operator
	// can still see it and its expiry; what they cannot do here is replace it.
	External bool `json:"external,omitempty"`
	// Encrypted says whether this outbound dependency is carried over TLS at all: "yes", "no", or "" when the
	// configured endpoint does not declare a scheme and this node will not guess.
	//
	// ★★★ A PLAIN-HTTP LINK WAS LISTED ON THE CERTIFICATES SCREEN (2026-09-05, read off a live deployment).
	// The section exists because "an expiry on any of them takes a function down", and under it sat
	//
	//	external   Storing logs           http://dsse-clickhouse:8123
	//	external   Long-term log archive  dsse-archive:9000
	//
	// The first has no certificate to expire — it is not TLS — and a screen about certificates that lists it
	// without saying so implies a protection that is not there. The second declares no scheme, and the honest
	// answer to that is not "yes" and not "no": this node has only the configured string, and a guess on a PKI
	// screen is the worst of the three answers. So the field has three states and the third is stated.
	Encrypted string `json:"encrypted,omitempty"`
}

// endpointEncryption reads the only thing the configured endpoint actually declares. Deliberately not a
// heuristic on the port: 8123 is ClickHouse's HTTP port and 9440 its TLS one, and encoding that table here
// would produce a confident answer from a coincidence.
func endpointEncryption(endpoint string) string {
	switch {
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(endpoint)), "https://"):
		return "yes"
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(endpoint)), "http://"):
		return "no"
	default:
		return ""
	}
}

type pkiPathsReport struct {
	SchemaVersion string    `json:"schema_version"`
	Paths         []pkiPath `json:"paths"`
	// The inventory these paths reference, kept so the tenant filter can substitute the caller's own item for
	// one it had to blank. Not serialised — /admin/pki/certificates is where the inventory is served.
	inventory []pkiCertificateItem
}

// pkiPathsForTenant blanks the references that name another organization's material. The path itself stays:
// it describes a connection this node serves for everybody, and the customer's question — what must my devices
// bring, and where — is answered without saying whose CA sits behind it.
func pkiPathsForTenant(paths []pkiPath, callerTenant string, inv []pkiCertificateItem) []pkiPath {
	// ★★ THE NAME IS NOT ASKED ANY MORE, AND UNKNOWN FAILS CLOSED (2026-08-19). This used to fall back to
	// scanning the subject for "tenant_" when the inventory did not attribute the material — the only thing it
	// had, since a path names a certificate by its subject string. Two problems: a subject is typed by whoever
	// minted the certificate, so it is an attribution anyone can claim; and it was wrong on this deployment,
	// where a device CA registered to one organization still carries the id of the track it was minted on.
	//
	// Attribution now comes from the SIGNATURE (admin_pki_certificates.go), so the inventory answers for real
	// material. What is left is the case where it CANNOT answer, and on a deployment that registers CAs per
	// organization that is not "everybody's" — it is "not established". A customer is not told the name of a
	// certificate this node cannot place, which is the same rule the inventory already applies to a device
	// client CA and an interception root with no owner.
	//
	// perTenant, not always: a single-organization deployment attributes nothing at all, and there the node's
	// device CA genuinely is that customer's to see.
	perTenant := false
	for i := range inv {
		if strings.TrimSpace(inv[i].TenantID) != "" {
			perTenant = true
			break
		}
	}
	foreign := func(owner, _ string) bool {
		o := strings.TrimSpace(owner)
		if o == "" {
			return false
		}
		return !strings.EqualFold(o, callerTenant)
	}
	// unplaceable is the fail-closed half: named material this node cannot attribute, on a node that attributes.
	unplaceable := func(owner, subject string) bool {
		return perTenant && strings.TrimSpace(owner) == "" && strings.TrimSpace(subject) != ""
	}
	// The caller's OWN item for a role, so a blanked reference can be replaced rather than merely emptied.
	// Blanking alone would tell Acme that its interception path has no certificate, which is true and useless;
	// a tenant that HAS its own root should see its own on its own path.
	ownForRole := func(role string) *pkiCertificateItem {
		for i := range inv {
			if inv[i].Role == role && strings.EqualFold(strings.TrimSpace(inv[i].TenantID), callerTenant) {
				return &inv[i]
			}
		}
		return nil
	}
	out := make([]pkiPath, 0, len(paths))
	for _, p := range paths {
		if foreign(p.ServerCertTenantID, p.ServerCertSubject) || p.ServerCertOwnerUnknown ||
			unplaceable(p.ServerCertTenantID, p.ServerCertSubject) {
			role := ""
			if i := strings.Index(p.ServerCertID, ":"); i > 0 {
				role = p.ServerCertID[:i]
			} else {
				role = p.ServerCertID
			}
			p.ServerCertSubject, p.ServerCertID, p.ServerCertTenantID = "", "", ""
			p.ServerCertDays = nil
			if own := ownForRole(role); own != nil {
				p.ServerCertID, p.ServerCertSubject, p.ServerCertTenantID = own.ID, own.Subject, own.TenantID
			}
		}
		if foreign(p.ClientAuthTenantID, p.ClientAuthVerifiedBy) ||
			unplaceable(p.ClientAuthTenantID, p.ClientAuthVerifiedBy) {
			p.ClientAuthVerifiedBy, p.ClientAuthTenantID = "", ""
		}
		out = append(out, p)
	}
	return out
}

type pkiPathsInput struct {
	Now time.Time
	// The same inventory the certificates endpoint serves, so paths reference real item IDs.
	Inventory pkiCertificateInventory

	MainListen      string
	AdminListen     string
	TransportListen string
	RecoveryListen  string
	// RecoveryWindowHours is how long after expiry the recovery listener will still renew a device. It is the
	// one fact about that listener an operator needs and the only thing the retired Health screen showed that
	// had no other home — a device switched off for longer than this cannot get back on its own.
	RecoveryWindowHours int

	TrustBundleSerial int64
	// TrustBundleSignedBy is the signing key devices verify the distribution with.
	TrustBundleSignedBy string
	DeviceCertCount     int

	EnrolmentConfigured bool
	InterceptionEnabled bool
	KeyCustodyHealthy   bool
	HSMAgentSocket      string
	UpstreamCABundle    bool

	ConfigSourceURL    string // set on a pulling Edge
	AuditIngestEnabled bool   // set on the receiving control plane

	// Paths this node dials whose server certificate belongs to someone else. They are listed so the registry
	// is complete; their material is not ours to replace, which the view says rather than leaving them out.
	IdPIssuerURL string
	// IdPIssuers are the sign-in endpoints registered from the Console, which is how a real deployment
	// configures them — the flag is only one way in.
	IdPIssuers          []string
	MeshPeerSpec        string
	HotStoreEndpoint    string
	ColdArchiveEndpoint string
}

func pkiInvFind(inv pkiCertificateInventory, id string) *pkiCertificateItem {
	for i := range inv.Items {
		if inv.Items[i].ID == id || strings.HasPrefix(inv.Items[i].ID, id) {
			return &inv.Items[i]
		}
	}
	return nil
}

func pkiPathCertFields(p *pkiPath, item *pkiCertificateItem, now time.Time) {
	if item == nil {
		return
	}
	p.ServerCertID = item.ID
	p.ServerCertSubject = item.Subject
	p.ServerCertTenantID = item.TenantID
	p.ServerCertOwnerUnknown = item.OwnerUnknown
	if item.NotAfter != "" {
		if at, err := time.Parse(time.RFC3339, item.NotAfter); err == nil {
			d := int(at.Sub(now).Hours() / 24)
			p.ServerCertDays = &d
			if d <= 30 {
				p.Status = "attention"
			}
		}
	}
}

func buildPKIPaths(in pkiPathsInput) pkiPathsReport {
	now := in.Now
	paths := []pkiPath{}
	add := func(p pkiPath) {
		if p.Status == "" {
			p.Status = "ok"
		}
		paths = append(paths, p)
	}

	// Devices → this node, over the encrypted transport (and its recovery listener).
	if strings.TrimSpace(in.TransportListen) != "" {
		p := pkiPath{ID: "device_transport", From: "agents", To: "node", ClientAuth: "device_certificate", Count: in.DeviceCertCount}
		if ca := pkiInvFind(in.Inventory, "device_client_ca"); ca != nil {
			p.ClientAuthVerifiedBy, p.ClientAuthTenantID = ca.Subject, ca.TenantID
		} else if ca := pkiInvFind(in.Inventory, "device_issuing_ca"); ca != nil {
			p.ClientAuthVerifiedBy, p.ClientAuthTenantID = ca.Subject, ca.TenantID
		}
		p.Addresses = append(p.Addresses, in.TransportListen)
		if a := strings.TrimSpace(in.RecoveryListen); a != "" {
			p.Addresses = append(p.Addresses, a)
			p.RecoveryWindowHours = in.RecoveryWindowHours
		}
		pkiPathCertFields(&p, pkiInvFind(in.Inventory, "transport_server"), now)
		add(p)

		// This node → devices: the certificates they trust, distributed by serial.
		if in.TrustBundleSerial > 0 {
			// D4: what devices check the distribution's signature with. The distribution is only trustworthy
			// because of that key, and the path said nothing about it.
			signedBy := in.TrustBundleSignedBy
			if signedBy == "" {
				if k := pkiInvFind(in.Inventory, "agent_policy_signing_key"); k != nil {
					signedBy = k.Subject
				}
			}
			add(pkiPath{ID: "trust_distribution", From: "node", To: "agents", TrustSerial: in.TrustBundleSerial,
				ClientAuthVerifiedBy: signedBy,
				Addresses:            []string{strings.TrimSpace(in.MainListen)}})
		}
	}

	// Devices → this node: certificate issuance (enrolment + renewal).
	if in.EnrolmentConfigured {
		p := pkiPath{ID: "enrolment", From: "agents", To: "node", ClientAuth: "enrolment_token",
			Addresses: []string{strings.TrimSpace(in.MainListen)}}
		pkiPathCertFields(&p, pkiInvFind(in.Inventory, "device_issuing_ca"), now)
		add(p)
	}

	// Connectors → this node.
	if strings.TrimSpace(in.MainListen) != "" {
		p := pkiPath{ID: "connector", From: "connectors", To: "node", ClientAuth: "connector_identity",
			Addresses: []string{strings.TrimSpace(in.MainListen)}}
		pkiPathCertFields(&p, pkiInvFind(in.Inventory, "component_server"), now)
		add(p)
	}

	// Endpoints ⇄ this node: interception (what endpoint trust stores must hold), and this node → real sites.
	if in.InterceptionEnabled {
		p := pkiPath{ID: "interception", From: "endpoints", To: "node"}
		pkiPathCertFields(&p, pkiInvFind(in.Inventory, "interception_root"), now)
		if !in.KeyCustodyHealthy {
			p.Status = "attention"
		}
		add(p)
		if in.UpstreamCABundle {
			add(pkiPath{ID: "upstream_tls", From: "node", To: "real_sites"})
		}
		if s := strings.TrimSpace(in.HSMAgentSocket); s != "" {
			st := "ok"
			if !in.KeyCustodyHealthy {
				st = "attention"
			}
			add(pkiPath{ID: "key_custody", From: "node", To: "hsm", Extra: s, Status: st})
		}
	}

	// Console → this node's admin surface.
	if strings.TrimSpace(in.AdminListen) != "" {
		p := pkiPath{ID: "admin_api", From: "console", To: "node", ClientAuth: "admin_session",
			Addresses: []string{strings.TrimSpace(in.AdminListen)}}
		pkiPathCertFields(&p, pkiInvFind(in.Inventory, "component_server"), now)
		add(p)
	}

	// This node → its control plane (config pull); edges → this node (audit ingest).
	if u := strings.TrimSpace(in.ConfigSourceURL); u != "" {
		add(pkiPath{ID: "config_pull", From: "node", To: "control_plane", Extra: u, ClientAuth: "bearer_token"})
	}
	if in.AuditIngestEnabled {
		p := pkiPath{ID: "audit_ingest", From: "edges", To: "node", ClientAuth: "bearer_token",
			Addresses: []string{strings.TrimSpace(in.MainListen)}}
		pkiPathCertFields(&p, pkiInvFind(in.Inventory, "component_server"), now)
		add(p)
	}

	// The paths whose certificate belongs to someone else. Each is a real TLS connection this node makes, so
	// an expiry on any of them takes a function of the product down — and none of them appeared anywhere in the
	// Console before. Listed, attributed to their owner, and explicitly not replaceable from here.
	idpEndpoints := append([]string{}, in.IdPIssuers...)
	if u := strings.TrimSpace(in.IdPIssuerURL); u != "" {
		idpEndpoints = append(idpEndpoints, u)
	}
	for _, ext := range []struct{ id, from, to, endpoint string }{
		{"identity_provider", "node", "idp", strings.Join(idpEndpoints, " / ")},
		{"region_mesh", "node", "peer_regions", in.MeshPeerSpec},
		{"hot_store", "node", "hot_store", in.HotStoreEndpoint},
		{"cold_archive", "node", "object_store", in.ColdArchiveEndpoint},
	} {
		endpoint := strings.TrimSpace(ext.endpoint)
		if endpoint == "" {
			continue
		}
		add(pkiPath{ID: ext.id, From: ext.from, To: ext.to, Addresses: []string{endpoint},
			External: true, Status: "ok", Encrypted: endpointEncryption(endpoint)})
	}

	return pkiPathsReport{SchemaVersion: "admin_pki_paths.v1", Paths: paths, inventory: in.Inventory.Items}
}

func registerAdminPKIPaths(mux *http.ServeMux, build func() pkiPathsReport,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /admin/pki/paths", adminEndpoint("admin.certs.read", func(w http.ResponseWriter, r *http.Request) {
		out := build()
		// ★ A PATH IS THIS NODE'S, BUT WHAT IT NAMES CAN BE SOMEBODY ELSE'S (2026-08-16). The paths are the
		// same for every organization on this node and a customer needs to see them, so they are not dropped —
		// but the certificate a path REFERENCES may belong to another organization, and its subject carries
		// that organization's id. Measured as Northwind's administrator: the enrolment path named another
		// organization's device issuing CA. The reference is blanked rather than the path removed, because
		// hiding the path would tell the customer less about their own deployment, not less about others.
		if tenant, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			out.Paths = pkiPathsForTenant(out.Paths, tenant, out.inventory)
		}
		writeJSON(w, http.StatusOK, out)
	}))
}
