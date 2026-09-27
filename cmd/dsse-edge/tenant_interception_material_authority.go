package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"
)

// tenant_interception_material_authority.go — the control plane mints SHORT-LIVED interception issuing
// material for the Edges, under an authority the customer signed once.
//
// ★★★ THE ROOT IS NOT CREATED HERE, IT IS DELEGATED FROM (decided 2026-08-20). What an organization's devices
// TRUST is its interception root, and that root is deliberately offline — it lives with the customer, not on
// a machine that terminates their traffic. Creating one here would mean asking every device to trust
// something the operator made, which is the opposite of the line the operator/customer boundary draws.
//
// So the shape is three tiers, and the customer signs the middle one ONCE:
//
//	customer's interception root (offline, with the customer, in every device's store)
//	  └─ an issuing authority the customer signs FOR the operator (years, held here / in an HSM)
//	       └─ a per-Edge intermediate (hours)   ← what an Edge is handed
//	            └─ the leaf for each intercepted flow (signed locally, because it is per flow)
//
// Rotating the per-Edge tier changes nothing a device holds: the root is unchanged, so there is no adoption
// to measure and no overlap to run. That is the whole reason interception can be done this way while the
// transport certificate needed the careful dance — devices verify the transport certificate against its
// issuer directly, and they verify an intercepted leaf against a root two tiers up.
//
// ★ AND THE ENGINE ALREADY CARRIES A CHAIN OF ANY LENGTH (measured: interception mints with
// `append([][]byte{leafDER}, issuer.chain...)`), so adding this tier needs no change to the data path.
// restart-durability: cp_durable — written through the persister the moment an authority is imported (a CP
// state blob, Postgres-backed on a real control plane), and an import that could not be persisted is refused
// rather than reported. An authority that vanished on restart would leave every Edge unable to intercept for
// that organization at the next fetch, with nothing to say why.
//
// populated-by: assertion — reloaded from that blob at start-up. Nothing is inferred from what an Edge asks
// for: a request for an organization with no imported authority is refused, never answered by creating one.
type tenantInterceptionAuthority struct {
	snapshot []byte

	mu      sync.Mutex
	issuers map[string]*storedTenantInterceptionIssuer
	persist func([]byte) error
	// reload re-reads the SHARED store — see the transport authority's refreshedRowLocked.
	reload func() ([]byte, error)
	now    func() time.Time
	// generation changes whenever the set of authorities does, so an Edge asking the cheap question about the
	// material response sees an interception authority that was imported since it last fetched. See
	// materialGeneration: a change the number does not carry is invisible.
	generation uint64
}

// ★ AND THE TWO TIERS PERSIST DIFFERENTLY, ON PURPOSE (2026-08-21, written down after moving the reference
// deployment's organizations onto this path). The DEVICE-IDENTITY tier writes nothing to disk: an Edge that
// appears under load and is gone in an hour must not leave an organization's enrolment key behind, and a node
// that cannot re-fetch simply enrols nobody — a device is refused, which is the safe direction.
//
// Interception cannot take that answer. A node that cannot sign for an organization does not fail closed on
// one act; every HTTPS request from every device of that organization stops. So the short-lived per-node
// intermediate this authority mints IS written down, sealed with the deployment's KEK, and it is what the node
// starts from when the control plane is briefly unreachable. What that buys is bounded by design: the material
// lasts twelve hours and is minted per node, so what a lost disk yields is one node's ability to intercept for
// one organization until this evening — not the organization's issuing key, which after this migration is
// nowhere on any Edge.

// Generation is never zero for a live authority: zero is what an Edge sends when it has never asked.
func (a *tenantInterceptionAuthority) Generation() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	return a.generation + 1
}

type storedTenantInterceptionIssuer struct {
	TenantID string `json:"tenant_id"`
	// RootPEM is the customer's root. Held only so the material handed to an Edge can carry the chain up to
	// what devices actually trust; nothing here ever signs with it, because its key is not here.
	RootPEM string `json:"root_pem"`
	// IssuingCertPEM and IssuingKeyPEM are the tier the customer signed for the operator.
	IssuingCertPEM string `json:"issuing_cert_pem"`
	IssuingKeyPEM  string `json:"issuing_key_pem"`
	ImportedAt     string `json:"imported_at"`
	// Incoming is an authority this organization has handed over but which NOTHING SIGNS WITH YET.
	//
	// ★★★ WHY (2026-08-22). Import replaced outright: a:issuers[key] = row, and the previous authority was
	// kept only long enough to roll back a failed write. So handing over a replacement switched every Edge to
	// signing under the new root on its next material fetch — and every device that had not yet added that
	// root lost every HTTPS site, at once. That is not hypothetical: it is the eighteen minutes of 2026-08-19,
	// and it happened with both sides reporting healthy.
	//
	// An interception rotation is the transport shape, not the device-identity one: devices must TRUST the new
	// root before anything signs under it. The Edge already has the receiving half — offlineTenantIncomingRoots
	// is a root that is announced to devices and signed with by nothing — and it had no way to be told. This is
	// that way. Staging announces; Promote is the switch; the existing retiring machinery drops the old one.
	Incoming *storedTenantInterceptionIssuer `json:"incoming,omitempty"`
}

type tenantInterceptionMaterial struct {
	TenantID string `json:"tenant_id"`
	RootPEM  string `json:"root_pem"`
	// ChainPEM is the per-Edge intermediate followed by the issuing authority: everything between the leaf
	// this Edge will mint and the root a device holds.
	ChainPEM string `json:"chain_pem"`
	KeyPEM   string `json:"key_pem"`
	NotAfter string `json:"not_after"`
	// IncomingRootPEM is a root this organization is MOVING TO and which nothing signs under yet. An Edge
	// announces it to devices so they can adopt it, and goes on signing under RootPEM until the control plane
	// promotes. Empty unless a replacement is staged.
	//
	// ★ THE EDGE ALREADY HAD THE RECEIVING HALF AND NO WAY TO BE TOLD (2026-08-22).
	// offlineTenantIncomingRoots is exactly "announced, signed with by nothing", and the only thing that could
	// fill it was an operator calling POST /admin/interception-roots/{tenant}/announce by hand on each node.
	// Material is how everything else about an organization reaches a fleet; this makes the announcement
	// travel the same way, so a node that joins mid-rotation announces it too instead of quietly not.
	IncomingRootPEM string `json:"incoming_root_pem,omitempty"`
}

func newTenantInterceptionAuthority(seed []byte, persist func([]byte) error, now func() time.Time) *tenantInterceptionAuthority {
	return newTenantInterceptionAuthorityWithReload(seed, persist, nil, now)
}

// newTenantInterceptionAuthorityWithReload is the same, plus the way back to the SHARED store.
func newTenantInterceptionAuthorityWithReload(seed []byte, persist func([]byte) error,
	reload func() ([]byte, error), now func() time.Time) *tenantInterceptionAuthority {
	a := newTenantInterceptionAuthorityInner(seed, persist, now)
	a.reload = reload
	return a
}

func newTenantInterceptionAuthorityInner(seed []byte, persist func([]byte) error, now func() time.Time) *tenantInterceptionAuthority {
	a := &tenantInterceptionAuthority{issuers: map[string]*storedTenantInterceptionIssuer{}, persist: persist, now: now}
	if a.now == nil {
		a.now = time.Now
	}
	if len(seed) > 0 {
		var rows []storedTenantInterceptionIssuer
		if err := json.Unmarshal(seed, &rows); err == nil {
			for i := range rows {
				row := rows[i]
				a.issuers[strings.ToLower(strings.TrimSpace(row.TenantID))] = &row
			}
		}
	}
	a.snapshot = encodeAuthoritySnapshot(a.issuers)
	return a
}

func (a *tenantInterceptionAuthority) saveLocked() error {
	rows := make([]*storedTenantInterceptionIssuer, 0, len(a.issuers))
	for _, row := range a.issuers {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TenantID < rows[j].TenantID })
	data, err := json.Marshal(rows)
	if err == nil && a.persist != nil {
		err = a.persist(data)
	}
	if err != nil {
		a.issuers = restoreAuthoritySnapshot(a.snapshot, interceptionAuthorityRowKey)
		return err
	}
	a.snapshot = data
	a.generation++
	return nil
}

// Import accepts the authority an organization has signed for the operator, with the root it chains to.
//
// ★ IT VERIFIES THE CHAIN BEFORE ACCEPTING IT. An issuing certificate that does not chain to the root, or is
// not a CA, or whose key does not match it, would produce leaves every device refuses — and the refusal would
// arrive at the browser, not here.
func (a *tenantInterceptionAuthority) Import(tenant, rootPEM, issuingPEM, issuingKeyPEM string) (*storedTenantInterceptionIssuer, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	if key == "" {
		return nil, fmt.Errorf("an organization must be named")
	}
	root, err := parseFirstCertificatePEM([]byte(rootPEM))
	if err != nil {
		return nil, fmt.Errorf("read the organization's root: %w", err)
	}
	issuing, err := parseFirstCertificatePEM([]byte(issuingPEM))
	if err != nil {
		return nil, fmt.Errorf("read the issuing authority: %w", err)
	}
	if !issuing.IsCA {
		return nil, fmt.Errorf("the issuing certificate is not a CA, so it can sign nothing")
	}
	// ★★★ AND IT MUST BE ABLE TO HAVE A CA BENEATH IT (2026-08-21, measured after accepting one that could not).
	//
	// This control plane does not hand an Edge the authority it was given. It mints a SHORT-LIVED, PER-NODE
	// tier underneath and hands that out — which is the whole reason the long-lived key can stay here instead
	// of living on every node. That tier is a CA, so the authority above it needs room for one.
	//
	// A carefully issued issuing CA carries pathLenConstraint:0, meaning "nothing below me may be a CA". The
	// reference deployment's did. The import was accepted, the per-node tier was minted, and the chain it
	// produced is INVALID: openssl answers "path length constraint exceeded" and git stopped being able to
	// reach github from an intercepted machine. Chrome accepted it, which is exactly why this has to be caught
	// here — the browser is the door where it looks fine.
	//
	// Refused at the door, in the customer's terms, rather than at a verifier on somebody's laptop.
	if issuing.MaxPathLen == 0 && issuing.MaxPathLenZero {
		return nil, fmt.Errorf("this issuing authority is marked pathLenConstraint:0, which means no CA may sit " +
			"beneath it — and this deployment mints a short-lived certificate authority per Edge underneath " +
			"the one you give us, so that your long-lived key never has to be copied onto them. Sign an " +
			"issuing authority that permits one more level (pathLenConstraint of at least 1) under the same " +
			"root, and send that instead: your devices keep trusting the same root, so nothing on them changes")
	}
	if err := issuing.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("the issuing authority was not signed by the root given with it (%w) — devices "+
			"trust the root, so a chain that does not reach it is refused at the browser", err)
	}
	signer, err := parseECKeyPEM([]byte(issuingKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("read the issuing key: %w", err)
	}
	if !signer.PublicKey.Equal(issuing.PublicKey) {
		return nil, fmt.Errorf("the key does not belong to the issuing certificate")
	}
	now := a.now().UTC()
	row := &storedTenantInterceptionIssuer{
		TenantID: key, RootPEM: strings.TrimSpace(rootPEM) + "\n",
		IssuingCertPEM: strings.TrimSpace(issuingPEM) + "\n",
		IssuingKeyPEM:  strings.TrimSpace(issuingKeyPEM) + "\n",
		ImportedAt:     now.Format(time.RFC3339),
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	previous, had := a.issuers[key]
	// ★★★ A REPLACEMENT IS STAGED, NOT SWITCHED (2026-08-22). Handing over a second authority used to become
	// the signer on every Edge's next material fetch, and every device that had not yet added the new root
	// lost every HTTPS site at once — the eighteen minutes of 2026-08-19, with both sides reporting healthy.
	//
	// The FIRST authority for an organization is not a replacement and takes effect immediately: there is
	// nothing to lose, nothing is signing, and no device trusts anything yet.
	if had && previous != nil {
		if previous.Incoming != nil {
			return nil, fmt.Errorf("%q is already moving to a new interception authority (staged %s) — promote "+
				"it or withdraw it before staging another; devices cannot be asked to adopt two at once",
				tenant, previous.Incoming.ImportedAt)
		}
		staged := *previous
		staged.Incoming = row
		a.issuers[key] = &staged
		if err := a.saveLocked(); err != nil {
			a.issuers[key] = previous
			return nil, fmt.Errorf("a staged authority that is not persisted would vanish on the next restart "+
				"while devices were being asked to adopt its root: %w", err)
		}
		return row, nil
	}
	a.issuers[key] = row
	if err := a.saveLocked(); err != nil {
		if had {
			a.issuers[key] = previous
		} else {
			delete(a.issuers, key)
		}
		return nil, fmt.Errorf("an authority that is not persisted would be gone at the next restart, and every "+
			"Edge would stop being able to intercept for this organization: %w", err)
	}
	return row, nil
}

// Promote makes the staged authority the one every Edge signs under. Nothing about a device changes here: the
// root it was asked to adopt while this was staged is the root leaves are now signed by.
//
// ★ IT IS AN ACT, AND THE EVIDENCE COMES FIRST. Whether devices actually hold the incoming root is measured
// from what they REPORT holding (pinned_interception_root_sha256), which only an Edge collects. Promoting
// before that is the same mistake staging exists to prevent, one step later — see
// interceptionAuthorityRotationReadiness.
func (a *tenantInterceptionAuthority) Promote(tenant string) (*storedTenantInterceptionIssuer, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.issuers[key]
	if !ok || row == nil {
		return nil, fmt.Errorf("%q has no interception authority", tenant)
	}
	if row.Incoming == nil {
		return nil, fmt.Errorf("%q is not moving to a new interception authority, so there is nothing to promote", tenant)
	}
	promoted := row.Incoming
	promoted.Incoming = nil
	a.issuers[key] = promoted
	if err := a.saveLocked(); err != nil {
		a.issuers[key] = row
		return nil, fmt.Errorf("a promotion that is not persisted would come back undone at the next restart, "+
			"so the fleet would disagree about which root it signs under: %w", err)
	}
	return promoted, nil
}

// WithdrawIncoming abandons a staged authority. The organization stays on the one it is signing under, and the
// root devices were asked to adopt simply stops being announced.
//
// ★ THE WAY BACK MATTERS AS MUCH AS THE WAY FORWARD. Without it a staged authority that turns out to be wrong
// — the wrong pathLenConstraint, the wrong root, a key nobody can produce — could only be got rid of by
// promoting it, which is the one thing it must not do.
func (a *tenantInterceptionAuthority) WithdrawIncoming(tenant string) (*storedTenantInterceptionIssuer, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.issuers[key]
	if !ok || row == nil {
		return nil, fmt.Errorf("%q has no interception authority", tenant)
	}
	if row.Incoming == nil {
		return nil, fmt.Errorf("%q is not moving to a new interception authority, so there is nothing to withdraw", tenant)
	}
	kept := *row
	kept.Incoming = nil
	a.issuers[key] = &kept
	if err := a.saveLocked(); err != nil {
		a.issuers[key] = row
		return nil, fmt.Errorf("a withdrawal that is not persisted would bring the staged authority back at the "+
			"next restart: %w", err)
	}
	return &kept, nil
}

// IssueFor mints one Edge's short-lived interception intermediate.
func (a *tenantInterceptionAuthority) IssueFor(tenant, edgeID string, ttl time.Duration) (tenantInterceptionMaterial, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	row, ok, rerr := a.refreshedIssuerLocked(key)
	row = copyAuthority(row)
	a.mu.Unlock()
	if rerr != nil {
		return tenantInterceptionMaterial{}, fmt.Errorf("%w (%v)", errAuthorityNotAsked, rerr)
	}
	if !ok {
		return tenantInterceptionMaterial{}, fmt.Errorf("no interception authority for %q — this control plane "+
			"cannot hand an Edge the right to intercept for an organization that has delegated it nothing", tenant)
	}
	if ttl <= 0 {
		return tenantInterceptionMaterial{}, fmt.Errorf("material handed to an Edge must expire, so a lifetime is required")
	}
	issuing, err := parseFirstCertificatePEM([]byte(row.IssuingCertPEM))
	if err != nil {
		return tenantInterceptionMaterial{}, err
	}
	issuingKey, err := parseECKeyPEM([]byte(row.IssuingKeyPEM))
	if err != nil {
		return tenantInterceptionMaterial{}, err
	}
	edgeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tenantInterceptionMaterial{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tenantInterceptionMaterial{}, err
	}
	now := a.now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{CommonName: strings.TrimSpace(issuing.Subject.CommonName) + " — " +
			strings.TrimSpace(edgeID)},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(ttl),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		// ★ NO FURTHER CAs BELOW THIS ONE. What an Edge is handed may mint leaves and nothing else; a node
		// that could mint another CA could delegate the organization's interception onward.
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuing, &edgeKey.PublicKey, issuingKey)
	if err != nil {
		return tenantInterceptionMaterial{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(edgeKey)
	if err != nil {
		return tenantInterceptionMaterial{}, err
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		strings.TrimSpace(row.IssuingCertPEM) + "\n"
	// ★ THE STAGED ROOT TRAVELS BESIDE THE ONE IN FORCE, and this Edge signs under neither of them by
	// accident: the chain above is built from row.IssuingCertPEM, the authority in force. See IncomingRootPEM.
	incomingRoot := ""
	if row.Incoming != nil {
		incomingRoot = row.Incoming.RootPEM
	}
	return tenantInterceptionMaterial{
		TenantID:        row.TenantID,
		RootPEM:         row.RootPEM,
		ChainPEM:        chain,
		KeyPEM:          string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		NotAfter:        template.NotAfter.Format(time.RFC3339),
		IncomingRootPEM: incomingRoot,
	}, nil
}

// Row is this organization's authority as it stands, for the read that a screen asks. A COPY: a caller that
// held the live row could change what this node signs with by accident, and the answer is a snapshot anyway.
// Has reports whether this organization already has an interception authority here. Asked before minting one:
// a second authority is a REPLACEMENT — staged, announced, promoted only once every device holds the incoming
// root — and nobody asks for that by leaving a request body empty.
func (a *tenantInterceptionAuthority) Has(tenant string) bool {
	if a == nil {
		return false
	}
	_, ok := a.Row(tenant)
	return ok
}

func (a *tenantInterceptionAuthority) Row(tenant string) (storedTenantInterceptionIssuer, bool) {
	if a == nil {
		return storedTenantInterceptionIssuer{}, false
	}
	// ★★★ AN ABSENCE HERE IS AN ANSWER A DEVICE IS INSTALLED FROM, SO IT COMES FROM THE SHARED STORE
	// (2026-08-31, measured on a live two-region deployment).
	//
	// Three organizations were minted their own authorities while the founding region's control plane led.
	// Leadership moved. Every profile issued afterwards was HTTP 200, correctly signed, and carried no device
	// CA pin, no interception root, no transport anchors and no organization door name — because this lookup
	// answered from the snapshot THIS node happened to load, and this node had not received the write. A
	// device installed from such a profile dials the deployment-wide name, pins nothing, and refuses every
	// page the moment its Edge inspects.
	//
	// The material paths already went through the shared store on a miss, with a comment saying exactly why —
	// "a control plane that did not receive a write does not refuse an organization's enrolments as if it had
	// none". The read that BUILDS THE PROFILE did not. Same rule, one call site over.
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	row, ok := a.issuers[key]
	if !ok || row == nil {
		var rerr error
		if row, ok, rerr = a.refreshedIssuerLocked(key); rerr != nil || !ok || row == nil {
			return storedTenantInterceptionIssuer{}, false
		}
	}
	return copyAuthority(*row), true
}

func (a *tenantInterceptionAuthority) Organizations() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	out := make([]string, 0, len(a.issuers))
	for tenant := range a.issuers {
		out = append(out, tenant)
	}
	sort.Strings(out)
	return out
}

// CountForTenant and RemoveTenant: an organization's delegated interception authority is that organization's,
// so it is counted in what an erasure has left and removed with them.
func (a *tenantInterceptionAuthority) CountForTenant(tenant string) int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	if _, ok := a.issuers[strings.ToLower(strings.TrimSpace(tenant))]; ok {
		return 1
	}
	return 0
}

func (a *tenantInterceptionAuthority) RemoveTenant(tenant string) int {
	n, _ := a.RemoveTenantChecked(tenant)
	return n
}

func (a *tenantInterceptionAuthority) RemoveTenantChecked(tenant string) (int, error) {
	if a == nil {
		return 0, nil
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return 0, err
	}
	if _, ok := a.issuers[key]; !ok {
		return 0, nil
	}
	delete(a.issuers, key)
	// saveLocked restores the previous snapshot when the save is unconfirmed.
	if err := a.saveLocked(); err != nil {
		return 0, err
	}
	return 1, nil
}

// registerTenantInterceptionAuthorityFlag declares where a control plane keeps the authorities organizations
// have delegated to it. In a sibling file, like every other flag, because main.go may not grow.
func registerTenantInterceptionAuthorityFlag() *string {
	return flag.String("tenant-interception-authority-store", "", "control plane: durable store for the interception issuing authorities organizations have DELEGATED to this operator (\"postgres\", \"postgres+import:FILE\", or a file path). Their roots are not here and never are. Empty = this node hands Edges no interception material")
}

// IsStaged reports whether this organization has a replacement authority held beside the one in force.
func (a *tenantInterceptionAuthority) IsStaged(tenant string) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	row, ok := a.issuers[strings.ToLower(strings.TrimSpace(tenant))]
	return ok && row != nil && row.Incoming != nil
}

// GenerationParts is what this authority IS — see the transport twin. The staged authority is included: an
// Edge that does not fetch after one is staged never announces the root devices are being asked to adopt.
func (a *tenantInterceptionAuthority) GenerationParts() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	out := make([]string, 0, len(a.issuers))
	for tenant, row := range a.issuers {
		if row == nil {
			continue
		}
		incoming := ""
		if row.Incoming != nil {
			incoming = row.Incoming.RootPEM + "\x1e" + row.Incoming.IssuingCertPEM
		}
		out = append(out, "interception\x1f"+tenant+"\x1f"+row.RootPEM+"\x1f"+row.IssuingCertPEM+
			"\x1f"+incoming)
	}
	return out
}

// refreshedIssuerLocked reads a complete current snapshot, including cache hits. Caller holds a.mu.
func (a *tenantInterceptionAuthority) refreshedIssuerLocked(key string) (*storedTenantInterceptionIssuer, bool, error) {
	if err := a.refreshLocked(); err != nil {
		return nil, false, err
	}
	row, ok := a.issuers[key]
	return row, ok, nil
}

func (a *tenantInterceptionAuthority) refreshLocked() error {
	if a.reload == nil {
		return nil
	}
	rows, raw, err := readAuthoritySnapshot(a.reload, interceptionAuthorityRowKey, a.issuers)
	if err != nil {
		return err
	}
	a.issuers, a.snapshot = rows, raw
	return nil
}

func interceptionAuthorityRowKey(row *storedTenantInterceptionIssuer) string {
	return strings.ToLower(strings.TrimSpace(row.TenantID))
}
