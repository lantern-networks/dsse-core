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
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// tenant_device_material_authority.go — the control plane holds a DEVICE-IDENTITY authority per organization,
// for the customers who do not run a PKI of their own.
//
// ★★★ THE PRODUCT ALREADY PROMISED THIS AND COULD NOT KEEP IT (2026-08-21, measured). An administrator of
// tenant_northwind issues an enrolment token through /admin/enrolment-tokens and gets 201. A device presenting
// that token to POST /enroll is refused 403, because the endpoint verifies the token against the NODE's
// organization and the Edge holds exactly one device-identity signer. So the screen mints credentials that can
// never be used, and the operator's log is the only place the reason appears.
//
// The other path is real and works — an organization may register its OWN device CA, hold the key, and issue
// its own certificates (walked end to end the same night: register, author the identity, issue, handshake).
// That is the right shape for a customer who wants independence, and it is NOT a shape a customer with no PKI
// can adopt. This deployment's own framing is that a tenant administrator may be a customer with little IT
// depth; telling them to run a CA is telling them the product does not work for them.
//
// So the deployment holds one, per organization, the same way it already holds their transport authority.
//
// ★ AND THE DIRECTION IS THE OPPOSITE OF THE INTERCEPTION ROOT, WHICH IS WHY THIS MAY BE HELD HERE AT ALL. An
// interception root is what an organization's devices TRUST, so creating one on the machine that terminates
// their traffic is exactly the line the operator/customer boundary draws and it is delegated from the customer instead. A device CA is
// what the deployment VERIFIES devices against — nothing trusts it, it identifies — so the operator holding it
// is the managed-service arrangement itself. A customer who does not want that registers their own and this
// authority is never created for them.
//
// The material handed to an Edge is the CA itself, short-lived by the fetch's TTL rather than by the
// certificate's — the same arrangement as the transport material, which hands an Edge the organization's
// server key. Handing a per-Edge INTERMEDIATE instead was considered and rejected: a device would then have to
// present leaf+intermediate and its chain would break when the intermediate lapsed, even though its own
// certificate was still valid, which is the failure this whole area exists to prevent.
//
// restart-durability: cp_durable — written through the persister the moment an authority is created, and a
// creation that could not be persisted is refused rather than reported. An authority regenerated after a
// restart would mean every device that organization enrolled is no longer identified by the CA the registry
// holds — the whole fleet unadmitted, with nothing to say why.
//
// populated-by: assertion — reloaded from that blob at start-up, and never inferred from what an Edge asks
// for. A request naming an organization with no authority is refused, not answered by creating one.
type tenantDeviceAuthority struct {
	snapshot []byte

	mu      sync.Mutex
	cas     map[string]*storedTenantDeviceCA
	persist func([]byte) error
	// reload re-reads the SHARED store. See the transport authority's refreshedRowLocked for the measurement:
	// a control plane that did not receive a write answered, as a fact, that an organization has nothing.
	reload func() ([]byte, error)
	now    func() time.Time
	// generation changes whenever the set of authorities does.
	//
	// ★★★ A CHANGE THE GENERATION DOES NOT CARRY IS INVISIBLE (2026-08-21, measured the moment this shipped).
	// An Edge asks the cheap question — "is anything different from generation N" — and the answer was
	// computed from the TRANSPORT authorities alone. So creating this organization's device-identity authority
	// changed nothing an Edge could see: both nodes fetched and installed "device identity for 0", and an
	// enrolment token issued a minute later would still have been refused. Same shape as the trust bundle's
	// serial, which had to be made to follow everything the bundle says rather than only its anchors.
	generation uint64
}

type storedTenantDeviceCA struct {
	RetiredAnchorSHA256 []string `json:"retired_anchor_sha256,omitempty"`
	TenantID            string   `json:"tenant_id"`
	CACertPEM           string   `json:"ca_cert_pem"`
	CAKeyPEM            string   `json:"ca_key_pem"`
	CreatedAt           string   `json:"created_at"`
	// IncomingWithdrawn says the rotation was ABANDONED: the incoming authority no longer signs, and is still
	// admitted.
	//
	// ★★★ A DEVICE ROTATION CANNOT BE ABANDONED BY DROPPING THE INCOMING AUTHORITY (2026-08-22). From the
	// moment a rotation starts, the incoming authority SIGNS — that is how devices migrate — so by the time
	// anybody decides the rotation was a mistake, real devices are holding real certificates from it.
	// Dropping it refuses exactly those devices at the handshake, which is the same shape as retiring the
	// outgoing one too early, only aimed at the devices that DID what they were told.
	//
	// So abandoning turns the movement around instead of cancelling it: signing goes back to the authority in
	// force, both stay admitted, and the abandoned one is dropped later by the ordinary retirement act once
	// the readiness answer says nobody presents it. One boolean rather than a third list, because an anchor
	// set with no way to shrink is the defect this file's neighbour spent this morning fixing.
	IncomingWithdrawn bool `json:"incoming_withdrawn,omitempty"`
	// Incoming is the authority this organization is MOVING TO, held beside the one in force.
	//
	// ★★★ WHY A DEVICE ROTATION IS THE OTHER WAY ROUND FROM A TRANSPORT ONE (2026-08-22). On the transport
	// side the Edge presents the certificate and the devices verify it, so a rotation waits for devices to
	// TRUST the new authority before the Edge serves it. Here the device presents the certificate and the Edge
	// verifies it — so the rotation waits for devices to be RE-ISSUED under the new authority, and the old one
	// has to stay trusted until the last of them has moved.
	//
	// That inverts which half is dangerous. Retiring a transport authority too early takes out an Edge that has
	// not promoted. Retiring a DEVICE authority too early takes out every device still holding a certificate
	// from it — they are refused at the handshake, and a device that is switched off during the rotation is
	// exactly the one that will be refused when it comes back.
	//
	// So during the overlap: the INCOMING authority signs (that is how devices migrate — every enrolment and
	// every renewal comes from the new one), and BOTH are registered as anchors (that is how the ones that
	// have not migrated yet are still admitted).
	Incoming *storedTenantDeviceCA `json:"incoming,omitempty"`
}

// tenantDeviceMaterial is what an Edge is handed for one organization: the authority its devices are issued
// under, and the moment this hand-over stops being usable.
type tenantDeviceMaterial struct {
	// Complete admitted set, authored by the CP from managed state and explicit
	// registrations. AnchorPEM below still describes managed rotation only.
	AdmissionComplete bool   `json:"admission_complete"`
	AdmissionCAPEM    string `json:"admission_ca_pem"`
	TenantID          string `json:"tenant_id"`
	CACertPEM         string `json:"ca_cert_pem"`
	CAKeyPEM          string `json:"ca_key_pem"`
	// AnchorPEM is what the tenant CA registry must hold so a device enrolled here is RESOLVED to this
	// organization at the handshake. It is the same certificate as CACertPEM, named separately because the
	// registry's copy is the public half and travels on its own.
	AnchorPEM string `json:"anchor_pem"`
	NotAfter  string `json:"not_after"`
}

func newTenantDeviceAuthority(seed []byte, persist func([]byte) error, now func() time.Time) *tenantDeviceAuthority {
	return newTenantDeviceAuthorityWithReload(seed, persist, nil, now)
}

// newTenantDeviceAuthorityWithReload is the same, plus the way back to the SHARED store.
func newTenantDeviceAuthorityWithReload(seed []byte, persist func([]byte) error, reload func() ([]byte, error),
	now func() time.Time) *tenantDeviceAuthority {
	a := &tenantDeviceAuthority{cas: map[string]*storedTenantDeviceCA{}, persist: persist, reload: reload, now: now}
	if a.now == nil {
		a.now = time.Now
	}
	if len(seed) > 0 {
		var rows []*storedTenantDeviceCA
		if err := json.Unmarshal(seed, &rows); err == nil {
			for _, row := range rows {
				if row == nil || strings.TrimSpace(row.TenantID) == "" {
					continue
				}
				a.cas[strings.ToLower(strings.TrimSpace(row.TenantID))] = row
			}
		}
	}
	a.snapshot = encodeAuthoritySnapshot(a.cas)
	return a
}

func (a *tenantDeviceAuthority) saveLocked() error {
	rows := make([]*storedTenantDeviceCA, 0, len(a.cas))
	for _, row := range a.cas {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TenantID < rows[j].TenantID })
	data, err := json.Marshal(rows)
	if err == nil && a.persist != nil {
		err = a.persist(data)
	}
	if err != nil {
		a.cas = restoreAuthoritySnapshot(a.snapshot, deviceAuthorityRowKey)
		return err
	}
	a.snapshot = data
	a.generation++
	return nil
}

// Generation is what an Edge compares against to decide whether to ask for material. Never zero for a live
// authority: zero is what an Edge sends when it has never asked, and the two must not be confusable.
func (a *tenantDeviceAuthority) Generation() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata keeps the committed view on a read error.
	return a.generation + 1
}

// EnsureCA creates this organization's device-identity authority if it has none, and is idempotent otherwise.
func (a *tenantDeviceAuthority) EnsureCA(tenant, displayName string) (*storedTenantDeviceCA, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	if key == "" {
		return nil, fmt.Errorf("an organization must be named")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	if existing, ok := a.cas[key]; ok {
		return existing, nil
	}
	label := strings.TrimSpace(displayName)
	if label == "" {
		label = key
	}
	row, err := a.mintDeviceCALocked(key, label)
	if err != nil {
		return nil, err
	}
	a.cas[key] = row
	if err := a.saveLocked(); err != nil {
		delete(a.cas, key)
		return nil, fmt.Errorf("an authority that is not persisted would be regenerated on the next restart, and "+
			"every device this organization has enrolled would stop being identified: %w", err)
	}
	return row, nil
}

// IssueFor hands one organization's authority to an Edge for a bounded window.
//
// It never CREATES one: an Edge asking about an organization the operator has not set up is told no, because
// answering by minting an authority would mean the identity basis of a fleet came into existence because a
// node asked a question.
func (a *tenantDeviceAuthority) IssueFor(tenant string, ttl time.Duration) (tenantDeviceMaterial, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	row, ok, rerr := a.refreshedRowLocked(key)
	if rerr != nil {
		return tenantDeviceMaterial{}, fmt.Errorf("%w (%v)", errAuthorityNotAsked, rerr)
	}

	if !ok {
		return tenantDeviceMaterial{}, fmt.Errorf("no device-identity authority exists for %q", tenant)
	}
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	// ★★ DURING A ROTATION THE SIGNER AND THE ANCHORS ARE NOT THE SAME SET (2026-08-22).
	//
	// The INCOMING authority signs, because that is how devices migrate: every enrolment and every renewal
	// from now on produces a certificate under the new one, and the fleet converges without anybody visiting a
	// laptop. BOTH are anchors, because a device that has not renewed yet still presents the old one and must
	// still be admitted — and must still be resolved to this organization, which is what the registry copy is
	// for. Handing only the incoming anchor would refuse every device that had not moved, at the handshake,
	// the moment the fleet picked up the material. That is the outage this shape exists to avoid.
	signer := row
	if row.Incoming != nil && !row.IncomingWithdrawn {
		signer = row.Incoming
	}
	return tenantDeviceMaterial{
		AdmissionComplete: true,
		AdmissionCAPEM:    deviceAdmissionAnchors(row, nil),
		TenantID:          row.TenantID,
		CACertPEM:         signer.CACertPEM,
		CAKeyPEM:          signer.CAKeyPEM,
		AnchorPEM:         deviceAnchorsOf(row),
		NotAfter:          a.now().UTC().Add(ttl).Format(time.RFC3339),
	}, nil
}

// deviceAnchorsOf is every authority whose certificates this organization's devices may still present: the one
// in force, and the one being rotated onto when a rotation is in flight. Concatenated PEM, which
// tenantca.TenantCARegistry.Register reads as a set.
func deviceAnchorsOf(row *storedTenantDeviceCA) string {
	if row == nil {
		return ""
	}
	anchors := strings.TrimSpace(row.CACertPEM)
	if row.Incoming != nil {
		if next := strings.TrimSpace(row.Incoming.CACertPEM); next != "" {
			anchors = anchors + "\n" + next
		}
	}
	return anchors + "\n"
}

// mintDeviceCALocked is the ONE place a device-identity authority is created, so the first one and the one an
// organization rotates onto cannot come to be shaped differently — a second minting path is where two answers
// to "what does this organization's device CA look like" start. Caller holds the lock.
func (a *tenantDeviceAuthority) mintDeviceCALocked(key, label string) (*storedTenantDeviceCA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := a.now().UTC()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// The organization is named in the subject so an operator reading a device certificate, or the
		// registry, can say whose it is without a lookup. The tenant id is authoritative and travels beside it.
		Subject:               pkix.Name{CommonName: label + " Device Identity CA", Organization: []string{label}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, err
	}
	return &storedTenantDeviceCA{
		TenantID:  key,
		CACertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		CAKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		CreatedAt: now.Format(time.RFC3339),
	}, nil
}

// deviceCALabelFrom recovers the organization label from an existing authority's subject, so a rotation keeps
// the name the first one was given rather than falling back to the tenant id and producing a fleet whose two
// authorities are called different things mid-rotation.
func deviceCALabelFrom(caCertPEM, fallback string) string {
	cert, err := parseFirstCertificatePEM([]byte(caCertPEM))
	if err != nil || cert == nil {
		return fallback
	}
	if len(cert.Subject.Organization) > 0 && strings.TrimSpace(cert.Subject.Organization[0]) != "" {
		return strings.TrimSpace(cert.Subject.Organization[0])
	}
	return strings.TrimSpace(strings.TrimSuffix(cert.Subject.CommonName, " Device Identity CA"))
}

// RotateCA begins a rotation: a NEW device-identity authority is minted and held beside the one in force.
// Nothing is taken away — the outgoing authority keeps admitting the devices that hold certificates from it
// until RetirePrevious, and every certificate issued from now on comes from the incoming one.
//
// ★ ONE ROTATION AT A TIME. A second incoming authority would leave devices spread across three, and the
// readiness question — "has everybody moved?" — would have no single answer to be measured against.
func (a *tenantDeviceAuthority) RotateCA(tenant string) (*storedTenantDeviceCA, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.cas[key]
	if !ok {
		return nil, fmt.Errorf("%q has no device-identity authority to rotate", tenant)
	}
	if row.Incoming != nil {
		return nil, fmt.Errorf("%q is already moving to a new device-identity authority (created %s) — finish "+
			"that rotation and retire the previous authority before starting another", tenant, row.Incoming.CreatedAt)
	}
	label := deviceCALabelFrom(row.CACertPEM, key)
	minted, err := a.mintDeviceCALocked(key, label)
	if err != nil {
		return nil, err
	}
	row.Incoming = minted
	if err := a.saveLocked(); err != nil {
		row.Incoming = nil
		return nil, fmt.Errorf("an incoming authority that is not persisted would vanish on the next restart "+
			"while devices were being issued certificates under it — and those devices would then be refused "+
			"by every Edge in the fleet: %w", err)
	}
	return minted, nil
}

// AbandonRotation gives up on a device-identity rotation without taking anything away from a device.
//
// ★★★ EVERY MOVEMENT NEEDS A WAY BACK, AND THIS TIER DID NOT HAVE ONE (2026-08-22, found by reading the
// roadmap against the tree). Interception could WithdrawIncoming; the transport rename could AbandonRename;
// a device rotation could only be ENDED by RetirePrevious, which is the act that refuses every device still
// on the outgoing authority. An operator who staged the wrong CA — or staged one and then found its key had
// been handled badly — had a choice between leaving it signing for ever and completing a rotation they no
// longer wanted.
//
// After this, signing returns to the authority in force and BOTH remain admitted, so a device that enrolled
// or renewed during the overlap keeps working. Dropping the abandoned authority is a separate, later act,
// gated on the same readiness answer as any other retirement — measured on what devices actually present.
func (a *tenantDeviceAuthority) AbandonRotation(tenant string) (*storedTenantDeviceCA, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.cas[key]
	if !ok {
		return nil, fmt.Errorf("%q has no device-identity authority", tenant)
	}
	if row.Incoming == nil {
		return nil, fmt.Errorf("%q is not moving to a new device-identity authority, so there is nothing to "+
			"abandon", tenant)
	}
	if row.IncomingWithdrawn {
		return nil, fmt.Errorf("%q has already abandoned this rotation — the incoming authority is admitted "+
			"and no longer signs. Retire it once no device presents it", tenant)
	}
	row.IncomingWithdrawn = true
	if err := a.saveLocked(); err != nil {
		row.IncomingWithdrawn = false
		return nil, fmt.Errorf("abandoning a rotation that is not persisted would have it signing again at the "+
			"next restart: %w", err)
	}
	return row, nil
}

// RetirePrevious ends a rotation: the incoming authority becomes the only one, and the outgoing one stops
// being an anchor anywhere.
//
// ★★★ THIS IS THE DESTRUCTIVE HALF, AND IT IS DESTRUCTIVE IN A WAY THE TRANSPORT ONE IS NOT. Every device
// still presenting a certificate from the outgoing authority is refused at the handshake the moment the fleet
// picks this up — including a laptop that was switched off for the whole rotation, which is precisely the one
// nobody was watching. There is no fail-open here and there must not be: admitting an unknown authority is
// the thing device identity exists to prevent.
//
// So this deliberately does NOT decide for itself. deviceAuthorityRotationReadiness answers "who has not
// moved" from what each device actually presented at a handshake, and an operator reads that first. This is
// the act; that is the evidence.
func (a *tenantDeviceAuthority) RetirePrevious(tenant string) (*storedTenantDeviceCA, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.cas[key]
	if !ok {
		return nil, fmt.Errorf("%q has no device-identity authority", tenant)
	}
	if row.Incoming == nil {
		return nil, fmt.Errorf("%q is not moving to a new device-identity authority, so there is no previous "+
			"one to retire", tenant)
	}
	// ★★★ WHICH AUTHORITY THIS RETIRES DEPENDS ON WHICH WAY THE ROTATION WAS RUNNING (2026-08-22, and getting
	// this wrong would have promoted the very authority an operator had just abandoned). After AbandonRotation
	// the incoming one no longer signs and is only kept because devices issued during the overlap present it;
	// retiring THEN means dropping it, not promoting it. Both directions end at "one authority", and the
	// readiness answer that gates the act is the same one — it just names a different set of devices.
	if row.IncomingWithdrawn {
		dropped := row.Incoming
		previousHistory := row.RetiredAnchorSHA256
		row.RetiredAnchorSHA256 = deviceRetirementHistory(row, dropped.CACertPEM)
		row.Incoming = nil
		row.IncomingWithdrawn = false
		if err := a.saveLocked(); err != nil {
			row.RetiredAnchorSHA256 = previousHistory
			row.Incoming, row.IncomingWithdrawn = dropped, true
			return nil, fmt.Errorf("dropping an abandoned authority that is not persisted would bring it back "+
				"on the next restart: %w", err)
		}
		return row, nil
	}
	promoted := row.Incoming
	promoted.RetiredAnchorSHA256 = deviceRetirementHistory(row, row.CACertPEM)
	promoted.Incoming = nil
	a.cas[key] = promoted
	if err := a.saveLocked(); err != nil {
		a.cas[key] = row
		return nil, fmt.Errorf("retiring an authority that is not persisted would bring it back on the next "+
			"restart, so the fleet would disagree about which devices it admits: %w", err)
	}
	return promoted, nil
}

// Organizations names every organization this authority can issue for, sorted.
// Row is this organization's authority as it stands, for the read that a screen asks. A COPY: a caller that
// held the live row could change what this node signs with by accident, and the answer is a snapshot anyway.
func (a *tenantDeviceAuthority) Row(tenant string) (storedTenantDeviceCA, bool) {
	if a == nil {
		return storedTenantDeviceCA{}, false
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
	row, ok := a.cas[key]
	if !ok || row == nil {
		var rerr error
		if row, ok, rerr = a.refreshedRowLocked(key); rerr != nil || !ok || row == nil {
			return storedTenantDeviceCA{}, false
		}
	}
	return copyAuthority(*row), true
}

func (a *tenantDeviceAuthority) Organizations() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	out := make([]string, 0, len(a.cas))
	for key := range a.cas {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// RemoveTenant erases an organization's device-identity authority. Returns how many were removed, so a purge
// can say what it did rather than assert that it did something.
func (a *tenantDeviceAuthority) RemoveTenant(tenant string) int {
	if a == nil {
		return 0
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return 0
	}
	if _, ok := a.cas[key]; !ok {
		return 0
	}
	delete(a.cas, key)
	if err := a.saveLocked(); err != nil {
		// Put it back rather than report an erasure that only happened in memory.
		return 0
	}
	return 1
}

// registerTenantDeviceAuthorityFlag declares where this control plane keeps the per-organization
// device-identity authorities. Empty shares the deployment's database when it has one, so a fleet does not
// depend on which node was given a path — see storeShouldBeWired.
func registerTenantDeviceAuthorityFlag() *string {
	return flag.String("tenant-device-authority-store", "",
		"control plane: durable store for the per-organization DEVICE-IDENTITY authorities this deployment "+
			"enrols with, for customers who do not run a PKI of their own. A path, \"postgres\", or empty to "+
			"use the shared database when there is one. An organization that registers its own device CA "+
			"through /admin/tenant-cas never has one of these.")
}

// registerTenantDeviceAuthorityAdminRoute is how an organization comes to be enrolled BY THIS DEPLOYMENT
// rather than by a CA of its own.
//
// ★ CREATING IT IS AN ACT, NOT A SIDE EFFECT — the same rule the transport authority states beside it. An
// authority minted on first sight of an organization would mean the identity basis of a customer's fleet came
// into existence because a node asked a question, and it would silently override the choice of a customer who
// intends to bring their own CA.
//
// Rights are the same either-of pair every per-organization PKI act uses: an organization's own administrator
// may do this for their own organization, and an operator crossing into another goes through the envelope.
func registerTenantDeviceAuthorityAdminRoute(mux *http.ServeMux,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, authority *tenantDeviceAuthority,
	configSourceURL string, tenantModels adminTenantModelRuntimeStore, gates ...pkiTransitionAdmission) {
	mux.HandleFunc("POST /admin/tenant-device-authority", adminEndpoint("admin.enrollment.write|admin.tenant.admin",
		func(w http.ResponseWriter, r *http.Request) {
			// Creating one is the control plane's too — see the act helper below.
			if configWriteRejectedWhenSourced(w, configSourceURL, "device-identity authority") {
				return
			}
			var body struct {
				TenantID    string `json:"tenant_id"`
				DisplayName string `json:"display_name"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			tenant, terr := adminTenantForWrite(r, body.TenantID)
			if terr != nil {
				writeError(w, http.StatusForbidden, terr)
				return
			}
			if err := adminTenantPKITargetAllowed(r, tenant, "creating a device-identity authority for"); err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			if authority == nil {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("this control plane holds no device-identity "+
					"authorities, so it can create none. Organizations here enrol with a CA they register "+
					"themselves through /admin/tenant-cas"))
				return
			}
			// ★★★ THE ONE CA THAT CAME OUT NAMED AFTER AN ID (2026-09-05, read off a live deployment's PKI
			// screen). Every other per-organization authority resolves the name from the registry when the
			// caller does not send one — the interception route does it a few files over, and the roots it
			// mints read "Kaede Foods Interception Root". This one took the name only from the request body,
			// and the published procedure (docs/organizations.md) does not send one, so the CA that signs
			// every device certificate in the organization came out as
			//
			//   CN=tenant_xkcgvvava4k5d63ral2q23iwu4 Device Identity CA, O=tenant_xkcgvvava4k5d63ral2q23iwu4
			//
			// while the deployment knew perfectly well that organization is called Kaede Foods. That subject
			// is what an operator reads on a device certificate and in a connector's --verify output, so the
			// one place a name was needed is the one place it was missing. The id still travels beside it —
			// display names are not unique — but it is not the label.
			displayName := strings.TrimSpace(body.DisplayName)
			if displayName == "" && tenantModels != nil {
				if model, err := tenantModels.Get(r.Context(), tenant); err == nil {
					displayName = strings.TrimSpace(model.DisplayName)
				}
			}
			row, err := authority.EnsureCA(tenant, displayName)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"tenant_id":  row.TenantID,
				"anchor_pem": row.CACertPEM,
				"created_at": row.CreatedAt,
				"applies_to": "every Edge in the fleet, as each one next fetches its material — from then on an " +
					"enrolment token issued by this organization admits a device on any of them",
			})
		}))

	// ★★★ THE TWO DOORS THIS AUTHORITY HAD NEITHER OF (2026-08-22). Transport could rotate and retire; the
	// authority that signs every DEVICE certificate could do neither, so a compromised key had no supported
	// replacement. See the notes on RotateCA and RetirePrevious — and note which of the two is the dangerous
	// one here, because it is the opposite one from the transport side.
	act := func(w http.ResponseWriter, r *http.Request, what string,
		do func(*tenantDeviceAuthority, string) (*storedTenantDeviceCA, error)) {
		var body struct {
			TenantID string `json:"tenant_id"`
		}
		// A body is optional: an organization administrator names nothing and means themselves.
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body)
		tenant, terr := adminTenantForWrite(r, body.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		if err := adminTenantPKITargetAllowed(r, tenant, what+" the device-identity authority of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		if authority == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("this control plane holds no device-identity "+
				"authorities, so there is none to %s", what))
			return
		}
		row, err := do(authority, tenant)
		if err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":  row.TenantID,
			"anchor_pem": row.CACertPEM,
			"created_at": row.CreatedAt,
			"rotating":   row.Incoming != nil,
			"note": "Every Edge picks this up on its next material fetch. Ask each one " +
				"GET /admin/device-authority-rotation before retiring: only an Edge has seen what a device " +
				"actually presented at a handshake, and retiring early refuses every device that has not moved.",
		})
	}

	mux.HandleFunc("POST /admin/tenant-device-authority/rotate",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			// ★★★ THE AUTHORITY IS THE CONTROL PLANE'S, AND THESE ROUTES DID NOT SAY SO (2026-08-22, measured
			// through the Console). One click in the GUI left three planes disagreeing:
			//
			//	edge-a  rotating=true      ← the act landed here
			//	edge-b  rotating=false
			//	CP      rotating=false
			//
			// with the Console — which reads the control plane — showing "not being replaced" while an Edge
			// refused the next attempt with "already moving".
			//
			// ★ AND IT IS AT EVERY ROUTE, NOT IN THE HELPER THEY SHARE. It was in the helper first, which is
			// where a reader would put it, and the Console's routing table is GENERATED by finding this call
			// beneath a HandleFunc — so a guard one level down protected the node and left the table with one
			// route out of four, which is the same split by another road.
			if configWriteRejectedWhenSourced(w, configSourceURL, "device-identity authority") {
				return
			}
			act(w, r, "rotating", func(a *tenantDeviceAuthority, t string) (*storedTenantDeviceCA, error) {
				return a.RotateCA(t)
			})
		}))

	mux.HandleFunc("POST /admin/tenant-device-authority/abandon-rotation",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			// ★★★ THE AUTHORITY IS THE CONTROL PLANE'S, AND THESE ROUTES DID NOT SAY SO (2026-08-22, measured
			// through the Console). One click in the GUI left three planes disagreeing:
			//
			//	edge-a  rotating=true      ← the act landed here
			//	edge-b  rotating=false
			//	CP      rotating=false
			//
			// with the Console — which reads the control plane — showing "not being replaced" while an Edge
			// refused the next attempt with "already moving".
			//
			// ★ AND IT IS AT EVERY ROUTE, NOT IN THE HELPER THEY SHARE. It was in the helper first, which is
			// where a reader would put it, and the Console's routing table is GENERATED by finding this call
			// beneath a HandleFunc — so a guard one level down protected the node and left the table with one
			// route out of four, which is the same split by another road.
			if configWriteRejectedWhenSourced(w, configSourceURL, "device-identity authority") {
				return
			}
			act(w, r, "abandoning the rotation of", func(a *tenantDeviceAuthority, t string) (*storedTenantDeviceCA, error) {
				return a.admitTransition(t, "abandon-rotation", gates, func(candidate *tenantDeviceAuthority, tenant string) (*storedTenantDeviceCA, error) {
					return candidate.AbandonRotation(tenant)
				})
			})
		}))

	mux.HandleFunc("POST /admin/tenant-device-authority/retire-previous",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			// ★★★ THE AUTHORITY IS THE CONTROL PLANE'S, AND THESE ROUTES DID NOT SAY SO (2026-08-22, measured
			// through the Console). One click in the GUI left three planes disagreeing:
			//
			//	edge-a  rotating=true      ← the act landed here
			//	edge-b  rotating=false
			//	CP      rotating=false
			//
			// with the Console — which reads the control plane — showing "not being replaced" while an Edge
			// refused the next attempt with "already moving".
			//
			// ★ AND IT IS AT EVERY ROUTE, NOT IN THE HELPER THEY SHARE. It was in the helper first, which is
			// where a reader would put it, and the Console's routing table is GENERATED by finding this call
			// beneath a HandleFunc — so a guard one level down protected the node and left the table with one
			// route out of four, which is the same split by another road.
			if configWriteRejectedWhenSourced(w, configSourceURL, "device-identity authority") {
				return
			}
			act(w, r, "retiring the previous", func(a *tenantDeviceAuthority, t string) (*storedTenantDeviceCA, error) {
				return a.admitTransition(t, "retire-previous", gates, func(candidate *tenantDeviceAuthority, tenant string) (*storedTenantDeviceCA, error) {
					return candidate.RetirePrevious(tenant)
				})
			})
		}))
}

// GenerationParts is what this authority IS — see the transport twin.
func (a *tenantDeviceAuthority) GenerationParts() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	out := make([]string, 0, len(a.cas))
	for tenant, row := range a.cas {
		if row == nil {
			continue
		}
		incoming := ""
		if row.Incoming != nil {
			incoming = row.Incoming.CACertPEM
		}
		// ★ The WITHDRAWN flag belongs here too: abandoning a rotation changes which authority signs, and a
		// change no Edge re-fetches is a change that never happened. The material is what this produces, not
		// what the row looks like.
		withdrawn := ""
		if row.IncomingWithdrawn {
			withdrawn = "withdrawn"
		}
		out = append(out, "device\x1f"+tenant+"\x1f"+row.CACertPEM+"\x1f"+incoming+"\x1f"+withdrawn+"\x1f"+strings.Join(row.RetiredAnchorSHA256, ","))
	}
	return out
}

// refreshedRowLocked re-reads the shared store on a miss. Same rule and same reason as the transport
// authority's: only "I think this organization has none" is worth the round trip, and a read that fails is
// not an absence.
//
// Called with a.mu held.
func (a *tenantDeviceAuthority) refreshedRowLocked(key string) (*storedTenantDeviceCA, bool, error) {
	if err := a.refreshLocked(); err != nil {
		return nil, false, err
	}
	row, ok := a.cas[key]
	return row, ok, nil
}

func (a *tenantDeviceAuthority) refreshLocked() error {
	if a.reload == nil {
		return nil
	}
	rows, raw, err := readAuthoritySnapshot(a.reload, deviceAuthorityRowKey, a.cas)
	if err != nil {
		return err
	}
	// Any read may first discover another CP's write. Count it here, rather
	// than only in Generation, so an earlier issuance read cannot hide a change
	// to the managed-organization list carried in the config bundle.
	if string(encodeAuthoritySnapshot(a.cas)) != string(encodeAuthoritySnapshot(rows)) {
		a.generation++
	}
	a.cas, a.snapshot = rows, raw
	return nil
}

func deviceAuthorityRowKey(row *storedTenantDeviceCA) string {
	return strings.ToLower(strings.TrimSpace(row.TenantID))
}
