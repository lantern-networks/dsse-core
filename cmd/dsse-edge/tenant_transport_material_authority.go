package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/transportca"
)

// tenant_transport_material_authority.go — the control plane holds each organization's transport CA and hands
// SHORT-LIVED server material to the Edges that need it.
//
// ★★★ WHY THIS EXISTS (decided 2026-08-20, after measuring). The Edge fleet is shared across organizations and
// grows and shrinks with load, so an Edge can appear that nobody prepared. Roadmap D gave each organization
// its own transport certificate, announced by name — and every one of those certificates was a FILE somebody
// had placed on that host. Measured: this repository's own scale-out definition carried none of them, and a
// node without them either refuses devices or, worse, rewrites what the fleet has promised.
//
// Handing the long-lived CA key to every machine that might appear is the wrong fix — it is a customer's key
// on hosts that come and go. So the authority stays here and issues material that EXPIRES:
//
//	customer's authority (long-lived, here or in an HSM)
//	  └─ per-Edge server certificate + key, valid for hours   ← what an Edge is given
//
// The blast radius of one Edge is then one organization, on one node, for a few hours — and a node that
// disappears takes nothing durable with it.
//
// ★ THE NAME IS PART OF THE MATERIAL, not something the Edge decides. Devices are told which name to send;
// the certificate they meet has to carry exactly that name, and the only way to keep those two together is
// for whoever mints the certificate to also own the name.
// restart-durability: cp_durable — every authority is written through the persister the moment it is created
// (a CP state blob, Postgres-backed on a real control plane), and EnsureCA refuses to hand back an authority
// it could not persist. An authority that did not survive a restart would be regenerated, and every device of
// that organization would be told to adopt a new anchor while the old one became un-issuable — which this lab
// has already done once by hand, by minting a CA in a temporary directory and losing the key.
//
// populated-by: assertion — the process reloads every authority from that blob at start-up (newTenantTransportAuthority)
// and only mints one for an organization it finds none for. Nothing here is rebuilt from what Edges happen to
// ask for; a request for an unknown organization is refused rather than answered by creating something.
type tenantTransportAuthority struct {
	snapshot []byte

	mu  sync.Mutex
	cas map[string]*storedTenantTransportCA
	// generation changes whenever the set of authorities does.
	//
	// ★★★ A ROTATION THAT NOBODY NOTICES FOR EIGHT HOURS IS NOT A ROTATION (2026-08-20, measured on the lab the
	// minute the act existed). Edges refresh their material at two thirds of its life — twelve hours, so eight
	// — and until then a rotation an operator performed has reached nobody: the incoming authority is not
	// announced, no device is asked to adopt it, and there is no signal that anything is pending. The act
	// succeeded and the fleet was unchanged.
	//
	// So the Edges can ask a cheap question often instead of an expensive one rarely: "has this changed since
	// generation N". Minting material on every poll would sign a certificate a minute per organization.
	generation uint64
	persist    func([]byte) error
	// reload re-reads the SHARED store. See refreshedRowLocked for why an absence must go through it.
	reload func() ([]byte, error)
	now    func() time.Time
}

// authorityNotAskedPhrase is the wording an Edge matches on. The refusal crosses the wire as a STRING — the
// material answer carries `refused: ["tenant_x: …"]` — so the two sides agree through this constant rather
// than through two copies of a sentence.
const authorityNotAskedPhrase = "could not read the deployment's transport authorities"

// errAuthorityNotAsked is returned when this node could not find out whether an organization has an authority,
// as opposed to finding out that it has none. The two must never be the same answer — see refreshedRowLocked.
var errAuthorityNotAsked = errors.New("this control plane " + authorityNotAskedPhrase + ", so it cannot say " +
	"whether this organization has one; it refused rather than answering that it has none")

// transportAuthorityRefusalIsNotEvidence reports whether a refusal an Edge was handed means "I could not find
// out" rather than "there is none". Only the second is something to act on.
func transportAuthorityRefusalIsNotEvidence(reason string) bool {
	return strings.Contains(strings.ToLower(reason), authorityNotAskedPhrase)
}

// authorityCouldNotBeAsked reports whether an error means "I could not find out", so a caller can hold instead
// of acting on an absence that was never established.
func authorityCouldNotBeAsked(err error) bool { return errors.Is(err, errAuthorityNotAsked) }

// Generation is what an Edge compares against to decide whether to fetch material at all.
//
// ★ NEVER ZERO FOR A LOADED STORE (2026-08-20, measured: every Edge was minting material a minute). Loading
// authorities from disk does not go through saveLocked, so the generation stayed at zero — and zero is what an
// Edge that has never asked sends, which has to mean "give me everything". The two were indistinguishable, so
// the cheap answer was never given and the poll cost a signature per organization per minute per node.
func (a *tenantTransportAuthority) Generation() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	return a.generation + 1
}

// storedTenantTransportCA is one organization's authority, as it is persisted.
//
// ★ THE PRIVATE KEY IS HERE, AND THAT IS THE POINT OF PUTTING IT ON THE CONTROL PLANE RATHER THAN ON EVERY
// EDGE. A production deployment puts it in an HSM instead and keeps only the handle; the shape of this file
// does not change when it does, because everything below asks the CA to sign rather than reading the key.
type storedTenantTransportCA struct {
	TenantID   string `json:"tenant_id"`
	ServerName string `json:"server_name"`
	CACertPEM  string `json:"ca_cert_pem"`
	CAKeyPEM   string `json:"ca_key_pem"`
	CreatedAt  string `json:"created_at"`
	// PreviousServerName is a name this organization is moving OFF, still carried by the certificate so the
	// devices that have not adopted the new one are not locked out.
	//
	// ★★★ WHY A NAME EVER NEEDS TO CHANGE (2026-08-22, measured). An organization created before
	// organization_id_is_not_a_name.go took its transport name from its id, and those ids are the customer's
	// own word: tenant_northwind is served as "northwind.dsse.invalid". SNI is plaintext, and this deployment
	// strips ECH, so every observer on the path between a device and the Edge is told which company that
	// laptop belongs to. New organizations do not have this — their ids are issued and unguessable, so the
	// derived name is too — which leaves exactly the organizations that predate it.
	//
	// ★ AND CHANGING IT WITHOUT AN OVERLAP IS AN OUTAGE. transportTenantCertificates is keyed BY NAME: the
	// moment the certificate stops carrying the old one, every device still sending it fails the handshake —
	// including the laptop that was switched off while the new name was being announced. So the certificate
	// carries both, the bundle announces the new one, and the old is dropped only when every device has said
	// it is sending the new one. That evidence is transport_server_name_sent, which this deployment could not
	// read until the same day this was written.
	PreviousServerName string `json:"previous_server_name,omitempty"`
	RenamedAt          string `json:"renamed_at,omitempty"`
	// Incoming is the authority this organization is MOVING TO, held beside the one in force.
	//
	// ★★★ THE OVERLAP MACHINERY HAD NOTHING THAT STARTED IT (found 2026-08-20 by trying to write a rotation
	// scenario). Announce-alongside, promote-on-evidence and withdraw-the-previous were all built and proven —
	// and the only way to give an organization a new authority was to destroy the old one and create another,
	// which is the order that stranded a device this morning. An operator must never be asked to perform that.
	//
	// So a rotation adds. Issuance stays on the authority in force, the incoming one is handed to Edges as a
	// SECOND material, and every Edge then does what it already does with material issued under an authority it
	// does not serve: announce it alongside, wait for its organization's devices to be measured holding it, and
	// only then start serving it. Nothing new decides anything — the decision stays where the evidence is.
	Incoming *storedTenantTransportCA `json:"incoming,omitempty"`
}

type tenantTransportMaterial struct {
	// SuccessorAnchorSHA256 names the incoming authority in this same CP snapshot.
	// An Edge already serving it must not stage this outgoing material as a new rotation.
	SuccessorAnchorSHA256 string `json:"successor_anchor_sha256,omitempty"`
	TenantID              string `json:"tenant_id"`
	ServerName            string `json:"server_name"`
	CertPEM               string `json:"cert_pem"`
	KeyPEM                string `json:"key_pem"`
	AnchorPEM             string `json:"anchor_pem"`
	NotAfter              string `json:"not_after"`
	// PreviousServerName is the name this organization is moving OFF, carried so an Edge can say which devices
	// have not adopted the new one yet. The certificate answers to both; this is how the node KNOWS that, so
	// the readiness answer comes from the material rather than from a certificate parse.
	PreviousServerName string `json:"previous_server_name,omitempty"`
}

func newTenantTransportAuthority(seed []byte, persist func([]byte) error, now func() time.Time) *tenantTransportAuthority {
	return newTenantTransportAuthorityWithReload(seed, persist, nil, now)
}

// newTenantTransportAuthorityWithReload is the same, plus the way back to the SHARED store. Without it this
// node can only ever answer from the snapshot it loaded — see refreshedRowLocked for what that cost.
func newTenantTransportAuthorityWithReload(seed []byte, persist func([]byte) error, reload func() ([]byte, error),
	now func() time.Time) *tenantTransportAuthority {
	a := &tenantTransportAuthority{cas: map[string]*storedTenantTransportCA{}, persist: persist, reload: reload, now: now}
	if a.now == nil {
		a.now = time.Now
	}
	if len(seed) > 0 {
		var rows []storedTenantTransportCA
		if err := json.Unmarshal(seed, &rows); err == nil {
			for i := range rows {
				row := rows[i]
				a.cas[strings.ToLower(strings.TrimSpace(row.TenantID))] = &row
			}
		}
	}
	a.snapshot = encodeAuthoritySnapshot(a.cas)
	return a
}

// saveLocked persists and bumps the generation: every change to the set of authorities goes through here, so
// there is one place that can forget to say something changed rather than four.
func (a *tenantTransportAuthority) saveLocked() error {
	rows := make([]*storedTenantTransportCA, 0, len(a.cas))
	for _, row := range a.cas {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TenantID < rows[j].TenantID })
	data, err := json.Marshal(rows)
	if err == nil && a.persist != nil {
		err = a.persist(data)
	}
	if err != nil {
		a.cas = restoreAuthoritySnapshot(a.snapshot, transportAuthorityRowKey)
		return err
	}
	a.snapshot = data
	a.generation++
	return nil
}

// EnsureCA returns this organization's transport authority, creating it on first use.
//
// ★ CREATED ONCE AND KEPT. An authority regenerated on restart would hand every device a new anchor to adopt
// on every restart — which is the "adopted and un-issuable" state the lab already reached once by minting a
// CA in a temporary directory and losing the key.
func (a *tenantTransportAuthority) EnsureCA(tenant, serverName string) (*storedTenantTransportCA, error) {
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
	name := strings.ToLower(strings.TrimSpace(serverName))
	if name == "" {
		return nil, fmt.Errorf("the name this organization's agents will send must be given when its authority is created")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := a.now().UTC()
	ca, err := transportca.NewCA(pkix.Name{CommonName: name + " Transport CA"}, caKey, now.Add(-time.Hour), now.AddDate(10, 0, 0))
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, err
	}
	row := &storedTenantTransportCA{
		TenantID:   key,
		ServerName: name,
		CACertPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})),
		CAKeyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		CreatedAt:  now.Format(time.RFC3339),
	}
	a.cas[key] = row
	if err := a.saveLocked(); err != nil {
		delete(a.cas, key)
		return nil, fmt.Errorf("an authority that is not persisted would be regenerated on the next restart, and "+
			"every device would be asked to adopt a new anchor: %w", err)
	}
	return row, nil
}

// RotateCA gives an organization a SECOND authority, beside the one in force.
//
// It refuses when one is already in flight: two incoming authorities at once would ask every device to hold
// three anchors and would leave nobody able to say which one the fleet is moving to. Finish the rotation
// (every device measured, every Edge serving it) and retire the previous one first.
func (a *tenantTransportAuthority) RotateCA(tenant string) (*storedTenantTransportCA, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.cas[key]
	if !ok {
		return nil, fmt.Errorf("%q has no transport authority to rotate", tenant)
	}
	if row.Incoming != nil {
		return nil, fmt.Errorf("%q is already moving to a new authority (created %s) — finish that rotation and "+
			"retire the previous authority before starting another", tenant, row.Incoming.CreatedAt)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := a.now().UTC()
	ca, err := transportca.NewCA(pkix.Name{CommonName: row.ServerName + " Transport CA"}, caKey,
		now.Add(-time.Hour), now.AddDate(10, 0, 0))
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, err
	}
	row.Incoming = &storedTenantTransportCA{
		TenantID:   key,
		ServerName: row.ServerName,
		CACertPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})),
		CAKeyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		CreatedAt:  now.Format(time.RFC3339),
	}
	if err := a.saveLocked(); err != nil {
		row.Incoming = nil
		return nil, fmt.Errorf("an incoming authority that is not persisted would vanish on the next restart "+
			"while devices were being asked to adopt it: %w", err)
	}
	return row.Incoming, nil
}

// AbandonRotation gives up on a transport CA rotation: the organization stays on the authority it is already
// serving, and the incoming one stops being announced and stops being minted from.
//
// ★★★ EVERY MOVEMENT NEEDS A WAY BACK, AND TWO OF THE THREE TIERS DID NOT HAVE ONE (2026-08-22, found by
// reading the roadmap against the tree). Interception could WithdrawIncoming and the transport RENAME could
// AbandonRename; a transport CA rotation and a device CA rotation could only be ENDED by retiring the
// previous authority — the destructive half. So an operator who staged the wrong CA, or staged one and then
// found the key had been handled badly, had a choice between leaving it announced for ever and completing a
// rotation they no longer wanted.
//
// ★ AND THIS IS THE SAFE DIRECTION, WHICH IS WHY IT DIFFERS FROM AbandonRename. A rename cannot simply drop
// the new name, because devices ADOPT a name and dial it; abandoning there had to turn the movement around.
// An incoming CA is only ever ANNOUNCED — devices add it to the set they will accept and nothing is served
// under it until a promotion — so dropping it takes nothing away that any device is relying on. A device that
// has already adopted it simply carries an anchor nobody signs with, which costs it nothing and goes away on
// its next bundle.
func (a *tenantTransportAuthority) AbandonRotation(tenant string) (*storedTenantTransportCA, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.cas[key]
	if !ok {
		return nil, fmt.Errorf("%q has no transport authority", tenant)
	}
	if row.Incoming == nil {
		return nil, fmt.Errorf("%q is not moving to a new authority, so there is nothing to abandon", tenant)
	}
	abandoned := row.Incoming
	row.Incoming = nil
	if err := a.saveLocked(); err != nil {
		row.Incoming = abandoned
		return nil, fmt.Errorf("abandoning a rotation that is not persisted would resume it at the next "+
			"restart: %w", err)
	}
	return row, nil
}

// RetireePrevious ends a rotation: the incoming authority becomes the only one.
//
// ★ IT IS AN ACT, NOT A SIDE EFFECT, and it is the destructive half. The Edges decide when to START SERVING
// the incoming authority, because they hold the evidence about devices; this decides when the PREVIOUS one
// stops existing, which no Edge can know on its own. Doing it too early takes out any Edge that has not
// promoted yet — which is the failure this whole shape exists to avoid, one level up.
func (a *tenantTransportAuthority) RetirePrevious(tenant string) (*storedTenantTransportCA, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.cas[key]
	if !ok {
		return nil, fmt.Errorf("%q has no transport authority", tenant)
	}
	if row.Incoming == nil {
		return nil, fmt.Errorf("%q is not moving to a new authority, so there is no previous one to retire", tenant)
	}
	promoted := row.Incoming
	promoted.Incoming = nil
	a.cas[key] = promoted
	if err := a.saveLocked(); err != nil {
		a.cas[key] = row
		return nil, fmt.Errorf("retiring an authority that is not persisted would bring it back on the next "+
			"restart: %w", err)
	}
	return promoted, nil
}

// IssueFor mints short-lived server material for one Edge, from this organization's authority.
func (a *tenantTransportAuthority) IssueFor(tenant, edgeID string, ttl time.Duration) (tenantTransportMaterial, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	row, ok, rerr := a.refreshedRowLocked(key)
	row = copyAuthority(row)
	a.mu.Unlock()
	if rerr != nil {
		return tenantTransportMaterial{}, fmt.Errorf("%w (%v)", errAuthorityNotAsked, rerr)
	}
	if !ok {
		return tenantTransportMaterial{}, fmt.Errorf("no transport authority for %q — an Edge cannot be given "+
			"material for an organization the control plane does not hold an authority for", tenant)
	}
	if ttl <= 0 {
		return tenantTransportMaterial{}, fmt.Errorf("material handed to an Edge must expire, so a lifetime is required")
	}
	return issueFromStoredCA(row, ttl, a.now)
}

// refreshedRowLocked reads a complete current snapshot, including cache hits. Caller holds a.mu.
func (a *tenantTransportAuthority) refreshedRowLocked(key string) (*storedTenantTransportCA, bool, error) {
	if err := a.refreshLocked(); err != nil {
		return nil, false, err
	}
	row, ok := a.cas[key]
	return row, ok, nil
}

// issueFromStoredCA is the one place a leaf is minted, so the authority in force and the one an organization is
// moving to cannot come to be issued differently — the second copy of an issuance path is where two answers to
// "what does this organization's certificate look like" start.
func issueFromStoredCA(row *storedTenantTransportCA, ttl time.Duration, clock func() time.Time) (tenantTransportMaterial, error) {
	caCert, err := parseFirstCertificatePEM([]byte(row.CACertPEM))
	if err != nil {
		return tenantTransportMaterial{}, err
	}
	caKey, err := parseECKeyPEM([]byte(row.CAKeyPEM))
	if err != nil {
		return tenantTransportMaterial{}, err
	}
	ca := &transportca.CA{Cert: caCert, Key: caKey}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tenantTransportMaterial{}, err
	}
	now := clock().UTC()
	// ★ AND THE RECOVERY NAME FOR THIS ORGANIZATION (2026-08-20). An organization on its own authority stops
	// trusting the deployment-wide certificate, which is what answers the deployment-wide recovery name — so
	// after roadmap D its devices could verify their transport and NOT the last resort they are pointed at.
	// Measured on the lab the night it first completed. The name is carried by the same certificate their
	// transport already uses, so nothing new has to be trusted for recovery to work.
	leaf, err := ca.IssueServerLeaf(leafKey, transportca.LeafRequest{
		Subject: pkix.Name{CommonName: row.ServerName},
		// ★ The organization's own name, plus the two folded paths a device reaches by name: recovery (an
		// expired certificate) and enrolment (no certificate at all). A fold that offers a name the
		// certificate does not carry is the defect the enrolment fold already paid for once.
		DNSNames:  transportLeafNames(row),
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(ttl),
	})
	if err != nil {
		return tenantTransportMaterial{}, err
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return tenantTransportMaterial{}, err
	}
	return tenantTransportMaterial{
		TenantID:           row.TenantID,
		ServerName:         row.ServerName,
		PreviousServerName: row.PreviousServerName,
		CertPEM:            string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),
		KeyPEM:             string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})),
		AnchorPEM:          row.CACertPEM,
		NotAfter:           leaf.NotAfter.UTC().Format(time.RFC3339),
	}, nil
}

// IssueAllFor is IssueFor plus, when a rotation is in flight, the material for the authority this organization
// is moving to.
//
// ★ THE SECOND MATERIAL IS WHAT MAKES THE OVERLAP HAPPEN, AND IT IS DELIBERATELY A FULL MATERIAL rather than a
// bare anchor. An Edge that is handed only an anchor could announce it and never serve it; an Edge that is
// handed the certificate and key can start serving the moment its organization's devices have been measured
// holding it, which is the decision it already makes. Handing less would have moved that decision to the
// control plane, where the evidence is not.
func (a *tenantTransportAuthority) IssueAllFor(tenant, edgeID string, ttl time.Duration) ([]tenantTransportMaterial, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("material handed to an Edge must expire, so a lifetime is required")
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	row, ok, err := a.refreshedRowLocked(key)
	row = copyAuthority(row)
	a.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", errAuthorityNotAsked, err)
	}
	if !ok {
		return nil, fmt.Errorf("no transport authority for %q", tenant)
	}
	current, err := issueFromStoredCA(row, ttl, a.now)
	if err != nil {
		return nil, err
	}
	out := []tenantTransportMaterial{current}

	incoming := (*storedTenantTransportCA)(nil)
	if ok && row.Incoming != nil {
		copyOf := *row.Incoming
		// ★★★ THE NAME BELONGS TO THE ORGANIZATION, NOT TO AN AUTHORITY (2026-08-22, measured on
		// tenant_northwind — its rename completed on the control plane and the Edge went on serving the old
		// name for ever).
		//
		// RotateCA copies the name into the incoming authority when it stages it. A rename afterwards changes
		// only the outer row, so the two authorities end up carrying DIFFERENT names — and which name a
		// device meets then depends on which authority this node happens to be serving, which is internal
		// state no operator can see. Measured: the control plane read server_name=st3zohor…, renaming=false,
		// and the certificate on the wire named northwind.dsse.invalid and nothing else, with no way to
		// finish because the organization has no devices to measure a promotion with.
		//
		// A rename and a rotation are two independent movements — that is why they are two acts. Minting the
		// incoming leaf from the OUTER row's names is what keeps them independent.
		copyOf.ServerName = row.ServerName
		copyOf.PreviousServerName = row.PreviousServerName
		incoming = &copyOf
	}
	if incoming == nil {
		return out, nil
	}
	mat, err := issueFromStoredCA(incoming, ttl, a.now)
	if err != nil {
		// The rotation is in flight and this Edge cannot be given the incoming material. Serving the current
		// one is still correct, so this is reported rather than fatal — but it means this node will not
		// announce what the organization is moving to, and the rotation will not finish through it.
		return out, fmt.Errorf("the incoming authority for %q could not be issued to %q (%w) — this Edge will "+
			"keep serving and announcing the authority in force, and the rotation cannot complete through it",
			tenant, edgeID, err)
	}
	out[0].SuccessorAnchorSHA256 = fingerprintOfFirstCert(mat.AnchorPEM)
	return append(out, mat), nil
}

// StateFor is what a screen needs to say where an organization's authority stands, without inferring it.
//
// ★ THE SCREEN MUST NOT DEDUCE THIS FROM THE ANCHOR COUNT. Whether a rotation is in flight is a fact the
// control plane holds; an Edge's anchor count says something else — how far the fleet has got — and after a
// promotion the two look identical while the previous authority still exists and still needs retiring.
// AnchorsFor is the CA (or CAs, during a rotation) that sign the certificate this organization's devices are
// served when they present its own name.
//
// ★★★ THE PROFILE TOLD A DEVICE TO PRESENT A NAME AND GAVE IT AN ANCHOR THAT CANNOT VERIFY IT (2026-08-29,
// measured on a real Mac). An organization with its own address on the Edges is served a certificate issued by
// its OWN transport CA — `CN=<name> Transport CA` — which the deployment root does not sign. A device handed
// the deployment anchor and told to dial the organization's name gets "unable to get local issuer
// certificate", and the enrolment that follows fails with a network error that says nothing about why.
//
// Both are returned during a rotation, for the same reason both are served: a device must be able to verify
// whichever one it is handed while the fleet moves.
func (a *tenantTransportAuthority) AnchorsFor(tenant string) []string {
	if a == nil {
		return nil
	}
	// ★★★ SAME RULE AS Row ON THE OTHER TWO AUTHORITIES (2026-08-31). These anchors are what a device
	// verifies its own organization's door against; a profile issued without them from a control plane that
	// merely had not received the write installs a device that cannot check what it is served.
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	row := a.cas[key]
	if row == nil {
		if refreshed, ok, rerr := a.refreshedRowLocked(key); rerr == nil && ok {
			row = refreshed
		}
	}
	if row == nil {
		return nil
	}
	out := []string{}
	if pem := strings.TrimSpace(row.CACertPEM); pem != "" {
		out = append(out, pem)
	}
	if row.Incoming != nil {
		if pem := strings.TrimSpace(row.Incoming.CACertPEM); pem != "" && pem != out[0] {
			out = append(out, pem)
		}
	}
	return out
}

// Row hands back this organization's stored transport authority so a read can NAME the certificate rather than
// only report that one exists.
//
// ★★★ THE ONE AUTHORITY AN OPERATOR REPLACES MOST OFTEN WAS THE ONE THE SCREEN COULD NOT NAME (2026-09-05,
// read off a live deployment's Certificates page). Three of the four cards there lead with the fact — "Now:",
// "In use:", "Issuing now:" — and the transport card had a "Replace it" button over prose and nothing else,
// because GET /admin/tenant-transport-authority answered with a server name and no certificate at all. Its two
// siblings both return a summary (device: signing; interception: root + issuing). So the operator was offered
// the act without being shown its object, and could not check what the fleet is actually on — which the
// deployment knows, because every device reports pinned_transport_ca_sha256.
//
// Same refresh-from-the-store fallback as StateFor: a control plane that has not yet seen the write must not
// answer "no certificate" for an organization that has one.
func (a *tenantTransportAuthority) Row(tenant string) (*storedTenantTransportCA, bool) {
	if a == nil {
		return nil, false
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	row, ok := a.cas[key]
	if !ok || row == nil {
		var rerr error
		if row, ok, rerr = a.refreshedRowLocked(key); rerr != nil || !ok || row == nil {
			return nil, false
		}
	}
	return copyAuthority(row), true
}

func (a *tenantTransportAuthority) StateFor(tenant string) (serverName, inForceSince, incomingSince string, rotating bool, known bool) {
	if a == nil {
		return "", "", "", false, false
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	row, ok := a.cas[key]
	if !ok {
		// ★ AND SO DOES THE NAME. This is where a profile gets organization.transport_server_name — the door
		// the device is told to dial and to expect a certificate for. Answering "unknown" from a stale
		// snapshot sends the device to the deployment-wide name instead of its organization's own.
		var rerr error
		if row, ok, rerr = a.refreshedRowLocked(key); rerr != nil || !ok || row == nil {
			return "", "", "", false, false
		}
	}
	if row.Incoming != nil {
		return row.ServerName, row.CreatedAt, row.Incoming.CreatedAt, true, true
	}
	return row.ServerName, row.CreatedAt, "", false, true
}

// RenameInFlight answers whether this organization is being MOVED OFF a name, and which one.
//
// ★★ A TRANSPORT AUTHORITY CAN BE IN TWO MOVEMENTS AT ONCE AND THE READ ONLY SHOWED ONE (2026-08-22, found by
// needing it). StateFor reports the CA rotation — rotating, incoming_since — and said nothing about a rename,
// so an organization whose certificate was carrying two name families read back exactly like one that was
// not. A screen offering "retire the previous name" had nothing to tell it a rename existed, and an operator
// checking their own work saw only the new name and no sign that the old one was still being served.
//
// Separate from StateFor because it is a separate movement, with a separate readiness answer (an Edge's
// GET /admin/transport-name-rename) and a separate way back (AbandonRename).
func (a *tenantTransportAuthority) RenameInFlight(tenant string) (previous, since string) {
	if a == nil {
		return "", ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	row, ok := a.cas[strings.ToLower(strings.TrimSpace(tenant))]
	if !ok {
		return "", ""
	}
	return row.PreviousServerName, row.RenamedAt
}

// Organizations lists the organizations this control plane can issue transport material for.
func (a *tenantTransportAuthority) Organizations() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	out := make([]string, 0, len(a.cas))
	for tenant := range a.cas {
		out = append(out, tenant)
	}
	sort.Strings(out)
	return out
}

// certificatesInPEM returns every certificate in a PEM blob, skipping anything that is not one. Used where a
// field carries a SET — the anchors an organization's devices may present during a rotation — and reading only
// the first would silently mean "the one in force", which is the half that is about to be retired.
func certificatesInPEM(data []byte) []*x509.Certificate {
	out := []*x509.Certificate{}
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, cert)
		}
	}
}

func parseFirstCertificatePEM(data []byte) (*x509.Certificate, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no certificate found")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// parseECKeyPEM reads an EC private key in either encoding a real key arrives in.
//
// ★★ IT ONLY UNDERSTOOD SEC1, AND THE ROUTE THAT NEEDS IT IS THE ONE A CUSTOMER USES (2026-08-21, hit while
// moving an organization's interception authority onto the control plane). POST
// /admin/tenant-interception-authority exists so an organization can hand over an issuing CA it signed under
// its own root — and a key generated by any current version of OpenSSL is PKCS#8 ("BEGIN PRIVATE KEY"), which
// this refused with an error naming a Go function. The customer-facing door for the whole
// customer-holds-the-root design rejected the default output of the tool a customer would use.
func parseECKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	// ★★ AND THE KEY IS NOT ALWAYS THE FIRST BLOCK (2026-08-21, hit by running the migration this route
	// exists for). `openssl ecparam -genkey -name prime256v1 -out key.pem` — one of the most common ways to
	// make an EC key — writes TWO blocks, EC PARAMETERS first and the key second. Reading only the first got
	//
	//	asn1: structure error: tags don't match (16 vs …) pkcs8 @2
	//
	// which tells a customer nothing except that their key is bad, when it is not. Same lesson as the PKCS#8
	// case below: this is the door a customer hands their own material through, so it has to accept what the
	// tool they used actually produces.
	block := firstPrivateKeyPEMBlock(data)
	if block == nil {
		return nil, fmt.Errorf("no private key found in this PEM (an EC PARAMETERS block on its own is not a " +
			"key — send the file that also contains BEGIN EC PRIVATE KEY or BEGIN PRIVATE KEY)")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	// PKCS#8 ("BEGIN PRIVATE KEY"), the default for openssl genpkey and for `openssl ecparam -genkey` on
	// current releases.
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("this is not an EC private key this deployment can read; both SEC1 "+
			"(\"BEGIN EC PRIVATE KEY\") and PKCS#8 (\"BEGIN PRIVATE KEY\") are accepted: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the key is a %T, and this authority signs with an EC key — an RSA or Ed25519 "+
			"key cannot be used here", parsed)
	}
	return key, nil
}

// CountForTenant and RemoveTenant are the two an erasure needs. An organization's transport authority is that
// organization's — if they ask to be erased, the CA that signs their Edge's certificate goes with them.
//
// ★ A STORE NOBODY COUNTS ANSWERS "complete" WHATEVER IT STILL HOLDS. That is how a customer's Named Networks
// survived an erasure that reported remaining.total = 0, and the gate that caught this one exists because of
// it.
func (a *tenantTransportAuthority) CountForTenant(tenant string) int {
	// Nil-safe: the footprint helper evaluates every store's count in one call, so a node that holds no
	// authorities must answer rather than crash.
	if a == nil {
		return 0
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.refreshLocked() // Metadata retains the last committed view on a read error; issuance refuses.
	if _, ok := a.cas[key]; ok {
		return 1
	}
	return 0
}

func (a *tenantTransportAuthority) RemoveTenant(tenant string) int {
	// Nil-safe: the footprint helper evaluates every store's count in one call, so a node that holds no
	// authorities must answer rather than crash.
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
		// Put it back rather than report a removal that did not survive: an erasure that says "done" over a
		// row still on disk is the failure this whole family is about.
		return 0
	}
	return 1
}

// registerTenantTransportMaterialFlags declares the three flags this mechanism needs.
//
// ★ THEY LIVE HERE RATHER THAN IN main.go because of the decomposition ratchet: a new flag in main.go fails
// the build on purpose, so the file that grew past being readable cannot grow again.
func registerTenantTransportMaterialFlags() (store *string, ttl *time.Duration, fromCP *bool) {
	store = flag.String("tenant-transport-authority-store", "", "control plane: durable store for each organization's TRANSPORT CA (\"postgres\", \"postgres+import:FILE\", or a file path). Empty = this node issues no per-organization transport material, and Edges cannot assemble themselves")
	ttl = flag.Duration("tenant-transport-material-ttl", 12*time.Hour, "control plane: how long the per-organization server material handed to an Edge is valid. Short on purpose: the fleet is autoscaled, so a node that disappears must take nothing durable with it")
	fromCP = flag.Bool("tenant-transport-material-from-cp", false, "edge: fetch each organization's transport certificate from the control plane at start-up and keep it fresh, instead of reading files somebody placed on this host. Uses the audit-ingest endpoint, token, CA and client identity")
	return store, ttl, fromCP
}

// firstPrivateKeyPEMBlock walks every PEM block and returns the first that could be a private key, skipping
// the parameter and certificate blocks that real-world key files are shipped beside. See parseECKeyPEM.
func firstPrivateKeyPEMBlock(data []byte) *pem.Block {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if strings.Contains(strings.ToUpper(block.Type), "PRIVATE KEY") {
			return block
		}
	}
}

// transportLeafNames is every name this organization's certificate must answer to: its own, the two folded
// paths reached BY name (recovery for an expired certificate, enrolment for no certificate at all), and —
// while a rename is in flight — the same three for the name it is moving off.
//
// ★ THE OLD SET IS CARRIED, NOT REPLACED. transportTenantCertificates is keyed by name, so a certificate that
// stops carrying the previous one locks out every device still sending it. See PreviousServerName.
func transportLeafNames(row *storedTenantTransportCA) []string {
	if row == nil {
		return nil
	}
	out := []string{row.ServerName, organizationRecoveryName(row.ServerName),
		organizationEnrolmentName(row.ServerName)}
	if prev := strings.ToLower(strings.TrimSpace(row.PreviousServerName)); prev != "" && prev != row.ServerName {
		out = append(out, prev, organizationRecoveryName(prev), organizationEnrolmentName(prev))
	}
	seen := map[string]bool{}
	deduped := out[:0]
	for _, n := range out {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		deduped = append(deduped, n)
	}
	return deduped
}

// RenameServerName starts a rename: the organization is served under a new name, and keeps answering to the
// old one until RetirePreviousServerName.
//
// ★ ONE AT A TIME, for the reason every other overlap here gives: two previous names would leave devices
// spread across three, and "has everybody moved?" would have no single answer.
func (a *tenantTransportAuthority) RenameServerName(tenant, newName string) (*storedTenantTransportCA, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	name := strings.ToLower(strings.TrimSpace(newName))
	if name == "" {
		return nil, fmt.Errorf("a new server name is required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.cas[key]
	if !ok {
		return nil, fmt.Errorf("%q has no transport authority to rename", tenant)
	}
	if strings.EqualFold(row.ServerName, name) {
		return nil, fmt.Errorf("%q is already served as %q", tenant, name)
	}
	if strings.TrimSpace(row.PreviousServerName) != "" {
		return nil, fmt.Errorf("%q is already moving off %q (since %s) — finish that rename and retire the "+
			"previous name before starting another; devices cannot be asked to adopt two at once",
			tenant, row.PreviousServerName, row.RenamedAt)
	}
	before, beforeAt := row.ServerName, row.RenamedAt
	row.PreviousServerName, row.ServerName = row.ServerName, name
	row.RenamedAt = a.now().UTC().Format(time.RFC3339)
	if err := a.saveLocked(); err != nil {
		row.ServerName, row.PreviousServerName, row.RenamedAt = before, "", beforeAt
		return nil, fmt.Errorf("a rename that is not persisted would come back undone at the next restart, "+
			"while devices were being asked to adopt the new name: %w", err)
	}
	return row, nil
}

// AbandonRename gives up on a rename by turning it around: the organization goes back to the name it was
// being moved off, and the one it was being moved TO becomes the previous name. The certificate keeps
// carrying both, so nothing is dropped by this act at all.
//
// ★ THE WAY BACK MATTERS AS MUCH AS THE WAY FORWARD, and this was missing when the rename was first written
// (2026-08-22, found by needing it). Without it a rename could only be ENDED by retiring the old name, which
// is the one act that fails the handshake for everything that has not moved.
//
// ★★★ AND THE FIRST VERSION OF THE WAY BACK BROKE THE FLEET IT WAS MEANT TO SAVE (2026-08-22, measured — it
// took this Mac off the network). It CLEARED the rename instead of turning it around, so the new name stopped
// being served the moment it was abandoned. Its own note said a device that had already adopted the new name
// "falls back on its next trust bundle" — which is false, and false in the worst possible way: THE BUNDLE IS
// FETCHED OVER THE TUNNEL THAT JUST BROKE. The device sent a name nothing served, got the deployment-wide
// certificate, refused it against its own anchor, and had no path left to be told anything. Recovered only by
// re-creating the name from the control plane.
//
// So the rule the whole transport plane already followed, stated once: A NAME IS NEVER DROPPED BY THE ACT
// THAT STOPS USING IT. It is announced, adoption is measured, and only then is it retired — and abandoning is
// simply a rename in the other direction, subject to the same gate. RetirePreviousServerName remains the only
// act that drops a name, and it is the only one that needs the readiness answer.
func (a *tenantTransportAuthority) AbandonRename(tenant string) (*storedTenantTransportCA, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.cas[key]
	if !ok {
		return nil, fmt.Errorf("%q has no transport authority", tenant)
	}
	if strings.TrimSpace(row.PreviousServerName) == "" {
		return nil, fmt.Errorf("%q is not being renamed, so there is nothing to abandon", tenant)
	}
	was, back := row.ServerName, row.PreviousServerName
	row.ServerName, row.PreviousServerName = back, was
	row.RenamedAt = a.now().UTC().Format(time.RFC3339)
	if err := a.saveLocked(); err != nil {
		row.ServerName, row.PreviousServerName = was, back
		return nil, fmt.Errorf("abandoning a rename that is not persisted would resume it at the next "+
			"restart: %w", err)
	}
	return row, nil
}

// RetirePreviousServerName ends a rename: the certificate stops carrying the old name.
//
// ★★★ THE DESTRUCTIVE HALF. Every device still sending the previous name fails the handshake from the moment
// the fleet picks this up — including the one that was switched off throughout, which is the one nobody was
// watching. The evidence is what devices report SENDING; this is the act.
func (a *tenantTransportAuthority) RetirePreviousServerName(tenant string) (*storedTenantTransportCA, error) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	row, ok := a.cas[key]
	if !ok {
		return nil, fmt.Errorf("%q has no transport authority", tenant)
	}
	if strings.TrimSpace(row.PreviousServerName) == "" {
		return nil, fmt.Errorf("%q is not moving off another name, so there is no previous one to retire", tenant)
	}
	before := row.PreviousServerName
	row.PreviousServerName = ""
	if err := a.saveLocked(); err != nil {
		row.PreviousServerName = before
		return nil, fmt.Errorf("retiring a name that is not persisted would bring it back at the next "+
			"restart, so the fleet would disagree about which names it answers to: %w", err)
	}
	return row, nil
}

// GenerationParts is what this authority IS, for the fingerprint an Edge compares against. Everything that
// changes what an Edge would be handed must appear here — the name it serves, the name it is moving off, the
// authority in force and the one being rotated onto. The short-lived material minted FROM them is deliberately
// absent: it differs on every call, and a fingerprint that changed every time would mean nothing.
func (a *tenantTransportAuthority) GenerationParts() []string {
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
		out = append(out, "transport\x1f"+tenant+"\x1f"+row.ServerName+"\x1f"+row.PreviousServerName+
			"\x1f"+row.CACertPEM+"\x1f"+incoming)
	}
	return out
}

func (a *tenantTransportAuthority) refreshLocked() error {
	if a.reload == nil {
		return nil
	}
	rows, raw, err := readAuthoritySnapshot(a.reload, transportAuthorityRowKey, a.cas)
	if err != nil {
		return err
	}
	a.cas, a.snapshot = rows, raw
	return nil
}

func transportAuthorityRowKey(row *storedTenantTransportCA) string {
	return strings.ToLower(strings.TrimSpace(row.TenantID))
}
