package tenantca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Tenant identification + isolation. Each tenant is trusted via ITS OWN CA; the tenant a
// connection belongs to is derived from WHICH registered Tenant CA the presented client cert chains to —
// not from any client-claimed field. This makes cross-tenant admission structurally impossible: a cert
// issued by tenant A's CA can only ever resolve to tenant A.
//
// The registry holds, per tenant, the CA trust anchor(s). It exposes (1) a single x509 Pool of ALL tenant
// CAs for mTLS ClientCAs verification, and (2) a resolver from a verified chain back to the owning tenant.

type TenantCAEntry struct {
	TenantID string `json:"tenant_id"`
	CAFile   string `json:"ca_file,omitempty"` // PEM path (may contain multiple CA certs for that tenant)
	// CAPEM carries the certificate INLINE. Added when the registry became writable at runtime: a CA
	// registered through the API has no file an operator placed, and inventing one would mean two things to
	// keep in step — the JSON and a directory of PEMs — where the pair going out of step is silent. ca_file
	// stays for the registries operators already wrote by hand.
	CAPEM string `json:"ca_pem,omitempty"`
}

type TenantCARegistryFile struct {
	MaterialManagedTenants []string        `json:"material_managed_tenants,omitempty"`
	Tenants                []TenantCAEntry `json:"tenants"`
}

type TenantCARegistry struct {
	authoritativeLoaded     bool
	pendingTrustWithdrawals map[string]bool
	pendingWithdrawals      map[string]string // local removals awaiting completion of trust and persistence

	// Persisted with admission anchors; only a successful material install sets ownership.
	materialManaged map[string]bool
	Pool            *x509.CertPool
	byAnchorKey     map[string]string // sha256(CA.Raw) -> tenant_id
	TenantCount     int
	// anchors are the parsed CA certificates, kept so a caller can MERGE them into another pool.
	//
	// ★ A POOL CANNOT BE ENUMERATED (2026-08-12). A control plane trusts two different sets of client
	// certificates — tenant devices, and the operator-issued identity an Edge ships audit records with — and
	// x509.CertPool offers no way to combine two built pools, so the second registration replaced the first
	// and one of the two sets stopped being able to connect at all.
	anchors []*x509.Certificate
	// mu guards byAnchorKey / anchors / TenantCount once the registry can be written at RUNTIME.
	//
	// ★ WHY IT BECAME MUTABLE (2026-08-15). The registry was load-once from a startup file, so creating a
	// tenant through the Console produced an organization whose devices could never be admitted: the CA that
	// identifies them was reachable only by editing a file and restarting every Edge. Measured while standing
	// up a second tenant — there is no API at all, and /admin/tenant-cas answered 404. The TRUST half of the
	// same problem (is this client certificate acceptable?) already had a live, persisted store; only the
	// ATTRIBUTION half — which tenant does this CA belong to — was frozen at boot.
	mu sync.RWMutex
	// generation advances on every registration and withdrawal, so the control plane's config bundle can carry
	// this registry and an Edge can tell a new view from the one it already applied.
	//
	// ★★★ A SECTION THAT DOES NOT MOVE THIS NUMBER NEVER TRAVELS. An Edge applies a bundle only when the
	// aggregate generation is newer, so registering a CA would change the bundle's CONTENTS and not its
	// VERSION. Measured twice in two days on other sections before this one was written.
	generation uint64
}

// ConfigGeneration is this registry's contribution to the config bundle's aggregate generation. Monotonic
// within a process; a restart resets it, which the bundle's epoch already covers.
func (r *TenantCARegistry) ConfigGeneration() uint64 {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.generation
}

// Anchors are the registered CA certificates, for a caller building a pool that must trust these AND others.
func (r *TenantCARegistry) Anchors() []*x509.Certificate {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*x509.Certificate, len(r.anchors))
	copy(out, r.anchors)
	return out
}

// CAAnchorKey is the stable identity of a CA certificate (sha256 of its DER), used to map a verified
// chain's trust anchor back to the tenant that registered it.
func CAAnchorKey(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// LoadTenantCARegistry builds the registry from a JSON file listing {tenant_id, ca_file}. Fail-closed:
// unreadable/unparseable file or CA, duplicate CA mapped to different tenants, or empty registry are
// errors — the Edge must not run multi-tenant admission with an ambiguous or empty trust map.
func LoadTenantCARegistry(path string) (*TenantCARegistry, error) {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("read tenant CA registry %q: %w", path, err)
	}
	var doc TenantCARegistryFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse tenant CA registry %q: %w", path, err)
	}
	reg := &TenantCARegistry{Pool: x509.NewCertPool(), byAnchorKey: map[string]string{}}
	for _, e := range doc.Tenants {
		tid := strings.TrimSpace(e.TenantID)
		if tid == "" {
			return nil, fmt.Errorf("tenant CA registry: entry with empty tenant_id")
		}
		if inline := strings.TrimSpace(e.CAPEM); inline != "" {
			certs, perr := ParseCACertsPEM([]byte(inline))
			if perr != nil {
				return nil, fmt.Errorf("tenant CA registry: tenant %q inline ca_pem: %w", tid, perr)
			}
			for _, c := range certs {
				reg.Pool.AddCert(c)
				reg.byAnchorKey[CAAnchorKey(c)] = tid
				reg.anchors = append(reg.anchors, c)
			}
			continue
		}
		pem, err := os.ReadFile(strings.TrimSpace(e.CAFile))
		if err != nil {
			return nil, fmt.Errorf("tenant %q: read CA %q: %w", tid, e.CAFile, err)
		}
		certs, err := ParseCACertsPEM(pem)
		if err != nil || len(certs) == 0 {
			return nil, fmt.Errorf("tenant %q: CA file %q has no usable certificate", tid, e.CAFile)
		}
		for _, c := range certs {
			key := CAAnchorKey(c)
			if existing, ok := reg.byAnchorKey[key]; ok && existing != tid {
				// The SAME CA cert mapped to two tenants would break isolation (a cert could resolve to
				// either tenant). Reject — each CA must belong to exactly one tenant.
				return nil, fmt.Errorf("tenant CA registry: CA shared by tenants %q and %q (isolation violation)", existing, tid)
			}
			reg.byAnchorKey[key] = tid
			reg.Pool.AddCert(c)
			reg.anchors = append(reg.anchors, c)
		}
	}
	// Counted from the map rather than per entry: two entries for one tenant are one tenant, and the inline
	// branch above returns early. The per-entry increment was already wrong for the first case.
	reg.TenantCount = reg.tenantCountLocked()
	if len(reg.byAnchorKey) == 0 {
		return nil, fmt.Errorf("tenant CA registry %q is empty", path)
	}
	if err := reg.restoreMaterialOwnership(doc.MaterialManagedTenants); err != nil {
		return nil, err
	}
	return reg, nil
}

// ParseCACertsPEM parses all CERTIFICATE blocks in a PEM blob.
func ParseCACertsPEM(pemBytes []byte) ([]*x509.Certificate, error) {
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
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// TenantForVerifiedChains resolves the owning tenant from mTLS-verified chains: the chain's trust anchor
// (last element) is a registered Tenant CA → its tenant. Returns ("", false) when no chain anchors to a
// registered tenant CA. Because the tenant is derived from the actual issuing CA, a cert from tenant A's
// CA can never resolve to tenant B (cross-tenant admission is structurally impossible).
func (r *TenantCARegistry) TenantForVerifiedChains(chains [][]*x509.Certificate) (string, bool) {
	if r == nil {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		anchor := chain[len(chain)-1]
		if tid, ok := r.byAnchorKey[CAAnchorKey(anchor)]; ok {
			return tid, true
		}
		// Also tolerate registries that registered an intermediate present mid-chain.
		for _, c := range chain {
			if tid, ok := r.byAnchorKey[CAAnchorKey(c)]; ok {
				return tid, true
			}
		}
	}
	return "", false
}

// Register adds (or re-points) a tenant's CA at RUNTIME and returns the anchors it added.
//
// It is idempotent per certificate: registering the same CA for the same tenant again changes nothing. Moving
// a CA to a DIFFERENT tenant is refused, because that CA is what identifies every device already carrying a
// certificate under it — re-pointing it would silently move a fleet between organizations, which is the same
// cross-tenant takeover the invite path was fixed for, one layer down.
func (r *TenantCARegistry) Register(tenantID string, pemBytes []byte) ([]*x509.Certificate, error) {
	if r == nil {
		return nil, fmt.Errorf("tenant CA registry is not configured")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	certs, err := ParseCACertsPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CA certificate found in the supplied PEM")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byAnchorKey == nil {
		r.byAnchorKey = map[string]string{}
	}
	for _, c := range certs {
		if _, pending := r.pendingWithdrawals[CAAnchorKey(c)]; pending {
			return nil, fmt.Errorf("CA withdrawal is pending; finish saving the withdrawal before registering it again")
		}
		if owner, ok := r.byAnchorKey[CAAnchorKey(c)]; ok && !strings.EqualFold(owner, tenantID) {
			return nil, fmt.Errorf("that CA already identifies tenant %q; a CA cannot be moved to another "+
				"organization, because every device already holding a certificate under it would move with it", owner)
		}
	}
	added := []*x509.Certificate{}
	for _, c := range certs {
		key := CAAnchorKey(c)
		if _, exists := r.byAnchorKey[key]; exists {
			continue
		}
		r.byAnchorKey[key] = tenantID
		r.anchors = append(r.anchors, c)
		if r.Pool != nil {
			r.Pool.AddCert(c)
		}
		added = append(added, c)
	}
	r.TenantCount = r.tenantCountLocked()
	r.generation++
	return added, nil
}

// Withdraw removes every CA registered to a tenant and returns how many went. The devices holding
// certificates under them stop resolving to that tenant, which is the point: it is how a tenant's identity
// basis is retired.
func (r *TenantCARegistry) Withdraw(tenantID string) int {
	if r == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	kept := make([]*x509.Certificate, 0, len(r.anchors))
	for _, c := range r.anchors {
		key := CAAnchorKey(c)
		if strings.EqualFold(r.byAnchorKey[key], tenantID) {
			delete(r.byAnchorKey, key)
			removed++
			continue
		}
		kept = append(kept, c)
	}
	delete(r.materialManaged, strings.ToLower(tenantID))
	r.anchors = kept
	// The pool cannot have a certificate removed, so it is rebuilt from what remains. A withdrawn CA that
	// stayed trusted would keep admitting the devices this call exists to stop admitting.
	pool := x509.NewCertPool()
	for _, c := range kept {
		pool.AddCert(c)
	}
	r.Pool = pool
	r.TenantCount = r.tenantCountLocked()
	r.generation++
	return removed
}

// AnchorRegistration is one registered CA and the organization it identifies.
type AnchorRegistration struct {
	TenantID string
	Cert     *x509.Certificate
}

// AnchorsByTenant enumerates every registered CA with its organization.
//
// Anchors() alone cannot answer "which of these belongs to whom", and a caller reconciling this registry
// against an authoritative view needs exactly that pairing: it decides both what to add and what may be
// removed. Building it from byAnchorKey rather than from the pool, because a pool cannot be enumerated.
func (r *TenantCARegistry) AnchorsByTenant() []AnchorRegistration {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]AnchorRegistration, 0, len(r.anchors))
	for _, c := range r.anchors {
		if tenantID, ok := r.byAnchorKey[CAAnchorKey(c)]; ok {
			out = append(out, AnchorRegistration{TenantID: tenantID, Cert: c})
		}
	}
	return out
}

// Registrations returns tenant_id -> the number of CAs registered to it. Caller-visible state for the admin
// surface, so an operator can see which organizations have an identity basis at all.
func (r *TenantCARegistry) Registrations() map[string]int {
	out := map[string]int{}
	if r == nil {
		return out
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, tenantID := range r.byAnchorKey {
		out[tenantID]++
	}
	return out
}

func (r *TenantCARegistry) tenantCountLocked() int {
	seen := map[string]bool{}
	for _, tenantID := range r.byAnchorKey {
		seen[tenantID] = true
	}
	return len(seen)
}

// Save writes the registry to path as JSON with every CA inline, atomically.
//
// Durability is the difference between a tenant that works and one that works until the next restart. The
// runtime half of this file exists because an organization created through the Console could not acquire the
// CA that identifies its devices; leaving that registration in memory would have moved the same failure one
// restart away, which is how the per-tenant interception root behaves today and why it counts as broken.
func (r *TenantCARegistry) Save(path string) error {
	return r.SaveWithdrawals(path)
}

// SaveWithdrawals is called after the named removal has completed its trust stage.
func (r *TenantCARegistry) SaveWithdrawals(path string, removedSHA256 ...string) error {
	if r == nil {
		return fmt.Errorf("tenant CA registry is not configured")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("no tenant CA registry path is configured, so this registration would be lost on restart")
	}
	r.mu.RLock()
	if err := r.checkWithdrawalSaveLocked(removedSHA256); err != nil {
		r.mu.RUnlock()
		return err
	}
	doc := TenantCARegistryFile{Tenants: make([]TenantCAEntry, 0, len(r.anchors)), MaterialManagedTenants: r.materialManagedTenantsLocked()}
	for _, c := range r.anchors {
		tenantID := r.byAnchorKey[CAAnchorKey(c)]
		if tenantID == "" {
			continue
		}
		doc.Tenants = append(doc.Tenants, TenantCAEntry{
			TenantID: tenantID,
			CAPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
		})
	}
	r.mu.RUnlock()
	sort.Slice(doc.Tenants, func(i, j int) bool { return doc.Tenants[i].TenantID < doc.Tenants[j].TenantID })

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// NewTenantCARegistry returns an empty registry, for a deployment whose registrations live in a shared store
// rather than in a file on this node.
func NewTenantCARegistry() *TenantCARegistry {
	return &TenantCARegistry{Pool: x509.NewCertPool(), byAnchorKey: map[string]string{}}
}

// Persister is a shared backend for the registry — blobstore.Persister, declared structurally so this package
// keeps no dependency it does not need.
type Persister interface {
	Load() ([]byte, error)
	Save(data []byte) error
}

// ★★★ WHOSE DEVICES AN EDGE ADMITS MUST NOT DEPEND ON WHICH EDGE ANSWERED THE REGISTRATION (2026-08-21).
//
// An organization's device CA is its own — the customer holds the key and the deployment only verifies — and
// it is registered through POST /admin/tenant-cas, whose answer says "this node, immediately". Measured: the
// control plane REFUSES to hold this registry at all (501, "this node has no tenant CA registry configured"),
// and the config bundle carries no CA of any kind. So the registration reaches exactly one Edge.
//
// In a fleet that grows and shrinks under load, that means an organization's devices are admitted on one node
// out of N and rejected at the handshake by every other — including every Edge added after the registration.
// The reference lab hides it, because all its Edges bind-mount the same registry file; a real deployment does
// not share a filesystem.
//
// Snapshot/Adopt are the shared-store half. File deployments use Save(path).

// Snapshot serialises the registry in the same form Save writes to a file.
func (r *TenantCARegistry) Snapshot() ([]byte, error) {
	return r.snapshot(nil, false)
}

func (r *TenantCARegistry) snapshot(removed []string, saving bool) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("tenant CA registry is not configured")
	}
	r.mu.RLock()
	if saving {
		if err := r.checkWithdrawalSaveLocked(removed); err != nil {
			r.mu.RUnlock()
			return nil, err
		}
	}
	doc := TenantCARegistryFile{Tenants: make([]TenantCAEntry, 0, len(r.anchors)), MaterialManagedTenants: r.materialManagedTenantsLocked()}
	for _, c := range r.anchors {
		tenantID := r.byAnchorKey[CAAnchorKey(c)]
		if tenantID == "" {
			continue
		}
		doc.Tenants = append(doc.Tenants, TenantCAEntry{
			TenantID: tenantID,
			CAPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
		})
	}
	r.mu.RUnlock()
	sort.Slice(doc.Tenants, func(i, j int) bool { return doc.Tenants[i].TenantID < doc.Tenants[j].TenantID })
	return json.MarshalIndent(doc, "", "  ")
}

// Adopt registers everything in a snapshot that this node does not already hold, and reports how many were
// new. It only ADDS: a withdrawal has to travel by its own route, because a node that has not yet seen a
// registration would otherwise undo it by writing back an older view.
func (r *TenantCARegistry) Adopt(data []byte) (int, error) {
	return r.adoptExcept(data, nil)
}

func (r *TenantCARegistry) adoptExcept(data []byte, skipSHA256 []string) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("tenant CA registry is not configured")
	}
	if len(data) == 0 {
		return 0, nil
	}
	var doc TenantCARegistryFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, err
	}
	skip := map[string]bool{}
	for _, h := range skipSHA256 {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			skip[h] = true
		}
	}
	added := 0
	for _, e := range doc.Tenants {
		tenantID := strings.TrimSpace(e.TenantID)
		if tenantID == "" || strings.TrimSpace(e.CAPEM) == "" {
			continue
		}
		certs, err := ParseCACertsPEM([]byte(e.CAPEM))
		if err != nil || len(certs) == 0 {
			continue
		}
		if sum := sha256.Sum256(certs[0].Raw); skip[hex.EncodeToString(sum[:])] {
			continue // this node has just withdrawn it; the shared view is behind, not right
		}
		r.mu.RLock()
		_, pending := r.pendingWithdrawals[CAAnchorKey(certs[0])]
		_, known := r.byAnchorKey[CAAnchorKey(certs[0])]
		r.mu.RUnlock()
		if known || pending {
			continue
		}
		if _, rerr := r.Register(tenantID, []byte(e.CAPEM)); rerr == nil {
			added++
		}
	}
	return added, nil
}

// SaveTo writes the registry to a shared backend, preserving anything another Edge registered that this node
// has not yet seen — read, merge, write, so two registrations minutes apart do not erase each other.
//
// ★★★ AND A WITHDRAWAL MUST NAME ITSELF, OR THE MERGE UNDOES IT (2026-08-21, caught the moment the first
// withdrawal was tried). The merge is what makes concurrent registrations safe, and it is exactly what
// resurrects a removal: the shared view still holds the CA this node has just retired, Adopt puts it back,
// and the snapshot written a line later contains it again. Measured: a device CA withdrawn on region-a
// answered 200 and was still listed on both Edges half a minute afterwards.
//
// So a removal is passed in and excluded from the merge. It is the same rule the export download tokens
// needed on the same night — a merge may only add what it does not know, never re-add what it was told to
// forget.
func (r *TenantCARegistry) SaveTo(p Persister, removedSHA256 ...string) error {
	if r == nil {
		return fmt.Errorf("tenant CA registry is not configured")
	}
	if p == nil {
		return fmt.Errorf("no shared backend is configured for the tenant CA registry")
	}
	r.mu.RLock()
	pendingErr := r.checkWithdrawalSaveLocked(removedSHA256)
	r.mu.RUnlock()
	if pendingErr != nil {
		return pendingErr
	}
	existing, err := p.Load()
	if err != nil {
		return fmt.Errorf("read shared tenant CA registry before saving: %w", err)
	}
	if len(existing) > 0 {
		if _, aerr := r.adoptExcept(existing, removedSHA256); aerr != nil {
			return aerr
		}
	}
	blob, err := r.snapshot(removedSHA256, true)
	if err != nil {
		return err
	}
	return p.Save(blob)
}

// Reconcile makes this node's registry match the fleet's: it adopts what the shared view names and DROPS what
// it no longer does. Returns how many were added and how many were removed.
//
// ★★★ A WITHDRAWAL THAT DOES NOT TRAVEL IS NOT A WITHDRAWAL (2026-08-21, measured). Adopting was add-only, so
// a device CA retired on region-a disappeared there and from the shared store, and region-b went on admitting
// every device that CA had issued — until a restart. Measured: after the withdrawal, region-a listed one CA
// for the organization and region-b listed two, minutes apart. A customer who retires a compromised issuing
// CA must have it stop admitting on every Edge, not on the one that took the request.
//
// The shared view is authoritative here, which is what makes a removal travel. The cost is a narrow race: a
// registration made on another Edge between this node's read and that node's write can be dropped and has to
// be made again. Registration itself is read-merge-write, so the window is one request long, and the
// alternative — a retired authority that keeps admitting — is the worse failure.
func (r *TenantCARegistry) Reconcile(data []byte) (added, removed int, err error) {
	if r == nil {
		return 0, 0, fmt.Errorf("tenant CA registry is not configured")
	}
	if len(data) == 0 {
		return 0, 0, nil
	}
	var doc TenantCARegistryFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, 0, err
	}
	fleet := map[string]bool{}
	for _, e := range doc.Tenants {
		certs, perr := ParseCACertsPEM([]byte(e.CAPEM))
		if perr != nil || len(certs) == 0 {
			continue
		}
		sum := sha256.Sum256(certs[0].Raw)
		fleet[hex.EncodeToString(sum[:])] = true
	}
	if len(fleet) == 0 {
		// An empty or unparsable shared view is not an instruction to forget everything.
		return 0, 0, nil
	}
	type gone struct {
		tenant string
		sha    string
	}
	drop := []gone{}
	r.mu.RLock()
	for _, c := range r.anchors {
		sum := sha256.Sum256(c.Raw)
		h := hex.EncodeToString(sum[:])
		if !fleet[h] {
			drop = append(drop, gone{tenant: r.byAnchorKey[CAAnchorKey(c)], sha: h})
		}
	}
	r.mu.RUnlock()
	for _, g := range drop {
		if g.tenant == "" {
			continue
		}
		if ok, _ := r.WithdrawAnchor(g.tenant, g.sha); ok {
			removed++
		}
	}
	added, err = r.Adopt(data)
	return added, removed, err
}

// ReconcileFrom is Reconcile against a shared backend.
func (r *TenantCARegistry) ReconcileFrom(p Persister) (added, removed int, err error) {
	if p == nil {
		return 0, 0, nil
	}
	data, lerr := p.Load()
	if lerr != nil {
		return 0, 0, lerr
	}
	return r.Reconcile(data)
}

// LoadFrom adopts what the fleet holds. Returns how many CAs this node did not have.
func (r *TenantCARegistry) LoadFrom(p Persister) (int, error) {
	if p == nil {
		return 0, nil
	}
	data, err := p.Load()
	if err != nil {
		return 0, err
	}
	n, err := r.Adopt(data)
	if err != nil {
		return n, err
	}
	var doc TenantCARegistryFile
	if len(data) > 0 {
		if err := json.Unmarshal(data, &doc); err != nil {
			return n, err
		}
	}
	return n, r.restoreMaterialOwnership(doc.MaterialManagedTenants)
}

// TenantCAFact is one organization's device CA, described rather than counted.
//
// ★ A COUNT IS NOT AN INVENTORY (2026-08-16). Registrations() answers "how many", and that was the only thing
// the admin surface could say: a tenant admin reading its own PKI saw `ca_count: 1` and nothing else — not
// which certificate, not who issued it, and NOT WHEN IT EXPIRES. The reference lab's second organization holds
// a 30-day CA. When it lapses, every device of that organization stops being admitted at the handshake, all at
// once, and the only warning anybody would have had is the outage.
//
// Everything here is public certificate material. The registry holds no key.
type TenantCAFact struct {
	TenantID     string `json:"tenant_id"`
	CommonName   string `json:"common_name"`
	SHA256       string `json:"sha256"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	DaysLeft     int    `json:"days_left"`
	Expired      bool   `json:"expired"`
	SelfSigned   bool   `json:"self_signed"`
	Organization string `json:"organization,omitempty"`
}

// Facts describes every registered CA, newest expiry last, so the one about to lapse reads first.
func (r *TenantCARegistry) Facts(now time.Time) []TenantCAFact {
	if r == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]TenantCAFact, 0, len(r.anchors))
	for _, cert := range r.anchors {
		if cert == nil {
			continue
		}
		key := CAAnchorKey(cert)
		fact := TenantCAFact{
			TenantID:   r.byAnchorKey[key],
			CommonName: cert.Subject.CommonName,
			SHA256:     key,
			NotBefore:  cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
			// Truncated towards zero on purpose: "0 days left" is the last day it works, never a day after.
			DaysLeft:   int(cert.NotAfter.UTC().Sub(now.UTC()).Hours() / 24),
			Expired:    now.UTC().After(cert.NotAfter.UTC()),
			SelfSigned: cert.Subject.String() == cert.Issuer.String(),
		}
		if len(cert.Subject.Organization) > 0 {
			fact.Organization = cert.Subject.Organization[0]
		}
		out = append(out, fact)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NotAfter < out[j].NotAfter })
	return out
}

// WithdrawAnchor removes ONE registered CA, by fingerprint, and reports whether it was there and how many that
// organization has left.
//
// ★ WITHDRAWAL WAS ALL-OR-NOTHING (2026-08-16). Withdraw() removes every CA an organization has, which is the
// right act for retiring an organization's identity basis and the wrong one for FINISHING A ROTATION. Both CAs
// are registered at once while devices are re-issued under the new one — that overlap is the entire method —
// and ending it meant removing both and re-registering the survivor, a window in which the organization's
// devices were admitted by nothing at all. So the two acts are separable now, and the caller can refuse the
// one that empties the set.
func (r *TenantCARegistry) WithdrawAnchor(tenantID, sha256Hex string) (removed bool, remaining int) {
	if r == nil {
		return false, 0
	}
	tenantID = strings.TrimSpace(tenantID)
	want := strings.ToLower(strings.TrimSpace(sha256Hex))
	if tenantID == "" || want == "" {
		return false, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := make([]*x509.Certificate, 0, len(r.anchors))
	for _, c := range r.anchors {
		key := CAAnchorKey(c)
		if strings.EqualFold(r.byAnchorKey[key], tenantID) && strings.EqualFold(key, want) {
			delete(r.byAnchorKey, key)
			removed = true
			continue
		}
		kept = append(kept, c)
	}
	r.anchors = kept
	// The pool cannot have a certificate removed, so it is rebuilt from what remains — a withdrawn CA that
	// stayed trusted would keep admitting the devices this call exists to stop admitting.
	pool := x509.NewCertPool()
	for _, c := range kept {
		pool.AddCert(c)
	}
	r.Pool = pool
	r.TenantCount = r.tenantCountLocked()
	r.generation++
	for _, owner := range r.byAnchorKey {
		if strings.EqualFold(owner, tenantID) {
			remaining++
		}
	}
	return removed, remaining
}
