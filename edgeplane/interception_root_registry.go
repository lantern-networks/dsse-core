package edgeplane

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// tenantInterceptionRootRegistry resolves the interception root PROVIDER for a tenant, so a per-SNI leaf is
// signed by THAT tenant's CA. This bounds blast radius (Slice 2 of docs/pki_trust_model.md): a leaked or
// compromised tenant root can impersonate sites only for that tenant's intercepted flows, not the whole fleet —
// instead of one shared fleet root that, if it leaks, lets an attacker MITM every tenant.
//
// SAFETY: per-tenant isolation is OFF by default. When off, every tenant resolves to the single default
// provider — byte-for-byte today's behavior, so the lab/North-Star/demo trust (devices trust the one existing
// root) is unchanged. Per-tenant roots are generated lazily ONLY when enabled. DISTRIBUTING each tenant's root
// to its devices (so they trust it) is an MDM concern — itself gated on the shipping lane — so per-tenant stays
// opt-in until that exists. This is the engine-side architecture that makes per-tenant interception possible;
// it does not by itself distribute trust.
type tenantInterceptionRootRegistry struct {
	mu              sync.Mutex
	defaultProvider InterceptionRootProvider
	perTenant       bool
	primaryTenant   string // the tenant the default root belongs to (resolves to defaultProvider even when on)
	// region is THIS edge's region (Slice 4). When set, a tenant's root is scoped to (region, tenant): the EU
	// edge's root for tenant T differs from the US edge's, so a leaked regional key can MITM only that region's
	// traffic, and the key is identifiably the region's (residency — "the EU key reads EU traffic"). "" =
	// region-agnostic per-tenant (Slice 2), unchanged.
	region    string
	now       func() time.Time
	providers map[string]InterceptionRootProvider // (region\x00tenant) -> lazily-created provider (when perTenant)
	// stateDir, when set, persists each per-tenant root to <stateDir>/<key>.pem (+ .key.pem) so a tenant's root
	// SURVIVES a restart — without it the lazily-generated per-tenant roots regenerate on restart and every
	// device that trusted the old one breaks. The default (primary) root persists separately via its own path.
	stateDir string
}

// PerTenantRootInfo describes a provisioned per-tenant interception root for export/distribution.
type PerTenantRootInfo struct {
	// Durable reports whether this root was written to disk. False means it exists only in this process and
	// disappears on restart.
	//
	// ★ MEASURED (2026-08-15). Provisioning a per-tenant root answered 200 with a certificate, listed it, and
	// lost it at the next restart — the lab has no -interception-per-tenant-root-dir, and nothing in the API
	// said so. An operator would have distributed that root to a customer's devices and then found the Edge
	// signing under a different one. A root nobody wrote down is worse than no root: the devices trust
	// something that no longer exists.
	Durable bool   `json:"durable"`
	Tenant  string `json:"tenant"`
	Region  string `json:"region,omitempty"`
	Key     string `json:"key"`
	CertPEM string `json:"cert_pem"`
}

// NewTenantInterceptionRootRegistry builds a registry that resolves every tenant to defaultProvider until
// per-tenant isolation is explicitly enabled (EnablePerTenant). The default keeps today's single-root behavior.
func NewTenantInterceptionRootRegistry(defaultProvider InterceptionRootProvider, now func() time.Time) *tenantInterceptionRootRegistry {
	if now == nil {
		now = time.Now
	}
	return &tenantInterceptionRootRegistry{
		defaultProvider: defaultProvider,
		now:             now,
		providers:       map[string]InterceptionRootProvider{},
	}
}

// EnablePerTenant turns on per-tenant interception roots. primaryTenant (the tenant the existing default root
// belongs to) keeps using the default root so already-trusting devices are unaffected; every OTHER tenant gets
// its own lazily-generated root. Enabling without distributing the per-tenant roots to devices would break TLS
// trust for those tenants, so this is a deliberate opt-in (default off) until MDM distribution exists.
func (r *tenantInterceptionRootRegistry) EnablePerTenant(primaryTenant string) {
	r.EnablePerTenantInRegion(primaryTenant, "")
}

// EnablePerTenantInRegion turns on per-tenant roots scoped to THIS edge's region (Slice 4). Same as
// EnablePerTenant but a non-primary tenant's root is keyed + labeled by `region`, so the same tenant on edges in
// different regions gets DISTINCT, region-identifiable roots ("EU traffic is read by the EU key"). region "" is
// region-agnostic per-tenant (Slice 2).
func (r *tenantInterceptionRootRegistry) EnablePerTenantInRegion(primaryTenant, region string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.perTenant = true
	r.primaryTenant = primaryTenant
	r.region = region
}

// resolve returns the provider that signs leaves for tenantID, plus the cache-tenant key to scope the leaf cache
// (empty when the default provider is used, so the off/default path shares one cache entry per host exactly as
// before). When per-tenant is off, or for the empty/primary tenant, the default provider is returned.
func (r *tenantInterceptionRootRegistry) resolve(tenantID string) (InterceptionRootProvider, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.perTenant || tenantID == "" || tenantID == r.primaryTenant {
		return r.defaultProvider, "", nil
	}
	// Key (and cache-scope) by (region, tenant): different regions -> different roots for the same tenant. The
	// root cert is labeled with the region so it is identifiably that region's key. region "" -> Slice-2 keying.
	key := tenantID
	if r.region != "" {
		key = r.region + "\x00" + tenantID
	}
	if p, ok := r.providers[key]; ok {
		return p, key, nil
	}
	p, err := r.loadOrCreateLocked(key)
	if err != nil {
		return nil, "", fmt.Errorf("per-tenant interception root for tenant %q region %q: %w", tenantID, r.region, err)
	}
	return p, key, nil
}

// keyFor maps a (region, tenant) to the cache/persistence key (region-agnostic = tenant alone).
// DefaultProvider returns the registry's default signing provider — the one whose key custody the admin
// surface reports. Per-tenant providers derive from the same custody backend, so the default is representative.
func (r *tenantInterceptionRootRegistry) DefaultProvider() InterceptionRootProvider {
	if r == nil {
		return nil
	}
	return r.defaultProvider
}

// Scope names how this registry RESOLVES a signing root: one shared root for everybody, one per tenant, or one
// per (region, tenant). It is the configured intent — whether those roots actually sign is a question about the
// issuer above them, which is why InterceptionSigningScope reports both and never just this.
func (r *tenantInterceptionRootRegistry) Scope() string {
	if r == nil {
		return "shared"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case !r.perTenant:
		return "shared"
	case r.region != "":
		return "per-region"
	default:
		return "per-tenant"
	}
}

func (r *tenantInterceptionRootRegistry) keyFor(tenantID string) string {
	if r.region != "" {
		return r.region + "\x00" + tenantID
	}
	return tenantID
}

// loadOrCreateLocked returns the provider for a key, loading it from stateDir (durable), else generating and
// (when stateDir is set) persisting it. Caller holds r.mu.
func (r *tenantInterceptionRootRegistry) loadOrCreateLocked(key string) (InterceptionRootProvider, error) {
	if p, ok := r.providers[key]; ok {
		return p, nil
	}
	if r.stateDir != "" {
		path := filepath.Join(r.stateDir, sanitizeRootKey(key)+".pem")
		material, reused, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(path, r.now)
		if err != nil {
			return nil, err
		}
		if material.Cert == nil {
			material, err = GenerateNetworkExtensionLabTLSRootMaterialScoped(rootScopeLabel(key), r.now)
			if err != nil {
				return nil, err
			}
			if err := WriteNetworkExtensionLabTLSPersistentRootMaterial(path, material); err != nil {
				return nil, err
			}
		}
		_ = reused
		p := NewFileInterceptionRootProvider(material)
		r.providers[key] = p
		return p, nil
	}
	material, err := GenerateNetworkExtensionLabTLSRootMaterialScoped(rootScopeLabel(key), r.now)
	if err != nil {
		return nil, err
	}
	p := NewFileInterceptionRootProvider(material)
	r.providers[key] = p
	return p, nil
}

// rootScopeLabel turns a registry key into the part of a generated root's NAME that says whose it is.
//
// ★ EVERY PER-TENANT ROOT WAS CALLED THE SAME THING (found 2026-08-16, and reported the same day from the
// Windows machine, which had two of them side by side). The generator already took a scope — it was being
// given the REGION, which is empty in the ordinary per-tenant deployment, so two organizations' roots came out
// with one common name and differed only by key and serial.
//
// A trust store shows names. An operator deciding which of two roots to remove from a machine sees one string
// twice, and the product has already had an outage from exactly that (two same-subject intermediates side by
// side, 2026-08-02). Naming the organization is not cosmetic: it is the difference between a removal an
// operator can make correctly and one they have to reconstruct from fingerprints.
//
// EXISTING roots keep their names. A rename is a new certificate, which is a replacement, and replacements go
// through the overlap rather than happening silently underneath a fleet.
func rootScopeLabel(key string) string {
	region, tenant := "", key
	if i := strings.IndexByte(key, 0); i >= 0 {
		region, tenant = key[:i], key[i+1:]
	}
	tenant = strings.TrimSpace(tenant)
	region = strings.TrimSpace(region)
	switch {
	case tenant == "" && region == "":
		return ""
	case region == "":
		return "(" + tenant + ")"
	case tenant == "":
		return "(" + region + ")"
	default:
		return "(" + region + " / " + tenant + ")"
	}
}

// SetStateDir enables durable persistence of per-tenant roots under dir.
func (r *tenantInterceptionRootRegistry) SetStateDir(dir string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stateDir = strings.TrimSpace(dir)
}

// Provision creates (and persists, when stateDir is set) a per-tenant root for tenantID and returns its key +
// cert PEM, so an operator can DISTRIBUTE that root to the tenant's devices BEFORE enabling per-tenant scope
// (otherwise the first device to connect would not trust the freshly-minted root). Works regardless of whether
// per-tenant resolution is currently on. The primary/empty tenant resolves to the default root.
func (r *tenantInterceptionRootRegistry) Provision(tenantID string) (PerTenantRootInfo, error) {
	tenantID = strings.TrimSpace(tenantID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if tenantID == "" || (r.primaryTenant != "" && tenantID == r.primaryTenant) {
		return PerTenantRootInfo{Tenant: tenantID, Region: r.region, Key: "", CertPEM: string(r.defaultProvider.CertPEM()), Durable: r.stateDir != ""}, nil
	}
	key := r.keyFor(tenantID)
	p, err := r.loadOrCreateLocked(key)
	if err != nil {
		return PerTenantRootInfo{}, err
	}
	return PerTenantRootInfo{Tenant: tenantID, Region: r.region, Key: key, CertPEM: string(p.CertPEM()), Durable: r.stateDir != ""}, nil
}

// List returns the per-tenant roots this node HAS — including the ones on disk that nothing has touched since
// the process started.
//
// ★ WHY IT READS THE DIRECTORY (2026-08-15). It used to return only the providers loaded into memory, which
// are loaded LAZILY, so immediately after a restart the list was empty even with every root sitting on disk.
// Measured on the lab: provision a root, restart, list — nothing; ask for that tenant again and it reappears.
// An operator reading that list would conclude no organization has a root and provision fresh ones, handing
// customers a trust anchor the Edge is not signing under. A list that depends on what happened to be asked
// for is not an inventory.
func (r *tenantInterceptionRootRegistry) List() []PerTenantRootInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []PerTenantRootInfo{}
	seen := map[string]bool{}
	for key, p := range r.providers {
		seen[sanitizeRootKey(key)] = true
		tenant := key
		region := ""
		if i := strings.IndexByte(key, 0); i >= 0 {
			region = key[:i]
			tenant = key[i+1:]
		}
		out = append(out, PerTenantRootInfo{Tenant: tenant, Region: region, Key: key, CertPEM: string(p.CertPEM()), Durable: r.stateDir != ""})
	}
	// And whatever else is on disk. Loaded on demand elsewhere; enumerated here so the inventory is what this
	// node HAS rather than what it has been asked for.
	if r.stateDir != "" {
		entries, err := os.ReadDir(r.stateDir)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("interception root registry: could not read %q, so this list covers only the roots already "+
				"loaded in memory and may look emptier than the node actually is: %v", r.stateDir, err)
			return out
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key.pem") {
				continue
			}
			key := strings.TrimSuffix(name, ".pem")
			if seen[key] {
				continue
			}
			material, _, lerr := LoadNetworkExtensionLabTLSPersistentRootMaterial(filepath.Join(r.stateDir, name), r.now)
			if lerr != nil || material.Cert == nil {
				log.Printf("interception root registry: %q is on disk but unreadable (%v) — reporting it so it is not "+
					"mistaken for a tenant that has no root", name, lerr)
				out = append(out, PerTenantRootInfo{Tenant: key, Key: key, Durable: true})
				continue
			}
			out = append(out, PerTenantRootInfo{
				Tenant:  key,
				Region:  r.region,
				Key:     key,
				CertPEM: string(NewFileInterceptionRootProvider(material).CertPEM()),
				Durable: true,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// sanitizeRootKey makes a (region\x00tenant) key safe as a filename.
func sanitizeRootKey(key string) string {
	var b strings.Builder
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		s = "tenant"
	}
	return s
}

// Retire removes a PROVISIONED per-tenant root: the provider this process holds and the files that would
// restore it. It refuses whenever that root is, or would become, the one signing for that organization.
//
// ★ WHY A PROVISIONED ROOT NEEDS RETIRING AT ALL (2026-08-16). These are DISTRIBUTION artifacts — created so
// an organization's root could be handed to its devices BEFORE per-tenant signing was turned on. On a
// deployment that then went a different way (offline per-tenant issuers) they sign nothing, and two of them
// sat on the reference lab carrying the same common name, which is precisely the thing an operator cannot
// resolve from a trust store. Leaving them is not neutral: they are certificates a customer may have been
// given, indistinguishable by name from another customer's, that no traffic will ever chain to.
//
// The refusal is the whole safety of it. With per-tenant scope ON, this root either signs that organization's
// leaves now or will be regenerated the moment one is asked for — removing it would change what that
// organization's devices must trust, silently, which is the flag day everything else here exists to avoid.
func (r *tenantInterceptionRootRegistry) Retire(tenantID string) (bool, error) {
	if r == nil {
		return false, fmt.Errorf("interception is not enabled")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return false, fmt.Errorf("tenant is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.perTenant {
		return false, fmt.Errorf("per-tenant interception roots are IN FORCE on this node, so %q's root is what its "+
			"leaves are signed under (or would be regenerated for the next flow). Retiring it would change what "+
			"that organization's devices must trust without telling them; replace it through the announced "+
			"overlap instead", tenantID)
	}
	// ★ THIS GUARD WAS INERT WHEN IT MATTERED (found by running it, 2026-08-16). It read
	// `tenantID == r.primaryTenant`, and primaryTenant is only ever set by EnablePerTenant* — so on a
	// deployment with per-tenant scope OFF, which is where this route is most likely to be used, the check
	// compared against an empty string and passed everything. It refused nothing while its message told an
	// operator it had protected the deployment anchor.
	//
	// A refusal has to check the thing it CLAIMS. So the anchor is identified by CERTIFICATE, not by a tenant
	// name that may never have been assigned.
	key := r.keyFor(tenantID)
	if provider, ok := r.providers[key]; ok && provider != nil && r.defaultProvider != nil {
		if anchor, held := r.defaultProvider.Certificate(), provider.Certificate(); anchor != nil && held != nil && anchor.Equal(held) {
			return false, fmt.Errorf("%q's provisioned root IS this node's anchor certificate; retiring it here "+
				"would remove the root every device verifies intercepted traffic against", tenantID)
		}
	}
	if r.primaryTenant != "" && tenantID == r.primaryTenant {
		return false, fmt.Errorf("%q is this node's primary tenant: its root is the deployment anchor, not a "+
			"provisioned per-tenant one", tenantID)
	}
	_, held := r.providers[key]
	delete(r.providers, key)
	removedFile := false
	if r.stateDir != "" {
		base := filepath.Join(r.stateDir, sanitizeRootKey(key))
		for _, path := range []string{base + ".pem", base + ".key.pem"} {
			if err := os.Remove(path); err == nil {
				removedFile = true
			} else if !os.IsNotExist(err) {
				// The provider is gone from this process either way. Say so rather than reporting a clean
				// retirement: the next restart would bring the certificate back and the operator would be
				// looking at a root they believe they removed.
				log.Printf("network_extension_lab_tls WARNING per_tenant_root_still_on_disk tenant=%q path=%q err=%v "+
					"(retired in this process; a restart would restore it)", tenantID, path, err)
			}
		}
	}
	if held || removedFile {
		log.Printf("network_extension_lab_tls progress=per_tenant_root_retired tenant=%q key=%q in_memory=%v on_disk=%v",
			tenantID, key, held, removedFile)
		return true, nil
	}
	return false, nil
}
