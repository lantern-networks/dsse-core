package edgeplane

import (
	"bytes"
	"crypto"
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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// staticInterceptionProvider is a generic InterceptionRootProvider backed by an in-memory cert + signer (RSA or
// EC). Used in offline-intermediate mode to satisfy the registry's provider slot; the actual leaf signer is the
// fixed offlineIssuer, so this provider's Signer is never used to mint leaves.
type staticInterceptionProvider struct {
	cert    *x509.Certificate
	certPEM []byte
	signer  crypto.Signer
}

func (p *staticInterceptionProvider) Certificate() *x509.Certificate { return p.cert }
func (p *staticInterceptionProvider) CertPEM() []byte                { return p.certPEM }
func (p *staticInterceptionProvider) Signer() crypto.Signer          { return p.signer }

// parseInterceptionPrivateKey accepts a PEM private key in PKCS#8, PKCS#1 (RSA) or SEC1 (EC) form.
// parseInterceptionPrivateKey accepts the key file an operator actually has.
//
// ★ IT USED TO READ ONLY THE FIRST PEM BLOCK (found 2026-08-16, onboarding a real tenant's issuer on the lab).
// `openssl ecparam -genkey`, the canonical way to generate an EC key, writes an `EC PARAMETERS` block BEFORE
// the key — so the most ordinary key file in existence was rejected with "unrecognized private key format",
// which reads as "your key is broken" rather than "this parser looked at the wrong block". A PKI onboarding
// step that fails on the standard tool's output is a step operators work around by mangling their key
// material, which is the last thing this surface should be teaching.
func parseInterceptionPrivateKey(keyPEM []byte) (crypto.Signer, error) {
	rest := keyPEM
	sawBlock := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawBlock = true
		// Skip the parameter blocks and anything else that is not key material, rather than failing on them.
		if !strings.Contains(strings.ToUpper(block.Type), "PRIVATE KEY") {
			continue
		}
		if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if s, ok := k.(crypto.Signer); ok {
				return s, nil
			}
			return nil, fmt.Errorf("PKCS#8 key is not a signer")
		}
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return k, nil
		}
	}
	if !sawBlock {
		return nil, fmt.Errorf("no PEM block in private key")
	}
	return nil, fmt.Errorf("unrecognized private key format (want PKCS#8, PKCS#1 or SEC1 EC)")
}

func ParseInterceptionCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// loadOfflineInterceptionIssuer validates an offline-root-issued intermediate bundle and returns the fixed leaf
// issuer + the root anchor (cert + PEM). The Edge holds NO root key — only the intermediate key signs leaves,
// and clients pin the root. Validates: both are CAs, the intermediate chains to (is signed by) the root, the
// intermediate is currently valid, and the key matches the intermediate cert.
func loadOfflineInterceptionIssuer(rootCertPEM, interCertPEM, interKeyPEM []byte, now func() time.Time) (issuer *InterceptionIssuer, root *x509.Certificate, err error) {
	if now == nil {
		now = time.Now
	}
	root, err = ParseInterceptionCertPEM(rootCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse interception root cert: %w", err)
	}
	// ★★★ THE INTERMEDIATE MAY BE A CHAIN (2026-08-20). Until now this took exactly one certificate signed
	// directly by the root — the shape produced when a customer signs an Edge's intermediate by hand. A shared,
	// autoscaled fleet cannot work that way: the material an Edge is handed has to be short-lived, so the
	// customer signs an issuing authority ONCE and the control plane mints a per-Edge tier under it. That is
	// two certificates between the leaf and the root.
	//
	// One certificate still means exactly what it meant before, so every existing deployment is unaffected.
	interChain, err := parseInterceptionCertChainPEM(interCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse interception intermediate cert: %w", err)
	}
	inter := interChain[0]
	key, err := parseInterceptionPrivateKey(interKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse interception intermediate key: %w", err)
	}
	if !root.IsCA {
		return nil, nil, fmt.Errorf("interception root is not a CA")
	}
	// Each tier must be signed by the next, and the last by the root — otherwise the browser is where the
	// chain gets checked, which is the wrong place to find out.
	for i := 0; i < len(interChain); i++ {
		parent := root
		if i+1 < len(interChain) {
			parent = interChain[i+1]
		}
		if err := interChain[i].CheckSignatureFrom(parent); err != nil {
			return nil, nil, fmt.Errorf("interception chain does not link: %q is not signed by %q: %w",
				interChain[i].Subject.CommonName, parent.Subject.CommonName, err)
		}
		if !interChain[i].IsCA {
			return nil, nil, fmt.Errorf("interception chain member %q is not a CA", interChain[i].Subject.CommonName)
		}
	}
	n := now().UTC()
	if n.Before(inter.NotBefore) || n.After(inter.NotAfter) {
		return nil, nil, fmt.Errorf("interception intermediate is not currently valid (%s..%s)", inter.NotBefore.Format(time.RFC3339), inter.NotAfter.Format(time.RFC3339))
	}
	// The intermediate's private key must match its certificate (sign+verify a nonce).
	if err := VerifySignerMatchesCert(key, inter); err != nil {
		return nil, nil, fmt.Errorf("intermediate key does not match intermediate cert: %w", err)
	}
	// ★★ THE TRUST ANCHOR IS NOT SENT (2026-08-21, found the moment a third tier appeared). The chain used to
	// end with the root, which was harmless while it was two deep: a client that trusts the root already has
	// it, and one that does not cannot be helped by receiving it. Adding the control plane's per-node
	// intermediate made the presented chain four long and ending in a self-signed certificate — and git on
	// this machine, whose verifier reports exactly that, stopped being able to reach github:
	//
	//	SSL certificate problem: self signed certificate in certificate chain
	//
	// Sending an anchor is not how a server helps a client verify; sending the INTERMEDIATES is. The root is
	// still published to endpoints (rootCACertOut, the install bundle, /admin/interception-roots) — that is
	// where a device gets it, and it is the only place it belongs.
	chain := make([][]byte, 0, len(interChain)+1)
	for _, c := range interChain {
		if isSelfSignedCertificate(c) {
			continue
		}
		chain = append(chain, c.Raw)
	}
	if !isSelfSignedCertificate(root) {
		// A root that is NOT self-signed is a cross-signed intermediate, and a client may genuinely need it.
		chain = append(chain, root.Raw)
	}

	// ★★★ AND THE MATERIAL IS TRIED BEFORE IT IS TRUSTED (2026-08-21, after eighteen minutes of broken HTTPS
	// on somebody's laptop).
	//
	// Accepting an issuing authority whose parent carried pathLenConstraint:0 produced a chain that reaches the
	// right root by a route no correct verifier accepts. The Edge served it happily; Chrome accepted it; the
	// first person to find out was an operator who could not reach a website. From win-dev-1's measurement:
	// 230 handshakes that got a certificate and were dropped by the client, over eighteen minutes, while the
	// agent reported enforcement=healthy every fifteen seconds.
	//
	// Nothing here asked the one question a device asks: does a leaf minted under this material actually verify
	// to the root we tell devices to trust? So it is asked now, on the material, before a single connection is
	// served with it — with Go's verifier, which is the same kind of verifier that rejected it in the field.
	// Material that cannot be verified is refused, and the reason is the verifier's own words rather than a
	// summary: "implementations disagree" is exactly what happened, so the disagreement is not flattened.
	if err := interceptionMaterialMintsAVerifiableLeaf(inter, key, chain, root, now()); err != nil {
		return nil, nil, fmt.Errorf("this interception material cannot mint a leaf that verifies to the root devices "+
			"are told to trust, so serving it would break every HTTPS request from every device of this "+
			"organization while the node reports itself healthy: %w", err)
	}
	issuer = &InterceptionIssuer{
		trustAnchor: root,
		signingCert: inter,
		signer:      key,
		chain:       chain,
	}
	return issuer, root, nil
}

// VerifySignerMatchesCert confirms the private key corresponds to the certificate's public key by comparing the
// marshaled public keys.
func VerifySignerMatchesCert(signer crypto.Signer, cert *x509.Certificate) error {
	signerPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(signerPub, certPub) {
		return fmt.Errorf("public key mismatch")
	}
	return nil
}

// ReloadOfflineIntermediate hot-swaps the offline intermediate (ROTATION without restart): the offline root
// re-issued a fresh intermediate, and the Edge starts signing leaves with it. The supplied root MUST equal the
// current anchor so device trust is unchanged (clients keep pinning the same root). Clears the leaf cache so new
// leaves are minted by the new intermediate. This is how a (possibly leaked) intermediate is rotated out — the
// old intermediate is no longer used by the Edge, and short-lived intermediates expire on their own.
func (interception *NetworkExtensionLabTLSInterception) ReloadOfflineIntermediate(rootCertPEM, interCertPEM, interKeyPEM []byte) error {
	if interception == nil {
		return fmt.Errorf("interception not enabled")
	}
	if interception.offlineIssuer == nil {
		return fmt.Errorf("offline intermediate mode is not active on this edge")
	}
	newRoot, err := ParseInterceptionCertPEM(rootCertPEM)
	if err != nil {
		return fmt.Errorf("parse root cert: %w", err)
	}
	if interception.rootCert == nil || !bytes.Equal(newRoot.Raw, interception.rootCert.Raw) {
		return fmt.Errorf("the new intermediate must chain to the CURRENT root anchor (device trust must not change); supply the same root cert")
	}
	issuer, _, err := loadOfflineInterceptionIssuer(rootCertPEM, interCertPEM, interKeyPEM, interception.now)
	if err != nil {
		return err
	}
	interception.issuerMu.Lock()
	interception.offlineIssuer = issuer
	interception.issuerMu.Unlock()
	interception.mu.Lock()
	interception.leafCache = map[string]tls.Certificate{}
	interception.mu.Unlock()
	log.Printf("network_extension_lab_tls progress=offline_intermediate_rotated intermediate_cn=%q not_after=%s", issuer.signingCert.Subject.CommonName, issuer.signingCert.NotAfter.Format(time.RFC3339))
	return nil
}

// LoadOfflineTenantIntermediate installs ONE ORGANIZATION's offline-issued intermediate, so that tenant's
// leaves are signed under that tenant's own root and no other tenant's traffic can be minted with it.
//
// This is the mechanism that was missing behind the per-tenant interception roots: those could be provisioned
// and distributed while the node went on signing every leaf with one shared intermediate. Loading the first
// one puts the node into per-tenant signing, which is FAIL-CLOSED for organizations that do not have one —
// see issuerFor. That is deliberate and it is the operationally sharp edge of this feature: enable it and any
// tenant you have not provisioned stops being intercepted.
//
// The bundle is validated exactly like the node-wide one (both CAs, intermediate signed by the root, in date,
// key matches cert). The root here is the TENANT's root and is NOT required to equal this node's anchor —
// that is the entire point, and it is the one check that must not be copied from ReloadOfflineIntermediate.
func (interception *NetworkExtensionLabTLSInterception) LoadOfflineTenantIntermediate(tenantID string, rootCertPEM, interCertPEM, interKeyPEM []byte) (*x509.Certificate, error) {
	if interception == nil {
		return nil, fmt.Errorf("interception not enabled")
	}
	key := normalizeInterceptionTenantKey(tenantID)
	if key == "" {
		return nil, fmt.Errorf("tenant is required: an intermediate loaded for nobody would sign for everybody")
	}
	issuer, root, err := loadOfflineInterceptionIssuer(rootCertPEM, interCertPEM, interKeyPEM, interception.now)
	if err != nil {
		return nil, err
	}
	// ★ A REVOKED AUTHORITY DOES NOT COME BACK. Without this the revocation would remove the loaded issuer and
	// nothing else: the next well-meaning load — a restore, a re-run of the onboarding call, an operator
	// repeating a step — would install the compromised key again, and the log would say "loaded" like any
	// other day.
	interception.issuerMu.Lock()
	if reason, dead := interception.revokedTenantRoots[interceptionCertSHA256Hex(root)]; dead {
		interception.issuerMu.Unlock()
		return nil, fmt.Errorf("this interception root was REVOKED on this node (%s) and cannot be loaded again; "+
			"issue a new authority for %q rather than restoring the revoked one", reason, key)
	}
	if interception.offlineTenantIssuers == nil {
		interception.offlineTenantIssuers = map[string]*InterceptionIssuer{}
		interception.offlineTenantRoots = map[string]*x509.Certificate{}
	}
	if interception.offlineTenantRetiringFingerprints == nil {
		interception.offlineTenantRetiringFingerprints = map[string][]string{}
	}
	// An announced-but-unused root stops being "incoming" the moment something signs under it: from here on it
	// is simply the current root, and announcing it twice would double it in the set devices are given.
	if incoming := interception.offlineTenantIncomingRoots[key]; len(incoming) > 0 {
		kept := incoming[:0]
		for _, c := range incoming {
			if !c.Equal(root) {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(interception.offlineTenantIncomingRoots, key)
		} else {
			interception.offlineTenantIncomingRoots[key] = kept
		}
	}
	var retiring *x509.Certificate
	// A REPLACEMENT keeps the outgoing root announced. See offlineTenantRetiringRoots: without this the
	// organization's devices are moved onto a new authority all at once, and the agent-side rule that an
	// overlap is a match can never fire because only one root is ever named.
	if previous := interception.offlineTenantRoots[key]; previous != nil && !previous.Equal(root) {
		if interception.offlineTenantRetiringRoots == nil {
			interception.offlineTenantRetiringRoots = map[string][]*x509.Certificate{}
		}
		already := false
		for _, r := range interception.offlineTenantRetiringRoots[key] {
			if r.Equal(previous) {
				already = true
			}
		}
		if !already {
			interception.offlineTenantRetiringRoots[key] = append(interception.offlineTenantRetiringRoots[key], previous)
			log.Printf("network_extension_lab_tls progress=offline_tenant_root_retiring tenant=%q retiring_cn=%q "+
				"new_cn=%q — the previous authority is still ANNOUNCED so devices pinned to it keep working; "+
				"withdraw it once they have moved", key, previous.Subject.CommonName, root.Subject.CommonName)
			retiring = previous
		}
	}
	interception.offlineTenantIssuers[key] = issuer
	interception.offlineTenantRoots[key] = root

	// ★★★ AND THE OVERLAP IS WRITTEN DOWN, so it outlives this process. The in-memory retiring set above only
	// records a replacement that happens on a LIVE engine; the procedure operators actually use is to replace
	// the files and recreate the node, and a restarted engine has no memory of what it was signing under
	// before. Recording it on EVERY load is what makes that case work — see
	// interception_announced_roots_survive_a_restart.go.
	interception.offlineTenantRetiringFingerprints[key] = recordAnnouncedRoot(
		interception.offlineTenantIntermediateDir, key, certFingerprintHex(root))
	// ★ THE KEY STAYS DEAD; THE ORGANIZATION RECOVERS (2026-08-16, found by the test written for it). A
	// revocation leaves that organization fail-closed, and loading a REPLACEMENT is exactly what ends that
	// state — the check above already refuses the revoked certificate itself, so anything reaching here is a
	// different authority. Without this, reporting a leak would leave a customer permanently un-intercepted:
	// a one-way door in the emergency path, which is the last place to put one.
	if _, wasRevoked := interception.revokedTenants[key]; wasRevoked {
		delete(interception.revokedTenants, key)
		log.Printf("network_extension_lab_tls progress=interception_authority_replaced_after_revocation tenant=%q "+
			"new_root_cn=%q — that organization is intercepted again, under a different authority; the revoked "+
			"fingerprints stay refused", key, root.Subject.CommonName)
	}
	interception.issuerMu.Unlock()
	// Leaves already minted for this tenant were signed by whatever was signing before — the shared
	// intermediate — so they must not be served again from cache. Clearing the whole cache is heavier than
	// needed and is the safe direction: a cache miss costs one signature, a stale entry serves the wrong CA.
	interception.mu.Lock()
	interception.leafCache = map[string]tls.Certificate{}
	interception.mu.Unlock()
	// The overlap has to SURVIVE A RESTART. Without this a redeploy in the middle of a replacement silently
	// ends it: the node comes back announcing only the new root, and every device still pinned to the previous
	// one stands aside — the flag day this whole mechanism exists to avoid, arriving by way of an unrelated
	// restart. Certificates only; there is no key here to lose.
	if retiring != nil {
		if err := interception.persistRetiringTenantRoot(key, retiring); err != nil {
			log.Printf("network_extension_lab_tls WARNING offline_tenant_retiring_root_not_durable tenant=%q err=%v "+
				"(the overlap is live now; a restart would end it and stand every device still on the previous "+
				"authority aside)", key, err)
		}
	}
	if err := interception.persistOfflineTenantIntermediate(key, rootCertPEM, interCertPEM, interKeyPEM); err != nil {
		// Live but not durable. NOT a failure of the load — refusing here would leave the node signing under a
		// bundle the caller was told had failed — but the caller must be able to see it, so the admin route
		// reports durable=false rather than letting a restart quietly stop intercepting this organization.
		//
		// ★ AND IT IS ONLY A PROBLEM IF NOTHING BRINGS IT BACK. See offlineTenantMaterialIsFetched: a node
		// that assembles itself from the control plane re-fetches this on the next start, and keeping a
		// short-lived signing key off its disk is the point rather than an oversight.
		interception.issuerMu.Lock()
		fetched := interception.offlineTenantMaterialIsFetched
		interception.issuerMu.Unlock()
		if !fetched {
			log.Printf("network_extension_lab_tls WARNING offline_tenant_intermediate_not_durable tenant=%q err=%v "+
				"(live now; a restart returns this organization to REFUSED until it is loaded again)", key, err)
		}
	}
	log.Printf("network_extension_lab_tls progress=offline_tenant_intermediate_loaded tenant=%q intermediate_cn=%q root_cn=%q not_after=%s",
		key, issuer.signingCert.Subject.CommonName, root.Subject.CommonName, issuer.signingCert.NotAfter.Format(time.RFC3339))
	return root, nil
}

// SetOfflineTenantIntermediateDir makes per-tenant offline intermediates durable under dir, and is also where
// they are read back from at boot.
// OfflineTenantMaterialIsFetched records that this node assembles its organizations from the control plane,
// so per-organization interception material returns on its own after a restart and is deliberately not
// written to this node's disk. See offlineTenantMaterialIsFetched.
func (interception *NetworkExtensionLabTLSInterception) OfflineTenantMaterialIsFetched() {
	if interception == nil {
		return
	}
	interception.issuerMu.Lock()
	interception.offlineTenantMaterialIsFetched = true
	interception.issuerMu.Unlock()
}

func (interception *NetworkExtensionLabTLSInterception) SetOfflineTenantIntermediateDir(dir string) {
	if interception == nil {
		return
	}
	interception.issuerMu.Lock()
	interception.offlineTenantIntermediateDir = strings.TrimSpace(dir)
	interception.issuerMu.Unlock()
}

func (interception *NetworkExtensionLabTLSInterception) persistOfflineTenantIntermediate(tenantKey string, rootPEM, interPEM, keyPEM []byte) error {
	interception.issuerMu.Lock()
	dir := interception.offlineTenantIntermediateDir
	interception.issuerMu.Unlock()
	if dir == "" {
		return fmt.Errorf("no -interception-offline-tenant-intermediate-dir is configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	safe := sanitizeRootKey(tenantKey)
	sealedKey, err := maybeSealInterceptionKeyForDisk(keyPEM)
	if err != nil {
		return fmt.Errorf("seal intermediate key: %w", err)
	}
	for name, content := range map[string][]byte{
		safe + ".root.pem":         rootPEM,
		safe + ".intermediate.pem": interPEM,
		safe + ".key.pem":          sealedKey,
	} {
		mode := os.FileMode(0o600)
		if err := os.WriteFile(filepath.Join(dir, name), content, mode); err != nil {
			return err
		}
	}
	return nil
}

// LoadOfflineTenantIntermediatesFromDir restores every per-tenant bundle written by the route above. Called at
// boot BEFORE traffic, because the alternative is a node that starts refusing organizations it was serving
// five seconds earlier.
//
// A bundle that cannot be loaded is REPORTED AND SKIPPED, not fatal: one organization's expired intermediate
// must not stop the node from serving every other organization, and a diagnostic that turns a running
// deployment into a crash loop is worse than the defect it finds. The skipped tenant then fails closed, which
// is the same answer as having no bundle at all, and it is loud in the log.
func (interception *NetworkExtensionLabTLSInterception) LoadOfflineTenantIntermediatesFromDir(dir string) (int, error) {
	if interception == nil {
		return 0, fmt.Errorf("interception not enabled")
	}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return 0, nil
	}
	interception.SetOfflineTenantIntermediateDir(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	// Revocations FIRST, so a bundle that survived on disk cannot be restored ahead of the record that says it
	// is dead. Ordering is the whole difference between a revocation and a suggestion.
	interception.restoreRevocations(dir, entries)
	loaded := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".root.pem") {
			continue
		}
		tenant := strings.TrimSuffix(name, ".root.pem")
		rootPEM, rerr := os.ReadFile(filepath.Join(dir, name))
		interPEM, ierr := os.ReadFile(filepath.Join(dir, tenant+".intermediate.pem"))
		rawKey, kerr := os.ReadFile(filepath.Join(dir, tenant+".key.pem"))
		if rerr != nil || ierr != nil || kerr != nil {
			log.Printf("network_extension_lab_tls WARNING offline_tenant_intermediate_incomplete tenant=%q root=%v intermediate=%v key=%v "+
				"(this organization will NOT be intercepted until a complete bundle is loaded)", tenant, rerr, ierr, kerr)
			continue
		}
		keyPEM, uerr := maybeUnsealInterceptionKeyFromDisk(rawKey)
		if uerr != nil {
			log.Printf("network_extension_lab_tls WARNING offline_tenant_intermediate_unseal_failed tenant=%q err=%v "+
				"(this organization will NOT be intercepted; the KEK that sealed it is not the one configured now)", tenant, uerr)
			continue
		}
		// Restore the overlap BEFORE the bundle, so loading the current issuer does not see an empty retiring
		// set and conclude there is nothing to keep announcing.
		interception.restoreRetiringTenantRoots(dir, normalizeInterceptionTenantKey(tenant))
		if _, err := interception.LoadOfflineTenantIntermediate(tenant, rootPEM, interPEM, keyPEM); err != nil {
			log.Printf("network_extension_lab_tls WARNING offline_tenant_intermediate_rejected tenant=%q err=%v "+
				"(this organization will NOT be intercepted)", tenant, err)
			continue
		}
		loaded++
	}
	return loaded, nil
}

// SetOfflinePrimaryTenant names the organization the node-wide offline intermediate belongs to, so that tenant
// keeps signing under the anchor its devices ALREADY trust once per-tenant issuers appear. Without it, turning
// per-tenant signing on would fail closed for the one organization that was working.
func (interception *NetworkExtensionLabTLSInterception) SetOfflinePrimaryTenant(tenantID string) {
	if interception == nil {
		return
	}
	interception.issuerMu.Lock()
	interception.offlinePrimaryTenant = strings.TrimSpace(tenantID)
	interception.issuerMu.Unlock()
}

// OfflinePrimaryTenant reports which organization the node-wide offline intermediate belongs to. Exposed so
// the admin inventory can attribute that certificate to its owner instead of showing it to every tenant as
// theirs — an interception root with no owner reads as "the provider decrypts you", which is what this product
// says it does not do.
func (interception *NetworkExtensionLabTLSInterception) OfflinePrimaryTenant() string {
	if interception == nil {
		return ""
	}
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	return interception.offlinePrimaryTenant
}

// OfflineTenantInterceptionRoots reports, per organization, the anchor its devices must trust and when the
// intermediate signing for it expires. An anchor nobody can export is an anchor nobody deploys, and an
// intermediate whose expiry nobody can see is the outage that arrives on a date of its own choosing.
type OfflineTenantInterceptionIssuer struct {
	Tenant          string `json:"tenant"`
	RootCommonName  string `json:"root_common_name"`
	RootPEM         string `json:"root_pem"`
	RootSHA256      string `json:"root_sha256"`
	IntermediateCN  string `json:"intermediate_common_name"`
	IntermediateEnd string `json:"intermediate_not_after"`
	Durable         bool   `json:"durable"`
	// Retiring are roots this organization's devices are still TOLD to look for while they move off them.
	// They sign nothing. An empty list means no replacement is in progress; a non-empty one is an overlap
	// somebody has to finish, and leaving it open forever is how a "temporary" second authority becomes
	// permanent.
	Retiring []OfflineTenantRetiringRoot `json:"retiring,omitempty"`
	// Incoming are roots this organization is MOVING TO and which nothing signs under yet.
	//
	// ★★★ THIS WAS THE ONE ROOT NOTHING COULD DELIVER (2026-08-27, found while building the channel that
	// puts these into a Mac's trust store). Replacing an organization's authority is announce, MEASURE,
	// switch, withdraw: an agent reports which of the ANNOUNCED roots it found in its own store, and the
	// withdrawal gate reads those reports. OfflineTenantAnnouncedRootFingerprints names the incoming root
	// among them — so every device was told to look for a fingerprint whose certificate this surface, the
	// one that exists to hand these out, did not carry. The adoption measurement could never leave zero,
	// and the honest reading of that is not "the devices are slow": nothing had been delivered.
	Incoming []OfflineTenantIncomingRoot `json:"incoming,omitempty"`
}

// OfflineTenantIncomingRoot is one authority an organization is being moved onto, before anything signs
// under it.
type OfflineTenantIncomingRoot struct {
	CommonName string `json:"common_name"`
	SHA256     string `json:"sha256"`
	NotAfter   string `json:"not_after"`
	PEM        string `json:"pem"`
}

// OfflineTenantRetiringRoot is one authority an organization is being moved off.
type OfflineTenantRetiringRoot struct {
	CommonName string `json:"common_name"`
	SHA256     string `json:"sha256"`
	NotAfter   string `json:"not_after"`
	PEM        string `json:"pem"`
}

// ListOfflineTenantIntermediates returns those, sorted, for the admin surface.
func (interception *NetworkExtensionLabTLSInterception) ListOfflineTenantIntermediates() []OfflineTenantInterceptionIssuer {
	if interception == nil {
		return nil
	}
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	out := make([]OfflineTenantInterceptionIssuer, 0, len(interception.offlineTenantIssuers))
	for tenant, issuer := range interception.offlineTenantIssuers {
		root := interception.offlineTenantRoots[tenant]
		row := OfflineTenantInterceptionIssuer{
			Tenant:          tenant,
			IntermediateCN:  issuer.signingCert.Subject.CommonName,
			IntermediateEnd: issuer.signingCert.NotAfter.UTC().Format(time.RFC3339),
			Durable:         interception.offlineTenantIntermediateDir != "",
		}
		if root != nil {
			row.RootCommonName = root.Subject.CommonName
			row.RootSHA256 = interceptionCertSHA256Hex(root)
			row.RootPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
		}
		for _, retiring := range interception.offlineTenantRetiringRoots[tenant] {
			row.Retiring = append(row.Retiring, OfflineTenantRetiringRoot{
				CommonName: retiring.Subject.CommonName,
				SHA256:     interceptionCertSHA256Hex(retiring),
				NotAfter:   retiring.NotAfter.UTC().Format(time.RFC3339),
				PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: retiring.Raw})),
			})
		}
		for _, incoming := range interception.offlineTenantIncomingRoots[tenant] {
			row.Incoming = append(row.Incoming, OfflineTenantIncomingRoot{
				CommonName: incoming.Subject.CommonName,
				SHA256:     interceptionCertSHA256Hex(incoming),
				NotAfter:   incoming.NotAfter.UTC().Format(time.RFC3339),
				PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: incoming.Raw})),
			})
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tenant < out[j].Tenant })
	return out
}

// InterceptionIntermediateStatus reports the current leaf-issuance mode for the admin view.
// setReparentRestoreFailed records (or clears) that a persisted re-parent could not be restored at boot.
func (interception *NetworkExtensionLabTLSInterception) setReparentRestoreFailed(reason string) {
	if interception == nil {
		return
	}
	interception.issuerMu.Lock()
	interception.reparentRestoreFailedReason = reason
	interception.issuerMu.Unlock()
}

// InterceptionIntermediateStatus reports the interception CA posture, decorated with a reparent-restore-failure
// flag when one is set so the "expected MSSP root, serving self-signed" case is visible, not silent.
func (interception *NetworkExtensionLabTLSInterception) InterceptionIntermediateStatus() map[string]any {
	m := interception.interceptionIntermediateStatusBase()
	if interception == nil {
		return m
	}
	interception.issuerMu.Lock()
	reason := interception.reparentRestoreFailedReason
	interception.issuerMu.Unlock()
	if reason != "" {
		m["reparent_restore_failed"] = reason
	}
	return m
}

// InterceptionIntermediateStatusForTenant answers the same question ABOUT ONE ORGANIZATION.
//
// ★★ THE STATUS HANDLER NEVER MENTIONED A TENANT (2026-08-18, measured as an operator inside Northwind —
// which has its own root). It answered: mode=offline, intermediate_cn="Lantern DSSE Interception Issuing CA
// (tenant_reference_lab)", root_cn="Lantern DSSE MSSP Root CA v2". Every field was about a DIFFERENT
// organization's issuer and the provider's root, and nothing in the answer said so.
//
// That is the read-side twin of the write-side work: a screen asking "what intercepts THIS tenant" received
// the node's own answer and rendered it as the tenant's. The certificate inventory next door was fixed the
// same day for the same reason.
//
// The deployment-wide facts — key custody, signing counts, the node's own intermediate — are deliberately NOT
// here. They belong to whoever answers for the deployment.
func (interception *NetworkExtensionLabTLSInterception) InterceptionIntermediateStatusForTenant(tenantID string) map[string]any {
	if interception == nil {
		return map[string]any{"tenant_id": tenantID, "mode": "none",
			"detail": "interception is not enabled on this node"}
	}
	key := normalizeInterceptionTenantKey(tenantID)
	out := map[string]any{"tenant_id": strings.TrimSpace(tenantID)}

	if reason, revoked := interception.TenantInterceptionRevoked(tenantID); revoked {
		out["mode"] = "revoked"
		out["revoked_reason"] = reason
		out["detail"] = "the interception authority of this tenant was revoked here, so its traffic is not " +
			"inspected at all until a replacement is loaded"
		return out
	}
	for _, issuer := range interception.ListOfflineTenantIntermediates() {
		if normalizeInterceptionTenantKey(issuer.Tenant) != key {
			continue
		}
		out["mode"] = "own_offline_root"
		out["root_common_name"] = issuer.RootCommonName
		out["root_sha256"] = issuer.RootSHA256
		out["intermediate_common_name"] = issuer.IntermediateCN
		out["not_after"] = issuer.IntermediateEnd
		out["durable"] = issuer.Durable
		if len(issuer.Retiring) > 0 {
			out["retiring"] = issuer.Retiring
		}
		out["detail"] = "this tenant's traffic is inspected under its own root"
		return out
	}

	scope := interception.InterceptionRootScope()
	interception.issuerMu.Lock()
	primary := strings.TrimSpace(interception.offlinePrimaryTenant)
	nodeIssuer := interception.offlineIssuer
	rootCert := interception.rootCert
	interception.issuerMu.Unlock()

	if primary != "" && strings.EqualFold(primary, strings.TrimSpace(tenantID)) && nodeIssuer != nil {
		out["mode"] = "node_intermediate"
		if rootCert != nil {
			out["root_common_name"] = rootCert.Subject.CommonName
		}
		if nodeIssuer.signingCert != nil {
			out["intermediate_common_name"] = nodeIssuer.signingCert.Subject.CommonName
			out["not_after"] = nodeIssuer.signingCert.NotAfter.Format(time.RFC3339)
		}
		out["detail"] = "this tenant is inspected under the node's own intermediate — the anchor its devices " +
			"already trust — rather than a root of its own"
		return out
	}
	if scope.PerTenantSigning {
		out["mode"] = "none"
		out["detail"] = "this tenant has no interception authority of its own, and this node signs per tenant, " +
			"so its traffic is REFUSED rather than inspected under another tenant's CA"
		return out
	}
	out["mode"] = "shared"
	if rootCert != nil {
		out["root_common_name"] = rootCert.Subject.CommonName
	}
	out["detail"] = "this deployment signs every tenant under one authority"
	return out
}

func (interception *NetworkExtensionLabTLSInterception) interceptionIntermediateStatusBase() map[string]any {
	if interception == nil {
		return map[string]any{"mode": "none"}
	}
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	if interception.offlineIssuer != nil {
		c := interception.offlineIssuer.signingCert
		rootCN := ""
		if interception.rootCert != nil {
			rootCN = interception.rootCert.Subject.CommonName
		}
		return map[string]any{
			"mode":             "offline",
			"intermediate_cn":  c.Subject.CommonName,
			"not_after":        c.NotAfter.Format(time.RFC3339),
			"name_constraints": c.PermittedDNSDomains,
			"root_cn":          rootCN,
			"key_custody":      interception.keyCustody(),
		}
	}
	if interception.useIntermediate {
		// Report the intermediates that actually exist, with the facts an operator needs in order to decide
		// whether to rotate: what it is called, and when it stops working. The offline branch above has always
		// reported these; this one reported only its mode, so the screen describing the most consequential CA in
		// the system could say that an intermediate was in use and nothing whatsoever about it.
		//
		// Runtime intermediates are created per cache-tenant on first use, so an Edge that has not yet
		// intercepted anything legitimately has none. That is reported as an empty list rather than hidden,
		// because "none yet" and "not configured" look identical otherwise and mean opposite things.
		issuers := []map[string]any{}
		for tenant, issuer := range interception.interceptIssuers {
			if issuer == nil || issuer.signingCert == nil {
				continue
			}
			issuers = append(issuers, map[string]any{
				"cache_tenant": tenant,
				"common_name":  issuer.signingCert.Subject.CommonName,
				"not_before":   issuer.signingCert.NotBefore.Format(time.RFC3339),
				"not_after":    issuer.signingCert.NotAfter.Format(time.RFC3339),
			})
		}
		sort.Slice(issuers, func(i, j int) bool {
			return issuers[i]["cache_tenant"].(string) < issuers[j]["cache_tenant"].(string)
		})
		rootCN, rootNotAfter := "", ""
		if interception.rootCert != nil {
			rootCN = interception.rootCert.Subject.CommonName
			rootNotAfter = interception.rootCert.NotAfter.Format(time.RFC3339)
		}
		return map[string]any{
			"key_custody":      interception.keyCustody(),
			"mode":             "runtime",
			"intermediates":    issuers,
			"root_cn":          rootCN,
			"root_not_after":   rootNotAfter,
			"name_constraints": interception.intermediatePermittedDNS,
			// The note must follow custody, not assume it: with the hsm-agent wired the root key is in a
			// PKCS#11 token and is NOT on the Edge, so the old fixed wording became false the moment the
			// sidecar landed.
			"note": interception.rootKeyLocationNote(),
		}
	}
	return map[string]any{"mode": "direct", "note": "the root signs leaves directly (no intermediate)"}
}

// NewNetworkExtensionLabTLSInterceptionOfflineIntermediate builds an interception engine in OFFLINE-ROOT mode:
// the Edge loads a name-constrained intermediate (cert+key) signed by an offline root and the root cert (anchor).
// The root key is never present. Leaves chain [leaf, intermediate, root]; clients trust the root, so the
// intermediate can be rotated/revoked without re-distributing trust. Writes the ROOT cert to rootCACertOut (that
// is what endpoints must trust).
func NewNetworkExtensionLabTLSInterceptionOfflineIntermediate(hostPatterns []string, now func() time.Time, rootCertPEM, interCertPEM, interKeyPEM []byte, rootCACertOut string) (*NetworkExtensionLabTLSInterception, error) {
	hosts := NormalizedNetworkExtensionLabTLSHostPatterns(hostPatterns)
	if len(hosts) == 0 {
		return nil, nil
	}
	if now == nil {
		now = time.Now
	}
	issuer, root, err := loadOfflineInterceptionIssuer(rootCertPEM, interCertPEM, interKeyPEM, now)
	if err != nil {
		return nil, err
	}
	// Build a leaf key + session-ticket key exactly like the default constructor.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate lab TLS leaf key: %w", err)
	}
	var sessionTicketKeys [][32]byte
	var ticketKey [32]byte
	if _, err := rand.Read(ticketKey[:]); err == nil {
		sessionTicketKeys = [][32]byte{ticketKey}
	}
	rootPEMCopy := append([]byte(nil), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
	// The registry provider slot is filled with the intermediate (a valid provider); it is never used to mint
	// leaves because offlineIssuer short-circuits issuerFor. The anchor surfaced to clients/admin is the ROOT.
	interProvider := &staticInterceptionProvider{cert: issuer.signingCert, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.signingCert.Raw}), signer: issuer.signer}
	engine := &NetworkExtensionLabTLSInterception{
		rootCert:           root,
		rootRegistry:       NewTenantInterceptionRootRegistry(interProvider, now),
		rootCertPEM:        rootPEMCopy,
		leafKey:            leafKey,
		sessionTicketKeys:  sessionTicketKeys,
		hosts:              hosts,
		leafCache:          map[string]tls.Certificate{},
		interceptIssuers:   map[string]*InterceptionIssuer{},
		offlineIssuer:      issuer,
		now:                now,
		pinDetectThreshold: 2,
		pinnedHosts:        map[string]bool{},
		handshakeFailures:  map[string]int{},
		everSucceededHosts: map[string]bool{},
		// FAIL-SAFE DEFAULT OFF: auto-pin — a detection turning straight into a raw forward, and so into an
		// escape from interception — is enabled only by the explicit opt-in of
		// SetDynamicPinDetectionEnabled(true). Defaulting it to true would mean any path that does not call
		// Set has auto-bypass silently on.
		autoPinEnabled: false,
	}
	engine.rootCACertOutPath = strings.TrimSpace(rootCACertOut)
	if engine.rootCACertOutPath != "" {
		if err := WriteNetworkExtensionLabTLSRootCertificatePEM(engine.rootCACertOutPath, rootPEMCopy); err != nil {
			return nil, fmt.Errorf("write interception root anchor: %w", err)
		}
	}
	log.Printf("network_extension_lab_tls progress=offline_intermediate_loaded root_cn=%q intermediate_cn=%q name_constraints=%v", root.Subject.CommonName, issuer.signingCert.Subject.CommonName, issuer.signingCert.PermittedDNSDomains)
	return engine, nil
}

// keyCustody reports where the interception signing key lives and whether it can still sign, for the admin
// view. Kept on the interception type so every status branch can include it — an operator should never have to
// guess whether the crown-jewel key is in hardware or is bytes on the host.
func (interception *NetworkExtensionLabTLSInterception) keyCustody() map[string]any {
	if interception == nil {
		return map[string]any{"custody": "none", "healthy": false}
	}
	if interception.custodyChecker == nil {
		interception.custodyChecker = NewKeyCustodyChecker()
	}
	return KeyCustodyStatus(interception.custodyChecker, interception.rootRegistry.DefaultProvider(), time.Now)
}

// rootKeyLocationNote describes where the root signing key actually lives, for the admin view.
func (interception *NetworkExtensionLabTLSInterception) rootKeyLocationNote() string {
	if KeyCustodyOf(interception.rootRegistry.DefaultProvider()) == KeyCustodyFile {
		return "root key is on the Edge; rotate regenerates the intermediate from the root"
	}
	return "root key is in a PKCS#11 token (not on the Edge); rotate regenerates the intermediate, signed by the token"
}

// OfflineTenantAnnouncedRoots is every root this organization's devices should be told to look for: the one
// its traffic is signed under, plus any it is being moved OFF and has not been withdrawn from yet.
//
// The current root is first. A device that holds only one of them still matches, which is the point of the
// overlap; an operator reading the list needs to know which one is actually signing.
func (interception *NetworkExtensionLabTLSInterception) OfflineTenantAnnouncedRoots(tenantID string) []*x509.Certificate {
	if interception == nil {
		return nil
	}
	key := normalizeInterceptionTenantKey(tenantID)
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	out := []*x509.Certificate{}
	if current := interception.offlineTenantRoots[key]; current != nil {
		out = append(out, current)
	}
	out = append(out, interception.offlineTenantRetiringRoots[key]...)
	// ★ AND THE ONE THIS ORGANIZATION IS MOVING TO. Announced so its devices look for it and REPORT holding it,
	// which is the only way to know the switch is safe before making it — see offlineTenantIncomingRoots.
	out = append(out, interception.offlineTenantIncomingRoots[key]...)
	return out
}

// TenantRootFingerprints is what this node SIGNS under and what this organization is being asked to move to,
// by fingerprint. Either may be empty: no interception for that organization, or no rotation in flight.
//
// ★ SEPARATE FROM OfflineTenantAnnouncedRoots, WHICH FLATTENS THEM. That one answers "what should a device
// trust", where current, retiring and incoming are deliberately one list. A promotion gate needs the
// difference: promoting means signing under the incoming one, and a measurement that could not tell it from
// the current one would report every device as ready the moment the rotation began.
func (interception *NetworkExtensionLabTLSInterception) TenantRootFingerprints(tenantID string) (current, incoming string) {
	if interception == nil {
		return "", ""
	}
	key := normalizeInterceptionTenantKey(tenantID)
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	if c := interception.offlineTenantRoots[key]; c != nil {
		current = interceptionCertSHA256Hex(c)
	}
	// The first, because staging admits one at a time — see the control plane's Import.
	if in := interception.offlineTenantIncomingRoots[key]; len(in) > 0 && in[0] != nil {
		incoming = interceptionCertSHA256Hex(in[0])
	}
	return current, incoming
}

// WithdrawIncomingTenantRoot stops announcing a root this organization was being asked to adopt, because the
// control plane no longer holds it. Reports whether anything was announced.
//
// ★★★ A WITHDRAWAL THAT WROTE ONLY THE BOOKKEEPING (2026-08-22, measured — the staged rotation was withdrawn
// on the control plane and this node went on announcing it). The material stops carrying the incoming root the
// moment it is withdrawn, and nothing told the Edges. So every device would have gone on being asked to adopt
// a root that exists nowhere, for ever, and the readiness measurement would have gone on saying a rotation was
// in flight — a gate held open by a rotation nobody could finish or cancel.
//
// It cannot touch the root in force: that one is what this node's traffic is actually signed under.
func (interception *NetworkExtensionLabTLSInterception) WithdrawIncomingTenantRoot(tenantID string) bool {
	if interception == nil {
		return false
	}
	key := normalizeInterceptionTenantKey(tenantID)
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	if len(interception.offlineTenantIncomingRoots[key]) == 0 {
		return false
	}
	delete(interception.offlineTenantIncomingRoots, key)
	return true
}

// WithdrawRetiringTenantRoot stops announcing a root this organization has moved off. It cannot touch the root
// that is currently signing: withdrawing that would tell every one of this organization's devices to stop
// looking for the only certificate their traffic actually uses, which is not a withdrawal but an outage.
func (interception *NetworkExtensionLabTLSInterception) WithdrawRetiringTenantRoot(tenantID, sha256Hex string) (bool, error) {
	if interception == nil {
		return false, fmt.Errorf("interception not enabled")
	}
	key := normalizeInterceptionTenantKey(tenantID)
	want := strings.ToLower(strings.TrimSpace(sha256Hex))
	if key == "" || want == "" {
		return false, fmt.Errorf("tenant and root fingerprint are both required")
	}
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	if current := interception.offlineTenantRoots[key]; current != nil &&
		strings.EqualFold(interceptionCertSHA256Hex(current), want) {
		return false, fmt.Errorf("that root is the one %q is currently signed under; withdrawing it would tell "+
			"every device of that organization to stop looking for the certificate its own traffic uses", key)
	}
	kept := interception.offlineTenantRetiringRoots[key][:0:0]
	removed := false
	for _, r := range interception.offlineTenantRetiringRoots[key] {
		if strings.EqualFold(interceptionCertSHA256Hex(r), want) {
			removed = true
			log.Printf("network_extension_lab_tls progress=offline_tenant_root_withdrawn tenant=%q cn=%q sha256=%s",
				key, r.Subject.CommonName, want)
			continue
		}
		kept = append(kept, r)
	}
	interception.offlineTenantRetiringRoots[key] = kept

	// ★ AND A RETIREMENT THIS NODE KNOWS ONLY AS A FINGERPRINT (2026-08-21). A node that came up on already
	// replaced material holds no certificate for what it was signing under before — only the durable record.
	// Withdrawing has to reach that too, or the announcement keeps naming a root an operator has just
	// withdrawn, for ever, and only on the nodes that restarted.
	fingerprintKept := interception.offlineTenantRetiringFingerprints[key][:0:0]
	for _, fp := range interception.offlineTenantRetiringFingerprints[key] {
		if strings.EqualFold(strings.TrimSpace(fp), want) {
			removed = true
			log.Printf("network_extension_lab_tls progress=offline_tenant_root_withdrawn tenant=%q sha256=%s "+
				"(known from the durable record; this node holds no certificate for it)", key, want)
			continue
		}
		fingerprintKept = append(fingerprintKept, fp)
	}
	interception.offlineTenantRetiringFingerprints[key] = fingerprintKept

	if removed {
		// Unlocked deliberately after the map edit: the file must go too, or the next restart announces a root
		// an operator has just withdrawn.
		go interception.forgetRetiringTenantRootByFingerprint(key, want)
		if err := forgetRetiringRoot(interception.offlineTenantIntermediateDir, key, want); err != nil {
			log.Printf("network_extension_lab_tls WARNING withdrawal_not_recorded tenant=%q sha256=%s err=%v — "+
				"this node has stopped announcing it, and the next restart will announce it again", key, want, err)
		}
	}
	return removed, nil
}

// interceptionCertSHA256Hex is the fingerprint form every surface in this product compares roots by.
func interceptionCertSHA256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// retiringRootFileName is how a root being moved off is recorded beside its organization's bundle. The
// fingerprint is in the NAME so withdrawing one is a single unlink and two operators cannot disagree about
// which file is which root.
func retiringRootFileName(tenantKey string, cert *x509.Certificate) string {
	return sanitizeRootKey(tenantKey) + ".retiring-" + interceptionCertSHA256Hex(cert)[:16] + ".pem"
}

func (interception *NetworkExtensionLabTLSInterception) persistRetiringTenantRoot(tenantKey string, cert *x509.Certificate) error {
	interception.issuerMu.Lock()
	dir := interception.offlineTenantIntermediateDir
	interception.issuerMu.Unlock()
	if dir == "" {
		return fmt.Errorf("no -interception-offline-tenant-intermediate-dir is configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, retiringRootFileName(tenantKey, cert)),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600)
}

// restoreRetiringTenantRoots reads back the roots an organization is being moved off. Called from the same
// boot path that restores the bundles, for the same reason.
func (interception *NetworkExtensionLabTLSInterception) restoreRetiringTenantRoots(dir, tenantKey string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := sanitizeRootKey(tenantKey) + ".retiring-"
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".pem") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			continue
		}
		cert, perr := ParseInterceptionCertPEM(raw)
		if perr != nil || cert == nil {
			log.Printf("network_extension_lab_tls WARNING offline_tenant_retiring_root_unreadable tenant=%q file=%q err=%v",
				tenantKey, name, perr)
			continue
		}
		// ★ A REVOKED ROOT CAME BACK THROUGH THE RETIRING SET (2026-08-16, found on the lab). Revocation
		// removed the issuer and its bundle files, and the refusal to LOAD a revoked root is checked on the
		// bundle path — but a root being retired is persisted separately and restored by this loop, which
		// asked nothing. After a restart the organization's devices were told to trust a root this node had
		// declared compromised, listed beside its replacement. Checked here as well as at the source, because
		// a file that predates the fix is exactly the case that matters.
		fingerprint := interceptionCertSHA256Hex(cert)
		interception.issuerMu.Lock()
		reason, revoked := interception.revokedTenantRoots[fingerprint]
		interception.issuerMu.Unlock()
		if revoked {
			log.Printf("network_extension_lab_tls ★ offline_tenant_retiring_root_REFUSED tenant=%q cn=%q sha256=%s "+
				"— this root was REVOKED on this node (%s) and will not be announced to devices; removing its file",
				tenantKey, cert.Subject.CommonName, fingerprint[:16], reason)
			interception.forgetRetiringTenantRootByFingerprint(tenantKey, fingerprint)
			continue
		}
		interception.issuerMu.Lock()
		if interception.offlineTenantRetiringRoots == nil {
			interception.offlineTenantRetiringRoots = map[string][]*x509.Certificate{}
		}
		already := false
		for _, r := range interception.offlineTenantRetiringRoots[tenantKey] {
			if r.Equal(cert) {
				already = true
			}
		}
		if !already {
			interception.offlineTenantRetiringRoots[tenantKey] = append(interception.offlineTenantRetiringRoots[tenantKey], cert)
		}
		interception.issuerMu.Unlock()
		log.Printf("network_extension_lab_tls progress=offline_tenant_retiring_root_restored tenant=%q cn=%q",
			tenantKey, cert.Subject.CommonName)
	}
}

// forgetRetiringTenantRootByFingerprint removes the on-disk record of a withdrawn root. Matching by the
// fingerprint in the file NAME rather than by parsing every file: the name is what persistRetiringTenantRoot
// wrote, and re-deriving it from a parse would let a corrupt file keep a withdrawal from taking effect.
func (interception *NetworkExtensionLabTLSInterception) forgetRetiringTenantRootByFingerprint(tenantKey, sha256Hex string) {
	interception.issuerMu.Lock()
	dir := interception.offlineTenantIntermediateDir
	interception.issuerMu.Unlock()
	if dir == "" {
		return
	}
	name := sanitizeRootKey(tenantKey) + ".retiring-" + strings.ToLower(sha256Hex)[:16] + ".pem"
	if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
		log.Printf("network_extension_lab_tls WARNING offline_tenant_retiring_root_still_on_disk tenant=%q file=%q err=%v "+
			"(withdrawn from this process; a restart would announce it again)", tenantKey, name, err)
	}
}

// RevokeTenantInterceptionAuthority is what a LEAK needs, and it is deliberately not what withdrawal does.
//
// Withdrawal ends a planned replacement and REFUSES to touch the root currently signing, because telling an
// organization's devices to stop looking for the certificate their traffic uses is an outage. A compromised
// key inverts that: the outage is the correct outcome. Signing with it must stop immediately, it must stop
// being announced, and it must not be loadable again — including by a well-meaning restore of the bundle that
// is still sitting on disk.
//
// The organization is FAIL-CLOSED afterwards: no issuer, so its traffic is not intercepted until a
// replacement is loaded. That is visible and recoverable. Continuing to sign with a key somebody else may hold
// is neither.
//
// The revoked fingerprints are remembered DURABLY. A revocation a restart forgets is the worst of both: the
// operator believes the key is dead, and the node quietly starts using it again the next time it boots.
func (interception *NetworkExtensionLabTLSInterception) RevokeTenantInterceptionAuthority(tenantID, reason string) ([]string, error) {
	if interception == nil {
		return nil, fmt.Errorf("interception not enabled")
	}
	key := normalizeInterceptionTenantKey(tenantID)
	if key == "" {
		return nil, fmt.Errorf("tenant is required")
	}
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("a reason is required: a revoked authority is read months later by somebody " +
			"deciding whether it may come back, and \"revoked\" alone does not answer that")
	}
	interception.issuerMu.Lock()
	revoked := []string{}
	if current := interception.offlineTenantRoots[key]; current != nil {
		revoked = append(revoked, interceptionCertSHA256Hex(current))
	}
	for _, retiring := range interception.offlineTenantRetiringRoots[key] {
		revoked = append(revoked, interceptionCertSHA256Hex(retiring))
	}
	if len(revoked) == 0 {
		interception.issuerMu.Unlock()
		return nil, fmt.Errorf("%q has no interception authority on this node to revoke", tenantID)
	}
	delete(interception.offlineTenantIssuers, key)
	delete(interception.offlineTenantRoots, key)
	delete(interception.offlineTenantRetiringRoots, key)
	if interception.revokedTenantRoots == nil {
		interception.revokedTenantRoots = map[string]string{}
	}
	for _, fingerprint := range revoked {
		interception.revokedTenantRoots[fingerprint] = reason
	}
	// The ORGANIZATION, not only the fingerprints: removing the issuer alone empties the per-tenant map, which
	// this node reads as "per-tenant signing is off" and answers by signing under the deployment's own
	// authority instead. See revokedTenants.
	if interception.revokedTenants == nil {
		interception.revokedTenants = map[string]string{}
	}
	interception.revokedTenants[key] = reason
	dir := interception.offlineTenantIntermediateDir
	interception.issuerMu.Unlock()

	// Leaves minted under the revoked authority must not be served again from cache.
	interception.mu.Lock()
	interception.leafCache = map[string]tls.Certificate{}
	interception.mu.Unlock()

	if dir != "" {
		// The retiring roots are persisted one file each, separately from the bundle, and deleting the bundle
		// left them behind — so a restart restored a revoked root and announced it to devices beside its
		// replacement. Removed by fingerprint here as well as refused on restore: one stops it recurring, the
		// other repairs a node that already has the file.
		for _, fingerprint := range revoked {
			interception.forgetRetiringTenantRootByFingerprint(key, fingerprint)
		}
		if err := interception.persistRevocation(dir, key, revoked, reason); err != nil {
			log.Printf("network_extension_lab_tls ★ WARNING interception_revocation_not_durable tenant=%q err=%v — "+
				"the authority is dead in THIS process only; a restart would load it again from disk. Remove the "+
				"bundle files by hand before restarting.", key, err)
		}
	}
	log.Printf("network_extension_lab_tls ★ interception_authority_revoked tenant=%q roots=%v reason=%q — that "+
		"organization is NOT being intercepted until a replacement issuer is loaded, and these roots can no "+
		"longer be loaded on this node", key, revoked, reason)
	return revoked, nil
}

// revocationFileName is where a tenant's revoked fingerprints live, beside the bundles they refer to.
func revocationFileName(tenantKey string) string { return sanitizeRootKey(tenantKey) + ".revoked.json" }

type persistedRevocation struct {
	Tenant  string            `json:"tenant"`
	Reason  string            `json:"reason"`
	Revoked map[string]string `json:"revoked_sha256_reason"`
}

func (interception *NetworkExtensionLabTLSInterception) persistRevocation(dir, tenantKey string, fingerprints []string, reason string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	record := persistedRevocation{Tenant: tenantKey, Reason: reason, Revoked: map[string]string{}}
	// Merge with anything already revoked for this organization: a second revocation must not erase the first,
	// or the earlier key becomes loadable again.
	if raw, err := os.ReadFile(filepath.Join(dir, revocationFileName(tenantKey))); err == nil {
		var existing persistedRevocation
		if json.Unmarshal(raw, &existing) == nil {
			for fingerprint, why := range existing.Revoked {
				record.Revoked[fingerprint] = why
			}
		}
	}
	for _, fingerprint := range fingerprints {
		record.Revoked[fingerprint] = reason
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, revocationFileName(tenantKey)), encoded, 0o600); err != nil {
		return err
	}
	// And take the bundle out of the way, so a restore cannot walk the revoked key back in.
	safe := sanitizeRootKey(tenantKey)
	for _, name := range []string{safe + ".root.pem", safe + ".intermediate.pem", safe + ".key.pem"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// RevokedTenantInterceptionRoots reports what this node refuses to load, and why.
func (interception *NetworkExtensionLabTLSInterception) RevokedTenantInterceptionRoots() map[string]string {
	if interception == nil {
		return nil
	}
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	out := map[string]string{}
	for fingerprint, reason := range interception.revokedTenantRoots {
		out[fingerprint] = reason
	}
	return out
}

// TenantInterceptionRevoked reports whether THIS organization's interception authority was revoked here, and
// why. Distinct from RevokedTenantInterceptionRoots, which answers "may this certificate be loaded" — a
// question about material. This one answers "is this organization fail-closed", a question about the
// organization, and the two stop agreeing the moment a replacement is loaded: the old fingerprints stay
// refused for good while the organization itself recovers.
func (interception *NetworkExtensionLabTLSInterception) TenantInterceptionRevoked(tenantID string) (string, bool) {
	if interception == nil {
		return "", false
	}
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	reason, revoked := interception.revokedTenants[normalizeInterceptionTenantKey(tenantID)]
	return reason, revoked
}

// restoreRevocations reads back what this node refuses to load. Called before any bundle is restored.
func (interception *NetworkExtensionLabTLSInterception) restoreRevocations(dir string, entries []os.DirEntry) {
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".revoked.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var record persistedRevocation
		if err := json.Unmarshal(raw, &record); err != nil {
			log.Printf("network_extension_lab_tls ★ WARNING interception_revocation_unreadable file=%q err=%v — this "+
				"node cannot tell which authorities were revoked, so it may load one that was", name, err)
			continue
		}
		interception.issuerMu.Lock()
		if interception.revokedTenantRoots == nil {
			interception.revokedTenantRoots = map[string]string{}
		}
		for fingerprint, reason := range record.Revoked {
			interception.revokedTenantRoots[fingerprint] = reason
		}
		if interception.revokedTenants == nil {
			interception.revokedTenants = map[string]string{}
		}
		if strings.TrimSpace(record.Tenant) != "" && len(record.Revoked) > 0 {
			interception.revokedTenants[normalizeInterceptionTenantKey(record.Tenant)] = record.Reason
		}
		interception.issuerMu.Unlock()
		log.Printf("network_extension_lab_tls progress=interception_revocations_restored tenant=%q count=%d",
			record.Tenant, len(record.Revoked))
	}
}

// parseInterceptionCertChainPEM reads one or more certificates, SIGNING TIER FIRST. The first is what mints
// leaves; each one after it is its issuer, up to (but not including) the root.
func parseInterceptionCertChainPEM(data []byte) ([]*x509.Certificate, error) {
	out := []*x509.Certificate{}
	rest := data
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
			return nil, err
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}
	return out, nil
}

// isSelfSignedCertificate reports whether this certificate is its own issuer — a trust anchor, which a server
// has no reason to present. See the note in loadOfflineInterceptionIssuer.
func isSelfSignedCertificate(c *x509.Certificate) bool {
	if c == nil {
		return false
	}
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}

// interceptionChainWithoutTheAnchor is the chain a server should present: every certificate between the leaf
// and the trust anchor, and not the anchor itself. A cross-signed "root" that is not self-signed IS a chain
// member and is kept.
func interceptionChainWithoutTheAnchor(members ...*x509.Certificate) [][]byte {
	out := make([][]byte, 0, len(members))
	for _, c := range members {
		if c == nil || isSelfSignedCertificate(c) {
			continue
		}
		out = append(out, c.Raw)
	}
	return out
}

// interceptionMaterialMintsAVerifiableLeaf answers the question a device asks, before a device has to ask it:
// does a leaf minted under this material chain to the root we publish?
//
// It mints a throwaway leaf for a name nobody resolves, builds the pool exactly as a correctly provisioned
// device would — the announced root as the only anchor, the presented chain as the intermediates — and
// verifies. See the note at the call site for what this exists to stop.
func interceptionMaterialMintsAVerifiableLeaf(issuing *x509.Certificate, signer crypto.Signer,
	presented [][]byte, root *x509.Certificate, now time.Time) error {
	// ★ THE PROBE NAME HAS TO BE ONE THIS MATERIAL MAY SIGN. A name-constrained intermediate — which is the
	// careful way to delegate interception — permits only its own domains, so a fixed probe name would make
	// every correctly constrained authority look broken. Ask the certificate what it is allowed to sign.
	// A constraint anywhere in the chain applies, not only on the certificate that signs — so the name is
	// taken from whichever member declares one first.
	probeName := "interception-material-probe.invalid"
	constrainedBy := []*x509.Certificate{issuing}
	for _, raw := range presented {
		if c, perr := x509.ParseCertificate(raw); perr == nil {
			constrainedBy = append(constrainedBy, c)
		}
	}
	for _, c := range constrainedBy {
		if len(c.PermittedDNSDomains) == 0 {
			continue
		}
		if permitted := strings.TrimPrefix(strings.TrimSpace(c.PermittedDNSDomains[0]), "."); permitted != "" {
			probeName = "interception-material-probe." + permitted
			break
		}
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate a probe key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: probeName},
		DNSNames:  []string{probeName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuing, &leafKey.PublicKey, signer)
	if err != nil {
		return fmt.Errorf("mint a probe leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse the probe leaf: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	for _, raw := range presented {
		c, perr := x509.ParseCertificate(raw)
		if perr != nil {
			return fmt.Errorf("parse a presented chain member: %w", perr)
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: probeName, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return err
	}
	return nil
}

// AnnounceTenantInterceptionRoot tells an organization's devices to look for a root that NOTHING SIGNS UNDER
// yet, so their adoption can be measured before the switch that depends on it.
//
// ★★★ WHY THIS EXISTS (2026-08-21). An agent reports which of the ANNOUNCED interception roots it found in its
// own store. Until this, the only announced roots were the one in force and any being retired — so the first
// evidence that a new root had reached a device was the traffic that needed it. Switching blind is what took
// every site on win-dev-1 down for eighteen minutes.
//
// ★ ANNOUNCING IS NOT TRUSTING. The bundle carries fingerprints; the certificate itself is distributed out of
// band, deliberately, because a device that accepted a root because a bundle carried it would be trusting the
// wrong thing. This says "look for this and tell me if you have it", nothing more.
func (interception *NetworkExtensionLabTLSInterception) AnnounceTenantInterceptionRoot(tenantID string, rootPEM []byte) (*x509.Certificate, error) {
	if interception == nil {
		return nil, fmt.Errorf("interception not enabled")
	}
	key := strings.ToLower(strings.TrimSpace(tenantID))
	if key == "" {
		return nil, fmt.Errorf("an organization must be named: a root announced to nobody is announced to everybody")
	}
	root, err := ParseInterceptionCertPEM(rootPEM)
	if err != nil {
		return nil, fmt.Errorf("read the root to announce: %w", err)
	}
	if !root.IsCA {
		return nil, fmt.Errorf("that certificate is not a CA, so no device could ever chain to it")
	}
	interception.mu.Lock()
	defer interception.mu.Unlock()
	if current := interception.offlineTenantRoots[key]; current != nil && current.Equal(root) {
		return nil, fmt.Errorf("this is already the root %q signs under, so there is nothing to announce", key)
	}
	if interception.offlineTenantIncomingRoots == nil {
		interception.offlineTenantIncomingRoots = map[string][]*x509.Certificate{}
	}
	for _, c := range interception.offlineTenantIncomingRoots[key] {
		if c.Equal(root) {
			return root, nil
		}
	}
	interception.offlineTenantIncomingRoots[key] = append(interception.offlineTenantIncomingRoots[key], root)
	log.Printf("network_extension_lab_tls progress=offline_tenant_root_announced tenant=%q incoming_cn=%q "+
		"— devices are asked to look for it and report; NOTHING signs under it yet", key, root.Subject.CommonName)
	return root, nil
}

// certFingerprintHex is the SHA-256 of a certificate, lowercase hex — the form devices are told to look for.
func certFingerprintHex(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// OfflineTenantAnnouncedRootFingerprints is every root this organization should be looking for: the one in
// force, any announced ahead of it, and any being retired — including retirements this node knows about only
// from its durable record, whose certificates it may no longer hold.
func (interception *NetworkExtensionLabTLSInterception) OfflineTenantAnnouncedRootFingerprints(tenantID string) []string {
	if interception == nil {
		return nil
	}
	key := strings.ToLower(strings.TrimSpace(tenantID))
	seen := map[string]bool{}
	out := []string{}
	add := func(fp string) {
		fp = strings.ToLower(strings.TrimSpace(fp))
		if fp == "" || seen[fp] {
			return
		}
		seen[fp] = true
		out = append(out, fp)
	}
	for _, c := range interception.OfflineTenantAnnouncedRoots(tenantID) {
		add(certFingerprintHex(c))
	}
	interception.mu.Lock()
	for _, fp := range interception.offlineTenantRetiringFingerprints[key] {
		add(fp)
	}
	interception.mu.Unlock()
	return out
}
