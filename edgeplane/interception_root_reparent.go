package edgeplane

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Moving interception under a central (MSSP) root WITHOUT taking the signing key out of its token.
//
// The two shapes that already existed each satisfy half of what docs/pki_hierarchy_gap_2026_08_01.ja.md
// asks for, and give up the other half:
//
//   - runtime mode (today): the signing key is inside the PKCS#11 token, non-exportable ✔ — but the ROOT is
//     that same self-signed certificate, so the root lives on the Edge ✘.
//   - offline-intermediate mode: the root is held centrally ✔ — but ReloadOfflineIntermediate takes the
//     intermediate's PRIVATE KEY as a PEM, so the signing key becomes a file on the Edge ✘.
//
// There is a third shape, and it is the one the design actually describes: keep the key exactly where it is
// and RE-PARENT it. The token's key gets a new certificate — same public key, same token, now signed by the
// central root instead of by itself. Nothing is exported, nothing is generated, and the Edge stops holding a
// root because its certificate is an intermediate from that moment on.
//
// Two steps, deliberately separated by whoever holds the root:
//
//  1. the Edge emits a CSR for the key in its token (InterceptionIntermediateCSR)
//  2. the central root signs it offline, and the resulting certificate is adopted (AdoptReparentedIntermediate)
//
// Step 2 changes what every steered endpoint must already trust, so it runs behind the same reporting gate as
// every other trust change: interceptionRootSwitchGate.

// InterceptionIntermediateCSR builds a PKCS#10 request for the key the interception signer currently uses —
// whatever holds it. With a token-backed signer the private key never leaves the token: CreateCertificateRequest
// only ever asks it to sign, which is exactly what the HSM agent's /sign endpoint does.
//
// The subject carries the deployment's own name rather than the current certificate's: this request is asking
// to become an INTERMEDIATE under someone else's root, and reusing a root's common name for an intermediate
// leaves two very different certificates answering to the same name — a confusion that already cost a lab
// outage when two same-subject intermediates sat side by side (2026-08-02).
// interceptionCSRMaker is a signing key whose custodian will produce a PKCS#10 request for it. A key held
// in a token implements this; a key this process holds does not need to, because it can sign its own
// request directly. Declared as an interface so the edgeplane package does not have to know what an
// hsm-agent is.
type interceptionCSRMaker interface {
	CertificateRequestDER(commonName string, organization []string) ([]byte, error)
}

func InterceptionIntermediateCSR(interception *NetworkExtensionLabTLSInterception, commonName, organization string) ([]byte, error) {
	if interception == nil {
		return nil, fmt.Errorf("interception is not enabled on this edge")
	}
	provider := interception.rootRegistry.DefaultProvider()
	if provider == nil {
		return nil, fmt.Errorf("no interception signing provider is configured")
	}
	signer := provider.Signer()
	if signer == nil {
		return nil, fmt.Errorf("the interception signing key is not available to sign a request")
	}
	if commonName == "" {
		return nil, fmt.Errorf("a common name for the intermediate is required")
	}
	subject := pkix.Name{CommonName: commonName}
	if organization != "" {
		subject.Organization = []string{organization}
	}
	// ★ A KEY IN A TOKEN CANNOT SIGN ITS OWN REQUEST FROM HERE (2026-08-15). CreateCertificateRequest signs
	// the request body with the key it names — and when that key lives in a PKCS#11 token behind the
	// hsm-agent, signing arbitrary bytes is exactly what the purpose binding refuses (403). The agent will
	// build the request itself instead: same key, same subject, but the bytes are assembled next to the key
	// rather than handed to it. A signer that can do that says so; everything else signs locally as before.
	if maker, ok := signer.(interceptionCSRMaker); ok {
		der, err := maker.CertificateRequestDER(subject.CommonName, subject.Organization)
		if err != nil {
			return nil, fmt.Errorf("ask the signing key's custodian for a certificate request: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, signer)
	if err != nil {
		return nil, fmt.Errorf("build certificate request with the interception signing key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// AdoptReparentedIntermediate installs a certificate that a central root issued for the key this Edge ALREADY
// signs with, and makes that root the anchor endpoints verify against.
//
// The refusals are the whole point:
//
//   - a certificate whose public key is not the token's would silently move signing to a key this Edge does
//     not hold, and every interception handshake would fail at the first site
//   - a certificate not signed by the supplied root is not a re-parenting at all
//   - a certificate that is not a CA cannot issue the leaves interception mints per site
//
// The caller applies interceptionRootSwitchGate first: this function changes the anchor, and an anchor an
// endpoint does not hold breaks every site on it at once.
// reparentedRootFileName / reparentedIntermediateFileName are where a completed re-parent is persisted so it
// SURVIVES A RESTART. Without this the adopt was in-memory only, and the first redeploy silently dropped the
// Edge back to its self-signed interception root — the posture reported as migrated had rolled back
// (docs/pki_hierarchy_gap_2026_08_01.ja.md). Certificates only; the signing key is and stays in the token.
const (
	reparentedRootFileName         = "interception_reparent_root.pem"
	reparentedIntermediateFileName = "interception_reparent_intermediate.pem"
)

// AdoptReparentedIntermediate installs the re-parented certificate and, when persistDir is set, writes the
// root+intermediate there so a restart can restore this exact posture rather than reverting to self-signed.
func AdoptReparentedIntermediate(interception *NetworkExtensionLabTLSInterception, rootPEM, intermediatePEM []byte, persistDir string) error {
	// PERSIST-THEN-SWITCH. Validate the pair without mutating anything, make it durable, and only
	// then make it live — so the durable and live states can never diverge on a mid-adopt failure.
	if _, _, err := validateReparentPair(interception, rootPEM, intermediatePEM); err != nil {
		return err
	}
	// A live trust change that cannot survive a restart is REFUSED, not silently accepted: a warn-and-succeed
	// reads as "migration done", and the first redeploy reverts to the self-signed root. The state dir is not
	// optional for a durable switch.
	if strings.TrimSpace(persistDir) == "" {
		return fmt.Errorf("interception reparent requires -interception-reparent-state-dir: refusing a live trust change that cannot survive a restart")
	}
	// Persist BEFORE switching live. Both certificates are written to temp files and then renamed into place, so
	// a failure here leaves the live state untouched — nothing has changed yet, and there is nothing to unwind.
	if err := persistReparentAtomically(persistDir, rootPEM, intermediatePEM); err != nil {
		return fmt.Errorf("persist re-parent (live state untouched): %w", err)
	}
	// Persistence succeeded, so a crash during the live switch below restores exactly this posture at boot.
	return installReparentedIntermediate(interception, rootPEM, intermediatePEM)
}

// persistReparentAtomically writes the root+intermediate durably as a pair: both to temp files first (so a
// failure leaves the existing pair untouched), then renamed into place back to back. Each rename is atomic; the
// tiny window where only the root is renamed is caught on restore, which re-validates that the pair chains
// before trusting it (ReapplyPersistedReparent), so a half-applied pair falls back rather than being served.
func persistReparentAtomically(dir string, rootPEM, intermediatePEM []byte) error {
	rootTmp, err := writeReparentTemp(dir, rootPEM)
	if err != nil {
		return err
	}
	interTmp, err := writeReparentTemp(dir, intermediatePEM)
	if err != nil {
		_ = os.Remove(rootTmp)
		return err
	}
	if err := os.Rename(rootTmp, filepath.Join(dir, reparentedRootFileName)); err != nil {
		_ = os.Remove(rootTmp)
		_ = os.Remove(interTmp)
		return err
	}
	if err := os.Rename(interTmp, filepath.Join(dir, reparentedIntermediateFileName)); err != nil {
		_ = os.Remove(interTmp)
		return err
	}
	return nil
}

// writeReparentTemp writes data to a fsync'd temp file in dir and returns its path, or cleans up and errors.
func writeReparentTemp(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, ".reparent-*.tmp")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// ReapplyPersistedReparent restores a re-parent recorded by a previous adopt. Called at boot, AFTER the HSM
// provider is built (its token key is what the persisted intermediate was issued for) and before any traffic
// is served. It runs the same validation installReparentedIntermediate does — a persisted pair that no longer
// matches the token key, or fails to chain, is ignored with a loud line rather than trusted, so a device
// falls back to its provisioned self-signed root instead of presenting a chain it cannot sign under.
//
// No gate here: boot is restoring a decision an operator already made through the gated adopt, not making a
// new one. Absent files are the ordinary case (never re-parented) and say nothing.
func ReapplyPersistedReparent(interception *NetworkExtensionLabTLSInterception, persistDir string) {
	if interception == nil || strings.TrimSpace(persistDir) == "" {
		return
	}
	rootPEM, rerr := os.ReadFile(filepath.Join(persistDir, reparentedRootFileName))
	interPEM, ierr := os.ReadFile(filepath.Join(persistDir, reparentedIntermediateFileName))
	if os.IsNotExist(rerr) || os.IsNotExist(ierr) {
		return // never re-parented, or only half-written — the day-0 self-signed root stands
	}
	// From here the files EXIST: a re-parent WAS adopted, so a failure to restore it is not the day-0 case — it
	// is "the operator meant the MSSP root and we are serving the self-signed one". Record that so it shows as
	// degraded/not-ready rather than being a silent revert.
	if rerr != nil || ierr != nil {
		reason := fmt.Sprintf("persisted re-parent unreadable (root=%v inter=%v)", rerr, ierr)
		log.Printf("network_extension_lab_tls progress=interception_reparent_restore_skipped reason=unreadable root=%v inter=%v — serving self-signed; marking DEGRADED", rerr, ierr)
		interception.setReparentRestoreFailed(reason)
		return
	}
	if err := installReparentedIntermediate(interception, rootPEM, interPEM); err != nil {
		log.Printf("network_extension_lab_tls progress=interception_reparent_restore_skipped reason=%q — serving self-signed; marking DEGRADED", err.Error())
		interception.setReparentRestoreFailed(fmt.Sprintf("persisted re-parent failed validation: %v", err))
		return
	}
	interception.setReparentRestoreFailed("") // restored cleanly — clear any prior degraded flag
	log.Printf("network_extension_lab_tls progress=interception_reparent_restored — a previously adopted MSSP-issued interception root was restored at boot; the signing key stayed in its token")
}

// validateReparentPair checks a root+intermediate pair WITHOUT mutating any live or durable state, returning
// the parsed certificates so a caller can persist or apply them. Extracting validation is what lets adopt
// persist before it switches and reject a bad pair before touching anything.
func validateReparentPair(interception *NetworkExtensionLabTLSInterception, rootPEM, intermediatePEM []byte) (*x509.Certificate, *x509.Certificate, error) {
	if interception == nil {
		return nil, nil, fmt.Errorf("interception is not enabled on this edge")
	}
	root, err := ParseInterceptionCertPEM(rootPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse root certificate: %w", err)
	}
	inter, err := ParseInterceptionCertPEM(intermediatePEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse intermediate certificate: %w", err)
	}
	if !root.IsCA {
		return nil, nil, fmt.Errorf("the supplied root is not a CA")
	}
	if !inter.IsCA {
		return nil, nil, fmt.Errorf("the supplied intermediate is not a CA, so it cannot issue the per-site leaves interception mints")
	}
	if err := inter.CheckSignatureFrom(root); err != nil {
		return nil, nil, fmt.Errorf("the intermediate is not signed by the supplied root: %w", err)
	}
	// The intermediate must be able to ISSUE. CheckSignatureFrom(root) validates the ROOT's certSign, not the
	// intermediate's — and IsCA (basicConstraints CA:TRUE) does not imply keyCertSign. An intermediate minted
	// CA:TRUE but with a keyUsage that omits certSign (the "openssl did not copy the extensions" mistake behind
	// the 2026-07-31 outage) would be adopted here, then every per-site leaf would chain leaf→inter→root and be
	// REJECTED by endpoints' platform verifiers because the issuing intermediate cannot sign certificates. When
	// keyUsage is asserted it must include certSign; an absent keyUsage places no restriction, as the verifiers
	// themselves read it.
	if inter.KeyUsage != 0 && inter.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, fmt.Errorf("the intermediate's keyUsage does not include certSign, so endpoints will reject every leaf it issues")
	}
	now := interception.now().UTC()
	if now.Before(inter.NotBefore) || now.After(inter.NotAfter) {
		return nil, nil, fmt.Errorf("the intermediate is not currently valid (%s..%s)",
			inter.NotBefore.Format(time.RFC3339), inter.NotAfter.Format(time.RFC3339))
	}
	// The root is the anchor endpoints pin; an expired or not-yet-valid root fails SecTrustEvaluate on the whole
	// chain. CheckSignatureFrom verifies the root's key and CA status but NOT its dates, so check them here —
	// otherwise an expiring root passes adopt while healthy and then, re-installed by ReapplyPersistedReparent
	// after a restart past its notAfter, breaks every site instead of falling back to the self-signed root.
	if now.Before(root.NotBefore) || now.After(root.NotAfter) {
		return nil, nil, fmt.Errorf("the supplied root is not currently valid (%s..%s)",
			root.NotBefore.Format(time.RFC3339), root.NotAfter.Format(time.RFC3339))
	}
	provider := interception.rootRegistry.DefaultProvider()
	if provider == nil {
		return nil, nil, fmt.Errorf("no interception signing provider is configured")
	}
	signer := provider.Signer()
	if signer == nil {
		return nil, nil, fmt.Errorf("the interception signing key is not available")
	}
	// The certificate must belong to the key this Edge signs with. Without this check an operator could adopt
	// any CA certificate at all and the Edge would present a chain it cannot sign under.
	if err := VerifySignerMatchesCert(signer, inter); err != nil {
		return nil, nil, fmt.Errorf("the intermediate was not issued for this Edge's signing key — the key stays in its token and only its certificate changes: %w", err)
	}
	return root, inter, nil
}

// installReparentedIntermediate validates the pair and, if good, swaps it into the LIVE interception state.
// Callers that also need durability (adopt) persist first; this is the live half alone, and is what boot's
// ReapplyPersistedReparent runs to restore an already-adopted decision.
func installReparentedIntermediate(interception *NetworkExtensionLabTLSInterception, rootPEM, intermediatePEM []byte) error {
	root, inter, err := validateReparentPair(interception, rootPEM, intermediatePEM)
	if err != nil {
		return err
	}
	provider := interception.rootRegistry.DefaultProvider()
	issuer := &InterceptionIssuer{
		signingCert: inter,
		signer:      provider.Signer(),
		// [intermediate, root]: endpoints pin the root and receive the path to it. The root is included
		// because a device that has just adopted it may not have it indexed for path building yet.
		// See loadOfflineInterceptionIssuer: intermediates are presented, the anchor is not.
		chain: interceptionChainWithoutTheAnchor(inter, root),
	}

	interception.issuerMu.Lock()
	interception.offlineIssuer = issuer
	interception.interceptIssuers = map[string]*InterceptionIssuer{}
	interception.issuerMu.Unlock()

	interception.mu.Lock()
	interception.rootCert = root
	anchorPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	interception.rootCertPEM = anchorPEM
	// Leaves already minted chain to the OLD root; keeping them would serve a path endpoints no longer verify.
	interception.leafCache = map[string]tls.Certificate{}
	outPath := interception.rootCACertOutPath
	interception.mu.Unlock()

	// ★ AND THE FILE DEVICES ARE TOLD TO INSTALL FROM (2026-08-16). That file exists for exactly one purpose —
	// "this is the root to put in a machine's trust store" — and it was written once at startup and never
	// again. Measured on the reference lab AFTER its root was re-parented to the MSSP root: the Edge served
	// 36973669… and the distribution file still held 5a74ac31…. An operator following the deployment's own
	// procedure installs a root that verifies nothing, every HTTPS site fails on that machine, and the file
	// that told them to do it looks perfectly valid.
	//
	// A failure to rewrite is NOT fatal: the re-parent itself has already succeeded and is live, and undoing
	// it here would trade a stale file for a broken deployment. It is loud instead, because the next person to
	// read that file is about to trust it.
	if strings.TrimSpace(outPath) != "" {
		if err := WriteNetworkExtensionLabTLSRootCertificatePEM(outPath, anchorPEM); err != nil {
			log.Printf("network_extension_lab_tls WARNING interception_root_anchor_file_stale path=%q err=%v — the "+
				"re-parent is LIVE but the file devices are told to install still holds the previous root; anyone "+
				"who distributes it will break every HTTPS site on that machine", outPath, err)
		} else {
			log.Printf("network_extension_lab_tls progress=interception_root_anchor_file_rewritten path=%q root_cn=%q",
				outPath, root.Subject.CommonName)
		}
	}

	log.Printf("network_extension_lab_tls progress=interception_root_reparented root_cn=%q intermediate_cn=%q "+
		"not_after=%s key_custody=%s — the signing key did not move",
		root.Subject.CommonName, inter.Subject.CommonName, inter.NotAfter.Format(time.RFC3339), KeyCustodyOf(provider))
	return nil
}
