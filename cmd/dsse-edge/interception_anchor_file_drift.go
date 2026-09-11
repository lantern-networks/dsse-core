package main

import (
	"bytes"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// warnIfInterceptionAnchorFileHasDrifted compares the certificate sitting in -...-root-ca-cert-out with the
// anchor this Edge actually signs under, and says so when they differ.
//
// ★ THAT FILE IS WHAT OPERATORS ARE TOLD TO INSTALL, AND IT GOES STALE (measured 2026-08-16). On the reference
// lab it held 5a74ac31… ("DSSE Interception Root") while every leaf chained to 36973669… (the MSSP root the
// interception was re-parented under). The Windows handoff document tells an operator to copy that exact file
// to the machine and add it to the trust store — so following the deployment's own procedure installs a root
// that verifies nothing, every HTTPS site fails on that machine, and nothing anywhere reports a problem.
//
// It is NOT rewritten here, and that restraint is the point. In persistent-root mode this path is not an
// output at all: it is half of where the root MATERIAL lives, paired with a sibling .key.pem. Overwriting the
// certificate would leave a certificate and a private key that no longer match, and the next boot would load
// that pair as the deployment's root — a distribution fix that costs the deployment its root is worse than
// the stale file it set out to correct. The rewrite happens only where the path really is an output: the
// offline-intermediate constructor, which writes cert-only and holds no key there at all.
//
// So: warn, name both certificates, and point at the surface that is always current. The install bundle and
// GET /admin/interception-roots answer from the anchor in force and cannot drift.
func warnIfInterceptionAnchorFileHasDrifted(interception *edgeplane.NetworkExtensionLabTLSInterception, path string) {
	path = strings.TrimSpace(path)
	if interception == nil || path == "" {
		return
	}
	inForcePEM := interception.RootCertificatePEM()
	inForce, err := edgeplane.ParseInterceptionCertPEM(inForcePEM)
	if err != nil || inForce == nil {
		return
	}
	onDisk, rerr := os.ReadFile(path)
	if rerr != nil {
		// Absent is not drift: the file is written on first run, and a deployment that has not created one yet
		// has nothing to distribute wrongly.
		return
	}
	fileCert, perr := edgeplane.ParseInterceptionCertPEM(onDisk)
	if perr != nil || fileCert == nil {
		log.Printf("interception: WARNING the anchor file %q does not contain a readable certificate (%v) — anyone "+
			"following a procedure that distributes it has nothing usable; take the anchor from "+
			"GET /admin/interception-roots or /admin/tenant-install-bundle/{tenant} instead", path, perr)
		return
	}
	if bytes.Equal(fileCert.Raw, inForce.Raw) {
		return
	}
	log.Printf("interception: ★ WARNING the anchor file %q holds %q but this Edge signs under %q — a machine given "+
		"the file loses every HTTPS site, and the file looks perfectly valid. It is NOT rewritten because in "+
		"persistent-root mode that path holds the root MATERIAL and overwriting it would destroy the key. "+
		"Distribute the anchor from GET /admin/interception-roots (default_root_pem) or "+
		"/admin/tenant-install-bundle/{tenant}, which answer from the anchor in force.",
		path, fileCert.Subject.CommonName, inForce.Subject.CommonName)
}

// agentTrustedCABundle is what an agent of this organization is INSTALLED with: the interception root its
// endpoints must hold, named as its own or as the deployment's shared one.
//
// It answers from the anchor in force rather than from any file on disk, which is the whole point — the file
// the previous procedure distributed had drifted from what the Edge signs under, and nothing said so. The
// certificate travels here so the agent's trust and its configuration cannot be delivered out of step: they
// are one document.
//
// A fingerprint is included beside the certificate on purpose. It is what an operator compares by hand and
// what a device reports back, and computing it from the PEM at three different moments is how two of them end
// up disagreeing.
func agentTrustedCABundle(interception *edgeplane.NetworkExtensionLabTLSInterception, tenantID, nodeTenant string) map[string]any {
	if interception == nil {
		return nil
	}
	tenant := strings.TrimSpace(tenantID)
	if tenant == "" {
		tenant = strings.TrimSpace(nodeTenant)
	}
	rootPEM, own, commonName := "", false, ""
	for _, issuer := range interception.ListOfflineTenantIntermediates() {
		if strings.EqualFold(strings.TrimSpace(issuer.Tenant), tenant) {
			rootPEM, own, commonName = issuer.RootPEM, true, issuer.RootCommonName
		}
	}
	if rootPEM == "" {
		rootPEM = string(interception.RootCertificatePEM())
		if cert, err := edgeplane.ParseInterceptionCertPEM([]byte(rootPEM)); err == nil && cert != nil {
			commonName = cert.Subject.CommonName
		}
	}
	if strings.TrimSpace(rootPEM) == "" {
		return nil
	}
	bundle := map[string]any{
		"tenant_id":                     tenant,
		"interception_root_pem":         rootPEM,
		"interception_root_common_name": commonName,
		// False means this is the DEPLOYMENT's shared anchor because the organization has no issuer of its
		// own — correct to install today, and the thing to revisit the moment it gets one, because its
		// devices will then be shown a different CA.
		"interception_root_is_own": own,
	}
	if cert, err := edgeplane.ParseInterceptionCertPEM([]byte(rootPEM)); err == nil && cert != nil {
		bundle["interception_root_sha256"] = certFingerprint(cert)
	}
	return bundle
}

// interceptionRootsIndistinguishableByName groups the roots this node knows that share a common name.
//
// ★ A TRUST STORE SHOWS NAMES (2026-08-16). Two certificate authorities can carry the same subject, and this
// deployment has had that twice: two same-subject intermediates side by side caused an outage on 2026-08-02,
// and on the day this was written the Windows machine reported two per_tenant roots with one name and
// different keys. An operator removing "the old one" from a machine is choosing between two identical
// strings — and the wrong choice breaks every HTTPS site on it.
//
// Newly generated per-tenant roots now name their organization. This exists for the ones already in the
// field, and for the ones a CUSTOMER supplies, which this Edge cannot rename: those collisions are found by
// looking rather than prevented by naming. Reported, not resolved — the fix for a collision is a replacement,
// which goes through the announced overlap, and doing that silently is what would deserve the word outage.
func interceptionRootsIndistinguishableByName(certs map[string]string) map[string][]string {
	byName := map[string][]string{}
	for fingerprint, commonName := range certs {
		name := strings.TrimSpace(commonName)
		if name == "" {
			continue
		}
		byName[name] = append(byName[name], fingerprint)
	}
	out := map[string][]string{}
	for name, fingerprints := range byName {
		if len(fingerprints) < 2 {
			continue
		}
		sort.Strings(fingerprints)
		out[name] = fingerprints
	}
	return out
}
