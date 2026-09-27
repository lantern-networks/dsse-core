package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/lantern-networks/dsse-core/certreload"
	"github.com/lantern-networks/dsse-core/configversion"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

// Management-plane served-certificate admin routes (list, guarded hot rotation, S7
// versions/rollback). // Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
//
// Takes serverConfig whole: the rotation guard judges against the node's full
// served-material configuration.
func registerCertsAdminRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer) {
	mux.HandleFunc("GET /admin/certs", adminEndpoint("admin.certs.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"certs": certInventory()})
	}))
	mux.HandleFunc("PUT /admin/certs/{name}", adminEndpoint("admin.certs.write", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		// Would a DEVICE accept this? Checked BEFORE anything is written, through the same guard the
		// rollback path uses. Validity and key-match — all this path used to check — accepted the
		// certificate that stranded the fleet for 47 minutes on 2026-07-31.
		if verr := guardServedCertificateChange(config, r.PathValue("name"), req.CertPEM); verr != nil {
			writeError(w, http.StatusBadRequest, verr)
			return
		}
		certRotationMu.Lock()
		defer certRotationMu.Unlock()
		if err := preserveNamedCertVersion(r, config.CPVersions, r.PathValue("name")); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("previous certificate could not be saved in history; no replacement applied: %w", err))
			return
		}
		entry, err := rotateNamedCertLocked(r.PathValue("name"), req.CertPEM, req.KeyPEM, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// S7: version the cert+key so a bad rotation can be rolled back. The note carries non-secret
		// metadata for the (redacted) history; the payload (incl. the key) is used only by rollback.
		certNote := fmt.Sprintf("subject=%s not_after=%s fp=%s", entry.Subject, entry.NotAfter, entry.FingerprintSHA256)
		shipConfigVersionToCP(r, config.CPVersions, configversion.ResourceCertificate, r.PathValue("name"),
			configversion.ActionUpsert, certNote, certVersionSnapshot{CertPEM: req.CertPEM, KeyPEM: req.KeyPEM})
		// The versions record WHAT this node now serves; they do not record who put it there. For the
		// certificate a component presents, both questions get asked, and only one had an answer.
		recordPKIMaterialChange(writer, r, evaluator, adminTenantIDFromRequest(r),
			"certificate_replaced", "certificate", r.PathValue("name"),
			"The certificate this node serves was replaced. The previous version is retained and can be rolled back.",
			map[string]any{
				"subject":            entry.Subject,
				"not_after":          entry.NotAfter,
				"fingerprint_sha256": entry.FingerprintSHA256,
				"dns_names":          entry.DNSNames,
				"ip_addresses":       entry.IPAddresses,
			})
		writeJSON(w, http.StatusOK, entry)
	}))
	// S7: certificate history + rollback (a bad rotation that locks out peers can be reverted). The history
	// REDACTS the cert/key payload (only the note's non-secret metadata is shown); rollback uses the snapshot.
	mux.HandleFunc("GET /admin/certs/{name}/versions", adminEndpoint("admin.certs.read", func(w http.ResponseWriter, r *http.Request) {
		if config.CPVersions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("config versioning is not enabled"))
			return
		}
		versions, err := config.CPVersions.List(r.Context(), configversion.ResourceCertificate, r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		for i := range versions {
			versions[i].Payload = nil // redact cert + private key from the history listing
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
	}))
	mux.HandleFunc("POST /admin/certs/{name}/rollback", adminEndpoint("admin.certs.write", func(w http.ResponseWriter, r *http.Request) {
		if config.CPVersions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("config versioning is not enabled"))
			return
		}
		var body struct {
			VersionNo int64 `json:"version_no"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil || body.VersionNo <= 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("a positive version_no is required"))
			return
		}
		name := r.PathValue("name")
		version, ok, err := config.CPVersions.Get(r.Context(), configversion.ResourceCertificate, name, body.VersionNo)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("version %d not found", body.VersionNo))
			return
		}
		var snap certVersionSnapshot
		if err := json.Unmarshal(version.Payload, &snap); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("decode version payload: %w", err))
			return
		}
		// A stored version was acceptable when it was stored; acceptability is relative to the trust
		// distribution of the MOMENT. The certificate that caused the 2026-07-31 outage is itself a
		// version, and an anchor withdrawn since leaves an older one verifiable by nobody — so rollback
		// is admitted on today's terms, not on the terms it was saved under.
		if verr := guardServedCertificateChange(config, name, snap.CertPEM); verr != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("rollback refused: %w", verr))
			return
		}
		certRotationMu.Lock()
		defer certRotationMu.Unlock()
		if err := preserveNamedCertVersion(r, config.CPVersions, name); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("current certificate could not be saved before rollback; no replacement applied: %w", err))
			return
		}
		entry, err := rotateNamedCertLocked(name, snap.CertPEM, snap.KeyPEM, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		certNote := fmt.Sprintf("rolled back to version %d (subject=%s fp=%s)", body.VersionNo, entry.Subject, entry.FingerprintSHA256)
		shipConfigVersionToCP(r, config.CPVersions, configversion.ResourceCertificate, name, configversion.ActionRollback, certNote, snap)
		// A rollback changes what this node presents, exactly as a replacement does, and it is the operation
		// reached for DURING an incident — the moment it matters most who did it. It was the one certificate
		// change with no record of its author.
		recordPKIMaterialChange(config.Writer, r, evaluator, adminTenantIDFromRequest(r),
			"certificate_rolled_back", "certificate", name,
			"The certificate this node serves was rolled back to an earlier version.",
			map[string]any{
				"version":            body.VersionNo,
				"subject":            entry.Subject,
				"not_after":          entry.NotAfter,
				"fingerprint_sha256": entry.FingerprintSHA256,
			})
		writeJSON(w, http.StatusOK, map[string]any{"rolled_back_to": body.VersionNo, "certificate": entry})
	}))

	// Admin-managed steer exclusions (per tenant / device-group / device). The control plane is the authority;
	// the resolved set is later signed and delivered to the agent so the endpoint user cannot change it.
}

// A first replacement has no previous version until we record the material that
// is actually serving. The caller serializes this with the ensuing replacement.
func preserveNamedCertVersion(r *http.Request, client *cpConfigVersionClient, name string) error {
	if client == nil {
		return fmt.Errorf("config versioning is not enabled")
	}
	var selected *certreload.ReloadableCert
	for _, c := range certreload.Registered() {
		if deriveCertName(c.CertFile()) != name {
			continue
		}
		if selected != nil && (filepath.Clean(selected.CertFile()) != filepath.Clean(c.CertFile()) || filepath.Clean(selected.KeyFile()) != filepath.Clean(c.KeyFile())) {
			return fmt.Errorf("certificate name is ambiguous across backing files")
		}
		selected = c
	}
	if selected == nil {
		return fmt.Errorf("no registered certificate with this name")
	}
	cert, err := os.ReadFile(selected.CertFile())
	if err != nil {
		return err
	}
	key, err := os.ReadFile(selected.KeyFile())
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("current certificate backing files do not form a valid pair")
	}
	current := selected.Current()
	if current == nil || len(current.Certificate) != len(pair.Certificate) {
		return fmt.Errorf("backing certificate differs from the serving certificate")
	}
	for i, der := range current.Certificate {
		if !bytes.Equal(der, pair.Certificate[i]) {
			return fmt.Errorf("backing certificate differs from the serving certificate")
		}
	}
	entry, _ := certEntryFor(selected)
	return client.Ship(r.Context(), configversion.ResourceCertificate, name, configversion.ActionUpsert, principalIDForAudit(r),
		fmt.Sprintf("retained before change subject=%s fp=%s", entry.Subject, entry.FingerprintSHA256), certVersionSnapshot{CertPEM: string(cert), KeyPEM: string(key)})
}
