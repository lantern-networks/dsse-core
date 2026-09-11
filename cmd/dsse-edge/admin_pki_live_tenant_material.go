package main

import (
	"crypto/x509"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// Static startup files do not describe CP-distributed tenant material. Read the
// public certificates from the same indexes used for SNI selection and device
// admission. Never serialize a tls.Certificate or signer (both carry private keys).
func liveTenantPKICertificateItems(transport *transportTenantCerts, signers *tenantDeviceSigners, registry *tenantca.TenantCARegistry, now time.Time) []pkiCertificateItem {
	items := []pkiCertificateItem{}
	if transport != nil {
		transport.mu.RLock()
		seen := map[string]int{}
		for name, pair := range transport.bySNI {
			tenant := transport.tenantOf[name]
			if pair == nil || len(pair.Certificate) == 0 || tenant == "" {
				continue
			}
			cert, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				continue
			}
			item := pkiItemFromCert(cert)
			key := tenant + ":" + item.SHA256
			if idx, exists := seen[key]; exists {
				items[idx].PresentedAt = append(items[idx].PresentedAt, name)
				continue
			}
			seen[key] = len(items)
			item.ID = "transport_server:" + tenant + ":" + item.SHA256[:16]
			item.Role = "transport_server"
			item.TenantID = tenant
			item.Active = transport.refused[tenant] == "" && !transport.retiring[tenant] && now.Before(cert.NotAfter)
			if end := transport.activeDeadlineOf[tenant]; !end.IsZero() && !now.Before(end) {
				item.Active = false
			}
			item.StartupProblem = transport.refused[tenant]
			item.ChainLength = len(pair.Certificate)
			item.PresentedAt = []string{name}
			item.VerifiedBy = []string{"device_transport_anchors"}
			item.Capabilities = []string{"download"}
			items = append(items, item)
		}
		transport.mu.RUnlock()
	}
	// Install/config reconciliation holds this mutex while replacing admission and
	// attribution. The inventory must not label one generation's CA with another's owner.
	deviceCAUpdateMu.Lock()
	owners := map[string]string{}
	if registry != nil {
		for _, f := range registry.Facts(now) {
			owners[f.SHA256] = f.TenantID
		}
	}
	issuing := map[string]string{}
	if signers != nil {
		signers.mu.RLock()
		for tenant, signer := range signers.signers {
			if signer != nil {
				for _, c := range parseAllCerts(signer.CAPEM()) {
					issuing[certFingerprint(c)] = tenant
				}
			}
		}
		signers.mu.RUnlock()
	}
	edgeClientCAsMu.Lock()
	anchors := append([]*x509.Certificate(nil), edgeClientRegistryAnchors...)
	edgeClientCAsMu.Unlock()
	seen := map[string]bool{}
	for _, cert := range anchors {
		if cert == nil {
			continue
		}
		item := pkiItemFromCert(cert)
		if seen[item.SHA256] {
			continue
		}
		seen[item.SHA256] = true
		item.TenantID = owners[item.SHA256]
		item.Role = "device_client_ca"
		item.OwnerUnknown = item.TenantID == ""
		if owner := issuing[item.SHA256]; owner != "" && owner == item.TenantID {
			item.Role = "device_issuing_ca"
		}
		item.ID = item.Role + ":" + item.SHA256[:16]
		item.Active = true // this CA is in the installed admission set, even without a recent device
		item.Verifies = []string{"device_certificates"}
		item.Capabilities = []string{"download"}
		if item.Role == "device_issuing_ca" {
			// Renewal orders act on devices, not on the CA file. CP-distributed
			// issuers support the same order as a startup-file issuer. The inventory
			// route removes this deployment-wide action for tenant-scoped callers.
			item.Capabilities = append(item.Capabilities, "renew_all")
		}
		// Managed/BYO authorities use their tenant-scoped routes. The generic local
		// device-client-cas deletion cannot withdraw CP-distributed material.
		items = append(items, item)
	}
	deviceCAUpdateMu.Unlock()
	for i := range items {
		sort.Strings(items[i].PresentedAt)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func mergeLiveTenantPKIInventory(inv pkiCertificateInventory, live []pkiCertificateItem) pkiCertificateInventory {
	replace := map[string]bool{}
	for _, item := range live {
		if strings.HasPrefix(item.Role, "device_") {
			replace[item.SHA256] = true
		}
	}
	out := make([]pkiCertificateItem, 0, len(inv.Items)+len(live))
	for _, item := range inv.Items {
		if strings.HasPrefix(item.Role, "device_") && replace[item.SHA256] {
			continue
		}
		out = append(out, item)
	}
	inv.Items = append(out, live...)
	return inv
}
