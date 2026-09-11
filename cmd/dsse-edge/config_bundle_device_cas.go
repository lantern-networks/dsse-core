package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// config_bundle_device_cas.go — carrying the device-CA registry from the control plane to the Edges.
//
// ★★★ THIS REGISTRY IS THE ENTRANCE TO EVERY DECISION. It answers "which organization does this certificate
// belong to", and the Edge takes a device's organization from the CA that issued its certificate rather than
// from anything the device says. Get it wrong in one direction and a customer's laptop is identified as
// somebody else's fleet; get it wrong in the other and that organization stops being admitted at all.
//
// ★★★ AND ITS AUTHORITY WAS ON THE WRONG SIDE (2026-08-23, measured). The flag was on the two ENFORCEMENT
// Edges and not on the control plane, so the registry was authored where it is enforced. The Edges kept it in
// agreement by sharing one Postgres row — a whole-snapshot blob keyed only by store name, with no node in the
// key — which is the shape behind an anchor that flapped between two Edges sharing one store, and which is why
// every enforcement node holds a database connection.
//
// It travels in the signed bundle now: the control plane authors, every Edge takes the same view.
//
// ★★★ AN EMPTY SECTION NEVER REMOVES ANYTHING, and this reverses the rule the Site catalogue follows two files
// over. The asymmetry is deliberate and it is about what "empty" COSTS:
//
//   - An empty Site catalogue stops NEW connectors enrolling. Refusing growth.
//   - An empty device-CA registry stops EVERY DEVICE of EVERY organization at the handshake. Fleet down.
//
// A control plane that has lost its registry, or that was never given one, publishes empty — and this
// deployment has already had exactly that shape: the flag was absent from the control plane while the fleet's
// registry lived on the Edges. Applying that as "there are none" would have been a total outage authored by a
// missing flag. So removals are per organization and only from a section that NAMES that organization.
//
// The withdrawal route stays. Retiring a CA is an act with a decision behind it, and it travels as one.

// deviceCARegistryBundle carries the device-CA registry as the registry's own snapshot format.
type deviceCARegistryBundle struct {
	// CP-declared ownership, available before an Edge has fetched its signer.
	ManagedTenants  []string `json:"managed_tenants"`
	ManagedComplete bool     `json:"managed_complete"`
	// Snapshot is tenantca.TenantCARegistryFile as the registry itself writes it, so the two cannot drift.
	Snapshot json.RawMessage `json:"snapshot"`
	// Tenants names the organizations this section SPEAKS FOR. An organization not named here is one the
	// control plane has said nothing about, and this Edge leaves it exactly as it is.
	Tenants []string `json:"tenants"`
	// Complete says the publisher could read its whole registry. False means "I could not look", which must
	// never be read as "there is nothing".
	Complete bool `json:"complete"`
}

// deviceCABundleSection builds the section the control plane publishes, or nil when this node holds no registry
// — then it is not the authority for device CAs and must not appear to be one.
func deviceCABundleSection(reg *tenantca.TenantCARegistry, managed *tenantDeviceAuthority) *deviceCARegistryBundle {
	if reg == nil {
		return nil
	}
	snapshot, err := reg.Snapshot()
	if err != nil || len(snapshot) == 0 {
		return nil
	}
	section := &deviceCARegistryBundle{Snapshot: snapshot, Tenants: []string{}, Complete: true}
	source, err := managed.materialSnapshot()
	if managed == nil && cpStateBlobDB != nil {
		// A missing flag on one CP is not evidence that the shared deployment
		// owns no organizations. Read the common store even without a signer.
		rows, _, readErr := readAuthoritySnapshot((postgresBlobPersister{db: cpStateBlobDB, key: "tenant_device_authorities"}).Load, deviceAuthorityRowKey, nil)
		err = readErr
		if err == nil {
			source = &tenantDeviceAuthority{cas: rows}
		}
	}
	if err != nil {
		section.Complete = false
		return section
	}
	section.ManagedComplete = true
	section.ManagedTenants = []string{}
	if source != nil {
		section.ManagedTenants = source.Organizations()
	}
	for tenant := range reg.Registrations() {
		if t := strings.TrimSpace(tenant); t != "" {
			section.Tenants = append(section.Tenants, t)
		}
	}
	return section
}

// applyDeviceCABundleSection makes this Edge's registry match the control plane's, for the organizations the
// section speaks for. Returns how many anchors were added and removed.
//
// ★ ADDING COMES FIRST, and removal only for organizations the section named. An anchor this Edge holds for an
// organization the control plane did not mention stays: the section is a statement about what it looked at,
// never about the rest of the world.
func applyDeviceCABundleSection(reg *tenantca.TenantCARegistry, section *deviceCARegistryBundle,
	persist func(*tenantca.TenantCARegistry) error, logf func(string, ...interface{})) (added, removed int) {
	deviceCAUpdateMu.Lock()
	defer deviceCAUpdateMu.Unlock()
	if section != nil && !section.ManagedComplete {
		if logf != nil {
			logf("config_bundle_device_cas_kept_local reason=%q", "the control plane did not identify its managed organizations")
		}
		return 0, 0
	}
	managed := map[string]bool{}
	if section != nil {
		for _, tenant := range section.ManagedTenants {
			managed[strings.ToLower(strings.TrimSpace(tenant))] = true
		}
	}
	// For managed tenants the material route carries BOTH managed and registered
	// CAs from the CP. Applying the independent registry section here could undo a
	// newer retirement or BYO withdrawal; its changes arrive through material too.
	if section != nil {
		var doc tenantca.TenantCARegistryFile
		if json.Unmarshal(section.Snapshot, &doc) == nil {
			kept := doc.Tenants[:0]
			for _, entry := range doc.Tenants {
				if !managed[strings.ToLower(strings.TrimSpace(entry.TenantID))] && !reg.MaterialManaged(entry.TenantID) && tenantDeviceIdentity.For(entry.TenantID) == nil {
					kept = append(kept, entry)
				}
			}
			doc.Tenants = kept
			copySection := *section
			copySection.Snapshot, _ = json.Marshal(doc)
			copySection.Tenants = nil
			for _, tenant := range section.Tenants {
				if !managed[strings.ToLower(strings.TrimSpace(tenant))] && !reg.MaterialManaged(tenant) && tenantDeviceIdentity.For(tenant) == nil {
					copySection.Tenants = append(copySection.Tenants, tenant)
				}
			}
			section = &copySection
		}
	}
	if reg == nil || section == nil || !section.Complete {
		if section != nil && !section.Complete && logf != nil {
			logf("config_bundle_device_cas_kept_local reason=%q",
				"the control plane did not report a complete device-CA registry")
		}
		return 0, 0
	}
	if len(section.Tenants) == 0 || len(section.Snapshot) == 0 {
		// Nothing named. See the file header: applying this as "there are none" would stop every device of
		// every organization at the handshake, and the likeliest cause of an empty section is a control plane
		// that was never given a registry at all.
		if logf != nil {
			logf("config_bundle_device_cas_kept_local reason=%q",
				"the control plane named no organization, and an empty registry would refuse every device")
		}
		return 0, 0
	}

	n, err := reg.Adopt(section.Snapshot)
	if err != nil {
		if logf != nil {
			logf("config_bundle_device_cas_adopt_failed err=%v", err)
		}
		return 0, 0
	}
	added = n

	// Removals, per organization the section spoke for. Which anchors the control plane holds for it, versus
	// which this Edge does.
	var doc tenantca.TenantCARegistryFile
	if err := json.Unmarshal(section.Snapshot, &doc); err != nil {
		if logf != nil {
			logf("config_bundle_device_cas_snapshot_unreadable err=%v", err)
		}
		return added, 0
	}
	// ★★★ AND ONLY ORGANIZATIONS THE SNAPSHOT ACTUALLY CARRIES AN ENTRY FOR (2026-08-23, found by planting the
	// fault). Naming an organization and carrying nothing for it is the shape a half-migrated control plane has
	// — the flag absent here, the fleet's registry still on the Edges — and reading it as "this organization
	// has no CAs" would withdraw every anchor it has. Retiring an organization's authorities is a decision and
	// travels as a withdrawal; a section that says nothing about one says nothing.
	//
	// The last-anchor guard below is a SECOND line, not this one. Planting the fault here changed nothing while
	// that guard was the only thing holding, which is how a test comes to measure a rule it does not name.
	carries := map[string]bool{}
	authored := map[string]bool{}
	for _, e := range doc.Tenants {
		if t := strings.ToLower(strings.TrimSpace(e.TenantID)); t != "" && strings.TrimSpace(e.CAPEM) != "" {
			carries[t] = true
		}
		certs, perr := tenantca.ParseCACertsPEM([]byte(e.CAPEM))
		if perr != nil {
			// One unreadable entry must not make the rest look like removals — that is how a parse error
			// becomes an outage. Report incomplete by refusing to remove anything at all.
			if logf != nil {
				logf("config_bundle_device_cas_entry_unreadable tenant=%q err=%v", e.TenantID, perr)
			}
			return added, 0
		}
		for _, cert := range certs {
			authored[tenantca.CAAnchorKey(cert)] = true
		}
	}
	named := map[string]bool{}
	for _, t := range section.Tenants {
		if key := strings.ToLower(strings.TrimSpace(t)); carries[key] {
			named[key] = true
		} else if logf != nil {
			logf("config_bundle_device_cas_named_but_empty tenant=%q reason=%q", t,
				"the control plane named this organization and carried no CA for it, so nothing was removed "+
					"— a retirement travels as a withdrawal")
		}
	}
	for _, held := range reg.AnchorsByTenant() {
		if !named[strings.ToLower(strings.TrimSpace(held.TenantID))] {
			continue // an organization the control plane said nothing about
		}
		if authored[tenantca.CAAnchorKey(held.Cert)] {
			continue
		}
		gone, remaining := reg.WithdrawAnchor(held.TenantID, tenantca.CAAnchorKey(held.Cert))
		if !gone {
			continue
		}
		if remaining == 0 {
			// ★★★ AND THE LAST ONE IS NOT REMOVED THIS WAY. An organization with no registered CA is an
			// organization whose every device is refused at the handshake. Retiring the last authority is an
			// act with a decision behind it and it travels by the withdrawal route, which carries that
			// decision; a config poll that happens to arrive with one fewer entry does not.
			if _, rerr := reg.Register(held.TenantID, encodeCertPEM(held.Cert)); rerr == nil {
				if logf != nil {
					logf("config_bundle_device_ca_kept tenant=%q subject=%q reason=%q", held.TenantID,
						held.Cert.Subject.String(),
						"it is this organization's last registered CA; removing it would refuse every one of "+
							"its devices, so a retirement has to travel as a withdrawal")
				}
				continue
			}
		}
		// ★★★ AND OUT OF THE TRUST SET, NOT ONLY THE ATTRIBUTION (2026-08-23, found by the withdrawal gate
		// refusing on exactly this ground). The registry answers "whose device is this"; what a handshake
		// verifies against is a SEPARATE pool. Removing the attribution alone would report a rotation that did
		// not happen — the CA would go on admitting devices while every screen said it had been retired.
		//
		// Same two steps, in the same order, as the withdrawal route: take it out of the trust store, then
		// rebuild the pool a handshake reads, because nothing else will.
		if trust := trustAnchorStoreOrNil(deviceClientCAs); trust != nil {
			if _, _, terr := trust.Withdraw(tenantca.CAAnchorKey(held.Cert)); terr != nil &&
				!strings.Contains(terr.Error(), "no distributed certificate has that fingerprint") {
				if logf != nil {
					logf("config_bundle_device_ca_still_trusted tenant=%q subject=%q err=%v", held.TenantID,
						held.Cert.Subject.String(), terr)
				}
			}
			if rerr := trust.Reapply(); rerr != nil && logf != nil {
				logf("config_bundle_device_ca_pool_not_rebuilt tenant=%q err=%v", held.TenantID, rerr)
			}
		}
		removed++
		// ★ BY NAME, never only a count. Removing a device CA stops those devices at the handshake, and a
		// number in a log is not something an operator can act on.
		if logf != nil {
			logf("config_bundle_device_ca_removed tenant=%q subject=%q reason=%q",
				held.TenantID, held.Cert.Subject.String(),
				"the control plane's registry does not contain it")
		}
	}

	if (added > 0 || removed > 0) && persist != nil {
		if err := persist(reg); err != nil && logf != nil {
			// Live but not durable: this node admits the right organizations now and would forget on restart.
			logf("config_bundle_device_cas_applied_but_not_persisted err=%v", err)
		}
	}
	if logf != nil && (added > 0 || removed > 0) {
		logf("config_bundle_device_cas_applied added=%d removed=%d", added, removed)
	}
	setEdgeClientRegistryCAs(reg.Anchors())
	return added, removed
}

// encodeCertPEM re-encodes a parsed certificate. Used to put back an anchor that turned out to be an
// organization's last one — the registry takes PEM, and the certificate it just handed out is the only source
// for it that cannot have drifted.
func encodeCertPEM(c *x509.Certificate) []byte {
	if c == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
