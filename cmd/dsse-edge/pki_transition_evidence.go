package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// Shared identifies the PostgreSQL population backend to the ledger's checked read.
func (p postgresBlobPersister) Shared() bool { return p.db != nil }

type pkiRegionTrustProbe func(context.Context, regionEndpoint, string, string, string, string) (agentpolicy.TrustBundlePayload, error)

// Probe the public enrolment door, which presents the organization's serving
// certificate without requiring a device identity. Both normal TLS verification and
// the deployment's pinned signature are required; redirects and session reuse are off.
func probePKIRegionTrust(ctx context.Context, region regionEndpoint, tenant, serverName, anchors, publicKey string) (agentpolicy.TrustBundlePayload, error) {
	var empty agentpolicy.TrustBundlePayload
	endpoint, err := url.Parse(region.Endpoint)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && endpoint.Scheme != "wss") {
		return empty, fmt.Errorf("invalid configured region endpoint")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(anchors)) {
		return empty, fmt.Errorf("no verifiable retained transport authority")
	}
	endpoint.Scheme = "https"
	endpoint.Path = "/bootstrap/trust-bundle"
	endpoint.RawPath = ""
	endpoint.RawQuery = url.Values{"tenant": {tenant}}.Encode()
	endpoint.Fragment = ""
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: organizationEnrolmentName(serverName), MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return empty, err
	}
	response, err := client.Do(req)
	if err != nil {
		return empty, fmt.Errorf("region %s serving certificate: %w", region.Region, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return empty, fmt.Errorf("region %s did not return a verified trust bundle (HTTP %d)", region.Region, response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return empty, err
	}
	if len(raw) > 1<<20 {
		return empty, fmt.Errorf("trust bundle exceeds limit")
	}
	var envelope agentpolicy.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return empty, fmt.Errorf("region %s trust envelope: %w", region.Region, err)
	}
	payload, err := agentpolicy.VerifyTrustBundle(envelope, publicKey, 0)
	if err != nil {
		return empty, fmt.Errorf("region %s trust signature: %w", region.Region, err)
	}
	if payload.TenantID != tenant || payload.TransportServerName != serverName {
		return empty, fmt.Errorf("region %s bundle does not name the requested organization and transport name", region.Region)
	}
	return payload, nil
}

func newPKITransitionAdmission(config serverConfig) pkiTransitionAdmission {
	return newPKITransitionAdmissionWithProbe(config, probePKIRegionTrust)
}
func newPKITransitionAdmissionWithProbe(config serverConfig, probe pkiRegionTrustProbe) pkiTransitionAdmission {
	return func(change pkiAuthorityTransition) error {
		if config.AgentPolicySigner == nil || config.EnrolledLedger == nil || config.FleetConfigStatus == nil || probe == nil {
			return fmt.Errorf("pki_evidence_unavailable: shared inventory, trust signer and fleet membership are required")
		}
		observations, ok := config.ObservedExclusions.(*postgresObservedExclusionStore)
		if !ok || observations == nil || observations.db == nil {
			return fmt.Errorf("pki_evidence_unavailable: adoption source must be shared PostgreSQL telemetry, not a node-local cache")
		}
		inventory, err := config.EnrolledLedger.ListForPKI()
		if err != nil {
			return fmt.Errorf("pki_population_unavailable: %w", err)
		}
		known, err := pkiTransitionPopulation(config, change, inventory)
		if err != nil {
			return err
		}
		var registrations deviceCARegistrationSnapshot
		if change.Kind == "device" {
			registrations, err = readDeviceCARegistrations(config.TenantCARegistry, tenantCARegistryShared)
			if err != nil {
				return err
			}
			change.DeviceAdmissionCAPEM = deviceAdmissionAnchors(change.DeviceAfter, registrations)
		}
		catalog := regionMap.Catalog()
		if catalog == nil {
			catalog = config.RegionEndpoints
		}
		if catalog == nil || len(catalog.order) == 0 || len(catalog.order) > 16 {
			return fmt.Errorf("pki_fleet_unavailable: explicit region endpoints are required")
		}
		regions := catalog.allowedRegionEndpoints(nil, "")
		membership, err := pkiSingleNodeMembership(config.FleetConfigStatus, regions, time.Now())
		if err != nil {
			return err
		}
		transport := change.TransportBefore
		if change.Kind != "transport" {
			if config.TenantTransportAuthority == nil {
				return fmt.Errorf("pki_transport_unavailable: no organization transport authority")
			}
			snapshot, err := config.TenantTransportAuthority.materialSnapshot()
			if err != nil {
				return err
			}
			transport = snapshot.cas[change.Tenant]
		}
		if transport == nil {
			return fmt.Errorf("pki_transport_unavailable: organization transport authority missing")
		}
		transportState := encodeAuthoritySnapshot(map[string]*storedTenantTransportCA{change.Tenant: transport})
		roots := transport.CACertPEM
		if transport.Incoming != nil {
			roots += "\n" + transport.Incoming.CACertPEM
		}
		if change.Kind == "transport" {
			roots = change.TransportAfter.CACertPEM
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		bundles := make([]agentpolicy.TrustBundlePayload, 0, len(regions))
		for _, region := range regions {
			bundle, err := probe(ctx, region, change.Tenant, transport.ServerName, roots, config.AgentPolicySigner.PublicKeyHex())
			if err != nil {
				return fmt.Errorf("pki_fleet_not_ready: %w", err)
			}
			bundles = append(bundles, bundle)
		}
		// Read adoption after probing so all comparisons refer to the distribution just measured.
		reports, err := observations.loadTenantRows(change.Tenant)
		if err != nil {
			return fmt.Errorf("pki_adoption_unavailable: %w", err)
		}
		if err := checkPKITransitionEvidence(change, known, reports, deviceCertificates.snapshot(), bundles, time.Now()); err != nil {
			return err
		}
		// A changed population, topology or auxiliary authority requires a new judgement.
		inventory, err = config.EnrolledLedger.ListForPKI()
		if err != nil {
			return err
		}
		after, err := pkiTransitionPopulation(config, change, inventory)
		if err != nil {
			return err
		}
		if strings.Join(after, "\x00") != strings.Join(known, "\x00") {
			return fmt.Errorf("pki_population_changed: retry with the current device population")
		}
		current := regionMap.Catalog()
		if current == nil {
			current = config.RegionEndpoints
		}
		if current == nil || current.digest() != catalog.digest() {
			return fmt.Errorf("pki_regions_changed: retry with the current region map")
		}
		members, err := pkiSingleNodeMembership(config.FleetConfigStatus, regions, time.Now())
		if err != nil {
			return err
		}
		if members != membership {
			return fmt.Errorf("pki_fleet_changed: retry after membership stabilizes")
		}
		if change.Kind != "transport" {
			snapshot, err := config.TenantTransportAuthority.materialSnapshot()
			if err != nil {
				return err
			}
			if string(encodeAuthoritySnapshot(map[string]*storedTenantTransportCA{change.Tenant: snapshot.cas[change.Tenant]})) != string(transportState) {
				return fmt.Errorf("pki_transport_changed: retry against the current transport authority")
			}
		}
		if change.Kind == "device" {
			after, err := readDeviceCARegistrations(config.TenantCARegistry, tenantCARegistryShared)
			if err != nil {
				return err
			}
			if after.fingerprint() != registrations.fingerprint() {
				return fmt.Errorf("pki_device_registrations_changed: retry with the current registered CAs")
			}
		}
		return nil
	}
}

func pkiSingleNodeMembership(store *fleetConfigStatusStore, regions []regionEndpoint, now time.Time) (string, error) {
	if store == nil || !store.HasFormed(now) {
		return "", fmt.Errorf("pki_fleet_unavailable: fleet view has not formed")
	}
	wanted := map[string]bool{}
	for _, r := range regions {
		wanted[r.Region] = true
	}
	byRegion := map[string][]string{}
	for _, entry := range store.List(0, "", now) {
		if !wanted[entry.RegionID] || !entry.HaveApplied || entry.LastError != "" || entry.NodeID == "" {
			return "", fmt.Errorf("pki_fleet_unavailable: an unaccounted or unhealthy Edge is reporting")
		}
		byRegion[entry.RegionID] = append(byRegion[entry.RegionID], entry.NodeID)
	}
	ids := []string{}
	for _, r := range regions {
		if len(byRegion[r.Region]) != 1 {
			return "", fmt.Errorf("pki_fleet_unavailable: region %s must have exactly one reporting node; multi-node regional admission requires individual node evidence", r.Region)
		}
		ids = append(ids, r.Region+"/"+byRegion[r.Region][0])
	}
	sort.Strings(ids)
	return strings.Join(ids, "\x00"), nil
}

func pkiTransitionPopulation(config serverConfig, change pkiAuthorityTransition, entries []enrolledinventory.Entry) ([]string, error) {
	known := []string{}
	seen := map[string]bool{}
	connectors := connectorIdentitiesFor(config.Registry, change.Tenant)
	for _, entry := range entries {
		if !entry.Enabled {
			continue
		}
		if strings.TrimSpace(entry.TenantID) == "" {
			return nil, fmt.Errorf("pki_population_unattributed: enabled identity %s has no organization", entry.Identity)
		}
		if entry.TenantID != change.Tenant {
			continue
		}
		if change.Kind != "device" && (entry.Kind == enrolledinventory.KindService || isConnectorIdentity(connectors, entry.Identity)) {
			continue
		}
		id := strings.ToLower(strings.TrimSpace(entry.Identity))
		if id == "" || seen[id] {
			return nil, fmt.Errorf("pki_population_invalid: duplicate or empty identity")
		}
		seen[id] = true
		known = append(known, id)
	}
	if len(known) == 0 {
		return nil, fmt.Errorf("pki_population_empty: no enabled device to measure; absence is not adoption evidence")
	}
	sort.Strings(known)
	return known, nil
}

func checkPKITransitionEvidence(change pkiAuthorityTransition, known []string, reports []observedExclusionEntry, facts []deviceCertificateFact,
	bundles []agentpolicy.TrustBundlePayload, now time.Time) error {
	if len(known) == 0 || len(bundles) == 0 {
		return fmt.Errorf("pki_evidence_unavailable: population and regional bundles must be nonempty")
	}
	sinceText := ""
	requiredRoots := []string{}
	retainedDevice := map[string]bool{}
	switch change.Kind {
	case "transport":
		if change.TransportBefore == nil || change.TransportBefore.Incoming == nil || change.TransportAfter == nil {
			return fmt.Errorf("pki_transition_invalid")
		}
		sinceText = change.TransportBefore.Incoming.CreatedAt
		requiredRoots = []string{fingerprintOfFirstCert(change.TransportAfter.CACertPEM)}
	case "interception":
		if change.InterceptionBefore == nil || change.InterceptionBefore.Incoming == nil || change.InterceptionAfter == nil {
			return fmt.Errorf("pki_transition_invalid")
		}
		sinceText = change.InterceptionBefore.Incoming.ImportedAt
		requiredRoots = []string{fingerprintOfFirstCert(change.InterceptionAfter.RootPEM)}
		// Every device must also keep verifying Edges which have not applied the switch yet.
		if change.Action == "promote" {
			requiredRoots = append(requiredRoots, fingerprintOfFirstCert(change.InterceptionBefore.RootPEM))
		}
	case "device":
		if change.DeviceBefore == nil || change.DeviceBefore.Incoming == nil || change.DeviceAfter == nil {
			return fmt.Errorf("pki_transition_invalid")
		}
		sinceText = change.DeviceBefore.Incoming.CreatedAt
		for _, cert := range certificatesInPEM([]byte(deviceAnchorsOf(change.DeviceAfter))) {
			retainedDevice[certFingerprint(cert)] = true
		}
		for _, cert := range certificatesInPEM([]byte(change.DeviceAdmissionCAPEM)) {
			retainedDevice[certFingerprint(cert)] = true
		}
		if len(retainedDevice) == 0 {
			return fmt.Errorf("pki_transition_invalid: no retained device CA")
		}
	default:
		return fmt.Errorf("pki_transition_invalid: unknown authority type")
	}
	for _, fp := range requiredRoots {
		if fp == "" {
			return fmt.Errorf("pki_transition_invalid: unreadable retained CA")
		}
	}
	since, err := time.Parse(time.RFC3339, sinceText)
	if err != nil || since.After(now) {
		return fmt.Errorf("pki_transition_invalid: rotation time is unavailable")
	}
	serial := bundles[0].Serial
	if serial <= 0 {
		return fmt.Errorf("pki_distribution_unknown: no current serial")
	}
	for _, bundle := range bundles {
		if bundle.TenantID != change.Tenant || bundle.Serial != serial {
			return fmt.Errorf("pki_distribution_diverged: regions do not publish the same organization and serial")
		}
		announced := map[string]bool{}
		if change.Kind == "transport" {
			for _, cert := range certificatesInPEM([]byte(bundle.TransportCAPEM)) {
				announced[certFingerprint(cert)] = true
			}
		}
		if change.Kind == "interception" {
			for _, fp := range bundle.InterceptionRootSHA256 {
				announced[fp] = true
			}
		}
		for _, fp := range requiredRoots {
			if !announced[fp] {
				return fmt.Errorf("pki_distribution_missing: a region is not announcing every required CA")
			}
		}
	}
	latest := map[string]observedExclusionEntry{}
	for _, report := range reports {
		if report.TenantID != change.Tenant {
			continue
		}
		id := strings.ToLower(strings.TrimSpace(report.DeviceIdentity))
		if previous, exists := latest[id]; !exists || report.ReportedAt.After(previous.ReportedAt) {
			latest[id] = report
		}
	}
	strict := newObservedExclusionStore(len(known) + 1)
	for _, id := range known {
		if change.Kind == "device" {
			continue
		} // Service identities do not consume an agent trust bundle.
		report, ok := latest[strings.ToLower(id)]
		if !ok || report.ReportedAt.IsZero() || report.ReportedAt.Before(since) || report.ReportedAt.After(now) || now.Sub(report.ReportedAt) > pkiAdoptionFreshFor || report.AdoptedTrustSerial != serial {
			return fmt.Errorf("pki_adoption_not_current: %s has no fresh report for current serial %d after rotation", id, serial)
		}
		strict.Record(report)
		if change.Kind == "interception" {
			// Holding a root in the OS store does not change the profile's fixed pin.
			// An armed agent stops steering when its pinned root leaves the bundle.
			if strings.ToLower(strings.TrimSpace(report.InterceptionRootPinSHA256)) != requiredRoots[0] {
				return fmt.Errorf("pki_interception_pin_not_migrated: %s does not report the retained root as its profile pin", id)
			}
			held := map[string]bool{}
			for _, fp := range report.PinnedInterceptionRootSHA256 {
				held[fp] = true
			}
			for _, fp := range requiredRoots {
				if !held[fp] {
					return fmt.Errorf("pki_interception_not_adopted: %s has not adopted a required root", id)
				}
			}
		}
	}
	if change.Kind == "transport" {
		coverage := anchorCoverageAtSerial(serverConfig{ObservedExclusions: strict}, change.Tenant, requiredRoots[0], known, serial)
		// Operator acknowledgements must not substitute for the actual reports in this gate.
		measured := strict.TransportCAReadinessAtSerial(change.Tenant, requiredRoots[0], known, serial)
		if !coverage.SafeToCut || !measured.SafeToCut {
			return fmt.Errorf("pki_transport_not_adopted: every enabled device must report the retained CA")
		}
	}
	if change.Kind == "device" {
		latestFacts := map[string]deviceCertificateFact{}
		for _, fact := range facts {
			if fact.TenantID == change.Tenant {
				id := strings.ToLower(strings.TrimSpace(fact.Identity))
				if previous, ok := latestFacts[id]; !ok || fact.LastSeenAt > previous.LastSeenAt {
					latestFacts[id] = fact
				}
			}
		}
		for _, id := range known {
			fact, ok := latestFacts[strings.ToLower(id)]
			seen, err := time.Parse(time.RFC3339, fact.LastSeenAt)
			expiry, eerr := time.Parse(time.RFC3339, fact.NotAfter)
			if !ok || err != nil || eerr != nil || seen.Before(since) || seen.After(now) || now.Sub(seen) > pkiAdoptionFreshFor || !expiry.After(now) || !retainedDevice[fact.AnchorSHA256] {
				return fmt.Errorf("pki_device_not_migrated: %s has no fresh verified certificate under a retained CA", id)
			}
		}
	}
	return nil
}
