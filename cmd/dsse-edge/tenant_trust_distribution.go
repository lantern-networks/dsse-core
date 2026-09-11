package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// Every region forwards this envelope unchanged. A node's certificate refresh,
// restart or local announcement counter must never author an agent trust revision.
type tenantTrustDistribution struct {
	Envelope         agentpolicy.Envelope `json:"envelope"`
	ActivateIncoming string               `json:"activate_incoming,omitempty"`
	// Zero means the introduction predates this metadata and is unknown.
	RecoveryNameSince int64 `json:"recovery_name_since,omitempty"`
}
type storedTenantTrustDistribution struct {
	Distribution tenantTrustDistribution `json:"distribution"`
}
type tenantTrustDistributionState struct {
	RecoveryHistoryVersion int                                      `json:"recovery_history_version,omitempty"`
	SchemaVersion          int                                      `json:"schema_version"`
	SerialFloor            int64                                    `json:"serial_floor"`
	Tenants                map[string]storedTenantTrustDistribution `json:"tenants"`
}

const emptyTenantTrustDistribution = `{"schema_version":1,"serial_floor":0,"tenants":{}}`

// restart-durability: cp_durable — revisions and signed envelopes live in the
// configured CP blob store; each publication reloads that durable state.
// populated-by: authored — tenant authority snapshots and verified adoption facts.
type tenantTrustDistributor struct {
	mu     sync.Mutex
	config serverConfig
	store  blobstore.Persister
	now    func() time.Time
}

func (d *tenantTrustDistributor) For(tenant string) (agentpolicy.Envelope, bool) {
	tr, err := d.config.TenantTransportAuthority.materialSnapshot()
	if err != nil {
		return agentpolicy.Envelope{}, false
	}
	in, err := d.config.TenantInterceptionAuthority.materialSnapshot()
	if err != nil {
		return agentpolicy.Envelope{}, false
	}
	all, err := d.Publish(tr, in)
	if err != nil {
		logInfof("tenant_trust_distribution unavailable: %v", err)
		return agentpolicy.Envelope{}, false
	}
	item, ok := all[tenant]
	return item.Envelope, ok
}

// Publish binds the signed public document to the same authority snapshot as the
// private material response. PostgreSQL holds source rows against concurrent CAS
// updates until the revision is durable. No network probes run in this transaction.
func (d *tenantTrustDistributor) Publish(tr *tenantTransportAuthority, in *tenantInterceptionAuthority) (map[string]tenantTrustDistribution, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.store == nil || d.config.AgentPolicySigner == nil || tr == nil {
		return nil, fmt.Errorf("trust distribution authority is unavailable")
	}
	expectedTr := encodeAuthoritySnapshot(tr.cas)
	var expectedIn []byte
	if in != nil {
		expectedIn = encodeAuthoritySnapshot(in.issuers)
	}
	sharedPEM := d.config.TrustBundleCAPEM
	var population []enrolledinventory.Entry
	tenants := map[string]bool{}
	for tenant := range tr.cas {
		tenants[tenant] = true
	}
	if in != nil {
		for tenant := range in.issuers {
			tenants[tenant] = true
		}
	}
	var raw []byte
	var save func([]byte) error
	var finish func() error = func() error { return nil }
	if pg, ok := d.store.(postgresBlobPersister); ok {
		ctx, cancel := context.WithTimeout(context.Background(), cpStateBlobDBTimeout)
		defer cancel()
		tx, err := pg.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		read := func(key string) ([]byte, error) {
			var b []byte
			err := tx.QueryRowContext(ctx, "SELECT payload FROM cp_state_blobs WHERE store_key=$1 FOR SHARE", key).Scan(&b)
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return b, err
		}
		b, err := read("tenant_transport_authorities")
		if err != nil {
			return nil, err
		}
		rows, _, err := readAuthoritySnapshot(func() ([]byte, error) { return b, nil }, transportAuthorityRowKey, tr.cas)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(encodeAuthoritySnapshot(rows), expectedTr) {
			return nil, errAuthorityConflict
		}
		if in != nil {
			b, err = read("tenant_interception_authorities")
			if err != nil {
				return nil, err
			}
			rows, _, err := readAuthoritySnapshot(func() ([]byte, error) { return b, nil }, interceptionAuthorityRowKey, in.issuers)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(encodeAuthoritySnapshot(rows), expectedIn) {
				return nil, errAuthorityConflict
			}
		}
		if d.config.TransportTrustSharedStore != nil {
			b, err = read("transport_trust")
			if err != nil {
				return nil, err
			}
			var shared transportTrustStoreState
			if err := json.Unmarshal(b, &shared); err != nil {
				return nil, fmt.Errorf("shared transport trust: %w", err)
			}
			sharedPEM = shared.AnchorsPEM
		}
		b, err = read("enrolled_inventory")
		if err != nil {
			return nil, err
		}
		if b != nil {
			population, err = enrolledinventory.DecodePKIPopulation(b)
			if err != nil {
				return nil, err
			}
		}
		if d.config.TenantModelStore != nil {
			rows, err := tx.QueryContext(ctx, "SELECT tenant_id FROM admin_tenant_models FOR SHARE")
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var tenant string
				if err := rows.Scan(&tenant); err != nil {
					rows.Close()
					return nil, err
				}
				tenants[tenant] = true
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, err
			}
		}
		// Initialize and lock the one durable revision ledger, including on first boot.
		_, err = tx.ExecContext(ctx, "INSERT INTO cp_state_blobs(store_key,payload) VALUES($1,$2) ON CONFLICT DO NOTHING", pg.key, []byte(emptyTenantTrustDistribution))
		if err != nil {
			return nil, err
		}
		if err := tx.QueryRowContext(ctx, "SELECT payload FROM cp_state_blobs WHERE store_key=$1 FOR UPDATE", pg.key).Scan(&raw); err != nil {
			return nil, err
		}
		save = func(b []byte) error {
			_, err := tx.ExecContext(ctx, "UPDATE cp_state_blobs SET payload=$2,updated_at=now() WHERE store_key=$1", pg.key, b)
			return err
		}
		finish = tx.Commit
	} else {
		// File deployments support one authority writer. Its mutexes bind this read to
		// the local authority; the distribution file separately detects other writers.
		if transportTrust != nil && d.config.TransportTrustSharedStore == nil && d.config.TransportTrustStorePath != "" {
			transportTrust.mu.Lock()
			defer transportTrust.mu.Unlock()
			sharedPEM = transportTrust.pems
		}
		source := d.config.TenantTransportAuthority
		source.mu.Lock()
		defer source.mu.Unlock()
		if err := source.refreshLocked(); err != nil {
			return nil, err
		}
		if !bytes.Equal(encodeAuthoritySnapshot(source.cas), expectedTr) {
			return nil, errAuthorityConflict
		}
		if sourceIn := d.config.TenantInterceptionAuthority; sourceIn != nil {
			sourceIn.mu.Lock()
			defer sourceIn.mu.Unlock()
			if err := sourceIn.refreshLocked(); err != nil {
				return nil, err
			}
			if !bytes.Equal(encodeAuthoritySnapshot(sourceIn.issuers), expectedIn) {
				return nil, errAuthorityConflict
			}
		}
		if d.config.EnrolledLedger != nil {
			population = d.config.EnrolledLedger.List()
		}
		if d.config.TenantModelStore != nil {
			admin := tenantModelAdminStoreOrNil(d.config.TenantModelStore)
			if admin == nil {
				return nil, fmt.Errorf("tenant population cannot be read")
			}
			rows, err := admin.List(context.Background())
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				tenants[row.TenantID] = true
			}
		}

		var err error
		raw, err = d.store.Load()
		if err != nil {
			return nil, err
		}
		save = d.store.Save
	}
	state, err := decodeTenantTrustDistributions(raw)
	if err != nil {
		return nil, err
	}
	state.RecoveryHistoryVersion = 1
	records := state.Tenants
	now := d.now()
	out := map[string]tenantTrustDistribution{}
	for tenant := range tenants {
		row := tr.cas[tenant]
		reports, err := d.reports(tenant)
		if err != nil {
			return nil, err
		}
		name := ""
		pems := strings.TrimSpace(sharedPEM) + "\n"
		if row != nil {
			name = row.ServerName
			own := strings.TrimSpace(row.CACertPEM) + "\n"
			if row.Incoming != nil {
				own += strings.TrimSpace(row.Incoming.CACertPEM) + "\n"
			}
			pems += own
			// A tenant using shared transport has no own CA to withdraw toward.
			if row.Incoming == nil && d.adopted(population, reports, tenant, name, fingerprintOfFirstCert(row.CACertPEM), 0, time.Time{}, now) {
				pems = own
			}
		}

		var roots []string
		if in != nil && in.issuers[tenant] != nil {
			issuer := in.issuers[tenant]
			roots = interceptionRootFingerprintsFromPEM(issuer.RootPEM)
			if issuer.Incoming != nil {
				roots = append(roots, interceptionRootFingerprintsFromPEM(issuer.Incoming.RootPEM)...)
			}
		} else {
			roots = nodeWideInterceptionRootFingerprints(d.config)
			if len(roots) == 0 && d.config.NetworkExtensionLabTLS == nil {
				roots = interceptionRootFingerprintsFromPEM(d.config.InterceptionAnchorPEM)
			}
		}
		recovery := ""
		if strings.TrimSpace(d.config.RenewalRecoverySNI) != "" {
			recovery = strings.TrimSpace(d.config.RenewalRecoverySNI)
			if name != "" {
				recovery = organizationRecoveryName(name)
			}
		}
		payload := agentpolicy.TrustBundlePayload{TenantID: tenant, TransportCAPEM: pems, TransportServerName: name,
			RenewalRecoveryEndpoint: d.config.TrustBundleRecoveryEndpoint, RenewalRecoverySNI: recovery,
			InterceptionRootSHA256: roots, AgentPolicyPublicKeys: d.config.AgentPolicyNextPublicKeys}
		digest := tenantTrustContentDigest(payload, d.config.AgentPolicySigner.PublicKeyHex())
		previous, exists := records[tenant]
		serial := int64(0)
		unchanged := false
		previousRecovery := ""
		if exists {
			held, err := agentpolicy.VerifyTrustBundleWithKeys(previous.Distribution.Envelope, append([]string{d.config.AgentPolicySigner.PublicKeyHex()}, d.config.AgentPolicyNextPublicKeys...), 0)
			if err != nil || held.TenantID != tenant {
				return nil, fmt.Errorf("invalid persisted trust envelope for %s", tenant)
			}
			if err := validateRecoveryIntroduction(previous.Distribution, held); err != nil {
				return nil, fmt.Errorf("invalid persisted recovery introduction for %s: %w", tenant, err)
			}
			previousRecovery = held.RenewalRecoverySNI
			serial = held.Serial
			if serial > state.SerialFloor {
				return nil, fmt.Errorf("trust revision exceeds durable serial floor")
			}
			unchanged = tenantTrustContentDigest(held, d.config.AgentPolicySigner.PublicKeyHex()) == digest
		}
		item := previous.Distribution
		if !unchanged {
			serial = state.SerialFloor
			if serial == math.MaxInt64 {
				return nil, fmt.Errorf("trust serial exhausted")
			}
			serial++
			// Migration floor exceeds the old per-node counters. Subsequent revisions
			// still depend on the durable predecessor, never on clock monotonicity.
			if floor := now.UnixMilli(); floor > serial {
				serial = floor
			}
			state.SerialFloor = serial
			payload.Serial = serial
			env, err := d.config.AgentPolicySigner.SignTrustBundlePayload(payload, now)
			if err != nil {
				return nil, err
			}
			item = tenantTrustDistribution{Envelope: env}
			if recovery != "" {
				if exists && sameRecoveryName(previousRecovery, recovery) {
					// Unrelated revisions never move the first introduction. Legacy
					// records stay unknown rather than inventing a migration date.
					item.RecoveryNameSince = previous.Distribution.RecoveryNameSince
				} else {
					item.RecoveryNameSince = serial
				}
			}
		}
		if row != nil && row.Incoming != nil {
			fp := fingerprintOfFirstCert(row.Incoming.CACertPEM)
			since, timeErr := time.Parse(time.RFC3339, row.Incoming.CreatedAt)
			if previous.Distribution.ActivateIncoming == fp || (timeErr == nil && d.adopted(population, reports, tenant, row.ServerName, fp, serial, since, now)) {
				item.ActivateIncoming = fp
			}
		}
		records[tenant] = storedTenantTrustDistribution{Distribution: item}
		out[tenant] = item
	}
	// Tenant erasure removes the public record while retaining an anonymous global floor.
	next, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, next) {
		if err := save(next); err != nil {
			return nil, err
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *tenantTrustDistributor) reports(tenant string) ([]observedExclusionEntry, error) {
	if pg, ok := d.config.ObservedExclusions.(*postgresObservedExclusionStore); ok {
		return pg.loadTenantRows(tenant)
	}
	if _, shared := d.store.(postgresBlobPersister); shared {
		return nil, fmt.Errorf("shared trust publication requires shared adoption telemetry")
	}
	if d.config.ObservedExclusions == nil {
		return nil, nil
	}
	return d.config.ObservedExclusions.Query(tenant, observedQueryFilter{}).Entries, nil
}
func (d *tenantTrustDistributor) adopted(pop []enrolledinventory.Entry, reports []observedExclusionEntry, tenant, name, fp string, serial int64, since, now time.Time) bool {
	known, err := pkiTransitionPopulation(d.config, pkiAuthorityTransition{Tenant: tenant, Kind: "transport"}, pop)
	if err != nil || len(known) == 0 || fp == "" {
		return false
	}
	for _, id := range known {
		ready := false
		for _, r := range reports {
			if !strings.EqualFold(r.TenantID, tenant) || !strings.EqualFold(r.DeviceIdentity, id) {
				continue
			}
			if r.ReportedAt.IsZero() || r.ReportedAt.After(now) || now.Sub(r.ReportedAt) > pkiAdoptionFreshFor || r.ReportedAt.Before(since) || r.AdoptedTrustSerial <= 0 || (serial > 0 && r.AdoptedTrustSerial != serial) || !strings.EqualFold(r.TransportServerNameSent, name) {
				continue
			}
			for _, held := range r.PinnedTransportCASHA256 {
				if strings.EqualFold(held, fp) {
					ready = true
				}
			}
		}
		if !ready {
			return false
		}
	}
	return true
}

func decodeTenantTrustDistributions(raw []byte) (tenantTrustDistributionState, error) {
	state := tenantTrustDistributionState{SchemaVersion: 1, Tenants: map[string]storedTenantTrustDistribution{}}
	if raw != nil {
		if err := json.Unmarshal(raw, &state); err != nil {
			return state, err
		}
	}
	if state.SchemaVersion != 1 || state.RecoveryHistoryVersion < 0 || state.RecoveryHistoryVersion > 1 || state.SerialFloor < 0 || state.Tenants == nil {
		return state, fmt.Errorf("invalid persisted tenant trust distributions")
	}
	return state, nil
}
func tenantTrustContentDigest(p agentpolicy.TrustBundlePayload, ownKey string) string {
	p.SchemaVersion = ""
	p.Serial = 0
	p.IssuedAt = ""
	normalize := func(values []string) []string {
		set := map[string]bool{}
		for _, v := range values {
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
				set[v] = true
			}
		}
		out := make([]string, 0, len(set))
		for v := range set {
			out = append(out, v)
		}
		sort.Strings(out)
		return out
	}
	p.AgentPolicyPublicKeys = normalize(append(append([]string(nil), p.AgentPolicyPublicKeys...), ownKey))
	p.InterceptionRootSHA256 = normalize(p.InterceptionRootSHA256)
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func (d *tenantTrustDistributor) CountForTenant(tenant string) (int, error) {
	if d == nil {
		return 0, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	raw, err := d.store.Load()
	if err != nil {
		return 0, err
	}
	state, err := decodeTenantTrustDistributions(raw)
	if err != nil {
		return 0, err
	}
	if _, ok := state.Tenants[tenant]; ok {
		return 1, nil
	}
	return 0, nil
}
func (d *tenantTrustDistributor) RemoveTenant(tenant string) (int, error) {
	if d == nil {
		return 0, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	raw, err := d.store.Load()
	if err != nil {
		return 0, err
	}
	state, err := decodeTenantTrustDistributions(raw)
	if err != nil {
		return 0, err
	}
	if _, ok := state.Tenants[tenant]; !ok {
		return 0, nil
	}
	delete(state.Tenants, tenant)
	next, err := json.Marshal(state)
	if err != nil {
		return 0, err
	}
	if cas, ok := d.store.(authorityCASBackend); ok {
		err = cas.CompareAndSwap(raw, next)
	} else {
		err = d.store.Save(next)
	}
	if err != nil {
		return 0, err
	}
	return 1, nil
}
