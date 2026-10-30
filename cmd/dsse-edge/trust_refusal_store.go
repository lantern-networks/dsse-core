package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// Where refusals live, and why not in the telemetry store beside them.
//
// The observed-exclusion store is memory by default and says so: an agent re-reports its effective set on
// every poll, so a restart costs nothing. Refusals are the opposite. A device clears its journal once this
// Edge has accepted them — correctly, they are the only copy and must not be lost in flight — so it will
// never send them again. Keeping them in a store that empties on restart destroys the evidence permanently,
// and an Edge restart is precisely what happens during a certificate incident.
//
// So they are kept here, durable by default off -state-dir, independent of how telemetry is stored.

type trustRefusalStore struct {
	mu      sync.Mutex
	path    string
	by      map[string][]observedTrustRefusal
	loadErr error
}

func newTrustRefusalStore(path string) *trustRefusalStore {
	s := &trustRefusalStore{path: strings.TrimSpace(path), by: map[string][]observedTrustRefusal{}}
	if s.path == "" {
		return s
	}
	blob, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("trust_refusal_store progress=load_failed detail=%v", err)
			s.loadErr = err
		}
		return s
	}
	var stored struct {
		SchemaVersion string                            `json:"schema_version"`
		By            map[string][]observedTrustRefusal `json:"by"`
	}
	if err := json.Unmarshal(blob, &stored); err != nil {
		log.Printf("trust_refusal_store progress=load_failed detail=%v", err)
		s.loadErr = err
		return s
	}
	if stored.SchemaVersion != "trust_refusal_store.v1" || stored.By == nil {
		s.loadErr = fmt.Errorf("invalid trust refusal journal schema")
		log.Printf("trust_refusal_store progress=load_failed detail=%v", s.loadErr)
		return s
	}
	for k, v := range stored.By {
		if k != "" && len(v) > 0 {
			s.by[k] = v
		}
	}
	log.Printf("trust_refusal_store progress=loaded devices=%d", len(s.by))
	return s
}

func trustRefusalKey(tenantID, identity string) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.ToLower(strings.TrimSpace(identity))
}

// Merge folds a device's report into what is already recorded and returns the result. Merging rather than
// replacing is required, not a nicety: the device empties its journal once accepted, so its very next report
// carries none, and a store that took that at face value would erase what it had just been given.
func (s *trustRefusalStore) Merge(tenantID, identity string, incoming []observedTrustRefusal) ([]observedTrustRefusal, error) {
	if s == nil || strings.TrimSpace(identity) == "" || strings.TrimSpace(tenantID) == "" {
		if len(incoming) > 0 {
			return nil, fmt.Errorf("trust refusal journal has no organization, identity, or store")
		}
		return nil, nil
	}
	key := trustRefusalKey(tenantID, identity)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil && len(incoming) > 0 {
		return nil, fmt.Errorf("trust refusal journal could not be loaded: %w", s.loadErr)
	}
	merged := mergeTrustRefusals(s.by[key], incoming)
	if len(merged) == 0 {
		return nil, nil
	}
	if len(incoming) == 0 {
		return merged, nil
	}
	if err := s.persistLocked(key, merged); err != nil {
		return nil, err
	}
	s.by[key] = merged
	return merged, nil
}

// ForTenant returns every device's refusals, device identity attached.
func (s *trustRefusalStore) ForTenant(tenantID string) map[string][]observedTrustRefusal {
	out := map[string][]observedTrustRefusal{}
	if s == nil {
		return out
	}
	prefix := strings.TrimSpace(tenantID) + "\x00"
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.by {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		out[strings.TrimPrefix(k, prefix)] = append([]observedTrustRefusal{}, v...)
	}
	return out
}

// All returns every tenant's refusals, keyed by device identity. For whoever answers for the deployment: a
// refusal that only one tenant's screen could show is a refusal nobody sees when it spans the fleet, which is
// exactly when it matters.
//
// Identities are unique across tenants (they are certificate subjects), so flattening cannot merge two
// tenants' devices into one row.
func (s *trustRefusalStore) All() map[string][]observedTrustRefusal {
	out := map[string][]observedTrustRefusal{}
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.by {
		identity := k
		if i := strings.Index(k, "\x00"); i >= 0 {
			identity = k[i+1:]
		}
		out[identity] = append(out[identity], v...)
	}
	return out
}

func (s *trustRefusalStore) persistLocked(key string, merged []observedTrustRefusal) error {
	if s.path == "" {
		return fmt.Errorf("trust refusal journal has no durable path")
	}
	candidate := make(map[string][]observedTrustRefusal, len(s.by)+1)
	for k, v := range s.by {
		candidate[k] = v
	}
	candidate[key] = merged
	blob, err := json.MarshalIndent(struct {
		SchemaVersion string                            `json:"schema_version"`
		By            map[string][]observedTrustRefusal `json:"by"`
	}{"trust_refusal_store.v1", candidate}, "", "  ")
	if err != nil {
		return err
	}
	// ★ ONE DURABLE WRITE (2026-08-14). Staged by hand and finished on a bare os.Rename — see
	// ops/checks/one_durable_write.sh: the gate matched only the copies that fsync the directory, so the
	// ones that never did were invisible to it and read as compliant.
	if err := durablefile.Write(s.path, blob, 0o600); err != nil {
		return err
	}
	return nil
}

// sortedDeviceKeys keeps the report stable across reads.
func sortedDeviceKeys(m map[string][]observedTrustRefusal) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
