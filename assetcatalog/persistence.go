package assetcatalog

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// persistedCatalog is the on-disk snapshot of the OPERATOR-authored catalog. Enrolled-device endpoints are
// deliberately excluded: they are re-derived from the (separately persisted) enrolled inventory on boot via
// SyncEnrolledEndpoints. Only explicit operator aliases are persisted separately;
// they never create an endpoint without inventory. Persisting full endpoints would (a) leave stale endpoints for de-enrolled devices that
// have no delete path, and (b) rewrite the file on every auto-sync (which runs on each admin list).
type persistedCatalog struct {
	EnrolledAliases map[string]map[string]string   `json:"enrolled_aliases,omitempty"`
	Seq             int                            `json:"seq"`
	Endpoints       map[string]map[string]Endpoint `json:"endpoints"`
	Groups          map[string]map[string]Group    `json:"groups"`
	Services        map[string]map[string]Service  `json:"services"`
	Aliases         map[string]map[string]string   `json:"aliases"`
}

// SetStatePath enables durable persistence: the store loads any previously-authored catalog from path and
// persists after every operator mutation, so endpoints/groups/services authored in the Console survive an
// edge restart (they were in-memory only before, and vanished on restart).
func (s *Store) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return s.SetPersister(nil)
	}
	return s.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or shared Postgres): operator-authored
// endpoints/groups/services survive a restart — and, on a shared persister, a CP failover.
func (s *Store) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, shared := p.(contextUpdater); shared {
		raw, err := p.Load()
		if err != nil {
			return ErrPersistence
		}
		n, err := s.sharedCandidateLocked(raw)
		if err != nil {
			return ErrPersistence
		}
		s.adoptLocked(n)
		s.persister = p
		return nil
	}
	next := s.candidateLocked()
	next.persister = p
	if err := next.loadLocked(); err != nil {
		return err
	}
	s.adoptLocked(next)
	s.persister = p
	return nil
}

func (s *Store) loadLocked() error {
	if s.persister == nil {
		return nil
	}
	data, err := s.persister.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snap persistedCatalog
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	for tenant, services := range snap.Services {
		for id, service := range services {
			normalized, err := normalizeServiceTransports(service)
			if err != nil {
				return fmt.Errorf("invalid service transport in catalog snapshot: %w", err)
			}
			snap.Services[tenant][id] = normalized
		}
	}
	if snap.EnrolledAliases != nil {
		s.enrolledAliases = snap.EnrolledAliases
	}
	if snap.Endpoints != nil {
		s.endpoints = snap.Endpoints
	}
	if snap.Groups != nil {
		s.groups = snap.Groups
	}
	if snap.Services != nil {
		s.services = snap.Services
	}
	if snap.Aliases != nil {
		s.aliases = snap.Aliases
	}
	if snap.Seq > s.seq {
		s.seq = snap.Seq
	}
	return nil
}

// enrolledOwnerPrefix matches the stable id assigned to enrolled-device endpoints (enrolledEndpointID).
const enrolledOwnerPrefix = "enrolled-"

// persistLocked snapshots the operator-authored catalog. The error MUST reach the mutating caller: a
// swallowed Save meant an authored endpoint/group/service (which rules resolve against) was acknowledged
// while nothing hit disk, silently vanishing on restart. Caller holds s.mu.
func (s *Store) persistLocked() error {
	if s.persister == nil {
		return nil
	}
	snap := s.authoredStateLocked()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal asset-catalog snapshot: %w", err)
	}
	if err := s.persister.Save(data); err != nil {
		return fmt.Errorf("persist asset catalog: %w", err)
	}
	return nil
}

func (s *Store) authoredStateLocked() persistedCatalog {
	snap := persistedCatalog{
		Seq:             s.seq,
		EnrolledAliases: s.enrolledAliases,
		Endpoints:       map[string]map[string]Endpoint{},
		Groups:          s.groups,
		Services:        s.services,
		Aliases:         map[string]map[string]string{},
	}
	for tenant, byID := range s.endpoints {
		for id, e := range byID {
			if e.Source == SourceEnrolled {
				continue
			}
			if snap.Endpoints[tenant] == nil {
				snap.Endpoints[tenant] = map[string]Endpoint{}
			}
			snap.Endpoints[tenant][id] = e
		}
	}
	for tenant, byAlias := range s.aliases {
		for alias, ownerID := range byAlias {
			if strings.HasPrefix(ownerID, enrolledOwnerPrefix) && s.enrolledAliases[tenant][ownerID] != alias {
				continue
			}
			if snap.Aliases[tenant] == nil {
				snap.Aliases[tenant] = map[string]string{}
			}
			snap.Aliases[tenant][alias] = ownerID
		}
	}
	return snap
}
