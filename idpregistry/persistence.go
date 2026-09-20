package idpregistry

import (
	"encoding/json"
	"errors"
	"log"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// persistedRegistry is the snapshot: the connections (incl. the RP secret, so a restart keeps a working
// connection) plus each tenant's default.
type persistedRegistry struct {
	Connections map[string]map[string]Connection `json:"connections"`
	Defaults    map[string]string                `json:"defaults"`
}

// SetStatePath enables durable file persistence at path (historical behaviour); empty = in-memory only. A
// back-compat convenience over SetPersister(blobstore.FilePersister{...}).
func (s *Store) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return s.SetPersister(nil)
	}
	return s.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or shared Postgres): tenant IdP connections +
// defaults survive a restart — and, on a shared persister, a CP failover.
func (s *Store) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil {
		s.persister = nil
		s.authorityKnown = false
		return nil
	}
	raw, err := p.Load()
	if err != nil {
		return err
	}
	if raw == nil {
		if s.authorityKnown {
			return ErrPersistence
		}
		s.persister = p
		return nil
	}
	snap, err := decodeRegistry(raw)
	if err != nil {
		return err
	}
	s.connections, s.defaults, s.persister, s.authorityKnown = snap.Connections, snap.Defaults, p, true
	return nil
}

// ErrPersistence means a candidate could not be saved and was not published.
var ErrPersistence = errors.New("identity provider settings could not be saved")

func (s *Store) snapshotLocked() persistedRegistry {
	snapshot := persistedRegistry{Connections: make(map[string]map[string]Connection, len(s.connections)), Defaults: make(map[string]string, len(s.defaults))}
	for tenant, connections := range s.connections {
		copied := make(map[string]Connection, len(connections))
		for id, connection := range connections {
			connection.VerifiedDomains = append([]string(nil), connection.VerifiedDomains...)
			copied[id] = connection
		}
		snapshot.Connections[tenant] = copied
	}
	for tenant, id := range s.defaults {
		snapshot.Defaults[tenant] = id
	}
	return snapshot
}

func (s *Store) saveLocked(snapshot persistedRegistry) error {
	if s.persister == nil {
		return nil
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err == nil {
		err = s.persister.Save(data)
	}
	if err != nil {
		log.Printf("identity provider settings save: %v", err)
		if !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) || errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			return ErrPersistence
		}
	}
	return nil
}

// Tenant removal and bundle replacement retain their separate best-effort contract.
func (s *Store) persistLocked() {
	_ = s.saveLocked(persistedRegistry{Connections: s.connections, Defaults: s.defaults})
}
