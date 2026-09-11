package idpregistry

import (
	"encoding/json"
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
	s.persister = p
	if p == nil {
		return nil
	}
	return s.loadLocked()
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
	var snap persistedRegistry
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Connections != nil {
		s.connections = snap.Connections
	}
	if snap.Defaults != nil {
		s.defaults = snap.Defaults
	}
	return nil
}

func (s *Store) persistLocked() {
	if s.persister == nil {
		return
	}
	data, err := json.MarshalIndent(persistedRegistry{Connections: s.connections, Defaults: s.defaults}, "", "  ")
	if err != nil {
		return
	}
	_ = s.persister.Save(data)
}
