package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lantern-networks/dsse-core/blobstore"
)

var errSharedTransportTrust = errors.New("shared trust commit was not confirmed")

type transportTrustUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

// A private candidate reuses the file-store validation and mutation rules. Its
// persistence never leaves this transaction; signing only stages a future swap.
type transportTrustCandidate struct{ raw []byte }

func (p *transportTrustCandidate) Load() ([]byte, error) { return bytes.Clone(p.raw), nil }
func (p *transportTrustCandidate) Save(raw []byte) error { p.raw = bytes.Clone(raw); return nil }

func decodeSharedTransportTrust(raw []byte) (transportTrustStoreState, error) {
	var st transportTrustStoreState
	if len(bytes.TrimSpace(raw)) == 0 {
		return st, fmt.Errorf("known shared trust distribution disappeared")
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, err
	}
	if st.Serial <= 0 || len(parseAllCerts([]byte(st.AnchorsPEM))) == 0 {
		return st, fmt.Errorf("shared trust distribution has no serial or certificates")
	}
	st.AnnouncedInterception = canonicalAnnouncement(st.AnnouncedInterception)
	return st, nil
}

func mergeTransportTrustState(raw []byte, st transportTrustStoreState) ([]byte, error) {
	fields := map[string]json.RawMessage{}
	if len(raw) != 0 {
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, err
		}
	}
	encoded, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	var next map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &next); err != nil {
		return nil, err
	}
	// Optional known fields must also disappear when cleared, without removing extensions.
	for _, k := range []string{"announced_interception", "recovery_name_since", "adopted_authored_serial"} {
		delete(fields, k)
	}
	for k, v := range next {
		fields[k] = v
	}
	return json.Marshal(fields)
}

func (s *transportTrustStore) setStateLocked(st transportTrustStoreState) {
	s.pems, s.serial, s.announced = st.AnchorsPEM, st.Serial, st.AnnouncedInterception
	s.recoveryNameSince, s.adoptedAuthored = st.RecoveryNameSince, st.AdoptedAuthored
}

// Caller holds the process mutex; the database holds the row lock and accepted
// leadership term. Neither the local store nor served signatures change before
// commit confirmation. An uncertain commit must be re-read before retrying.
func (s *transportTrustStore) mutateSharedLocked(ctx context.Context, edit func(*transportTrustStore) error) (bool, error) {
	p, ok := s.shared.(transportTrustUpdater)
	if !ok {
		return false, nil
	}
	var accepted transportTrustStoreState
	var publish func()
	var rejected error
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		st, err := decodeSharedTransportTrust(raw)
		if err != nil {
			return nil, err
		}
		if st.Serial < s.serial {
			return nil, fmt.Errorf("shared trust serial regressed")
		}
		memory := &transportTrustCandidate{raw: bytes.Clone(raw)}
		candidate := &transportTrustStore{shared: memory}
		candidate.setStateLocked(st)
		candidate.resign = func(pems string, serial int64) (func(), error) {
			commit := func() {}
			if s.resign != nil {
				var err error
				commit, err = s.resign(pems, serial)
				if err != nil {
					return nil, err
				}
			}
			return func() { publish = commit }, nil
		}
		if err := edit(candidate); err != nil {
			rejected = err
			return nil, err
		}
		accepted, err = decodeSharedTransportTrust(memory.raw)
		if err != nil {
			return nil, err
		}
		// A no-op may still need to adopt a peer's already committed distribution.
		if publish == nil && s.resign != nil && (accepted.Serial != s.serial || accepted.AnchorsPEM != s.pems) {
			publish, err = s.resign(accepted.AnchorsPEM, accepted.Serial)
			if err != nil {
				return nil, err
			}
		}
		return mergeTransportTrustState(raw, accepted)
	})
	if err != nil {
		if rejected != nil {
			return true, rejected
		}
		return true, fmt.Errorf("%w: %v", errSharedTransportTrust, err)
	}
	s.setStateLocked(accepted)
	if publish != nil {
		publish()
	}
	return true, nil
}

// Reads used by management and config publication must not turn a failed read
// into a plausible, stale answer. File receivers retain their existing contract.
func (s *transportTrustStore) RefreshShared() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.shared.(transportTrustUpdater); !ok {
		s.adoptNewerFromDiskLocked()
		return nil
	}
	raw, err := s.shared.Load()
	if err != nil {
		return err
	}
	st, err := decodeSharedTransportTrust(raw)
	if err != nil {
		return err
	}
	if st.Serial < s.serial {
		return fmt.Errorf("shared trust serial regressed")
	}
	if st.Serial == s.serial {
		if st.AnchorsPEM != s.pems || st.AnnouncedInterception != s.announced || st.RecoveryNameSince != s.recoveryNameSince {
			return fmt.Errorf("shared trust contents changed without advancing the serial")
		}
		return nil
	}
	var publish func()
	if s.resign != nil {
		publish, err = s.resign(st.AnchorsPEM, st.Serial)
		if err != nil {
			return err
		}
	}
	s.setStateLocked(st)
	if publish != nil {
		publish()
	}
	return nil
}

func openTransactionalTransportTrustStore(shared blobstore.Persister, p transportTrustUpdater, carriedFrom, seedPEM string, seedSerial int64, resign func(string, int64) (func(), error)) (*transportTrustStore, error) {
	s := &transportTrustStore{shared: shared, resign: resign}
	var accepted transportTrustStoreState
	err := p.UpdateContext(context.Background(), func(raw []byte) ([]byte, error) {
		var st transportTrustStoreState
		var err error
		if raw == nil {
			st = transportTrustStoreState{SchemaVersion: "transport_trust_store.v1", Serial: seedSerial, AnchorsPEM: seedPEM, AdoptedAuthored: seedSerial}
		} else {
			st, err = decodeSharedTransportTrust(raw)
			if err != nil {
				return nil, err
			}
		}
		if carried := carriedForwardTrustState(carriedFrom); carried != nil && carried.Serial > st.Serial {
			st = *carried
		}
		if seedSerial > st.Serial {
			st.Serial = seedSerial
		}
		next, err := mergeTransportTrustState(raw, st)
		if err != nil {
			return nil, err
		}
		accepted, err = decodeSharedTransportTrust(next)
		return next, err
	})
	if err != nil {
		return nil, err
	}
	s.setStateLocked(accepted)
	return s, nil
}
