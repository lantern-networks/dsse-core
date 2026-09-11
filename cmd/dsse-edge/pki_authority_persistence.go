package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
)

var errAuthorityConflict = errors.New("authority changed on another control plane; reload and retry the operation")

// CompareAndSwap changes only the snapshot the caller actually read. A nil expected
// payload means the row did not exist. Comparing payload bytes also works with existing
// installations, without treating a process-local generation as a database revision.
func (p postgresBlobPersister) CompareAndSwap(expected, next []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), cpStateBlobDBTimeout)
	defer cancel()
	var result sql.Result
	var err error
	if expected == nil {
		result, err = p.db.ExecContext(ctx, `INSERT INTO cp_state_blobs (store_key, payload, updated_at)
   VALUES ($1,$2,now()) ON CONFLICT (store_key) DO NOTHING`, p.key, next)
	} else {
		result, err = p.db.ExecContext(ctx, `UPDATE cp_state_blobs SET payload=$3, updated_at=now()
   WHERE store_key=$1 AND payload=$2`, p.key, expected, next)
	}
	if err != nil {
		return fmt.Errorf("persist authority %q: %w", p.key, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errAuthorityConflict
	}
	return nil
}

type authorityCASBackend interface {
	blobstore.Persister
	CompareAndSwap(expected, next []byte) error
}

// Used only for the three PKI stores. Other snapshot stores keep their existing contract.
// The owning authority serializes its Load -> mutate -> Save sequence with its mutex.
// The backend CAS protects that sequence from other processes; this mutex only protects
// the adapter's bookkeeping. A failed or ambiguous commit requires another successful Load.
type authorityCASPersister struct {
	backend  authorityCASBackend
	mu       sync.Mutex
	expected []byte
	loaded   bool
}

func (p *authorityCASPersister) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, err := p.backend.Load()
	if err != nil {
		p.loaded = false
		return nil, err
	}
	p.expected = bytes.Clone(raw)
	p.loaded = true
	return raw, nil
}

func (p *authorityCASPersister) Save(next []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.loaded {
		return errors.New("authority must be read successfully before it is changed")
	}
	if err := p.backend.CompareAndSwap(p.expected, next); err != nil {
		p.loaded = false
		return err
	}
	p.expected = bytes.Clone(next)
	return nil
}

func mustPKIAuthorityPersister(path, key string) blobstore.Persister {
	return protectPKIAuthorityPersister(mustCPStateBlobPersister(path, key), key)
}

func protectPKIAuthorityPersister(p blobstore.Persister, key string) blobstore.Persister {
	if p == nil {
		return nil
	}
	if backend, ok := p.(authorityCASBackend); ok {
		p = &authorityCASPersister{backend: backend}
	}
	// File backends retain their single-writer contract; replacement is not a shared CAS.
	validate := func(raw []byte) error {
		switch key {
		case "tenant_transport_authorities":
			return validateAuthorityRows(raw, transportAuthorityRowKey)
		case "tenant_device_authorities":
			return validateAuthorityRows(raw, deviceAuthorityRowKey)
		case "tenant_interception_authorities":
			return validateAuthorityRows(raw, interceptionAuthorityRowKey)
		default:
			return errors.New("unknown PKI authority store")
		}
	}
	return validatedAuthorityPersister{p, validate}
}

// A successfully decoded complete snapshot replaces the cache, including deletions.
// Corruption and failed reads leave the last committed cache intact and return an error.
func readAuthoritySnapshot[T any](reload func() ([]byte, error), key func(*T) string,
	current map[string]*T) (map[string]*T, []byte, error) {
	raw, err := reload()
	if err != nil {
		return nil, nil, err
	}
	if len(raw) == 0 && len(current) != 0 {
		return nil, nil, errors.New("authority store disappeared; refusing to interpret it as a deletion")
	}
	rows := []*T{}
	if raw != nil {
		if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '[' {
			return nil, nil, errors.New("authority store is not a row array")
		}
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, nil, fmt.Errorf("decode authority store: %w", err)
		}
	}
	out := make(map[string]*T, len(rows))
	for _, row := range rows {
		if row == nil || key(row) == "" {
			return nil, nil, errors.New("invalid authority row")
		}
		id := key(row)
		if _, exists := out[id]; exists {
			return nil, nil, errors.New("duplicate authority row")
		}
		out[id] = row
	}
	return out, bytes.Clone(raw), nil
}

func restoreAuthoritySnapshot[T any](raw []byte, key func(*T) string) map[string]*T {
	rows, _, err := readAuthoritySnapshot(func() ([]byte, error) { return raw, nil }, key, nil)
	if err != nil {
		panic("invalid committed authority snapshot")
	}
	return rows
}

// Copy rows before releasing an authority's mutex. Incoming authorities are nested
// pointers; shallow copies would still race with local rotate/rename operations.
func copyAuthority[T any](value T) T {
	raw, err := json.Marshal(value)
	if err != nil {
		panic("authority cannot be encoded")
	}
	var copy T
	if err := json.Unmarshal(raw, &copy); err != nil {
		panic("authority cannot be decoded")
	}
	return copy
}

// materialSnapshot binds a response's fingerprint and issued material to one read.
func (a *tenantTransportAuthority) materialSnapshot() (*tenantTransportAuthority, error) {
	if a == nil {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, fmt.Errorf("%w: %v", errAuthorityNotAsked, err)
	}
	return &tenantTransportAuthority{cas: copyAuthority(a.cas), now: a.now, generation: a.generation}, nil
}

// materialSnapshot binds a response's fingerprint and issued material to one read.
func (a *tenantDeviceAuthority) materialSnapshot() (*tenantDeviceAuthority, error) {
	if a == nil {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, fmt.Errorf("%w: %v", errAuthorityNotAsked, err)
	}
	return &tenantDeviceAuthority{cas: copyAuthority(a.cas), now: a.now, generation: a.generation}, nil
}

// materialSnapshot binds a response's fingerprint and issued material to one read.
func (a *tenantInterceptionAuthority) materialSnapshot() (*tenantInterceptionAuthority, error) {
	if a == nil {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, fmt.Errorf("%w: %v", errAuthorityNotAsked, err)
	}
	return &tenantInterceptionAuthority{issuers: copyAuthority(a.issuers), now: a.now, generation: a.generation}, nil
}

// Constructors retain a valid rollback snapshot even when used with legacy seed
// loaders. The runtime persister validates the input before construction.
func encodeAuthoritySnapshot[T any](rows map[string]*T) []byte {
	keys := make([]string, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]*T, 0, len(rows))
	for _, key := range keys {
		values = append(values, rows[key])
	}
	raw, err := json.Marshal(values)
	if err != nil {
		panic("authority cannot be encoded")
	}
	return raw
}

type validatedAuthorityPersister struct {
	blobstore.Persister
	validate func([]byte) error
}

func (p validatedAuthorityPersister) Load() ([]byte, error) {
	raw, err := p.Persister.Load()
	if err != nil {
		return nil, err
	}
	if err := p.validate(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func validateAuthorityRows[T any](raw []byte, key func(*T) string) error {
	_, _, err := readAuthoritySnapshot(func() ([]byte, error) { return raw, nil }, key, nil)
	return err
}
