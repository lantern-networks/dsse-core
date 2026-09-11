package main

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

type pkiAuthorityTransition struct {
	// Populated from a checked CP registration snapshot by the admission gate.
	DeviceAdmissionCAPEM                  string
	Kind, Action, Tenant                  string
	TransportBefore, TransportAfter       *storedTenantTransportCA
	DeviceBefore, DeviceAfter             *storedTenantDeviceCA
	InterceptionBefore, InterceptionAfter *storedTenantInterceptionIssuer
}
type pkiTransitionAdmission func(pkiAuthorityTransition) error

func requirePKIAdmission(gates []pkiTransitionAdmission, transition pkiAuthorityTransition) error {
	if len(gates) != 1 || gates[0] == nil {
		return fmt.Errorf("pki_evidence_unavailable: shared adoption and fleet evidence is required before changing a serving authority")
	}
	return gates[0](transition)
}

// Collect external evidence without holding the authority mutex. After evidence
// collection, refresh and compare the complete original snapshot before CAS so
// a concurrent writer cannot make the evidence authorize a different authority.
func (a *tenantTransportAuthority) admitTransition(tenant, action string, gates []pkiTransitionAdmission,
	operation func(*tenantTransportAuthority, string) (*storedTenantTransportCA, error)) (*storedTenantTransportCA, error) {
	a.mu.Lock()
	if err := a.refreshLocked(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	expected := encodeAuthoritySnapshot(a.cas)
	before := copyAuthority(a.cas[key])
	candidate := newTenantTransportAuthority(expected, nil, a.now)
	a.mu.Unlock()
	row, err := operation(candidate, key)
	if err != nil {
		return nil, err
	}
	transition := pkiAuthorityTransition{Kind: "transport", Action: action, Tenant: key,
		TransportBefore: before, TransportAfter: copyAuthority(candidate.cas[key])}
	if err := requirePKIAdmission(gates, transition); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	if !bytes.Equal(expected, encodeAuthoritySnapshot(a.cas)) {
		return nil, errAuthorityConflict
	}
	a.cas = candidate.cas
	if err := a.saveLocked(); err != nil {
		return nil, err
	}
	return copyAuthority(row), nil
}
func (a *tenantDeviceAuthority) admitTransition(tenant, action string, gates []pkiTransitionAdmission,
	operation func(*tenantDeviceAuthority, string) (*storedTenantDeviceCA, error)) (*storedTenantDeviceCA, error) {
	a.mu.Lock()
	if err := a.refreshLocked(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	expected := encodeAuthoritySnapshot(a.cas)
	before := copyAuthority(a.cas[key])
	candidate := newTenantDeviceAuthority(expected, nil, a.now)
	a.mu.Unlock()
	row, err := operation(candidate, key)
	if err != nil {
		return nil, err
	}
	transition := pkiAuthorityTransition{Kind: "device", Action: action, Tenant: key,
		DeviceBefore: before, DeviceAfter: copyAuthority(candidate.cas[key])}
	if err := requirePKIAdmission(gates, transition); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	if !bytes.Equal(expected, encodeAuthoritySnapshot(a.cas)) {
		return nil, errAuthorityConflict
	}
	a.cas = candidate.cas
	if err := a.saveLocked(); err != nil {
		return nil, err
	}
	return copyAuthority(row), nil
}
func (a *tenantInterceptionAuthority) admitTransition(tenant, action string, gates []pkiTransitionAdmission,
	operation func(*tenantInterceptionAuthority, string) (*storedTenantInterceptionIssuer, error)) (*storedTenantInterceptionIssuer, error) {
	a.mu.Lock()
	if err := a.refreshLocked(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	expected := encodeAuthoritySnapshot(a.issuers)
	before := copyAuthority(a.issuers[key])
	candidate := newTenantInterceptionAuthority(expected, nil, a.now)
	a.mu.Unlock()
	row, err := operation(candidate, key)
	if err != nil {
		return nil, err
	}
	transition := pkiAuthorityTransition{Kind: "interception", Action: action, Tenant: key,
		InterceptionBefore: before, InterceptionAfter: copyAuthority(candidate.issuers[key])}
	if err := requirePKIAdmission(gates, transition); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return nil, err
	}
	if !bytes.Equal(expected, encodeAuthoritySnapshot(a.issuers)) {
		return nil, errAuthorityConflict
	}
	a.issuers = candidate.issuers
	if err := a.saveLocked(); err != nil {
		return nil, err
	}
	return copyAuthority(row), nil
}

const pkiAdoptionFreshFor = 5 * time.Minute
