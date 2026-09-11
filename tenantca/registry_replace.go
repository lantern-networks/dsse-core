package tenantca

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// ReplaceTenant installs the complete device-authority set received from a
// trusted control plane. Validation precedes mutation; other tenants are retained.
// It differs from Register, whose additive semantics are intended for CA imports.
func (r *TenantCARegistry) ReplaceTenant(tenantID string, pemBytes []byte) error {
	return r.ReplaceTenantPersisted(tenantID, pemBytes, nil)
}

// ReplaceTenantPersisted persists a detached candidate before replacing live attribution.
func (r *TenantCARegistry) ReplaceTenantPersisted(tenantID string, pemBytes []byte, persist func(*TenantCARegistry) error) error {
	return r.replaceTenantPersisted(tenantID, pemBytes, persist, false)
}

// ReplaceManagedTenantPersisted commits ownership and anchors as one snapshot.
func (r *TenantCARegistry) ReplaceManagedTenantPersisted(tenantID string, pemBytes []byte, persist func(*TenantCARegistry) error) error {
	return r.replaceTenantPersisted(tenantID, pemBytes, persist, true)
}

func (r *TenantCARegistry) replaceTenantPersisted(tenantID string, pemBytes []byte, persist func(*TenantCARegistry) error, managed bool) error {
	if r == nil {
		return fmt.Errorf("tenant CA registry is not configured")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	certs, err := ParseCACertsPEM(pemBytes)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return fmt.Errorf("replacement has no CA certificate")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, cert := range certs {
		if owner, ok := r.byAnchorKey[CAAnchorKey(cert)]; ok && !strings.EqualFold(owner, tenantID) {
			return fmt.Errorf("CA already identifies another organization")
		}
	}
	owners := make(map[string]string, len(r.byAnchorKey)+len(certs))
	kept := make([]*x509.Certificate, 0, len(r.anchors)+len(certs))
	for _, cert := range r.anchors {
		key := CAAnchorKey(cert)
		owner := r.byAnchorKey[key]
		if strings.EqualFold(owner, tenantID) {
			continue
		}
		owners[key] = owner
		kept = append(kept, cert)
	}
	for _, cert := range certs {
		key := CAAnchorKey(cert)
		if _, ok := owners[key]; ok {
			continue
		}
		owners[key] = tenantID
		kept = append(kept, cert)
	}
	pool := x509.NewCertPool()
	for _, cert := range kept {
		pool.AddCert(cert)
	}
	ownership := make(map[string]bool, len(r.materialManaged)+1)
	for tenant, owned := range r.materialManaged {
		ownership[tenant] = owned
	}
	if managed {
		ownership[strings.ToLower(tenantID)] = true
	}
	candidate := &TenantCARegistry{byAnchorKey: owners, anchors: kept, Pool: pool, materialManaged: ownership}
	candidate.TenantCount = candidate.tenantCountLocked()
	if persist != nil {
		if err := persist(candidate); err != nil {
			return err
		}
	}
	r.materialManaged = ownership
	r.byAnchorKey = owners
	r.anchors = kept
	r.Pool = pool
	r.TenantCount = r.tenantCountLocked()
	r.generation++
	return nil
}

// CertPool returns a detached pool while the registry is being updated at runtime.
func (r *TenantCARegistry) CertPool() *x509.CertPool {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.Pool == nil {
		return nil
	}
	return r.Pool.Clone()
}
