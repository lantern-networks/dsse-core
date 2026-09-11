package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// tenant_device_signers.go — the authorities this node enrols each organization's devices under.
//
// ★★★ WHY THIS EXISTS (2026-08-21, measured). The Edge held exactly one device-identity signer, so POST
// /enroll verified the eligibility token against the NODE's organization and refused every other one. An
// administrator of tenant_northwind could mint an enrolment token (201) that no device could ever use (403).
// The material for the other organizations is now fetched alongside their transport and interception
// material, and lands here.
//
// ★ NOTHING IS WRITTEN DOWN. The material is short-lived and re-fetched; an Edge that appears under load and
// disappears an hour later must not leave an organization's issuing key on a disk. Same rule as the
// interception tier beside it.
//
// ★ AND THE ANCHOR IS REGISTERED, OR THE CERTIFICATE IDENTIFIES NOBODY. A device is resolved to its
// organization by the CA that issued it (tenantca.TenantCARegistry), so installing an authority without
// registering its certificate would produce devices this deployment can issue and then cannot admit — the
// same "issued and unadmittable" shape, one step further along.
// restart-durability: ephemeral — deliberately. The authorities here are SHORT-LIVED material the control
// plane re-issues on every fetch, and writing them down would leave an organization's issuing key on a node
// that may be gone in an hour. A restart re-fetches within one poll; until it does this node enrols nobody,
// which is the safe direction — a device is refused rather than issued an identity under the wrong authority.
//
// populated-by: assertion — installed only from material the control plane HANDED this node, never inferred
// from a request. An Edge that asks about an organization the operator has not set up is refused, not
// answered by creating an authority.
type tenantDeviceSigners struct {
	mu      sync.RWMutex
	signers map[string]*deviceca.Signer
	// rotation records, per organization, the authority this node currently SIGNS with and the one it still
	// ADMITS beside it. Both come from the material the control plane handed this node, so a readiness answer
	// is about what this Edge is actually doing rather than about what a configuration says.
	//
	// ★ THE EDGE MEASURES, THE CONTROL PLANE ACTS (2026-08-22). Whether a rotation may finish depends on what
	// devices have PRESENTED, and only an Edge sees a handshake. Whether the previous authority stops existing
	// is a decision no single Edge can make. Same split as the recovery-name readiness, for the same reason.
	rotation map[string]deviceAuthorityFingerprints
}

// deviceAuthorityFingerprints is what this node signs with and what it still admits, for one organization.
type deviceAuthorityFingerprints struct {
	SignerSHA256 string
	// OutgoingSHA256 is empty when no rotation is in flight — one anchor, and it is the signer.
	OutgoingSHA256 string
}

// Serializes the registry/pool update against config-bundle reconciliation.
var deviceCAUpdateMu sync.Mutex

var tenantDeviceIdentity = &tenantDeviceSigners{signers: map[string]*deviceca.Signer{},
	rotation: map[string]deviceAuthorityFingerprints{}}

// Install takes one organization's authority and makes this node able to enrol for it. The registry is
// updated in the same step, and a registry failure is a failure: an authority that can sign but cannot be
// resolved is worse than none.
func (t *tenantDeviceSigners) Install(mat tenantDeviceMaterial, registry *tenantca.TenantCARegistry,
	persist func(*tenantca.TenantCARegistry) error) error {
	tenant := strings.ToLower(strings.TrimSpace(mat.TenantID))
	if tenant == "" {
		return fmt.Errorf("device-identity material names no organization")
	}
	certBlock, _ := pem.Decode([]byte(mat.CACertPEM))
	if certBlock == nil {
		return fmt.Errorf("device-identity material for %q carries no certificate", tenant)
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("device-identity material for %q: %w", tenant, err)
	}
	keyBlock, _ := pem.Decode([]byte(mat.CAKeyPEM))
	if keyBlock == nil {
		return fmt.Errorf("device-identity material for %q carries no key", tenant)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("device-identity material for %q: %w", tenant, err)
	}

	anchor := strings.TrimSpace(mat.AnchorPEM)
	if anchor == "" {
		anchor = mat.CACertPEM
	}
	if !key.PublicKey.Equal(caCert.PublicKey) {
		return fmt.Errorf("device authority key does not match its certificate")
	}
	if registry == nil {
		return fmt.Errorf("device authority requires a tenant registry")
	}
	// Missing admission data is not permission to discard an organization's BYO
	// authorities. Old CP material cannot safely replace the complete tenant set.
	if !mat.AdmissionComplete {
		return fmt.Errorf("device authority carries no complete admission snapshot")
	}
	admitted, err := tenantca.ParseCACertsPEM([]byte(mat.AdmissionCAPEM))
	if err != nil || len(admitted) == 0 {
		return fmt.Errorf("device authority carries no usable admission CAs")
	}
	admittedFPs := map[string]bool{}
	for _, cert := range admitted {
		if !cert.IsCA {
			return fmt.Errorf("device admission entry is not a CA")
		}
		admittedFPs[certFingerprint(cert)] = true
	}
	if !admittedFPs[certFingerprint(caCert)] {
		return fmt.Errorf("device signer is absent from the admission set")
	}
	for _, cert := range certificatesInPEM([]byte(anchor)) {
		if !admittedFPs[certFingerprint(cert)] {
			return fmt.Errorf("managed overlap CA is absent from the admission set")
		}
	}
	deviceCAUpdateMu.Lock()
	defer deviceCAUpdateMu.Unlock()
	if err := registry.ReplaceManagedTenantPersisted(tenant, []byte(mat.AdmissionCAPEM), persist); err != nil {
		return err
	}
	setEdgeClientRegistryCAs(registry.Anchors())
	if trust := trustAnchorStoreOrNil(deviceClientCAs); trust != nil {
		if err := trust.Reapply(); err != nil {
			return err
		}
	} else {
		seed := ""
		if p := transportClientSeedPEM.Load(); p != nil {
			seed = *p
		}
		pool, err := deviceTrustPoolFrom(registry.CertPool(), seed)
		if err != nil {
			return err
		}
		transportClientCAPool.Store(pool)
	}

	// What this node signs with, and what it still admits beside it — read from the material itself, so the
	// readiness answer cannot drift from what is installed.
	prints := deviceAuthorityFingerprints{SignerSHA256: certFingerprint(caCert)}
	for _, anchor := range certificatesInPEM([]byte(anchor)) {
		if fp := certFingerprint(anchor); fp != "" && fp != prints.SignerSHA256 {
			prints.OutgoingSHA256 = fp
			break
		}
	}

	t.mu.Lock()
	t.signers[tenant] = deviceca.NewSigner(caCert, key)
	if t.rotation == nil {
		t.rotation = map[string]deviceAuthorityFingerprints{}
	}
	t.rotation[tenant] = prints
	t.mu.Unlock()
	return nil
}

// Rotation reports which authority this node signs an organization's devices under, and which it still
// admits. The second is empty when no rotation is in flight.
func (t *tenantDeviceSigners) Rotation(tenantID string) (deviceAuthorityFingerprints, bool) {
	if t == nil {
		return deviceAuthorityFingerprints{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.rotation[strings.ToLower(strings.TrimSpace(tenantID))]
	return p, ok
}

// For answers which authority this node issues an organization's devices under, or nil.
func (t *tenantDeviceSigners) For(tenantID string) *deviceca.Signer {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.signers[strings.ToLower(strings.TrimSpace(tenantID))]
}

// Organizations names the organizations this node can enrol for, for the start-up line and the admin surface.
func (t *tenantDeviceSigners) Organizations() []string {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.signers))
	for tenant := range t.signers {
		out = append(out, tenant)
	}
	return out
}
