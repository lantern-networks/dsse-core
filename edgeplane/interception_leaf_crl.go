package edgeplane

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

func interceptionIssuerCRLBases(issuer *InterceptionIssuer, tenant string) ([]string, error) {
	parent := issuer.trustAnchor
	// A delegated Edge issuer is signed by the tenant issuing CA, while a
	// legacy single intermediate is signed directly by the root. The CDP in
	// either certificate must name its immediate signer, not always the root.
	if len(issuer.chain) > 1 {
		var err error
		parent, err = x509.ParseCertificate(issuer.chain[1])
		if err != nil {
			return nil, err
		}
	}
	return inspectioncrl.BasesFromPoints(issuer.signingCert.CRLDistributionPoints, tenant, parent)
}

// SignTenantLeafCRL signs the short-lived status for the one per-Edge issuer
// currently loaded for tenant. DSSE does not offer individual inspection-leaf
// revocation: leaves expire with their short-lived Edge issuer. The empty
// entry set therefore represents that issuer's actual revocation ledger, not
// a replacement for upstream origin-certificate revocation checking.
func (interception *NetworkExtensionLabTLSInterception) SignTenantLeafCRL(tenant string, now time.Time) (string, []byte, bool, error) {
	if interception == nil {
		return "", nil, false, fmt.Errorf("interception is unavailable")
	}
	key := normalizeInterceptionTenantKey(tenant)
	interception.issuerMu.Lock()
	issuer := interception.offlineTenantIssuers[key]
	interception.issuerMu.Unlock()
	if issuer == nil || issuer.signingCert == nil || !issuer.requiresTenantLeafCRL {
		return "", nil, false, nil
	}
	if _, err := interceptionIssuerCRLBases(issuer, key); err != nil {
		return "", nil, false, err
	}
	if issuer.signingCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return "", nil, false, fmt.Errorf("delegated issuer cannot sign CRLs")
	}
	if err := issuer.usableAt(now); err != nil {
		return "", nil, false, err
	}
	// A time-derived number survives a process restart without persistent Edge
	// state. The CP still rejects rollback and same-number equivocation.
	number := big.NewInt(now.UTC().UnixNano())
	der, err := inspectioncrl.Sign(issuer.signingCert, issuer.signer, number, nil, now.UTC(), 5*time.Minute)
	if err != nil {
		return "", nil, false, err
	}
	return inspectioncrl.Fingerprint(issuer.signingCert), der, true, nil
}

// ConfirmTenantLeafCRL opens leaf issuance only after the CP has acknowledged
// a durable write. It never extends readiness beyond the signed nextUpdate.
func (interception *NetworkExtensionLabTLSInterception) ConfirmTenantLeafCRL(tenant, fingerprint string, der []byte, now time.Time) error {
	if interception == nil {
		return fmt.Errorf("interception is unavailable")
	}
	interception.issuerMu.Lock()
	defer interception.issuerMu.Unlock()
	issuer := interception.offlineTenantIssuers[normalizeInterceptionTenantKey(tenant)]
	if issuer == nil || issuer.signingCert == nil || !issuer.requiresTenantLeafCRL || fingerprint != inspectioncrl.Fingerprint(issuer.signingCert) {
		return fmt.Errorf("interception issuer changed before CRL publication")
	}
	list, err := inspectioncrl.ParseAndValidate(der, issuer.signingCert, now)
	if err != nil {
		return err
	}
	issuer.leafCRLReadyUntil.Store(list.NextUpdate.UnixNano())
	return nil
}
