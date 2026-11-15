package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

type interceptionDelegation struct {
	EdgeID    string `json:"edge_id"`
	CertPEM   string `json:"cert_pem"`
	RevokedAt string `json:"revoked_at,omitempty"`
	LeafCRL   []byte `json:"leaf_crl,omitempty"`
}

// rootKeyNotKept (the last argument) is true for an authority this deployment made and whose root key it did
// not keep: its root list is the sealed one. See inspectioncrl.ParseAndValidateSealed.
func authorityCRLBases(root, issuing *x509.Certificate, tenant string, der []byte, now time.Time, rootKeyNotKept bool) ([]string, error) {
	if len(der) == 0 {
		if len(issuing.CRLDistributionPoints) > 0 {
			return nil, fmt.Errorf("CDP-bearing delegation requires signed root CRL")
		}
		return nil, nil
	}
	bases, err := inspectioncrl.BasesFromPoints(issuing.CRLDistributionPoints, tenant, root)
	if err != nil {
		return nil, err
	}
	list, err := validRootCRL(der, root, now, rootKeyNotKept)
	if err != nil {
		return nil, err
	}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(issuing.SerialNumber) == 0 {
			return nil, fmt.Errorf("issuing authority is already revoked")
		}
	}
	return bases, nil
}

// validRootCRL validates a root's list on the terms that root was set up under.
func validRootCRL(der []byte, root *x509.Certificate, now time.Time, rootKeyNotKept bool) (*x509.RevocationList, error) {
	if rootKeyNotKept {
		return inspectioncrl.ParseAndValidateSealed(der, root, now)
	}
	return inspectioncrl.ParseAndValidate(der, root, now)
}

func authorityCRLBase(root, issuing *x509.Certificate, tenant string, der []byte, now time.Time, rootKeyNotKept bool) (string, error) {
	bases, err := authorityCRLBases(root, issuing, tenant, der, now, rootKeyNotKept)
	if err != nil || len(bases) == 0 {
		return "", err
	}
	return bases[0], nil
}

func (a *tenantInterceptionAuthority) saveCRLLocked(ctx context.Context, materialChanged bool) error {
	data := encodeAuthoritySnapshot(a.issuers)
	var err error
	if a.persistContext != nil {
		err = a.persistContext(ctx, data)
	} else if a.persist != nil {
		err = a.persist(data)
	}
	if err != nil {
		a.issuers = restoreAuthoritySnapshot(a.snapshot, interceptionAuthorityRowKey)
		return err
	}
	a.snapshot = data
	// Refreshing public status must not cause every Edge to re-mint its
	// 12-hour issuer. The material generation changes only for revocation
	// decisions that affect what an Edge may sign.
	if materialChanged {
		a.generation++
	}
	return nil
}

// signIssuingCRL prepares a signed snapshot before it is committed. Reads of a
// CDP never sign or write: a failing control plane can still serve a valid,
// already committed CRL until its signed nextUpdate.
func signIssuingCRL(row *storedTenantInterceptionIssuer, now time.Time, force bool) error {
	if row == nil || row.CRLBaseURL == "" {
		return nil
	}
	root, err := parseFirstCertificatePEM([]byte(row.RootPEM))
	if err != nil {
		return err
	}
	issuing, err := parseFirstCertificatePEM([]byte(row.IssuingCertPEM))
	if err != nil {
		return err
	}
	if _, err = authorityCRLBase(root, issuing, row.TenantID, row.RootCRL, now, row.RootKeyNotKept); err != nil {
		return err
	}
	var number = big.NewInt(1)
	if len(row.IssuingCRL) != 0 {
		old, parseErr := x509.ParseRevocationList(row.IssuingCRL)
		if parseErr != nil {
			return parseErr
		}
		if err = old.CheckSignatureFrom(issuing); err != nil || old.Number == nil {
			return fmt.Errorf("invalid committed issuing CRL")
		}
		if !force && old.NextUpdate.After(now.Add(2*time.Minute)) {
			return nil
		}
		number = new(big.Int).Add(old.Number, big.NewInt(1))
	}
	key, err := parseECKeyPEM([]byte(row.IssuingKeyPEM))
	if err != nil {
		return err
	}
	var entries []x509.RevocationListEntry
	for _, d := range row.Delegations {
		if d.RevokedAt == "" {
			continue
		}
		cert, parseErr := parseFirstCertificatePEM([]byte(d.CertPEM))
		if parseErr != nil {
			return parseErr
		}
		if err = cert.CheckSignatureFrom(issuing); err != nil {
			return err
		}
		at, parseErr := time.Parse(time.RFC3339, d.RevokedAt)
		if parseErr != nil {
			return parseErr
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: cert.SerialNumber, RevocationTime: at})
	}
	der, err := inspectioncrl.Sign(issuing, key, number, entries, now, 5*time.Minute)
	if err != nil {
		return err
	}
	if err = inspectioncrl.AcceptUpdate(row.IssuingCRL, der, issuing, now); err != nil {
		return err
	}
	row.IssuingCRL = der
	return nil
}

// refreshIssuingCRLs is called by the active CP on a timer, not by a client
// fetching status. One committed snapshot serves every Edge after failover.
func (a *tenantInterceptionAuthority) refreshIssuingCRLs(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return err
	}
	changed := false
	for _, row := range a.issuers {
		if row == nil || row.CRLBaseURL == "" {
			continue
		}
		prior := append([]byte(nil), row.IssuingCRL...)
		if err := signIssuingCRL(row, a.now().UTC(), false); err != nil {
			a.issuers = restoreAuthoritySnapshot(a.snapshot, interceptionAuthorityRowKey)
			return err
		}
		changed = changed || !bytes.Equal(prior, row.IssuingCRL)
	}
	if !changed {
		return nil
	}
	return a.saveCRLLocked(ctx, false)
}

func (a *tenantInterceptionAuthority) recordDelegation(ctx context.Context, tenant, edgeID, certPEM string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	row, ok, err := a.refreshedIssuerLocked(strings.TrimSpace(tenant))
	if err != nil {
		return err
	}
	if !ok || row.CRLBaseURL == "" {
		return fmt.Errorf("CRL-enabled authority required")
	}
	cert, err := parseFirstCertificatePEM([]byte(certPEM))
	if err != nil {
		return err
	}
	issuer, err := parseFirstCertificatePEM([]byte(row.IssuingCertPEM))
	if err != nil {
		return err
	}
	if err = cert.CheckSignatureFrom(issuer); err != nil {
		return err
	}
	root, err := parseFirstCertificatePEM([]byte(row.RootPEM))
	if err != nil {
		return err
	}
	if _, err = authorityCRLBase(root, issuer, row.TenantID, row.RootCRL, a.now(), row.RootKeyNotKept); err != nil {
		return err
	}
	if !cert.IsCA || cert.MaxPathLen != 0 || !cert.MaxPathLenZero || cert.NotAfter.After(issuer.NotAfter) || cert.NotAfter.After(root.NotAfter) {
		return fmt.Errorf("invalid Edge delegation")
	}
	if strings.TrimSpace(edgeID) == "" {
		return fmt.Errorf("identified Edge required")
	}
	if row.Delegations == nil {
		row.Delegations = map[string]interceptionDelegation{}
	}
	fp := inspectioncrl.Fingerprint(cert)
	if old, exists := row.Delegations[fp]; exists {
		if old.EdgeID != edgeID || old.CertPEM != certPEM {
			return fmt.Errorf("delegation identity conflict")
		}
		return nil
	}
	row.Delegations[fp] = interceptionDelegation{EdgeID: edgeID, CertPEM: certPEM}
	return a.saveCRLLocked(ctx, false)
}

func (a *tenantInterceptionAuthority) publishLeafCRL(ctx context.Context, tenant, edgeID, fp string, der []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	row, ok, err := a.refreshedIssuerLocked(strings.TrimSpace(tenant))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown authority")
	}
	delegation, ok := row.Delegations[fp]
	if !ok || delegation.EdgeID != edgeID {
		return fmt.Errorf("issuer does not belong to this Edge")
	}
	issuer, err := parseFirstCertificatePEM([]byte(delegation.CertPEM))
	if err != nil {
		return err
	}
	if err = inspectioncrl.AcceptUpdate(delegation.LeafCRL, der, issuer, a.now()); err != nil {
		return err
	}
	if list, _ := x509.ParseRevocationList(der); list.NextUpdate.Sub(list.ThisUpdate) > 5*time.Minute {
		return fmt.Errorf("leaf CRL validity exceeds five minutes")
	}
	delegation.LeafCRL = append([]byte(nil), der...)
	row.Delegations[fp] = delegation
	return a.saveCRLLocked(ctx, false)
}

func (a *tenantInterceptionAuthority) updateRootCRL(ctx context.Context, tenant string, der []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	row, ok, err := a.refreshedIssuerLocked(strings.TrimSpace(tenant))
	if err != nil {
		return err
	}
	if !ok || row.CRLBaseURL == "" {
		return fmt.Errorf("CRL-enabled authority required")
	}
	if row.RootKeyNotKept {
		return fmt.Errorf("this organization's root was made by the deployment and its key was not kept, so no " +
			"new list can be signed for it. To withdraw its issuing authority, replace the root")
	}
	root, err := parseFirstCertificatePEM([]byte(row.RootPEM))
	if err != nil {
		return err
	}
	if err = inspectioncrl.AcceptUpdate(row.RootCRL, der, root, a.now()); err != nil {
		return err
	}
	row.RootCRL = append([]byte(nil), der...)
	return a.saveCRLLocked(ctx, true)
}

func (a *tenantInterceptionAuthority) revokeDelegation(ctx context.Context, tenant, fp string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	row, ok, err := a.refreshedIssuerLocked(strings.TrimSpace(tenant))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown authority")
	}
	d, ok := row.Delegations[fp]
	if !ok {
		return fmt.Errorf("unknown issued delegation")
	}
	if d.RevokedAt != "" {
		return nil
	}
	old := d
	d.RevokedAt = a.now().UTC().Format(time.RFC3339)
	row.Delegations[fp] = d
	if err := signIssuingCRL(row, a.now().UTC(), true); err != nil {
		row.Delegations[fp] = old
		return err
	}
	return a.saveCRLLocked(ctx, true)
}

// Status is signed DER plus public issuer/chain bytes; never a private key.
type inspectionCRLStatus struct {
	Tenant    string   `json:"tenant"`
	IssuerPEM string   `json:"issuer_pem"`
	ChainPEM  string   `json:"chain_pem"`
	DER       []byte   `json:"der"`
	BaseURL   string   `json:"-"`
	BaseURLs  []string `json:"-"`
}

func (a *tenantInterceptionAuthority) crlStatus(ctx context.Context, tenant, fp string) (inspectionCRLStatus, error) {
	if a == nil {
		return inspectionCRLStatus{}, fmt.Errorf("CRL authority unavailable")
	}
	a.mu.Lock()
	row, ok, err := a.refreshedIssuerLocked(strings.TrimSpace(tenant))
	if err != nil {
		// Read-only status may use the last committed signed snapshot during
		// a store failover. ParseAndValidate below still enforces nextUpdate;
		// writes and issuance continue to require the shared store.
		row, ok = a.issuers[strings.TrimSpace(tenant)]
	}
	row = copyAuthority(row)
	a.mu.Unlock()
	if err != nil && !ok {
		return inspectionCRLStatus{}, err
	}
	if !ok || row.CRLBaseURL == "" {
		return inspectionCRLStatus{}, fmt.Errorf("unknown CRL authority")
	}
	root, err := parseFirstCertificatePEM([]byte(row.RootPEM))
	if err != nil {
		return inspectionCRLStatus{}, err
	}
	issuing, err := parseFirstCertificatePEM([]byte(row.IssuingCertPEM))
	if err != nil {
		return inspectionCRLStatus{}, err
	}
	// Revocation status must remain readable after the issuing authority is
	// revoked: these signed bytes are how clients learn that revocation. Keep
	// the origin, signature and freshness checks; issuance separately rejects
	// revoked authorities through authorityCRLBases.
	bases, err := inspectioncrl.BasesFromPoints(issuing.CRLDistributionPoints, row.TenantID, root)
	if err != nil || len(bases) == 0 || bases[0] != row.CRLBaseURL {
		return inspectionCRLStatus{}, fmt.Errorf("CRL distribution origins differ from the committed authority")
	}
	if _, err = validRootCRL(row.RootCRL, root, a.now(), row.RootKeyNotKept); err != nil {
		return inspectionCRLStatus{}, err
	}
	rootList := false
	status := inspectionCRLStatus{Tenant: row.TenantID, BaseURL: row.CRLBaseURL, BaseURLs: bases}
	switch fp {
	case inspectioncrl.Fingerprint(root):
		status.IssuerPEM = row.RootPEM
		status.DER = row.RootCRL
		rootList = true
	case inspectioncrl.Fingerprint(issuing):
		status.IssuerPEM = row.IssuingCertPEM
		status.ChainPEM = row.RootPEM
		status.DER = row.IssuingCRL
	default:
		d, exists := row.Delegations[fp]
		if !exists {
			return inspectionCRLStatus{}, fmt.Errorf("unknown issued delegation")
		}
		status.IssuerPEM = d.CertPEM
		status.ChainPEM = row.IssuingCertPEM + row.RootPEM
		status.DER = d.LeafCRL
	}
	issuer, err := parseFirstCertificatePEM([]byte(status.IssuerPEM))
	if err != nil {
		return inspectionCRLStatus{}, err
	}
	if rootList {
		_, err = validRootCRL(status.DER, issuer, a.now(), row.RootKeyNotKept)
	} else {
		_, err = inspectioncrl.ParseAndValidate(status.DER, issuer, a.now())
	}
	if err != nil {
		return inspectionCRLStatus{}, err
	}
	return status, nil
}

func interceptionCertPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}
