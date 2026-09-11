package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// The CP registry describes explicitly registered authorities. Managed authorities
// come from the device-authority store, not from an Edge's combined admission cache.
// Read the durable registry on each publication: a stale CP cache must not undo a
// BYO withdrawal, and a read failure is not an empty registration set.
type deviceCARegistrationSnapshot map[string]string

func readDeviceCARegistrations(reg *tenantca.TenantCARegistry, shared tenantca.Persister) (deviceCARegistrationSnapshot, error) {
	var raw []byte
	var err error
	if shared != nil {
		raw, err = shared.Load()
	} else if reg != nil {
		raw, err = reg.Snapshot()
	}
	if err != nil {
		return nil, fmt.Errorf("device CA registrations unavailable: %w", err)
	}
	return decodeDeviceCARegistrations(raw)
}

func decodeDeviceCARegistrations(raw []byte) (deviceCARegistrationSnapshot, error) {
	out := deviceCARegistrationSnapshot{}
	if len(raw) == 0 {
		return out, nil
	}
	var doc tenantca.TenantCARegistryFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("device CA registrations invalid: %w", err)
	}
	if doc.Tenants == nil {
		return nil, fmt.Errorf("device CA registrations contain no complete snapshot")
	}
	owners := map[string]string{}
	for _, entry := range doc.Tenants {
		tenant := strings.ToLower(strings.TrimSpace(entry.TenantID))
		certs, err := tenantca.ParseCACertsPEM([]byte(entry.CAPEM))
		if tenant == "" || err != nil || len(certs) == 0 {
			return nil, fmt.Errorf("device CA registrations contain an incomplete entry")
		}
		for _, cert := range certs {
			if !cert.IsCA {
				return nil, fmt.Errorf("device CA registration is not a CA")
			}
			fp := certFingerprint(cert)
			if owner := owners[fp]; owner != "" {
				if owner != tenant {
					return nil, fmt.Errorf("device CA identifies multiple organizations")
				}
				continue
			}
			owners[fp] = tenant
			out[tenant] += string(encodeCertPEM(cert))
		}
	}
	return out, nil
}

func registerDeviceCARegistryBootstrapFlag() *string {
	return flag.String("transport-tenant-ca-registry-carried-from", "", "inline-PEM registry snapshot used only to initialize an absent shared registry; an existing shared row is never overwritten")
}

// The generated deployment's registry file is a bootstrap input, not a writable
// per-CP database. Initialize once with CAS so another CP or a prior withdrawal
// wins over an old file. This flag accepts the installer's inline-PEM format.
func initializeSharedDeviceCARegistry(p tenantca.Persister, carriedFrom string) error {
	if carriedFrom == "" {
		return nil
	}
	current, err := p.Load()
	if err != nil {
		return err
	}
	if current != nil {
		return nil
	}
	raw, err := os.ReadFile(carriedFrom)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return fmt.Errorf("bootstrap device CA registry is empty")
	}
	if _, err := decodeDeviceCARegistrations(raw); err != nil {
		return err
	}
	cas, ok := p.(interface{ CompareAndSwap([]byte, []byte) error })
	if !ok {
		return fmt.Errorf("shared device CA registry initialization requires compare-and-swap")
	}
	if err := cas.CompareAndSwap(nil, raw); err != nil {
		if !errors.Is(err, errAuthorityConflict) {
			return err
		}
		winner, err := p.Load()
		if err != nil {
			return err
		}
		if winner == nil {
			return errAuthorityConflict
		}
		_, err = decodeDeviceCARegistrations(winner)
		return err
	}
	return nil
}

func (s deviceCARegistrationSnapshot) fingerprint() uint64 {
	parts := []string{"device-registrations-v1"}
	for tenant, pem := range s {
		for _, cert := range certificatesInPEM([]byte(pem)) {
			parts = append(parts, tenant+"\x1f"+certFingerprint(cert))
		}
	}
	return materialFingerprint(parts)
}

// Retirement records contain only fingerprints, never issuing keys. Keeping them
// with the managed authority makes an explicit registration of an old managed CA
// unable to resurrect that CA after retirement or after a CP restart.
func deviceAdmissionAnchors(row *storedTenantDeviceCA, registrations deviceCARegistrationSnapshot) string {
	if row == nil {
		return ""
	}
	retired := map[string]bool{}
	for _, fp := range row.RetiredAnchorSHA256 {
		retired[fp] = true
	}
	certs := map[string]*x509.Certificate{}
	for _, cert := range certificatesInPEM([]byte(deviceAnchorsOf(row))) {
		certs[certFingerprint(cert)] = cert
	}
	for _, cert := range certificatesInPEM([]byte(registrations[row.TenantID])) {
		if fp := certFingerprint(cert); !retired[fp] {
			certs[fp] = cert
		}
	}
	keys := make([]string, 0, len(certs))
	for fp := range certs {
		keys = append(keys, fp)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, fp := range keys {
		out.Write(encodeCertPEM(certs[fp]))
	}
	return out.String()
}

func deviceRetirementHistory(row *storedTenantDeviceCA, retiringPEM string) []string {
	set := map[string]bool{}
	for _, fp := range row.RetiredAnchorSHA256 {
		set[fp] = true
	}
	for _, cert := range certificatesInPEM([]byte(retiringPEM)) {
		set[certFingerprint(cert)] = true
	}
	out := make([]string, 0, len(set))
	for fp := range set {
		out = append(out, fp)
	}
	sort.Strings(out)
	return out
}
