// dsse-inspection-pki keeps the root signer with the offline operator. Only
// import.private.json (issuing key, public root and signed status) reaches CP.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

type importBundle struct {
	TenantID       string `json:"tenant_id"`
	RootPEM        string `json:"root_pem"`
	IssuingCertPEM string `json:"issuing_cert_pem"`
	IssuingKeyPEM  string `json:"issuing_key_pem"`
	RootCRL        []byte `json:"root_crl"`
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
func parseCert(b []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(b)
	if p == nil || p.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate PEM required")
	}
	return x509.ParseCertificate(p.Bytes)
}
func serial() (*big.Int, error) {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e == nil && n.Sign() == 0 {
		return serial()
	}
	return n, e
}
func writeNew(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(data); e != nil {
		return e
	}
	return f.Sync()
}
func atomicWrite(path string, data []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".crl-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	// Windows cannot reliably open a directory as a synchronizable file.
	// The remove-before-update ordering still prevents a stale upload after
	// process interruption; directory durability is confirmed on Unix hosts.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, e := os.Open(path)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

func discardStaleUpdate(path string) error {
	if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
		return e
	}
	return syncDirectory(filepath.Dir(path))
}

func initialize(dir, tenant, name, base string, now time.Time) error {
	if tenant == "" || strings.TrimSpace(tenant) != tenant || strings.ContainsAny(tenant, "/\\\x00") {
		return fmt.Errorf("valid tenant required")
	}
	if name == "" {
		name = tenant
	}
	// Preserve the single-origin CLI contract, while allowing a comma-separated
	// ordered list of independent CRL origins for a redundant deployment.
	bases := strings.Split(base, ",")
	if len(bases) == 0 || len(bases) > 8 {
		return fmt.Errorf("one to eight CRL origins required")
	}
	// The caller chooses a fresh directory. Never overwrite a signer/trust anchor.
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		return fmt.Errorf("new offline custody directory required")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	keys := make([]*ecdsa.PrivateKey, 2)
	certs := make([]*x509.Certificate, 2)
	for i := 0; i < 2; i++ {
		var e error
		keys[i], e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		n, e := serial()
		if e != nil {
			return e
		}
		tmpl := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: name + []string{" Interception Root", " Interception Issuing CA"}[i], OrganizationalUnit: []string{tenant}}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add([]time.Duration{5 * 365 * 24 * time.Hour, 2 * 365 * 24 * time.Hour}[i]), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 2 - i, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		parent := tmpl
		key := keys[i]
		if i > 0 {
			parent = certs[0]
			key = keys[0]
			points, e := inspectioncrl.URLs(bases, tenant, parent)
			if e != nil {
				return e
			}
			tmpl.CRLDistributionPoints = points
		}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, parent, &keys[i].PublicKey, key)
		if e != nil {
			return e
		}
		certs[i], e = x509.ParseCertificate(der)
		if e != nil {
			return e
		}
	}
	der, e := inspectioncrl.Sign(certs[0], keys[0], big.NewInt(1), nil, now, inspectioncrl.MaxValidity)
	if e != nil {
		return e
	}
	keyDER, e := x509.MarshalECPrivateKey(keys[0])
	if e != nil {
		return e
	}
	if e = writeNew(filepath.Join(dir, "root-key.offline.private.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); e != nil {
		return e
	}
	if e = writeNew(filepath.Join(dir, "root.pem"), certPEM(certs[0])); e != nil {
		return e
	}
	if e = writeNew(filepath.Join(dir, "root.crl"), der); e != nil {
		return e
	}
	keyDER, e = x509.MarshalECPrivateKey(keys[1])
	if e != nil {
		return e
	}
	bundle := importBundle{TenantID: tenant, RootPEM: string(certPEM(certs[0])), IssuingCertPEM: string(certPEM(certs[1])), IssuingKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), RootCRL: der}
	data, e := json.MarshalIndent(bundle, "", "  ")
	if e != nil {
		return e
	}
	return writeNew(filepath.Join(dir, "import.private.json"), data)
}

func refresh(dir, revoke string, now time.Time) error {
	raw, e := os.ReadFile(filepath.Join(dir, "import.private.json"))
	if e != nil {
		return e
	}
	var b importBundle
	if e = json.Unmarshal(raw, &b); e != nil {
		return e
	}
	root, e := parseCert([]byte(b.RootPEM))
	if e != nil {
		return e
	}
	issuing, e := parseCert([]byte(b.IssuingCertPEM))
	if e != nil {
		return e
	}
	if e = issuing.CheckSignatureFrom(root); e != nil {
		return e
	}
	keyPEM, e := os.ReadFile(filepath.Join(dir, "root-key.offline.private.pem"))
	if e != nil {
		return e
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("missing offline root key")
	}
	key, e := x509.ParseECPrivateKey(keyBlock.Bytes)
	if e != nil {
		return e
	}
	// The bundle is the atomic authoritative record. root.crl is a convenience
	// copy repaired each run; disagreement after a crash never forgets a denial.
	prior, e := x509.ParseRevocationList(b.RootCRL)
	if e != nil {
		return e
	}
	if e = prior.CheckSignatureFrom(root); e != nil {
		return e
	}
	if prior.Number == nil || prior.Number.Sign() <= 0 {
		return fmt.Errorf("invalid prior number")
	}
	entries := append([]x509.RevocationListEntry(nil), prior.RevokedCertificateEntries...)
	if revoke != "" {
		if revoke != inspectioncrl.Fingerprint(issuing) {
			return fmt.Errorf("only this recorded issuing authority can be revoked")
		}
		found := false
		for _, v := range entries {
			if v.SerialNumber.Cmp(issuing.SerialNumber) == 0 {
				found = true
			}
		}
		if !found {
			entries = append(entries, x509.RevocationListEntry{SerialNumber: issuing.SerialNumber, RevocationTime: now})
		}
	}
	der, e := inspectioncrl.Sign(root, key, new(big.Int).Add(prior.Number, big.NewInt(1)), entries, now, inspectioncrl.MaxValidity)
	if e != nil {
		return e
	}
	if e = inspectioncrl.AcceptUpdate(b.RootCRL, der, root, now); e != nil {
		return e
	}
	b.RootCRL = der
	raw, e = json.MarshalIndent(b, "", "  ")
	if e != nil {
		return e
	}
	// The API payload is derived from the authoritative bundle. Remove any
	// previous payload before committing a newer bundle: interruption during
	// the following writes must never leave an old, uploadable CRL update.
	if e = discardStaleUpdate(filepath.Join(dir, "root-crl-update.json")); e != nil {
		return e
	}
	if e = atomicWrite(filepath.Join(dir, "import.private.json"), raw); e != nil {
		return e
	}
	if e = atomicWrite(filepath.Join(dir, "root.crl"), der); e != nil {
		return e
	}
	update, _ := json.MarshalIndent(struct {
		TenantID string `json:"tenant_id"`
		DER      []byte `json:"der"`
	}{b.TenantID, der}, "", "  ")
	return atomicWrite(filepath.Join(dir, "root-crl-update.json"), update)
}
func main() {
	dir := flag.String("offline-dir", "", "new private operator directory for init, existing for refresh")
	tenant := flag.String("tenant", "", "tenant ID")
	name := flag.String("display-name", "", "CA display name")
	base := flag.String("crl-base", "", "comma-separated HTTP origins serving the same signed CRLs, e.g. http://node-a:80,http://node-b:80")
	op := flag.String("operation", "init", "init or refresh")
	revoke := flag.String("revoke-issuing-sha256", "", "fingerprint of the recorded issuing CA to revoke permanently")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "offline-dir required")
		os.Exit(2)
	}
	var e error
	switch *op {
	case "init":
		e = initialize(*dir, *tenant, *name, *base, time.Now().UTC())
	case "refresh":
		e = refresh(*dir, *revoke, time.Now().UTC())
	default:
		e = fmt.Errorf("unknown operation")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("Signed authority status written; root private key remains in offline custody directory")
}
