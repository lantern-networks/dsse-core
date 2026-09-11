package main

// the_store_has_its_own_authority.go — the certificates the consensus store's members present to each other.
//
// ★★★ WHY THE STORE NEEDS ITS OWN, AND WHY THE CONTROL PLANE CANNOT ISSUE THEM (2026-08-31).
//
// Once the store has a member in each state-bearing region, its members talk across whatever is between those
// regions — which, between two cloud regions that nobody has peered, is the public network. What crosses is
// the deployment's durable decision state: which database is primary, every one-time decision, every identity
// claim. The database beside it had the same problem and it was fixed the same way (2026-08-24, sslmode was
// disable); this is that fix, one component over.
//
// The control plane holds this deployment's authorities and cannot issue these: it starts after Postgres,
// which starts after the store. By the time anything could ask the control plane for a certificate, the thing
// that needs one has already had to be running. The installer runs before all of them — it is what mints the
// deployment's anchor — so it mints this too.
//
// ★★★ AND IT IS A SEPARATE TREE FROM THE DEPLOYMENT'S ANCHOR, DELIBERATELY. deployment-anchor.pem is given to
// every device this deployment enrols. A root a device is told to trust must not also vouch for the peers of
// the store that decides which database is primary: the two differ in purpose, in lifetime, and in what is
// lost when one leaks. Nothing outside the state-bearing machines ever sees this one.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// storeMemberYears is how long a member certificate lasts. The same as the deployment's own authorities:
// these are node material an operator replaces by re-packing a machine, not something that rotates on its own.
const storeMemberYears = 5

const (
	storeCAFile        = "store-ca.pem"
	storeMemberFile    = "store-member.pem"
	storeMemberKeyFile = "store-member-key.pem"
	storeCAKeyFile     = "store-ca-key.pem" // authority/ only: this one never travels
)

type storeAuthority struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// mintStoreAuthority creates the store's own root.
func mintStoreAuthority(orgName string, now time.Time, years int) (*storeAuthority, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	cert, err := selfSigned(pkix.Name{
		Organization: []string{orgName},
		// ★ NAMED FOR WHAT IT IS. An operator reading a certificate store has to be able to tell this from the
		// deployment's anchor at a glance, because the two must never be confused for one another.
		CommonName: orgName + " Consensus Store CA",
	}, key, now, now.AddDate(years, 0, 0))
	if err != nil {
		return nil, err
	}
	return &storeAuthority{Cert: cert, Key: key}, nil
}

// loadStoreAuthority reads it back on a later run — carrying a machine happens long after minting.
func loadStoreAuthority(dir string) (*storeAuthority, error) {
	certPEMBytes, err := os.ReadFile(filepath.Join(dir, storeCAFile))
	if err != nil {
		return nil, err
	}
	keyPEMBytes, err := os.ReadFile(filepath.Join(dir, authorityDirName, storeCAKeyFile))
	if err != nil {
		return nil, err
	}
	cert, err := firstCertificateIn(certPEMBytes)
	if err != nil {
		return nil, err
	}
	key, err := firstECKeyIn(keyPEMBytes)
	if err != nil {
		return nil, err
	}
	return &storeAuthority{Cert: cert, Key: key}, nil
}

// writeStoreAuthority puts the certificate where members mount it and the key where only this program reads
// it. The authority directory is the one that does not travel, structurally — see carry.
func writeStoreAuthority(dir string, sa *storeAuthority) error {
	if err := os.MkdirAll(filepath.Join(dir, authorityDirName), 0o700); err != nil {
		return err
	}
	if err := writeContainerReadableFile(filepath.Join(dir, storeCAFile), certPEM(sa.Cert)); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, authorityDirName, storeCAKeyFile), keyPEM(sa.Key), 0o600)
}

// issueStoreMember issues one member's certificate. It is BOTH a server and a client certificate: etcd peers
// dial each other, so each member is the caller half the time and the answerer the other half, and a
// certificate good for only one of those makes a cluster that connects in one direction.
func issueStoreMember(sa *storeAuthority, memberName string, sans []string, now time.Time, years int) (
	*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: sa.Cert.Subject.Organization, CommonName: memberName},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(years, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, sa.Cert, &key.PublicKey, sa.Key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// writeStoreMember puts one member's material where the compose file mounts it.
//
// ★ THE SAME TWO PATHS ON EVERY MACHINE, with different contents. Carrying replaces the bytes for the machine
// being packed, the way it already replaces the compose file and the environment — so no machine holds
// another member's private key, and no path has to vary per region.
func writeStoreMember(dir string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	if err := os.WriteFile(filepath.Join(dir, storeMemberFile), certPEM(cert), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, storeMemberKeyFile), keyPEM(key), 0o600)
}

// storeMemberSANs is what a member's certificate has to be valid for: the name its peers dial it by. The
// member's own cluster name is included so a reader of the certificate can tell which member it is.
func storeMemberSANs(reachable, memberName string) []string {
	sans := []string{}
	if reachable != "" {
		sans = append(sans, reachable)
	}
	if memberName != "" {
		sans = append(sans, memberName)
	}
	if len(sans) == 0 {
		return nil
	}
	return sans
}

func firstECKeyIn(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, err := firstPEMBlock(pemBytes, "EC PRIVATE KEY")
	if err != nil {
		// The writer may have used PKCS#8; accept what it wrote.
		block, err = firstPEMBlock(pemBytes, "PRIVATE KEY")
		if err != nil {
			return nil, err
		}
		k, perr := x509.ParsePKCS8PrivateKey(block)
		if perr != nil {
			return nil, perr
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("the store authority's key is not an EC key")
		}
		return ec, nil
	}
	return x509.ParseECPrivateKey(block)
}

// firstPEMBlock returns the DER of the first block of the named type.
func firstPEMBlock(pemBytes []byte, want string) ([]byte, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no %s block found", want)
		}
		if block.Type == want {
			return block.Bytes, nil
		}
	}
}

// storeMemberMaterialFor issues the member material for the machine these values describe, or nothing at all
// when this deployment's store does not span regions.
//
// ★★★ THE SAN COMES FROM THE VALUE THAT TELLS PEERS WHERE TO GO (2026-08-31). A member advertises itself at
// DSSE_ETCD_A_PEER_ADVERTISE and its peers verify the name they dialled; deriving the certificate's name from
// anywhere else is two answers to one question, and the failure is a cluster whose members reach each other
// and refuse each other.
//
// ★ ONE DEFINITION, TWO CALLERS. The founding machine writes these into its own directory when the plan is
// applied to it; every other machine gets them substituted into the archive when it is packed. Both know the
// region and the name its peers use, and nothing else in this program does.
func storeMemberMaterialFor(dir string, values map[string]string, now time.Time, years int) (cert, key []byte, err error) {
	// ★★★ THE MATERIAL ALWAYS EXISTS, AND TLS IS WHAT IS CONDITIONAL (2026-08-31, caught while mounting it).
	// The compose file mounts these three paths on every machine, and Docker answers a mount of a path that
	// is not there by creating an EMPTY DIRECTORY — so a one-host deployment would start with a directory
	// where a certificate belongs and nothing would say so. Issuing material a single-host store never
	// presents costs one certificate; the alternative is a mount that silently becomes the wrong kind of
	// thing.
	name := strings.TrimSpace(values["DSSE_ETCD_A_NAME"])
	advertise := strings.TrimSpace(values["DSSE_ETCD_A_PEER_ADVERTISE"])
	if name == "" {
		name = "dsse-store-a" // the one-host member's own name, which is what its compose service is called
	}
	reachable := advertise
	if u, uerr := url.Parse(advertise); uerr == nil && u.Hostname() != "" {
		reachable = u.Hostname()
	}
	if strings.TrimSpace(reachable) == "" {
		reachable = name
	}
	sa, lerr := loadStoreAuthority(dir)
	if lerr != nil {
		// A deployment minted before this existed has no store authority, and a member certificate is not
		// something to invent from nothing. Saying so is better than a file that verifies against nobody.
		return nil, nil, fmt.Errorf("this deployment has no consensus-store authority to issue a member "+
			"certificate from (%w) — it was minted before the store had one, and re-minting is a rotation", lerr)
	}
	c, k, ierr := issueStoreMember(sa, name, storeMemberSANs(reachable, name), now, years)
	if ierr != nil {
		return nil, nil, ierr
	}
	return certPEM(c), keyPEM(k), nil
}
