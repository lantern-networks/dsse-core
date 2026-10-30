package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

const databaseCAFile = "database-ca.pem"
const databaseCAKeyFile = "database-ca-key.pem"
const storeClientFile = "store-client.pem"
const storeClientKeyFile = "store-client-key.pem"
const cpQuorumFile = "cp-quorum.pem"
const cpQuorumKeyFile = "cp-quorum-key.pem"
const databaseServerFile = "database-server.pem"
const databaseServerKeyFile = "database-server-key.pem"

// Store consumers and database servers have separate keys. The database CA never
// authenticates an etcd client, and neither CA signing key travels to a node.
func mintDatabaseAuthority(dir, org string, now time.Time, years int) error {
	key, err := newKey()
	if err != nil {
		return err
	}
	cert, err := selfSigned(pkix.Name{Organization: []string{org}, CommonName: org + " Database CA"}, key, now, now.AddDate(years, 0, 0))
	if err != nil {
		return err
	}
	if err = writeContainerReadableFile(filepath.Join(dir, databaseCAFile), certPEM(cert)); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, authorityDirName, databaseCAKeyFile), keyPEM(key), 0600)
}

func loadDatabaseAuthority(dir string) (*storeAuthority, error) {
	b, err := os.ReadFile(filepath.Join(dir, databaseCAFile))
	if err != nil {
		return nil, err
	}
	c, err := firstCertificateIn(b)
	if err != nil {
		return nil, err
	}
	b, err = os.ReadFile(filepath.Join(dir, authorityDirName, databaseCAKeyFile))
	if err != nil {
		return nil, err
	}
	k, err := firstECKeyIn(b)
	if err != nil {
		return nil, err
	}
	return &storeAuthority{Cert: c, Key: k}, nil
}

func databaseNames(values map[string]string) []string {
	names := []string{"postgres", "dsse-postgres-a", "localhost", "127.0.0.1"}
	address := values["DSSE_PG_A_ADVERTISE"]
	if host, _, err := net.SplitHostPort(address); err == nil {
		names = append(names, host)
	}
	for _, field := range []string{"DSSE_NODE_ADDRESS", "DSSE_PG_A_MEMBER_PUBLISH"} {
		v := values[field]
		if host, _, err := net.SplitHostPort(v); err == nil {
			v = host
		}
		if v != "" {
			names = append(names, v)
		}
	}
	return names
}

func runtimeTransportMaterialFor(dir string, values map[string]string, now time.Time) (map[string][]byte, error) {
	store, err := loadStoreAuthority(dir)
	if err != nil {
		return nil, err
	}
	db, err := loadDatabaseAuthority(dir)
	if err != nil {
		return nil, err
	}
	name := values["DSSE_PG_A_NAME"]
	if name == "" {
		name = "dsse-postgres-a"
	}
	out := map[string][]byte{}
	for _, spec := range []struct {
		ca            *storeAuthority
		cert, key, cn string
		usage         x509.ExtKeyUsage
		sans          []string
	}{
		{store, storeClientFile, storeClientKeyFile, "patroni-" + name, x509.ExtKeyUsageClientAuth, nil},
		{store, cpQuorumFile, cpQuorumKeyFile, "cp-quorum-" + name, x509.ExtKeyUsageClientAuth, nil},
		{db, databaseServerFile, databaseServerKeyFile, name, x509.ExtKeyUsageServerAuth, databaseNames(values)},
	} {
		if spec.cert == cpQuorumFile && !threeVoterProfile(values["DSSE_TOPOLOGY_PROFILE"]) {
			continue
		}
		c, k, err := issueStoreMember(spec.ca, spec.cn, nil, now, 1)
		if err != nil {
			return nil, err
		}
		c.ExtKeyUsage = []x509.ExtKeyUsage{spec.usage}
		c.DNSNames = nil
		c.IPAddresses = nil
		for _, s := range spec.sans {
			if ip := net.ParseIP(s); ip != nil {
				c.IPAddresses = append(c.IPAddresses, ip)
			} else {
				c.DNSNames = append(c.DNSNames, s)
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, c, spec.ca.Cert, &k.PublicKey, spec.ca.Key)
		if err != nil {
			return nil, err
		}
		c, err = x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		out[spec.cert], out[spec.key] = certPEM(c), keyPEM(k)
	}
	return out, nil
}

func writeRuntimeTransportMaterial(dir string, material map[string][]byte) error {
	for name, b := range material {
		if name == storeClientKeyFile || name == databaseServerKeyFile || name == cpQuorumKeyFile {
			if err := publishPrivateInstallerKey(filepath.Join(dir, name), b); err != nil {
				return err
			}
		} else if err := writeContainerReadableFile(filepath.Join(dir, name), b); err != nil {
			return err
		}
	}
	return nil
}

func validateRuntimeTransportMaterial(dir string, values map[string]string, now time.Time) error {
	for _, spec := range []struct {
		cert, key, ca string
		usage         x509.ExtKeyUsage
		sans          []string
	}{
		{storeClientFile, storeClientKeyFile, storeCAFile, x509.ExtKeyUsageClientAuth, nil},
		{cpQuorumFile, cpQuorumKeyFile, storeCAFile, x509.ExtKeyUsageClientAuth, nil},
		{databaseServerFile, databaseServerKeyFile, databaseCAFile, x509.ExtKeyUsageServerAuth, databaseNames(values)},
	} {
		if spec.cert == cpQuorumFile && !threeVoterProfile(values["DSSE_TOPOLOGY_PROFILE"]) {
			continue
		}
		if err := checkPrivateInstallerKey(filepath.Join(dir, spec.key)); err != nil {
			return err
		}
		pair, err := tls.LoadX509KeyPair(filepath.Join(dir, spec.cert), filepath.Join(dir, spec.key))
		if err != nil {
			return err
		}
		c, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return err
		}
		ca, err := os.ReadFile(filepath.Join(dir, spec.ca))
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return fmt.Errorf("invalid %s", spec.ca)
		}
		if c.IsCA || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != spec.usage {
			return fmt.Errorf("wrong purpose for %s", spec.cert)
		}
		name := values["DSSE_PG_A_NAME"]
		if name == "" {
			name = "dsse-postgres-a"
		}
		if spec.usage == x509.ExtKeyUsageClientAuth {
			prefix := "patroni-"
			if spec.cert == cpQuorumFile {
				prefix = "cp-quorum-"
			}
			name = prefix + name
		}
		if c.Subject.CommonName != name {
			return fmt.Errorf("%s belongs to a different node", spec.cert)
		}
		if _, err = c.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{spec.usage}}); err != nil {
			return err
		}
		for _, n := range spec.sans {
			if err = c.VerifyHostname(n); err != nil {
				return err
			}
		}
	}
	return nil
}

func runtimeTransportForPlanApply(dir string, values map[string]string, now time.Time) error {
	if err := validateRuntimeTransportMaterial(dir, values, now); err == nil {
		return nil
	}
	material, err := runtimeTransportMaterialFor(dir, values, now)
	if err != nil {
		return fmt.Errorf("runtime transport material is missing or does not match this node; re-pack on the issuing host, without importing CA private keys: %w", err)
	}
	return writeRuntimeTransportMaterial(dir, material)
}
