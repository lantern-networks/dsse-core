// dsse-deployment-crl is the issuer-only renewal and keyless HTTP publication
// companion for dsse-install deployment certificates. Run the publisher under
// a separate unprivileged OS account with access only to public certificates
// and DER files; never mount the authority directory into that service.
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/deploymentcrl"
)

type issuerFile struct {
	cert, key string
	optional  bool
}

var issuerFiles = []issuerFile{
	{"root.crt", "root.key", false},
	{"management-ca.crt", "management-ca.key", false},
	{"console-server-ca.crt", "console-server-ca.key", true},
	{"transport-ca.crt", "transport-ca.key", false},
	{"device-ca.crt", "device-ca.key", false},
	{"lantern_dsse_interception_root_ca.pem", "lantern_dsse_interception_root_ca.key.pem", false},
}

func main() {
	dir := flag.String("dir", "", "deployment directory; issuer-only modes require its authority subdirectory")
	mode := flag.String("mode", "", "renew, ready, revoke, serve, replicate, replica-ready, or replica-units")
	certPath := flag.String("revoke-cert", "", "with -mode revoke: certificate to revoke after verifying its issuing CA")
	reason := flag.Int("reason", 1, "with -mode revoke: RFC 5280 revocation reason")
	origins := flag.String("origins", "", "with -mode serve: comma-separated public HTTP origins matching the certificates' CDPs")
	sourceOrigin := flag.String("source-origin", "", "with -mode replicate: signer-host HTTP origin providing issuer-signed DER")
	replicaOrigin := flag.String("replica-origin", "", "with -mode replica-units: independent public HTTP origin encoded in the certificates")
	unitsDir := flag.String("units-dir", "", "with -mode replica-units: output directory for Linux systemd units and activation script")
	listen := flag.String("listen", "127.0.0.1:18080", "with -mode serve: local HTTP bind, normally behind the operator's public port-80 front door")
	flag.Parse()
	if err := run(*dir, *mode, *certPath, *reason, *origins, *sourceOrigin, *replicaOrigin, *unitsDir, *listen); err != nil {
		fmt.Fprintln(os.Stderr, "dsse-deployment-crl:", err)
		os.Exit(1)
	}
}

func run(dir, mode, certPath string, reason int, origins, sourceOrigin, replicaOrigin, unitsDir, listen string) error {
	if dir == "" || strings.TrimSpace(dir) != dir {
		return fmt.Errorf("-dir is required")
	}
	root, err := readCertificate(filepath.Join(dir, "root.crt"))
	if err != nil {
		return err
	}
	publicDir := filepath.Join(dir, "deployment-crl")
	authorityDir := filepath.Join(dir, "authority")
	certs, activeFiles, err := loadIssuerCertificates(dir, authorityDir, mode == "renew" || mode == "revoke")
	if err != nil {
		return err
	}
	switch mode {
	case "ready":
		if sourceOrigin != "" || certPath != "" || origins != "" || replicaOrigin != "" || unitsDir != "" {
			return fmt.Errorf("ready does not accept source, origins, or revocation")
		}
		return deploymentcrl.Ready(authorityDir, publicDir, root, certs, time.Now().UTC(), 2*time.Hour)
	case "replicate":
		if sourceOrigin == "" || certPath != "" || origins != "" || replicaOrigin != "" || unitsDir != "" {
			return fmt.Errorf("replicate requires only -source-origin")
		}
		return deploymentcrl.Replicate(context.Background(), sourceOrigin, publicDir, root, certs, nil, time.Now().UTC(), 2*time.Hour)
	case "replica-ready":
		if sourceOrigin != "" || certPath != "" || origins != "" || replicaOrigin != "" || unitsDir != "" {
			return fmt.Errorf("replica-ready does not accept source, origins, or revocation")
		}
		return deploymentcrl.ReplicaReady(publicDir, root, certs, time.Now().UTC(), 2*time.Hour)
	case "replica-units":
		if sourceOrigin == "" || replicaOrigin == "" || unitsDir == "" || certPath != "" || origins != "" || listen != "127.0.0.1:18080" {
			return fmt.Errorf("replica-units requires -source-origin, -replica-origin, and -units-dir; publisher binds fixed loopback 127.0.0.1:18081")
		}
		return writeReplicaServiceUnits(dir, unitsDir, sourceOrigin, replicaOrigin, root, certs)
	case "serve":
		if origins == "" || certPath != "" || sourceOrigin != "" || replicaOrigin != "" || unitsDir != "" {
			return fmt.Errorf("serve requires only -origins")
		}
		h, err := deploymentcrl.Handler(publicDir, root, certs, strings.Split(origins, ","))
		if err != nil {
			return err
		}
		server := &http.Server{Addr: listen, Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		return server.ListenAndServe()
	case "renew", "revoke":
		if sourceOrigin != "" || origins != "" || replicaOrigin != "" || unitsDir != "" {
			return fmt.Errorf("issuer-only modes do not accept source or publication origins")
		}
		if mode == "renew" && certPath != "" || mode == "revoke" && certPath == "" {
			return fmt.Errorf("-revoke-cert is required only with -mode revoke")
		}
		var issuers []deploymentcrl.Issuer
		for i, item := range activeFiles {
			keyPath := filepath.Join(authorityDir, item.key)
			if item.key == "device-ca.key" || item.key == "lantern_dsse_interception_root_ca.key.pem" {
				keyPath = filepath.Join(dir, item.key)
			}
			key, err := readSigner(keyPath)
			if err != nil {
				return err
			}
			issuers = append(issuers, deploymentcrl.Issuer{Certificate: certs[i], Key: key})
		}
		var additions []deploymentcrl.Revocation
		if mode == "revoke" {
			target, err := readCertificate(certPath)
			if err != nil {
				return err
			}
			for _, issuer := range certs {
				if target.CheckSignatureFrom(issuer) == nil {
					additions = []deploymentcrl.Revocation{{Issuer: issuer, Certificate: target, Reason: reason}}
					break
				}
			}
			if len(additions) == 0 {
				return fmt.Errorf("certificate is not issued by a deployment CA")
			}
		}
		if err := deploymentcrl.Refresh(authorityDir, publicDir, root, issuers, additions, time.Now().UTC()); err != nil {
			return err
		}
		return deploymentcrl.Ready(authorityDir, publicDir, root, certs, time.Now().UTC(), 2*time.Hour)
	default:
		return fmt.Errorf("-mode must be renew, ready, revoke, serve, replicate, replica-ready, or replica-units")
	}
}

func loadIssuerCertificates(dir, authorityDir string, needsSigningKeys bool) ([]*x509.Certificate, []issuerFile, error) {
	var certs []*x509.Certificate
	var activeFiles []issuerFile
	for _, item := range issuerFiles {
		if item.optional {
			certInfo, certErr := os.Stat(filepath.Join(dir, item.cert))
			if os.IsNotExist(certErr) {
				if needsSigningKeys {
					if _, keyErr := os.Stat(filepath.Join(authorityDir, item.key)); !os.IsNotExist(keyErr) {
						return nil, nil, fmt.Errorf("incomplete optional issuer %s", item.cert)
					}
				}
				continue
			}
			if certErr != nil || certInfo.IsDir() {
				return nil, nil, fmt.Errorf("incomplete optional issuer %s", item.cert)
			}
			// The keyless HTTP process may have the entire authority directory
			// masked by its service sandbox. Only the signer checks for keys.
			if needsSigningKeys {
				keyInfo, keyErr := os.Stat(filepath.Join(authorityDir, item.key))
				if keyErr != nil || keyInfo.IsDir() {
					return nil, nil, fmt.Errorf("incomplete optional issuer %s", item.cert)
				}
			}
		}
		cert, err := readCertificate(filepath.Join(dir, item.cert))
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
		activeFiles = append(activeFiles, item)
	}
	return certs, activeFiles, nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate at %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func readSigner(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("invalid private key at %s", path)
	}
	var key any
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key encoding at %s", path)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a signer at %s", path)
	}
	return signer, nil
}
