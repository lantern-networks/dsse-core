package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/lantern-networks/dsse-core/deploymentcrl"
)

// checkDeploymentCRLOnline is a read-only pre-connection check. Every declared
// public origin must return the current signed CRL for the actual deployed
// chain. It never adds trust roots or weakens TLS/browser verification.
func checkDeploymentCRLOnline(ctx context.Context, dir string, origins []string, controlPlane, edges bool) error {
	root, err := readCertificate(filepath.Join(dir, "root.crt"))
	if err != nil {
		return err
	}
	var leaves []string
	if controlPlane {
		leaves = append(leaves, "management.crt", "console-server.crt")
	}
	if edges {
		leaves = append(leaves, "transport.crt")
	}
	if len(leaves) == 0 {
		return fmt.Errorf("this node has no deployment TLS leaf to check")
	}
	for _, name := range leaves {
		chain, err := readIssuedChain(filepath.Join(dir, name), root)
		if err != nil {
			return err
		}
		for i := 0; i < len(chain)-1; i++ {
			expected, err := deploymentcrl.DistributionPoints(origins, root, chain[i+1])
			if err != nil || !slices.Equal(chain[i].CRLDistributionPoints, expected) {
				return fmt.Errorf("%s does not carry the planned issuer-bound public CDPs", name)
			}
		}
		if err := deploymentcrl.ProbeOnline(ctx, chain, nil, time.Now().UTC()); err != nil {
			return fmt.Errorf("%s has no valid Online revocation status: %w", name, err)
		}
	}
	return nil
}

func readIssuedChain(path string, root *x509.Certificate) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	chain := make([]*x509.Certificate, 0, 3)
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("invalid deployment certificate chain at %s", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
		data = rest
	}
	if len(chain) != 2 || root == nil {
		return nil, fmt.Errorf("deployment certificate chain must contain leaf and issuer")
	}
	return append(chain, root), nil
}
