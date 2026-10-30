package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func verifyOneRegionThreeNodesPortalCertificate(dir string, env map[string]string) verifyResult {
	const name = "shared-fleet browser portal certificate"
	fail := func(err error) verifyResult { return verifyResult{name: name, note: err.Error()} }
	if _, err := portalCertificateNames(env); err != nil {
		return fail(err)
	}
	cert, err := os.ReadFile(filepath.Join(dir, "clientless", "tls.crt"))
	if err != nil {
		return fail(fmt.Errorf("read browser certificate: %w", err))
	}
	key, err := os.ReadFile(filepath.Join(dir, "clientless", "tls.key"))
	if err != nil {
		return fail(fmt.Errorf("read browser private key: %w", err))
	}
	extra, err := os.ReadFile(filepath.Join(dir, "clientless", "trust.pem"))
	if err != nil && !os.IsNotExist(err) {
		return fail(err)
	}
	roots, err := portalTrustPool(extra)
	if err != nil {
		return fail(err)
	}
	if err := validatePortalPair(cert, key, env, roots); err != nil {
		return fail(fmt.Errorf("browser certificate/key pair: %w", err))
	}
	return verifyResult{name: name, ok: true, note: "all Portal names served by this Edge have a valid browser certificate under system or explicitly provisioned operator trust; the browser round trip still needs a live test"}
}
