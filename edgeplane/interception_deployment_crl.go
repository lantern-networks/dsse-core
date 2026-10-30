package edgeplane

import (
	"crypto/x509"
	"fmt"

	"github.com/lantern-networks/dsse-core/deploymentcrl"
)

// ConfigureDeploymentInterceptionCRL binds the shared deployment signing CA to
// its explicit root and existing issuer CRL publisher. Call before serving traffic.
// The provider certificate can be an intermediate, despite its historical "root"
// name. Its own CDP covers that CA; leaves need the CRL signed by that CA instead.
// Tenant-delegated issuers continue to use their separate publication protocol.
func (interception *NetworkExtensionLabTLSInterception) ConfigureDeploymentInterceptionCRL(rootsPEM []byte) error {
	// An explicitly loaded offline issuer already has its own authority contract;
	// the registry's provider there is only a custody placeholder, not the shared CA.
	interception.issuerMu.Lock()
	offline := interception.offlineIssuer != nil
	interception.issuerMu.Unlock()
	if offline {
		return nil
	}
	provider := interception.rootRegistry.DefaultProvider()
	cert := provider.Certificate()
	if len(cert.CRLDistributionPoints) == 0 {
		return nil
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("shared interception CA cannot sign its advertised leaf CRL")
	}
	roots, err := parseInterceptionCertChainPEM(rootsPEM)
	if err != nil {
		return fmt.Errorf("shared interception CA with CDP requires its deployment root: %w", err)
	}
	for _, root := range roots {
		if !isSelfSignedCertificate(root) || cert.Equal(root) || cert.CheckSignatureFrom(root) != nil {
			continue
		}
		pool := x509.NewCertPool()
		pool.AddCert(root)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: interception.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			continue
		}
		origins, err := deploymentcrl.DistributionPointsFromCertificate(cert, root, root)
		if err != nil {
			continue
		}
		points, err := deploymentcrl.DistributionPoints(origins, root, cert)
		if err != nil {
			return err
		}
		issuer := directInterceptionIssuer(provider)
		issuer.trustAnchor = root
		issuer.deploymentLeafCRLPoints = points
		interception.issuerMu.Lock()
		interception.deploymentCRLIssuer = issuer
		interception.issuerMu.Unlock()
		return nil
	}
	return fmt.Errorf("shared interception CA CDP does not bind its verified deployment root and parent issuer")
}

// Called with issuerMu held. Never infer a publisher for an unknown authority or
// silently serve leaves without revocation information when its CA advertises it.
func (interception *NetworkExtensionLabTLSInterception) directIssuerLocked(provider InterceptionRootProvider) (*InterceptionIssuer, error) {
	if len(provider.Certificate().CRLDistributionPoints) == 0 {
		return directInterceptionIssuer(provider), nil
	}
	issuer := interception.deploymentCRLIssuer
	if issuer == nil || !issuer.signingCert.Equal(provider.Certificate()) {
		return nil, fmt.Errorf("shared interception issuer CRL is not bound to a verified deployment root")
	}
	return issuer, nil
}
