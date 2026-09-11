package main

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// audit_ingest_authority.go — WHICH TENANTS an Edge may ship records for.
//
// ★ ONE CERTIFICATE CANNOT MEAN ONE TENANT HERE (2026-08-12, twelfth review, and this is a design correction
// rather than a bug fix). The first version derived the shipping Edge's tenant from which Tenant CA its
// certificate chained to — which conflates two different things: the tenant a certificate BELONGS to, and the
// set of tenants an Edge is allowed to speak for.
//
// An enforcing Edge serves several tenants and ships all of their records from ONE spool, over ONE connection,
// with ONE process identity. Binding the record's tenant to the certificate's tenant therefore forbids every
// record but one tenant's — the check would have been correct and the deployment impossible.
//
// So the certificate answers "which EDGE is this", and a map the control plane holds answers "which tenants may
// it ship for". The single-tenant case still works with no configuration: a certificate that chains to exactly
// one registered Tenant CA authorises that tenant, which is what a single-tenant Edge actually is.
type auditIngestAuthority struct {
	// byEdge maps an edge identity (the certificate's CN) to the tenants it may ship for. "*" authorises all,
	// and is deliberately spelled out rather than implied by an absent entry.
	byEdge map[string][]string
}

var auditIngestAuthorityMap *auditIngestAuthority

// LoadAuditIngestAuthority reads the edge→tenants map. Absent is not an error: a deployment with one tenant
// per Edge needs none, and the certificate's own CA answers for it.
func loadAuditIngestAuthority(path string) (*auditIngestAuthority, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var byEdge map[string][]string
	if jerr := json.Unmarshal(raw, &byEdge); jerr != nil {
		return nil, jerr
	}
	return &auditIngestAuthority{byEdge: byEdge}, nil
}

func setAuditIngestAuthority(a *auditIngestAuthority) { auditIngestAuthorityMap = a }

// auditIngestShipper is who a shipment came from: the certificate's identity, and the tenant its issuing CA
// belongs to when a registry resolved one. Both are needed — the identity is what the authority map is keyed
// by, and the CA's tenant is what authorises a single-tenant Edge with no map at all.
type auditIngestShipper struct {
	Identity   string
	CertTenant string
}

func (s auditIngestShipper) String() string {
	if s.CertTenant != "" {
		return s.Identity + " (certificate issued for tenant " + s.CertTenant + ")"
	}
	return s.Identity
}

// auditIngestShipperFrom answers who this shipment is from, and whether it was identified at all.
func auditIngestShipperFrom(r *http.Request, reg *tenantca.TenantCARegistry) (auditIngestShipper, bool) {
	identity, ok := transportDeviceIdentityFromRequest(r)
	if !ok || strings.TrimSpace(identity) == "" {
		return auditIngestShipper{}, false
	}
	shipper := auditIngestShipper{Identity: identity}
	if r.TLS != nil {
		if tenant, resolved := chainsToTenant(r.TLS.VerifiedChains, reg); resolved {
			shipper.CertTenant = tenant
		}
	}
	return shipper, true
}

// edgeMayShipForTenant is the authorisation itself.
//
// With a map configured, the edge's identity must list the tenant (or "*"). Without one, the certificate must
// chain to that tenant's registered CA — the single-tenant deployment, unchanged.
func edgeMayShipForTenant(shipper auditIngestShipper, tenantID string) bool {
	tenantID = strings.ToLower(strings.TrimSpace(tenantID))
	if strings.TrimSpace(shipper.Identity) == "" || tenantID == "" {
		return false
	}
	if auditIngestAuthorityMap != nil {
		for _, allowed := range auditIngestAuthorityMap.byEdge[strings.TrimSpace(shipper.Identity)] {
			allowed = strings.ToLower(strings.TrimSpace(allowed))
			if allowed == "*" || allowed == tenantID {
				return true
			}
		}
		return false
	}
	// No map: the certificate speaks for its own tenant and no other. That is the single-tenant deployment,
	// and a MULTI-tenant Edge needs the map — which is why its absence is reported at startup rather than
	// discovered as a wall of 403s.
	return strings.EqualFold(shipper.CertTenant, tenantID)
}

func chainsToTenant(chains [][]*x509.Certificate, reg *tenantca.TenantCARegistry) (string, bool) {
	if reg == nil || len(chains) == 0 {
		return "", false
	}
	return reg.TenantForVerifiedChains(chains)
}
