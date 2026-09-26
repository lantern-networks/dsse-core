package assetcatalog

import (
	"context"
	"errors"
	"strings"
)

const SourceCertPin = "cert_pin"
const certPinEndpointPrefix = "certpin-ep-"

var ErrCertPinEndpointOwnership = errors.New("cert-pin destinations must be managed through bypass review, not the endpoint catalog")

// Reserve the existing generated ID namespace as well as the source marker, so
// upgrades protect legacy manual-source destinations without rewriting policy.
func certPinEndpoint(e Endpoint) bool {
	return e.Source == SourceCertPin || strings.HasPrefix(e.ID, certPinEndpointPrefix)
}

// UpsertCertPinEndpointContext is for an approved candidate's derived destination.
// A legacy manual row can be adopted only if its target and generated shape still
// agree. A conflicting row is never silently retargeted by a retry.
func (s *Store) UpsertCertPinEndpointContext(ctx context.Context, candidateID string, e Endpoint) (Endpoint, error) {
	candidateID = strings.TrimSpace(candidateID)
	if candidateID == "" {
		return Endpoint{}, ErrCertPinEndpointOwnership
	}
	e = copyEndpoint(e)
	e.ID, e.Source = certPinEndpointPrefix+candidateID, SourceCertPin
	return mutateCatalogContext(ctx, s, func(n *Store) (Endpoint, error) {
		if current, found := n.GetEndpoint(e.TenantID, e.ID); found {
			legacy := (current.Source == SourceManual || current.Source == "") && current.Kind == KindNetwork && current.Address == e.Address && !current.Steered && current.Identity == "" && len(current.Tags) == 1 && current.Tags[0] == "cert_pin"
			if current.BuiltIn || current.Source != SourceCertPin && !legacy {
				return Endpoint{}, ErrCertPinEndpointOwnership
			}
		}
		return n.upsertEndpoint(e)
	})
}
