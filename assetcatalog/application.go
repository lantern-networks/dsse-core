package assetcatalog

import (
	"context"
	"errors"
	"strings"
)

// SourceApplication identifies a rule destination managed by application publish.
// Generic endpoint HTTP writes cannot claim or remove this ownership.

var ErrApplicationEndpointOwnership = errors.New("application endpoint ownership requires endpoint write permission")

// ApplicationEndpointWritable also supports legacy destinations that were stored
// as manual endpoints: only a caller authorized to edit endpoints may adopt them.
func ApplicationEndpointWritable(e Endpoint, applicationID string, allowManual bool) bool {
	if e.BuiltIn || e.ID != "app-"+applicationID {
		return false
	}
	return e.Source == SourceApplication || allowManual && (e.Source == SourceManual || e.Source == "")
}

func (s *Store) UpsertApplicationEndpointContext(ctx context.Context, applicationID string, e Endpoint, allowManual bool) (Endpoint, error) {
	applicationID = strings.TrimSpace(applicationID)
	if applicationID == "" {
		return Endpoint{}, ErrApplicationEndpointOwnership
	}
	e.ID, e.Source = "app-"+applicationID, SourceApplication
	e = copyEndpoint(e)
	return mutateCatalogContext(ctx, s, func(n *Store) (Endpoint, error) {
		if current, found := n.GetEndpoint(e.TenantID, e.ID); found && !ApplicationEndpointWritable(current, applicationID, allowManual) {
			return Endpoint{}, ErrApplicationEndpointOwnership
		}
		return n.upsertEndpoint(e)
	})
}

func (s *Store) DeleteApplicationEndpointContext(ctx context.Context, tenant, applicationID string, allowManual bool) (bool, error) {
	applicationID = strings.TrimSpace(applicationID)
	if applicationID == "" {
		return false, ErrApplicationEndpointOwnership
	}
	return mutateCatalogContext(ctx, s, func(n *Store) (bool, error) {
		id := "app-" + applicationID
		if current, found := n.GetEndpoint(tenant, id); found && !ApplicationEndpointWritable(current, applicationID, allowManual) {
			return false, ErrApplicationEndpointOwnership
		}
		return n.deleteEndpoint(tenant, id)
	})
}

// RenameApplicationEndpointContext updates the existing rule destination's display
// name without replacing its address, tags, identity or group references.
func (s *Store) RenameApplicationEndpointContext(ctx context.Context, tenant, applicationID, alias string, allowManual bool) error {
	_, err := mutateCatalogContext(ctx, s, func(n *Store) (Endpoint, error) {
		current, found := n.GetEndpoint(tenant, "app-"+applicationID)
		if !found || !ApplicationEndpointWritable(current, applicationID, allowManual) {
			return Endpoint{}, ErrApplicationEndpointOwnership
		}
		current.Alias = alias
		return n.upsertEndpoint(current)
	})
	return err
}
