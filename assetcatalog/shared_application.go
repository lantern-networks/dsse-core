package assetcatalog

import "context"

// Compatibility entry points use the same transaction as contextual callers.
var ErrSharedUpdateUnconfirmed = ErrPersistence

func (s *Store) UpsertApplicationEndpoint(id string, e Endpoint, allowManual bool) (Endpoint, error) {
	return s.UpsertApplicationEndpointContext(context.Background(), id, e, allowManual)
}
func (s *Store) DeleteApplicationEndpoint(tenant, id string, allowManual bool) (bool, error) {
	return s.DeleteApplicationEndpointContext(context.Background(), tenant, id, allowManual)
}
func (s *Store) RenameApplicationEndpoint(tenant, id, alias string, allowManual bool) error {
	return s.RenameApplicationEndpointContext(context.Background(), tenant, id, alias, allowManual)
}
