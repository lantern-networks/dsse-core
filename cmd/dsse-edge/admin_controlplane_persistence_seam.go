package main

import (
	agenttool "github.com/lantern-networks/dsse-core/agenttool"
	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	endpointinventory "github.com/lantern-networks/dsse-core/endpointinventory"
	"github.com/lantern-networks/dsse-core/policy"
	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"
	toolcallaudit "github.com/lantern-networks/dsse-core/toolcallaudit"
)

// Phase 3 control-plane persistence seams define the handler-visible store
// contracts without selecting or binding a durable backend.
type adminPolicyPersistenceSeam interface {
	policy.RuntimeStore
}

type adminApplicationCatalogPersistenceSeam interface {
	appcatalog.RuntimeStore
}

type adminPolicyCandidatePersistenceSeam interface {
	policycandidate.RuntimeStore
}

type adminAgentToolPersistenceSeam interface {
	agenttool.RuntimeStore
}

type adminEndpointInventoryPersistenceSeam interface {
	endpointinventory.RuntimeStore
}

type adminTenantModelPersistenceSeam interface {
	adminTenantModelRuntimeStore
}

type adminToolCallEventAuditPersistenceSeam interface {
	toolcallaudit.RuntimeStore
}

var (
	_ adminPolicyPersistenceSeam             = (*policy.Store)(nil)
	_ adminApplicationCatalogPersistenceSeam = (*appcatalog.Store)(nil)
	_ adminPolicyCandidatePersistenceSeam    = (*policycandidate.Store)(nil)
	_ adminAgentToolPersistenceSeam          = (*agenttool.Store)(nil)
	_ adminEndpointInventoryPersistenceSeam  = (*endpointinventory.Store)(nil)
	_ adminTenantModelPersistenceSeam        = (*adminTenantModelStore)(nil)
	_ adminToolCallEventAuditPersistenceSeam = (*toolcallaudit.Store)(nil)
)
