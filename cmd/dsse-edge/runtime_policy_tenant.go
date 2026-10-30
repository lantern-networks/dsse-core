package main

import (
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/policy"
)

// runtimeEvaluatorForTenant applies tenant-scoped Connector Access posture and
// rules for the identity proven on this flow. The base bundle names the node's
// tenant, which may differ from the mTLS device's tenant on a shared Edge.
func runtimeEvaluatorForTenant(base decision.Evaluator, store policy.RuntimeStore, tenantID string) decision.Evaluator {
	base.PolicyBundle.TenantID = strings.TrimSpace(tenantID)
	return runtimeEvaluatorForPolicyStore(base, store)
}
