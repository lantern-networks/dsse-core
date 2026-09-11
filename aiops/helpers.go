package aiops

import "github.com/lantern-networks/dsse-core/model"

// DecisionGetter is the minimal view of the access-decision store the explainer needs; cmd/edge injects
// the concrete store.
type DecisionGetter interface {
	Get(id string) (model.AccessDecision, bool)
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
