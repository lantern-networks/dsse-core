package edgeplane

import "github.com/lantern-networks/dsse-core/egressbroker"

// The browser-faithful egress broker client lives in dsse-core (package egressbroker): the broker is the only
// egress engine for decrypt-all in BOTH editions, so shipping the open edition without it would mean shipping
// only the fingerprint bot management detects. What stays here is the naming the composition root already uses
// — these aliases are the whole of the product-side surface, not a second implementation.
type BrokerHealthMonitor = egressbroker.HealthMonitor

// EgressEngineEmbedded is true in the -tags embedbroker build, where the engine runs in this process rather
// than as a sidecar. The composition root uses it to skip the broker health probe, which has nothing to probe
// and would otherwise report a failure the node does not have.
const EgressEngineEmbedded = egressbroker.EngineEmbedded

var (
	NewBrokerEgressRoundTripper = egressbroker.NewRoundTripper
	EgressBrokerURLFromEnv      = egressbroker.URLFromEnv
	BrokerIsWSUpgrade           = egressbroker.IsWSUpgrade
	NewBrokerHealthMonitor      = egressbroker.NewHealthMonitor
)
