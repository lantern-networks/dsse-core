package main

import (
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
)

// humanIdentityDirectoryFleetCarrier is what a directory store must be able to do for the people directory to
// reach an enforcing Edge: report a monotonic version the config bundle can aggregate, and list the source
// policies that describe the feeds.
//
// ★ NAMED, AND ASSERTED ON EVERY BACKEND AT COMPILE TIME. The same shape was once expressed as an anonymous
// assertion at the call site — `if x, ok := store.(interface{ ... }); ok` — and the production Postgres backend
// simply did not satisfy it, so the ok was discarded and the fleet was told nothing, silently, for as long as
// nobody looked. A backend that cannot carry the directory must fail to compile, not fail to speak.
type humanIdentityDirectoryFleetCarrier interface {
	humanidentity.HumanIdentityDirectoryRuntimeStore
	ConfigGeneration() uint64
	humanidentity.HumanIdentitySourcePolicyLister
}

var _ humanIdentityDirectoryFleetCarrier = (*humanidentity.HumanIdentityDirectoryStore)(nil)
var _ humanIdentityDirectoryFleetCarrier = postgresHumanIdentityDirectoryStore{}

// humanIdentityDirectoryCarrier returns the store as a carrier. It reports whether the store can carry rather
// than discarding the answer: a caller that cannot distribute the directory must say so.
func humanIdentityDirectoryCarrier(store humanidentity.HumanIdentityDirectoryRuntimeStore) (humanIdentityDirectoryFleetCarrier, bool) {
	carrier, ok := store.(humanIdentityDirectoryFleetCarrier)
	return carrier, ok && carrier != nil
}
