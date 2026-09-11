package main

import (
	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"
)

// usageMeterStoreMode type-switches on the concrete usage-meter store — including the Postgres-backed
// store, whose type lives in cmd/edge (DB infra) and is therefore unknown to the usagemeter package.
// Injected into usagemeter.UsageMeterHealthFor so the package stays free of the persistence import.
func usageMeterStoreMode(store usagemeter.UsageMeterRuntimeStore) string {
	switch store.(type) {
	case nil:
		return "none"
	case *usagemeter.UsageMeterStore:
		return "memory"
	case *postgresUsageMeterStore:
		return "postgres"
	default:
		return "custom"
	}
}
