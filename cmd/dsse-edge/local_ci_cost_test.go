package main

// local_ci_cost_test.go — the guard for the test-time bcrypt override in the package's TestMain.

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// ★ The guard for the override above. Making hashing cheap for tests is one edit away from making it cheap for
// everyone, and that failure has no symptom at all until someone dumps the credential store.
func TestProductionPasswordHashingStaysExpensive(t *testing.T) {
	if productionBcryptCost < 12 {
		t.Fatalf("productionBcryptCost = %d; a real deployment must hash at a cost that makes an offline "+
			"attack on the credential store expensive, and nothing else in this package will notice if it drops",
			productionBcryptCost)
	}
	// And the override must be a TEST-time thing: the default the production path takes is the constant.
	if productionBcryptCost == bcrypt.MinCost {
		t.Fatal("the production cost has been set to bcrypt.MinCost; that is the test override leaking into the build")
	}
}
