package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

func TestInterceptionRootWithdrawalIgnoresCaseDistinctOrganizationsDevices(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("other-device", "tenanta", "", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	config := serverConfig{EnrolledLedger: ledger, ObservedExclusions: newObservedExclusionStore(1)}
	verdict := interceptionRootWithdrawalGate(config, nil, "TenantA", "outgoing")
	if !verdict.Allowed || len(verdict.Silent) != 0 {
		t.Fatalf("another organization's device blocked root withdrawal: %+v", verdict)
	}
	verdict = deviceCAWithdrawalGate(config, "TenantA", "outgoing", 1)
	if !verdict.Allowed || len(verdict.Silent) != 0 {
		t.Fatalf("another organization's device blocked CA withdrawal: %+v", verdict)
	}
}

func TestDeviceCAWithdrawalDoesNotUseAnotherOrganizationsManagedCA(t *testing.T) {
	authority := newTenantDeviceAuthority(nil, nil, time.Now)
	if _, err := authority.EnsureCA("tenanta", "other organization"); err != nil {
		t.Fatal(err)
	}
	verdict := deviceCAWithdrawalGate(serverConfig{TenantDeviceAuthority: authority}, "TenantA", "outgoing", 0)
	if verdict.Allowed {
		t.Fatalf("another organization's managed CA made the last-CA withdrawal look safe: %+v", verdict)
	}
}

func TestDeviceCAWithdrawalRecognizesOwnCaseExactManagedCA(t *testing.T) {
	authority := newTenantDeviceAuthority(nil, nil, time.Now)
	if _, err := authority.EnsureCA("TenantA", "own organization"); err != nil {
		t.Fatal(err)
	}
	verdict := deviceCAWithdrawalGate(serverConfig{TenantDeviceAuthority: authority}, "TenantA", "outgoing", 0)
	if !verdict.Allowed {
		t.Fatalf("own managed CA was omitted from retained admission paths: %+v", verdict)
	}
}
