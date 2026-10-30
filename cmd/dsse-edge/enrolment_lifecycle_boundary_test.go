package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
	"github.com/lantern-networks/dsse-core/model"
)

type failedEnrollmentLifecycle struct{ adminTenantModelRuntimeStore }

func (failedEnrollmentLifecycle) Get(context.Context, string) (adminTenantModel, error) {
	return adminTenantModel{}, errors.New("registry unavailable")
}

func TestEnrollmentUsesApprovedTenantLifecycleBeforeSpending(t *testing.T) {
	old := tenantDeviceIdentity
	t.Cleanup(func() { tenantDeviceIdentity = old })
	now := time.Now().UTC()
	cert, key := interceptionTestCA(t, "enrollment fixture", nil, nil, now)
	signer := deviceca.NewSigner(cert, key)
	tenantDeviceIdentity = &tenantDeviceSigners{signers: map[string]*deviceca.Signer{"tenant_test": signer}}
	for _, status := range []string{"active", "suspended", "archived", "unavailable"} {
		t.Run(status, func(t *testing.T) {
			store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "node-tenant"}, now)
			desired := status
			if desired == "unavailable" {
				desired = "active"
			}
			if _, err := store.Put(context.Background(), adminTenantModel{TenantID: "tenant_test", DisplayName: "Target", Status: desired}, now); err != nil {
				t.Fatal(err)
			}
			var lifecycle adminTenantModelRuntimeStore = store
			if status == "unavailable" {
				lifecycle = failedEnrollmentLifecycle{store}
			}
			ledger, tokens := enrolledinventory.NewLedger(), enrolltoken.NewStore()
			mux := http.NewServeMux()
			registerEnrollEndpointWithIdP(mux, signer, ledger, tokens, nil, "", "node-tenant", "default", time.Hour, lifecycle, nil, nil, nil, nil)
			secret := mintOneTimeToken(t, tokens)
			code, _ := enrolWithOneTimeToken(t, mux, "device-"+status, secret)
			if status == "active" {
				if code != 200 {
					t.Fatalf("active target refused: %d", code)
				}
			} else {
				if code != 403 || ledger.IsAdmitted("device-"+status) {
					t.Fatalf("target %s admitted: %d", status, code)
				}
				if tokens.Outstanding("tenant_test", now) != 1 {
					t.Fatal("refused admission spent approval")
				}
			}
		})
	}
}

func TestTokenIssuanceRefusesUnavailableLifecycle(t *testing.T) {
	tokens := enrolltoken.NewStore()
	mux := http.NewServeMux()
	registerAdminEnrolmentTokenEndpoints(mux, tokens, enrolltoken.DefaultPolicy(), func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, nil, nil, "tenant_test", failedEnrollmentLifecycle{}, nil, "", "")
	code, _ := issueBatch(t, mux, `{"expires_in_hours":24}`)
	if code != 503 || tokens.Outstanding("tenant_test", time.Now()) != 0 {
		t.Fatalf("unavailable lifecycle issued token: %d", code)
	}
}
