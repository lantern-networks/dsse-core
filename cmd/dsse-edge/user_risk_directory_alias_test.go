package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

type unavailableRiskDirectory struct {
	humanidentity.HumanIdentityDirectoryRuntimeStore
}

func (d unavailableRiskDirectory) RiskIdentityIDs(context.Context, string, string) ([]string, error) {
	return nil, fmt.Errorf("private backend detail")
}
func TestDirectoryRiskAliasScopeAndReadFailure(t *testing.T) {
	ctx := context.Background()
	d := humanidentity.NewHumanIdentityDirectoryStore()
	risk := revocation.NewHighRiskOverlay()
	email := "new@example.invalid"
	for _, tenant := range []string{"one", "other"} {
		if _, err := d.Upsert(ctx, model.HumanIdentity{ID: "person", Subject: "new", Email: &email}, tenant, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := risk.SetUserRisk(revocation.UserRisk{ID: "person", TenantID: "one", Subjects: []string{"old"}, Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	before := risk.UserSnapshot()
	gen := risk.ConfigGeneration()
	for _, tc := range []struct{ tenant, user, want string }{{"one", "new", "high"}, {"one", email, "high"}, {"one", "NEW", ""}, {"other", "new", ""}, {"one", "missing", ""}} {
		req, err := enrichDecisionRequestWithDirectoryRisk(ctx, model.DecisionRequest{TenantID: tc.tenant, UserID: tc.user}, d, risk)
		if err != nil || req.RiskStateSeverity != tc.want {
			t.Fatalf("%+v severity=%s err=%v", tc, req.RiskStateSeverity, err)
		}
	}
	req, err := enrichDecisionRequestWithDirectoryRisk(ctx, model.DecisionRequest{TenantID: "one", UserID: "new", RiskStateSeverity: "critical"}, d, risk)
	if err != nil || req.RiskStateSeverity != "critical" {
		t.Fatal("stronger risk lost")
	}
	if _, err := enrichDecisionRequestWithDirectoryRisk(ctx, model.DecisionRequest{TenantID: "one", UserID: "new"}, unavailableRiskDirectory{d}, risk); err == nil || err.Error() != "user risk directory could not be read" {
		t.Fatalf("read failure=%v", err)
	}
	if !reflect.DeepEqual(before, risk.UserSnapshot()) || gen != risk.ConfigGeneration() {
		t.Fatal("read changed risk")
	}
	if _, err := risk.SetUserRisk(revocation.UserRisk{ID: "person", TenantID: "one", Severity: "none"}); err != nil {
		t.Fatal(err)
	}
	req, err = enrichDecisionRequestWithDirectoryRisk(ctx, model.DecisionRequest{TenantID: "one", UserID: "new"}, unavailableRiskDirectory{d}, risk)
	if err != nil || req.RiskStateSeverity != "" {
		t.Fatal("cleared risk still applied or unnecessary read")
	}
}

func TestPostgresDirectoryRiskAliasesFollowStoredUpdateE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range postgresHumanIdentityDirectorySchemaSQL() {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	tenant := "alias-" + time.Now().Format("150405.000000000")
	defer db.ExecContext(context.Background(), "DELETE FROM human_identities WHERE tenant_id IN ($1,$2)", tenant, tenant+"-other")
	d := postgresHumanIdentityDirectoryStore{DB: db}
	risk := revocation.NewHighRiskOverlay()
	now := time.Now()
	person, err := d.Upsert(ctx, model.HumanIdentity{ID: "person", Subject: "old"}, tenant, now)
	if err != nil {
		t.Fatal(err)
	}
	mark := directoryRiskMark(person)
	mark.Severity = "high"
	if _, err := risk.SetUserRisk(mark); err != nil {
		t.Fatal(err)
	}
	email := "current@example.invalid"
	person.Subject = "current"
	person.Email = &email
	if _, err := d.Upsert(ctx, person, tenant, now); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"person", "current", email} {
		req, err := enrichDecisionRequestWithDirectoryRisk(ctx, model.DecisionRequest{TenantID: tenant, UserID: id}, d, risk)
		if err != nil || req.RiskStateSeverity != "high" {
			t.Fatalf("%s risk=%s err=%v", id, req.RiskStateSeverity, err)
		}
	}
	ids, err := d.RiskIdentityIDs(ctx, tenant, "CURRENT")
	if err != nil || len(ids) != 0 {
		t.Fatal("case-folded subject")
	}
	ids, err = d.RiskIdentityIDs(ctx, tenant+"-other", email)
	if err != nil || len(ids) != 0 {
		t.Fatal("cross-tenant lookup")
	}
}
