package policyrule

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAuthoredZeroFreshnessSurvivesBothCompilers(t *testing.T) {
	for _, plane := range []string{PlaneEgress, PlaneEastWest} {
		for _, field := range []string{"", `,"max_age_seconds":0`, `,"max_age_seconds":300`} {
			t.Run(plane+field, func(t *testing.T) {
				var rule Rule
				body := `{"id":"rule","tenant_id":"tenant","plane":"` + plane + `","status":"active","source":["*"],"destination":["*"],"action":{"access":"authenticate"` + field + `}}`
				if err := json.Unmarshal([]byte(body), &rule); err != nil {
					t.Fatal(err)
				}
				if err := rule.normalizeAndValidate(); err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(rule)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), `"max_age_seconds"`) != (field != "") {
					t.Errorf("stored JSON lost presence: %s", encoded)
				}
				var dec model.AccessDecision
				if plane == PlaneEgress {
					rules := CompileEgressPolicies("tenant", []Rule{rule}, fakeEgressResolver{})
					dec = (decision.Evaluator{Policies: rules}).Evaluate(model.DecisionRequest{TenantID: "tenant"})
				} else {
					rules := CompileEastWest("tenant", []Rule{rule}, stubEWResolver{})
					dec = (decision.Evaluator{EastWestEnabled: true, EastWestRules: rules}).Evaluate(model.DecisionRequest{TenantID: "tenant", Destination: "10.0.0.1", ServiceFamily: "ssh", Protocol: "tcp", DestinationPort: 22})
				}
				if len(dec.Actions) != 1 {
					t.Fatalf("no auth action: %+v", dec)
				}
				age, present := dec.Actions[0].Metadata["max_age_seconds"]
				if present != (field != "") {
					t.Errorf("compiler lost explicit max_age presence: %+v", dec.Actions[0])
				}
				if field == `,"max_age_seconds":0` && age != 0 {
					t.Errorf("zero changed to %v", age)
				}
			})
		}
	}
}

func authMaxAgeForTest(v int) *int { return &v }

func TestAuthoredZeroFreshnessIsNotReleasedByLegacyGrant(t *testing.T) {
	var r Rule
	if err := json.Unmarshal([]byte(`{"id":"one","tenant_id":"tenant","plane":"east_west","direction":"outbound","status":"active","source":["*"],"destination":["*"],"action":{"access":"authenticate","max_age_seconds":0,"device_attested_auto":true}}`), &r); err != nil {
		t.Fatal(err)
	}
	e := decision.Evaluator{EastWestEnabled: true, EastWestRules: CompileEastWest("tenant", []Rule{r}, stubEWResolver{}), EastWestGrants: []decision.EastWestGrant{{ExpiresAt: time.Now().Add(time.Hour)}}}
	request := model.DecisionRequest{TenantID: "tenant", Destination: "10.0.0.1", ServiceFamily: "ssh", TransportClientCertVerified: true, TransportDeviceIdentity: "device"}
	if got := e.Evaluate(request); got.Decision != "authenticate_required" {
		t.Fatalf("one-request auth skipped by legacy grant: %s", got.Decision)
	}
	e.EastWestGrants = nil
	if got := e.Evaluate(request); got.Decision != "authenticate_required" {
		t.Fatalf("one-request auth skipped by device attestation: %s", got.Decision)
	}
}

func TestAuthoredMaxAgeValidationAndCopies(t *testing.T) {
	for _, age := range []int{-1, 86401} {
		r := Rule{TenantID: "t", Plane: PlaneEgress, Source: []string{"*"}, Destination: []string{"*"}, Action: Action{Access: AccessAuthenticate, MaxAgeSeconds: &age}}
		if err := r.normalizeAndValidate(); err == nil {
			t.Fatalf("invalid age %d accepted", age)
		}
	}
	r := Rule{Action: Action{MaxAgeSeconds: authMaxAgeForTest(0)}}
	copy := cloneRule(r)
	*copy.Action.MaxAgeSeconds = 300
	if *r.Action.MaxAgeSeconds != 0 {
		t.Fatal("record copy changed original authentication requirement")
	}
}

func TestAuthoredZeroFreshnessSurvivesPersistAndDistribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	s := NewStore()
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	r, err := s.Upsert(Rule{ID: "one", TenantID: "t", Plane: PlaneEastWest, Source: []string{"*"}, Destination: []string{"*"}, Action: Action{Access: AccessAuthenticate, MaxAgeSeconds: authMaxAgeForTest(0)}})
	if err != nil {
		t.Fatal(err)
	}
	*r.Action.MaxAgeSeconds = 600
	reloaded := NewStore()
	if err := reloaded.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	for _, store := range []*Store{s, reloaded} {
		got, ok := store.Get("t", "one")
		if !ok || got.Action.MaxAgeSeconds == nil || *got.Action.MaxAgeSeconds != 0 {
			t.Fatal("one-request semantics changed during persistence/copy")
		}
	}
	var transmitted []Rule
	encoded, err := json.Marshal(reloaded.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &transmitted); err != nil {
		t.Fatal(err)
	}
	if len(transmitted) != 1 || transmitted[0].Action.MaxAgeSeconds == nil || *transmitted[0].Action.MaxAgeSeconds != 0 {
		t.Fatal("distributed rule lost zero")
	}
	ew := CompileEastWest("t", transmitted, stubEWResolver{})
	encoded, err = json.Marshal(ew)
	if err != nil {
		t.Fatal(err)
	}
	var compiled []decision.EastWestRule
	if err := json.Unmarshal(encoded, &compiled); err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 1 || !compiled[0].MaxAgeSecondsSet || compiled[0].MaxAgeSeconds != 0 {
		t.Fatal("compiled distribution lost zero")
	}
}
