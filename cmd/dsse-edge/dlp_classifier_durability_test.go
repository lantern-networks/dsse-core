package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/logs"
)

type checkedClassifierPersister struct {
	data   []byte
	err    error
	writes int
}

func (p *checkedClassifierPersister) Load() ([]byte, error) {
	return append([]byte(nil), p.data...), nil
}
func (p *checkedClassifierPersister) Save(b []byte) error {
	p.writes++
	if p.err != nil {
		return p.err
	}
	p.data = append([]byte(nil), b...)
	return nil
}
func classifierFixtureSpecs(word string) []dlp.ClassifierSpec {
	return []dlp.ClassifierSpec{{Name: "project_code", Kind: dlp.ClassifierKeyword, Keywords: []string{word}}}
}

func TestDLPClassifierDurableReplacementFailureAndRestart(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newDLPClassifierRuntimeStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"own", "foreign"} {
		if err := s.SetSpecsDurable(tenant, classifierFixtureSpecs("OLD")); err != nil {
			t.Fatal(err)
		}
	}
	before := string(p.data)
	gen := s.generation
	for _, failure := range []error{errors.New("private storage failure"), blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed} {
		p.err = failure
		for _, specs := range [][]dlp.ClassifierSpec{classifierFixtureSpecs("NEW"), nil} {
			if !errors.Is(s.SetSpecsDurable("own", specs), failure) {
				t.Fatal("save failure hidden")
			}
			if s.generation != gen || s.dirty || string(p.data) != before || !reflect.DeepEqual(s.SpecsForTenant("own"), classifierFixtureSpecs("OLD")) {
				t.Fatal("failed candidate published")
			}
			if got := dlp.DetectWith([]byte("OLD"), "text/plain", s.ClassifierSetForTenant("own")); len(got) != 1 {
				t.Fatal("failed candidate changed scanner")
			}
			if err := s.PersistIfDirty(); err != nil {
				t.Fatal(err)
			}
		}
	}
	p.err = nil
	if err := s.SetSpecsDurable("own", classifierFixtureSpecs("NEW")); err != nil {
		t.Fatal(err)
	}
	restarted := newDLPClassifierRuntimeStore()
	if err := restarted.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if len(dlp.DetectWith([]byte("NEW"), "text/plain", restarted.ClassifierSetForTenant("own"))) != 1 || len(dlp.DetectWith([]byte("OLD"), "text/plain", restarted.ClassifierSetForTenant("own"))) != 0 {
		t.Fatal("restart lost committed scanner")
	}
	if !reflect.DeepEqual(restarted.SpecsForTenant("foreign"), classifierFixtureSpecs("OLD")) {
		t.Fatal("foreign tenant changed")
	}
	if err := s.SetSpecsDurable("own", nil); err != nil {
		t.Fatal(err)
	}
	restarted = newDLPClassifierRuntimeStore()
	if err := restarted.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if len(restarted.SpecsForTenant("own")) != 0 || restarted.ClassifierSetForTenant("own").Has("project_code") {
		t.Fatal("deletion did not survive restart")
	}
}

func TestDLPClassifierDurableValidationAndKeywordOwnership(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(map[bool]string{false: "staged", true: "durable"}[durable], func(t *testing.T) {
			p := &checkedClassifierPersister{}
			s := newDLPClassifierRuntimeStore()
			s.SetPersister(p)
			input := classifierFixtureSpecs("ORIGINAL")
			if durable {
				if err := s.SetSpecsDurable("own", input); err != nil {
					t.Fatal(err)
				}
			} else {
				s.SetSpecs("own", input)
			}
			input[0].Keywords[0] = "MUTATED"
			output := s.SpecsForTenant("own")
			output[0].Keywords[0] = "MUTATED-GET"
			if err := s.PersistIfDirty(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(p.data), "ORIGINAL") || strings.Contains(string(p.data), "MUTATED") {
				t.Fatal("caller changed stored definition")
			}
			if len(dlp.DetectWith([]byte("ORIGINAL"), "text/plain", s.ClassifierSetForTenant("own"))) != 1 {
				t.Fatal("scanner diverged")
			}
			before, gen, writes := string(p.data), s.generation, p.writes
			if err := s.SetSpecsDurable("own", append(classifierFixtureSpecs("NEW"), dlp.ClassifierSpec{Name: "bad", Kind: dlp.ClassifierRegex, Pattern: "["})); err == nil {
				t.Fatal("partial validation accepted")
			}
			if string(p.data) != before || s.generation != gen || p.writes != writes {
				t.Fatal("invalid proposal saved")
			}
		})
	}
}

func TestDLPClassifierPeriodicFlushCannotOverwriteAdminCommit(t *testing.T) {
	p := &gatedDLPPolicyPersister{entered: make(chan struct{}), release: make(chan struct{})}
	s := newDLPClassifierRuntimeStore()
	s.SetPersister(p)
	s.SetSpecs("own", classifierFixtureSpecs("OLD"))
	flushed := make(chan error, 1)
	go func() { flushed <- s.PersistIfDirty() }()
	<-p.entered
	committed := make(chan error, 1)
	go func() { committed <- s.SetSpecsDurable("own", classifierFixtureSpecs("NEW")) }()
	close(p.release)
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	var snap classifierStoreSnapshot
	if err := json.Unmarshal(p.data, &snap); err != nil {
		t.Fatal(err)
	}
	if p.writes != 2 || !reflect.DeepEqual(snap.Specs["own"], classifierFixtureSpecs("NEW")) || s.dirty {
		t.Fatal("flush overwrote acknowledged commit")
	}
}

func TestAdminDLPClassifierDurableSaveAndAudit(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newDLPClassifierRuntimeStore()
	s.SetPersister(p)
	s.SetSpecsDurable("tenant_other", classifierFixtureSpecs("FOREIGN"))
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "classifier-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "classifier-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("classifier-fixture"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "classifier-admin", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDLPRoutes(mux, newAdminEndpointMiddleware(testEvaluator(), writer, nil, auth, "", true, nil, nil, nil), testEvaluator(), nil, nil, nil, nil, nil, s, newEntitlementStore(map[string]bool{featureDLP: true}), nil, "")
	steps := []struct {
		body   string
		fail   bool
		status int
	}{
		{`{"classifiers":[{"name":"project_code","kind":"keyword","keywords":["ORIGINAL"]}]}`, false, 200},
		{`{"classifiers":[{"name":"project_code","kind":"keyword","keywords":["NEW"]}]}`, true, 500},
		{`{"classifiers":[]}`, true, 500}, {`{}`, false, 400}, {`{"classifiers":null}`, false, 400},
		{`{"classifiers":[{"name":"bad","kind":"regex","pattern":"["}]}`, false, 400},
		{`{"classifiers":[]}`, false, 200},
	}
	for _, step := range steps {
		p.err = nil
		if step.fail {
			p.err = errors.New("private-storage-location")
		}
		before, gen := string(p.data), s.generation
		req := httptest.NewRequest("POST", "/admin/dlp-classifiers", strings.NewReader(step.body))
		req.Header.Set("Authorization", "Bearer classifier-fixture")
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, req)
		if r.Code != step.status || strings.Contains(r.Body.String(), "private-storage-location") {
			t.Fatalf("response %d %s", r.Code, r.Body)
		}
		if step.status != 200 && (string(p.data) != before || s.generation != gen) {
			t.Fatal("rejected HTTP edit changed state")
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != len(steps) {
		t.Fatalf("audits %d", len(lines))
	}
	for i, line := range lines {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		want := "success"
		if steps[i].status != 200 {
			want = "error"
		}
		if row["result"] != want || row["actor_user_id"] != "classifier-admin" || row["tenant_id"] != "tenant_lab_001" {
			t.Fatalf("audit %d: %s", i, line)
		}
	}
	for _, secret := range []string{"ORIGINAL", "FOREIGN", "private-storage-location", "classifier-fixture"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("audit disclosed %q", secret)
		}
	}
}

func TestDLPClassifierFailedFlushRetainsPendingState(t *testing.T) {
	p := &checkedClassifierPersister{err: errors.New("unavailable")}
	s := newDLPClassifierRuntimeStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	s.SetSpecs("own", classifierFixtureSpecs("PENDING"))
	generation := s.generation
	if err := s.PersistIfDirty(); err == nil || !s.dirty {
		t.Fatal("failed flush discarded pending state")
	}
	if err := s.SetSpecsDurable("own", classifierFixtureSpecs("REJECTED")); err == nil || !s.dirty || s.generation != generation {
		t.Fatal("failed admin edit discarded pending state")
	}
	p.err = nil
	if err := s.PersistIfDirty(); err != nil || s.dirty {
		t.Fatalf("retry: %v", err)
	}
	if !strings.Contains(string(p.data), "PENDING") || strings.Contains(string(p.data), "REJECTED") {
		t.Fatal("failed proposal entered retry snapshot")
	}
}

type unconfirmedClassifierPersister struct {
	checkedClassifierPersister
	uncertain bool
}

func (p *unconfirmedClassifierPersister) Save(b []byte) error {
	if err := p.checkedClassifierPersister.Save(b); err != nil {
		return err
	}
	if p.uncertain {
		return blobstore.ErrDurabilityUnconfirmed
	}
	return nil
}
func TestDLPClassifierUnconfirmedWriteDoesNotClaimDiskRollback(t *testing.T) {
	p := &unconfirmedClassifierPersister{}
	s := newDLPClassifierRuntimeStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSpecsDurable("own", classifierFixtureSpecs("OLD")); err != nil {
		t.Fatal(err)
	}
	generation := s.generation
	p.uncertain = true
	if err := s.SetSpecsDurable("own", classifierFixtureSpecs("NEW")); !errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
		t.Fatal("unconfirmed write reported success")
	}
	if s.generation != generation || !reflect.DeepEqual(s.SpecsForTenant("own"), classifierFixtureSpecs("OLD")) {
		t.Fatal("unconfirmed write became live")
	}
	restarted := newDLPClassifierRuntimeStore()
	if err := restarted.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restarted.SpecsForTenant("own"), classifierFixtureSpecs("NEW")) {
		t.Fatal("fixture must exercise written-but-unconfirmed snapshot")
	}
}
