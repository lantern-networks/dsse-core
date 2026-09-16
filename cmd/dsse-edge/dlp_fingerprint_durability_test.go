package main

import (
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func edmFixtureCount(s *dlpFingerprintRuntimeStore, tenant, body string) int {
	for _, f := range dlp.DetectWithOptions([]byte(body), "text/plain", dlp.Options{Fingerprints: s.FingerprintSetForTenant(tenant)}) {
		if f.Type == "customer_record" {
			return f.Count
		}
	}
	return 0
}
func TestDLPFingerprintDurableMutationFailureAndRestart(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newDLPFingerprintRuntimeStore("salt")
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"own", "foreign"} {
		if n, err := s.SetDatasetDurable(tenant, "customer_record", []string{"CUST-100482", "cust100482", "AB"}); err != nil || n != 1 {
			t.Fatalf("create: %d %v", n, err)
		}
	}
	before, gen := string(p.data), s.generation
	for _, failure := range []error{errors.New("unavailable"), blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed} {
		p.err = failure
		if _, err := s.SetDatasetDurable("own", "customer_record", []string{"NEW-994400"}); !errors.Is(err, failure) {
			t.Fatal("replacement reported success")
		}
		if _, err := s.RemoveDatasetDurable("own", "customer_record"); !errors.Is(err, failure) {
			t.Fatal("deletion reported success")
		}
		if s.generation != gen || s.dirty || string(p.data) != before || edmFixtureCount(s, "own", "CUST-100482") != 1 || edmFixtureCount(s, "own", "NEW-994400") != 0 {
			t.Fatal("failed candidate changed saved/live state")
		}
	}
	p.err = nil
	if _, err := s.SetDatasetDurable("own", "customer_record", []string{"NEW-994400"}); err != nil {
		t.Fatal(err)
	}
	restarted := newDLPFingerprintRuntimeStore("salt")
	if err := restarted.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if edmFixtureCount(restarted, "own", "NEW-994400") != 1 || edmFixtureCount(restarted, "own", "CUST-100482") != 0 || edmFixtureCount(restarted, "foreign", "CUST-100482") != 1 {
		t.Fatal("restart lost saved detection or tenant isolation")
	}
	if removed, err := s.RemoveDatasetDurable("own", "customer_record"); err != nil || !removed {
		t.Fatalf("delete: %v %v", removed, err)
	}
	restarted = newDLPFingerprintRuntimeStore("salt")
	if err := restarted.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if len(restarted.DatasetsForTenant("own")) != 0 || edmFixtureCount(restarted, "own", "NEW-994400") != 0 {
		t.Fatal("deleted dataset returned after restart")
	}
	for _, value := range []string{"CUST-100482", "NEW-994400"} {
		if strings.Contains(string(p.data), value) {
			t.Fatal("raw value in snapshot")
		}
	}
}
func TestDLPFingerprintDurableInvalidReplacementPreservesDataset(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newDLPFingerprintRuntimeStore("salt")
	s.SetPersister(p)
	s.SetDatasetDurable("own", "customer_record", []string{"CUST-100482"})
	before, gen, writes := string(p.data), s.generation, p.writes
	for _, values := range [][]string{nil, {}, {"AB", "12-34"}, {"CUST-100482", "two words"}, {strings.Repeat("Z", 129)}, {"café-value"}} {
		if _, err := s.SetDatasetDurable("own", "customer_record", values); !errors.Is(err, errInvalidFingerprintDataset) {
			t.Fatalf("invalid dataset accepted: %v", err)
		}
		if string(p.data) != before || s.generation != gen || p.writes != writes || edmFixtureCount(s, "own", "CUST-100482") != 1 {
			t.Fatal("invalid replacement changed dataset")
		}
	}
	if _, err := s.SetDatasetDurable("own", "credit_card", []string{"CUST-100482"}); !errors.Is(err, errInvalidFingerprintDataset) {
		t.Fatal("reserved name accepted")
	}
}
func TestDLPFingerprintPeriodicFlushCannotOverwriteAdminCommit(t *testing.T) {
	p := &gatedDLPPolicyPersister{entered: make(chan struct{}), release: make(chan struct{})}
	s := newDLPFingerprintRuntimeStore("salt")
	s.SetPersister(p)
	s.SetDataset("own", "customer_record", []string{"CUST-100482"})
	flushed := make(chan error, 1)
	go func() { flushed <- s.PersistIfDirty() }()
	<-p.entered
	committed := make(chan error, 1)
	go func() {
		_, err := s.SetDatasetDurable("own", "customer_record", []string{"NEW-994400"})
		committed <- err
	}()
	close(p.release)
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	restarted := newDLPFingerprintRuntimeStore("salt")
	var snap fingerprintStoreSnapshot
	if err := json.Unmarshal(p.data, &snap); err != nil {
		t.Fatal(err)
	}
	restored := &checkedClassifierPersister{data: p.data}
	if err := restarted.SetPersister(restored); err != nil {
		t.Fatal(err)
	}
	if p.writes != 2 || s.dirty || edmFixtureCount(restarted, "own", "NEW-994400") != 1 {
		t.Fatal("old flush overwrote acknowledged edit")
	}
}
func TestDLPFingerprintPendingRemovalMustSaveEvenWhenAlreadyMissing(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newDLPFingerprintRuntimeStore("salt")
	s.SetPersister(p)
	s.SetDatasetDurable("own", "customer_record", []string{"CUST-100482"})
	s.RemoveDataset("own", "customer_record")
	p.err = errors.New("unavailable")
	if err := s.PersistIfDirty(); err == nil || !s.dirty {
		t.Fatal("flush lost pending deletion")
	}
	if _, err := s.RemoveDatasetDurable("own", "customer_record"); err == nil || !s.dirty {
		t.Fatal("missing-but-unsaved deletion reported success")
	}
	if _, err := s.SetDatasetDurable("own", "customer_record", []string{"NEW-994400"}); err == nil || !s.dirty {
		t.Fatal("failed candidate discarded old dirty state")
	}
	p.err = nil
	if removed, err := s.RemoveDatasetDurable("own", "customer_record"); err != nil || removed || s.dirty {
		t.Fatalf("retry: %v %v", removed, err)
	}
	if strings.Contains(string(p.data), "customer_record") {
		t.Fatal("pending deletion not saved")
	}
}
func TestDLPFingerprintUnconfirmedWriteDoesNotClaimDiskRollback(t *testing.T) {
	p := &unconfirmedClassifierPersister{}
	s := newDLPFingerprintRuntimeStore("salt")
	s.SetPersister(p)
	s.SetDatasetDurable("own", "customer_record", []string{"CUST-100482"})
	p.uncertain = true
	gen := s.generation
	if _, err := s.SetDatasetDurable("own", "customer_record", []string{"NEW-994400"}); !errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
		t.Fatal("unconfirmed result hidden")
	}
	if s.generation != gen || edmFixtureCount(s, "own", "CUST-100482") != 1 {
		t.Fatal("unconfirmed edit changed live state")
	}
	restarted := newDLPFingerprintRuntimeStore("salt")
	restarted.SetPersister(p)
	if edmFixtureCount(restarted, "own", "NEW-994400") != 1 {
		t.Fatal("fixture did not exercise changed disk")
	}
}
func TestAdminDLPFingerprintDurableSaveValidationAndAudit(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newDLPFingerprintRuntimeStore("salt")
	s.SetPersister(p)
	s.SetDatasetDurable("tenant_other", "customer_record", []string{"FOREIGN-123456"})
	foreign := s.DatasetsForTenant("tenant_other")
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "edm-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "edm-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("edm-fixture"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "edm-admin", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDLPRoutes(mux, newAdminEndpointMiddleware(testEvaluator(), writer, nil, auth, "", true, nil, nil, nil), testEvaluator(), nil, nil, nil, nil, s, nil, newEntitlementStore(map[string]bool{featureDLP: true}), nil, "")
	steps := []struct {
		method, query, body string
		fail                bool
		status              int
	}{
		{"POST", "", `{"name":"customer_record","values":["CUST-100482"]}`, false, 200},
		{"POST", "", `{"name":"customer_record","values":["NEW-994400"]}`, true, 500},
		{"POST", "", `{"name":"customer_record","values":["1234"]}`, false, 400},
		{"POST", "", `{"name":"customer_record","values":["SENSITIVE SUBMITTED VALUE"]}`, false, 400},
		{"POST", "", `{"name":"customer_record"}`, false, 400},
		{"POST", "", `{"name":"customer_record","values":null}`, false, 400},
		{"POST", "", `{"name":"customer_record","values":[]}`, false, 400},
		{"DELETE", "?name=customer_record", "", true, 500},
		{"DELETE", "?name=customer_record", "", false, 200},
	}
	for _, step := range steps {
		p.err = nil
		if step.fail {
			p.err = errors.New("private-storage-location")
		}
		before, gen := string(p.data), s.generation
		req := httptest.NewRequest(step.method, "/admin/dlp-fingerprints"+step.query, strings.NewReader(step.body))
		req.Header.Set("Authorization", "Bearer edm-fixture")
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, req)
		if r.Code != step.status {
			t.Fatalf("response %d %s", r.Code, r.Body)
		}
		for _, secret := range []string{"SENSITIVE SUBMITTED VALUE", "private-storage-location", "CUST-100482", "NEW-994400"} {
			if strings.Contains(r.Body.String(), secret) {
				t.Fatalf("response leaked %s", secret)
			}
		}
		if step.status != 200 && (string(p.data) != before || s.generation != gen) {
			t.Fatal("rejected edit changed dataset")
		}
	}
	if !reflect.DeepEqual(s.DatasetsForTenant("tenant_other"), foreign) {
		t.Fatal("foreign dataset changed")
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
		json.Unmarshal([]byte(line), &row)
		want := "success"
		if steps[i].status != 200 {
			want = "error"
		}
		if row["result"] != want || row["actor_user_id"] != "edm-admin" || row["tenant_id"] != "tenant_lab_001" {
			t.Fatalf("audit %d %s", i, line)
		}
	}
	for _, secret := range []string{"CUST-100482", "NEW-994400", "FOREIGN-123456", "SENSITIVE SUBMITTED VALUE", "private-storage-location", "edm-fixture"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("audit leaked %s", secret)
		}
	}
}

func TestDLPFingerprintSaltIsReadUnderBundleMutationLock(t *testing.T) {
	stores := dlpStoresForTest("initial-salt")
	bundle := dlpStoresForTest("source-salt").Snapshot()
	done := make(chan error, 2)
	go func() {
		for i := 0; i < 200; i++ {
			bundle.Salt = strings.Repeat("s", i%2+1)
			if err := stores.Apply(bundle); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	go func() {
		for i := 0; i < 200; i++ {
			stores.fingerprints.SetDataset("own", "customer_record", []string{"CUST-100482"})
			if _, err := stores.fingerprints.SetDatasetDurable("own", "customer_record", []string{"NEW-994400"}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := stores.fingerprints.SetDatasetDurable("own", "customer_record", []string{"CUST-100482"}); err != nil {
		t.Fatal(err)
	}
	if edmFixtureCount(stores.fingerprints, "own", "CUST-100482") != 1 {
		t.Fatal("published hashes use a different salt than the scanner")
	}
}
