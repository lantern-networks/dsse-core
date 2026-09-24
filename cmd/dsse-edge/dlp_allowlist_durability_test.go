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

func TestDLPAllowlistDurableFailureRetryAndRestart(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newDLPAllowlistRuntimeStore("salt")
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"own", "foreign"} {
		if err := s.SetValuesDurable(tenant, []string{"4111111111111111"}); err != nil {
			t.Fatal(err)
		}
	}
	before, gen := string(p.data), s.generation
	for _, failure := range []error{errors.New("unavailable"), blobstore.ErrDurabilityUnconfirmed} {
		p.err = failure
		for _, values := range [][]string{{"4242424242424242"}, nil} {
			if !errors.Is(s.SetValuesDurable("own", values), failure) {
				t.Fatal("save failure hidden")
			}
			if s.generation != gen || s.dirty || string(p.data) != before || !s.AllowlistForTenant("own").Allowed(dlp.CreditCard, []byte("4111111111111111")) || s.AllowlistForTenant("own").Allowed(dlp.CreditCard, []byte("4242424242424242")) {
				t.Fatal("failed exception changed accepted state")
			}
		}
	}
	p.err = nil
	if err := s.SetValuesDurable("own", []string{"4242424242424242"}); err != nil {
		t.Fatal(err)
	}
	restarted := newDLPAllowlistRuntimeStore("salt")
	if err := restarted.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if !restarted.AllowlistForTenant("own").Allowed(dlp.CreditCard, []byte("4242 4242 4242 4242")) || !reflect.DeepEqual(restarted.ValuesForTenant("foreign"), []string{"4111111111111111"}) {
		t.Fatal("restart lost replacement or foreign exception")
	}
	if err := s.SetValuesDurable("own", nil); err != nil {
		t.Fatal(err)
	}
	restarted = newDLPAllowlistRuntimeStore("salt")
	if err := restarted.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if restarted.AllowlistForTenant("own") != nil || restarted.AllowlistForTenant("foreign") == nil {
		t.Fatal("durable clear changed the wrong tenant")
	}
}

func TestDLPAllowlistDurableValidationAndOwnership(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newDLPAllowlistRuntimeStore("salt")
	s.SetPersister(p)
	values := []string{" BLUEFIN ", "BLUEFIN", "bluefin"}
	if err := s.SetValuesDurable("own", values); err != nil {
		t.Fatal(err)
	}
	values[0] = "MUTATED"
	output := s.ValuesForTenant("own")
	output[0] = "MUTATED-GET"
	if !reflect.DeepEqual(s.ValuesForTenant("own"), []string{"BLUEFIN", "bluefin"}) {
		t.Fatal("normalization or ownership changed")
	}
	before, gen, writes := string(p.data), s.generation, p.writes
	for _, invalid := range [][]string{{"valid", " \n"}, make([]string, maxDLPAllowlistValues+1)} {
		if err := s.SetValuesDurable("own", invalid); err == nil {
			t.Fatal("invalid exception accepted")
		}
		if string(p.data) != before || s.generation != gen || p.writes != writes {
			t.Fatal("invalid list saved")
		}
	}
}

func TestDLPAllowlistFlushSerializesWithAdminAndRetainsDirty(t *testing.T) {
	p := &gatedDLPPolicyPersister{entered: make(chan struct{}), release: make(chan struct{})}
	s := newDLPAllowlistRuntimeStore("salt")
	s.SetPersister(p)
	s.SetValues("own", []string{"OLD"})
	flushed := make(chan error, 1)
	go func() { flushed <- s.PersistIfDirty() }()
	<-p.entered
	committed := make(chan error, 1)
	go func() { committed <- s.SetValuesDurable("own", []string{"NEW"}) }()
	close(p.release)
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	var snap allowlistStoreSnapshot
	if err := json.Unmarshal(p.data, &snap); err != nil {
		t.Fatal(err)
	}
	if p.writes != 2 || s.dirty || !reflect.DeepEqual(snap.Values["own"], []string{"NEW"}) {
		t.Fatal("old flush overwrote acknowledged exception")
	}
	failing := &checkedClassifierPersister{err: errors.New("unavailable")}
	s = newDLPAllowlistRuntimeStore("salt")
	s.SetPersister(failing)
	s.SetValues("own", []string{"PENDING"})
	gen := s.generation
	if s.PersistIfDirty() == nil || !s.dirty {
		t.Fatal("failed flush lost dirty state")
	}
	if s.SetValuesDurable("own", []string{"REJECTED"}) == nil || !s.dirty || s.generation != gen {
		t.Fatal("failed admin edit lost staged state")
	}
	failing.err = nil
	if err := s.PersistIfDirty(); err != nil || s.dirty {
		t.Fatalf("retry: %v", err)
	}
	if !strings.Contains(string(failing.data), "PENDING") || strings.Contains(string(failing.data), "REJECTED") {
		t.Fatal("retry saved failed proposal")
	}
}

func TestDLPAllowlistUnconfirmedWriteDoesNotClaimDiskRollback(t *testing.T) {
	p := &unconfirmedClassifierPersister{}
	s := newDLPAllowlistRuntimeStore("salt")
	s.SetPersister(p)
	if err := s.SetValuesDurable("own", []string{"OLD"}); err != nil {
		t.Fatal(err)
	}
	gen := s.generation
	p.uncertain = true
	if !errors.Is(s.SetValuesDurable("own", []string{"NEW"}), blobstore.ErrDurabilityUnconfirmed) {
		t.Fatal("uncertain save reported success")
	}
	if s.generation != gen || !reflect.DeepEqual(s.ValuesForTenant("own"), []string{"OLD"}) {
		t.Fatal("unconfirmed save became live")
	}
	restarted := newDLPAllowlistRuntimeStore("salt")
	if err := restarted.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restarted.ValuesForTenant("own"), []string{"NEW"}) {
		t.Fatal("fixture must write before reporting uncertain durability")
	}
}

func TestAdminDLPAllowlistDurableSaveAndAudit(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newDLPAllowlistRuntimeStore("salt")
	s.SetPersister(p)
	s.SetValuesDurable("tenant_other", []string{"FOREIGN"})
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "allowlist-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "allowlist-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("allowlist-fixture"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "allowlist-admin", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDLPRoutes(mux, newAdminEndpointMiddleware(testEvaluator(), writer, nil, auth, "", true, nil, nil, nil), testEvaluator(), nil, nil, s, nil, nil, nil, newEntitlementStore(map[string]bool{featureDLP: true}), nil, "")
	steps := []struct {
		body   string
		fail   bool
		status int
	}{
		{`{"values":["ORIGINAL"]}`, false, 200}, {`{"values":["NEW"]}`, true, 500}, {`{"values":[]}`, true, 500},
		{`{}`, false, 400}, {`{"values":null}`, false, 400}, {`{"values":["valid"," "]}`, false, 400}, {`{"values":[]}`, false, 200},
	}
	for _, step := range steps {
		p.err = nil
		if step.fail {
			p.err = errors.New("private-storage-location")
		}
		before, gen := string(p.data), s.generation
		req := httptest.NewRequest("POST", "/admin/dlp-allowlist", strings.NewReader(step.body))
		req.Header.Set("Authorization", "Bearer allowlist-fixture")
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, req)
		if r.Code != step.status || strings.Contains(r.Body.String(), "private-storage-location") {
			t.Fatalf("response %d %s", r.Code, r.Body)
		}
		if step.status != 200 && (string(p.data) != before || s.generation != gen) {
			t.Fatal("rejected HTTP edit changed state")
		}
	}
	if !reflect.DeepEqual(s.ValuesForTenant("tenant_other"), []string{"FOREIGN"}) {
		t.Fatal("foreign values changed")
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
		if row["result"] != want || row["actor_user_id"] != "allowlist-admin" || row["tenant_id"] != "tenant_lab_001" {
			t.Fatalf("audit %d: %s", i, line)
		}
	}
	for _, value := range []string{"ORIGINAL", "FOREIGN", "private-storage-location", "allowlist-fixture"} {
		if strings.Contains(string(raw), value) {
			t.Fatalf("audit disclosed %q", value)
		}
	}
}
