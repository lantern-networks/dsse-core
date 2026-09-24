package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

func policyRestoreFixture() model.DLPPolicyObject {
	return model.DLPPolicyObject{ID: "own_policy", TenantID: "own", Name: "Fixture", Identifiers: []string{"credit_card"}, OnMatch: "block", InstanceScope: "any", Status: "active", DeviceRisk: []model.DLPDeviceRiskCondition{{MinCount: 3, WindowSeconds: 60, Severity: "high"}}, Metadata: map[string]any{"outer": map[string]any{"values": []any{"original"}}}}
}
func TestDLPPolicyRestoreRejectsInvalidSnapshotAndPreservesWriter(t *testing.T) {
	obj := policyRestoreFixture()
	encode := func(tenant, id string, obj model.DLPPolicyObject) string {
		raw, _ := json.Marshal(dlpPolicyObjectSnapshot{ByTenant: map[string]map[string]model.DLPPolicyObject{tenant: {id: obj}}})
		return string(raw)
	}
	invalid := []string{"", "null", "{}", "{bad", `{"by_tenant":null}`, `{"by_tenant":{},"BY_TENANT":null}`, `{"by_tenant":{},"unknown":"PRIVATE"}`, `{"by_tenant":{" ":{}}}`, `{"by_tenant":{"own":null}}`, encode("foreign", obj.ID, obj), encode("own", "different_id", obj)}
	for _, change := range []func(*model.DLPPolicyObject){func(p *model.DLPPolicyObject) { p.OnMatch = "bad" }, func(p *model.DLPPolicyObject) { p.Identifiers = nil }, func(p *model.DLPPolicyObject) { p.Identifiers = []string{"wrong name"} }, func(p *model.DLPPolicyObject) { p.InstanceScope = "bad" }, func(p *model.DLPPolicyObject) { p.Status = "unknown" }, func(p *model.DLPPolicyObject) { p.MinCount = -1 }, func(p *model.DLPPolicyObject) { p.DeviceRisk = []model.DLPDeviceRiskCondition{{MinCount: 0}} }} {
		bad := policyRestoreFixture()
		change(&bad)
		invalid = append(invalid, encode("own", obj.ID, bad))
	}
	for i, data := range invalid {
		s := newDLPPolicyObjectStore()
		p := &edmRestorePersister{}
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertDurable(obj); err != nil {
			t.Fatal(err)
		}
		gen, before := s.generation, string(p.data)
		bad := &edmRestorePersister{data: []byte(data)}
		if err := s.SetPersister(bad); err == nil {
			t.Errorf("case %d accepted invalid snapshot", i)
			continue
		} else if strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("error includes saved content")
		}
		got, ok := s.Get("own", obj.ID)
		if !ok || !reflect.DeepEqual(got, obj) || s.persister != p || s.generation != gen || s.dirty || string(p.data) != before {
			t.Fatalf("case %d changed state or writer", i)
		}
		changed := obj
		changed.Name = "Updated"
		if err := s.UpsertDurable(changed); err != nil {
			t.Fatal(err)
		}
		if bad.writes != 0 || string(p.data) == before {
			t.Fatal("failed load stole future saves")
		}
	}
}
func TestDLPPolicyCopyBoundariesKeepRuntimeAndDiskAligned(t *testing.T) {
	for _, boundary := range []string{"input", "staged-input", "get", "list", "snapshot"} {
		t.Run(boundary, func(t *testing.T) {
			s := newDLPPolicyObjectStore()
			p := &edmRestorePersister{}
			s.SetPersister(p)
			obj := policyRestoreFixture()
			expected := policyRestoreFixture()
			if boundary == "staged-input" {
				if err := s.Upsert(obj); err != nil {
					t.Fatal(err)
				}
				if err := s.PersistIfDirty(); err != nil {
					t.Fatal(err)
				}
			} else if err := s.UpsertDurable(obj); err != nil {
				t.Fatal(err)
			}
			gen, before := s.generation, string(p.data)
			candidate := obj
			switch boundary {
			case "get":
				candidate, _ = s.Get("own", obj.ID)
			case "list":
				candidate = s.List("own")[0]
			case "snapshot":
				s.mu.Lock()
				candidate = s.snapshotLocked().ByTenant["own"][obj.ID]
				s.mu.Unlock()
			}
			candidate.Identifiers[0] = "email"
			candidate.DeviceRisk[0].MinCount = 999
			candidate.Metadata["outer"].(map[string]any)["values"].([]any)[0] = "changed"
			got, _ := s.Get("own", obj.ID)
			if !reflect.DeepEqual(got, expected) || s.generation != gen || string(p.data) != before {
				t.Fatal("mutable alias changed store without save")
			}
			dec := model.AccessDecision{TenantID: "own", Actions: []model.DecisionAction{{Type: "dlp_inspect", Metadata: map[string]any{"dlp_policy_id": obj.ID}}}}
			policy, ok := dlpPolicyFromDecision(dec, "", s)
			if !ok || len(policy.Rules) != 1 || string(policy.Rules[0].Identifiers[0]) != "credit_card" {
				t.Fatal("alias changed runtime resolution")
			}
		})
	}
}
func TestDLPPolicyRestoreWriterLifecycleAndPendingDeletion(t *testing.T) {
	s := newDLPPolicyObjectStore()
	p := &checkedClassifierPersister{}
	s.SetPersister(p)
	obj := policyRestoreFixture()
	if err := s.UpsertDurable(obj); err != nil {
		t.Fatal(err)
	}
	saved := append([]byte(nil), p.data...)
	s.Delete("own", obj.ID)
	for _, writer := range []blobstore.Persister{nil, p, &edmRestorePersister{data: saved}} {
		if err := s.SetPersister(writer); err == nil || s.persister != p || !s.dirty {
			t.Fatal("discarded unsaved deletion")
		}
	}
	p.err = errors.New("unavailable")
	if _, err := s.DeleteDurable("own", obj.ID); err == nil || !s.dirty {
		t.Fatal("already-missing deletion hid failed persistence")
	}
	p.err = nil
	if removed, err := s.DeleteDurable("own", obj.ID); err != nil || removed || s.dirty {
		t.Fatal("deletion retry did not save pending state")
	}
	if err := s.SetPersister(&edmRestorePersister{data: saved}); err != nil {
		t.Fatal(err)
	}
	gen := s.generation
	previous := s.persister
	if err := s.SetPersister(&edmRestorePersister{loadErr: errors.New("read failure")}); err == nil || s.persister != previous || s.generation != gen {
		t.Fatal("read error replaced writer")
	}
	if err := s.SetPersister(&edmRestorePersister{data: []byte(`{"by_tenant":{}}`)}); err != nil || len(s.List("own")) != 0 || s.generation <= gen {
		t.Fatal("explicit clear did not replace state")
	}
	if err := s.SetPersister(&edmRestorePersister{data: saved}); err != nil {
		t.Fatal(err)
	}
	missing := &edmRestorePersister{}
	if err := s.SetPersister(missing); err != nil || !s.dirty {
		t.Fatal("new writer lost retained state")
	}
	if err := s.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, missing.data) {
		t.Fatal("retained state not saved")
	}
	if err := s.SetPersister(nil); err != nil || s.persister != nil || len(s.List("own")) != 1 {
		t.Fatal("clean detach changed live state")
	}
}
func TestDLPPolicyRestoreProductionStartup(t *testing.T) {
	if path := os.Getenv("DSSE_POLICY_RESTORE_CHILD"); path != "" {
		rt := buildDLPRuntime(serverConfig{DLPPolicyObjectStorePath: path})
		if os.Getenv("DSSE_POLICY_RESTORE_VALID") == "1" && len(rt.policyObjects.List("own")) == 1 {
			os.Exit(0)
		}
		os.Exit(9)
	}
	obj := policyRestoreFixture()
	valid, _ := json.Marshal(dlpPolicyObjectSnapshot{ByTenant: map[string]map[string]model.DLPPolicyObject{"own": {obj.ID: obj}}})
	custom := obj
	custom.Identifiers = []string{"project_code"}
	customData, _ := json.Marshal(dlpPolicyObjectSnapshot{ByTenant: map[string]map[string]model.DLPPolicyObject{"own": {obj.ID: custom}}})
	wrong, _ := json.Marshal(dlpPolicyObjectSnapshot{ByTenant: map[string]map[string]model.DLPPolicyObject{"foreign": {obj.ID: obj}}})
	for i, data := range [][]byte{valid, customData, {}, []byte("null"), []byte("{bad"), []byte("{}"), wrong} {
		path := filepath.Join(t.TempDir(), "policies.json")
		os.WriteFile(path, data, 0600)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDLPPolicyRestoreProductionStartup$")
		cmd.Env = append(os.Environ(), "DSSE_POLICY_RESTORE_CHILD="+path)
		if i < 2 {
			cmd.Env = append(cmd.Env, "DSSE_POLICY_RESTORE_VALID=1")
		}
		out, err := cmd.CombinedOutput()
		if i < 2 {
			if err != nil {
				t.Fatalf("valid startup: %v %s", err, out)
			}
		} else {
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || !strings.Contains(string(out), "load dlp policy object store") {
				t.Fatalf("invalid startup: %v %s", err, out)
			}
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		after, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(after, data) {
			t.Fatal("startup modified saved policy")
		}
	}
}

func TestDLPPolicyWriteRejectsInvalidIdentityAndMetadata(t *testing.T) {
	for _, durable := range []bool{false, true} {
		s := newDLPPolicyObjectStore()
		writer := &edmRestorePersister{}
		if err := s.SetPersister(writer); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertDurable(policyRestoreFixture()); err != nil {
			t.Fatal(err)
		}
		before, generation := string(writer.data), s.generation
		for _, change := range []func(*model.DLPPolicyObject){
			func(p *model.DLPPolicyObject) { p.ID = "" },
			func(p *model.DLPPolicyObject) { p.TenantID = " own" },
			func(p *model.DLPPolicyObject) { p.Status = "typo" },
			func(p *model.DLPPolicyObject) { p.DeviceRisk[0].WindowSeconds = -1 },
			func(p *model.DLPPolicyObject) { p.Metadata["bad"] = make(chan int) },
			func(p *model.DLPPolicyObject) { p.Metadata["cycle"] = p.Metadata },
		} {
			obj := policyRestoreFixture()
			change(&obj)
			var err error
			if durable {
				err = s.UpsertDurable(obj)
			} else {
				err = s.Upsert(obj)
			}
			if err == nil || s.generation != generation || s.dirty || string(writer.data) != before {
				t.Fatal("invalid write changed state or disk")
			}
		}
		got, _ := s.Get("own", "own_policy")
		if !reflect.DeepEqual(got, policyRestoreFixture()) {
			t.Fatal("invalid write changed live policy")
		}
	}
}
