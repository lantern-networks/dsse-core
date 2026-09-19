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
)

func TestEDMRestoreDistributedSaltAndTenantIsolation(t *testing.T) {
	for _, sourceSalt := range []string{"source-salt", ""} {
		t.Run(sourceSalt, func(t *testing.T) {
			cp, edge := dlpStoresForTest(sourceSalt), dlpStoresForTest("startup-salt")
			p := &checkedClassifierPersister{}
			if err := edge.fingerprints.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			cp.fingerprints.SetDataset("own", "customer_record", []string{"CUST-100482"})
			cp.fingerprints.SetDataset("foreign", "customer_record", []string{"FOREIGN-445566"})
			if err := edge.Apply(cp.Snapshot()); err != nil {
				t.Fatal(err)
			}
			if err := edge.fingerprints.PersistIfDirty(); err != nil {
				t.Fatal(err)
			}
			before := append([]byte(nil), p.data...)
			restarted := newDLPFingerprintRuntimeStore("startup-salt")
			if err := restarted.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if edmFixtureCount(restarted, "own", "CUST-100482") != 1 || edmFixtureCount(restarted, "foreign", "FOREIGN-445566") != 1 || edmFixtureCount(restarted, "own", "FOREIGN-445566") != 0 {
				t.Fatal("restart lost salt or tenant isolation")
			}
			if !bytes.Equal(before, p.data) {
				t.Fatal("load rewrote storage")
			}
			if _, err := restarted.SetDatasetDurable("own", "customer_record", []string{"NEW-994400"}); err != nil {
				t.Fatal(err)
			}
			again := newDLPFingerprintRuntimeStore("different-again")
			if err := again.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if edmFixtureCount(again, "own", "NEW-994400") != 1 || edmFixtureCount(again, "foreign", "FOREIGN-445566") != 1 {
				t.Fatal("durable edit omitted adopted salt")
			}
			for _, raw := range []string{"CUST-100482", "NEW-994400", "FOREIGN-445566"} {
				if bytes.Contains(p.data, []byte(raw)) {
					t.Fatal("snapshot contains source values")
				}
			}
		})
	}
}

type edmRestorePersister struct {
	data    []byte
	loadErr error
	writes  int
}

func (p *edmRestorePersister) Load() ([]byte, error) { return p.data, p.loadErr }
func (p *edmRestorePersister) Save(b []byte) error {
	p.writes++
	p.data = append([]byte(nil), b...)
	return nil
}

func TestEDMRestoreRejectsWholeInvalidSnapshotAndRetainsWriter(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for _, data := range []string{"", " ", "null", "{}", "{bad", `{"datasets":null}`, `{"datasets":{},"unknown":true}`, `{"datasets":{},"version":2,"salt":"salt"}`, `{"datasets":{},"version":1}`, `{"datasets":{},"version":null,"salt":"salt"}`, `{"datasets":{},"salt":"salt"}`, `{"datasets":{},"version":1,"salt":null}`, `{"datasets":{" ":{}}}`, `{"datasets":{"own":null}}`, `{"datasets":{"own":{"credit_card":["` + hash + `"]}}}`, `{"datasets":{"own":{"customer_record":null}}}`, `{"datasets":{"own":{"customer_record":[]}}}`, `{"datasets":{"own":{"customer_record":["BAD"]}}}`, `{"datasets":{"own":{"customer_record":["` + strings.ToUpper(hash) + `"]}}}`, `{"datasets":{"own":{"customer_record":["` + hash + `","` + hash + `"]}}}`, `{"datasets":{"valid":{"customer_record":["` + hash + `"]},"invalid":{"wrong name":["` + hash + `"]}}}`} {
		t.Run(data, func(t *testing.T) {
			p := &checkedClassifierPersister{}
			s := newDLPFingerprintRuntimeStore("original-salt")
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if _, err := s.SetDatasetDurable("own", "customer_record", []string{"CUST-100482"}); err != nil {
				t.Fatal(err)
			}
			before, gen := string(p.data), s.generation
			bad := &edmRestorePersister{data: []byte(data)}
			if err := s.SetPersister(bad); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
			if s.persister != p || s.generation != gen || s.dirty || s.salt != "original-salt" || edmFixtureCount(s, "own", "CUST-100482") != 1 || len(s.DatasetsForTenant("valid")) != 0 || string(p.data) != before || bad.writes != 0 {
				t.Fatal("invalid load changed state or writer")
			}
			if _, err := s.SetDatasetDurable("own", "customer_record", []string{"NEW-994400"}); err != nil {
				t.Fatal(err)
			}
			if bad.writes != 0 || string(p.data) == before {
				t.Fatal("failed replacement stole future saves")
			}
		})
	}
}

func TestEDMRestoreWriterLifecycleAndLegacy(t *testing.T) {
	p := &edmRestorePersister{}
	s := newDLPFingerprintRuntimeStore("legacy-salt")
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	s.SetDataset("own", "customer_record", []string{"CUST-100482"})
	for _, replacement := range []blobstore.Persister{nil, p, &edmRestorePersister{data: []byte(`{"datasets":{}}`)}} {
		if err := s.SetPersister(replacement); err == nil || s.persister != p || !s.dirty {
			t.Fatal("dirty state discarded")
		}
	}
	if err := s.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	gen := s.generation
	if err := s.SetPersister(&edmRestorePersister{loadErr: errors.New("read failure")}); err == nil || s.persister != p || s.generation != gen {
		t.Fatal("read failure changed writer")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(p.data, &raw); err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(map[string]any{"datasets": json.RawMessage(raw["datasets"])})
	old := &edmRestorePersister{data: legacy}
	if err := s.SetPersister(old); err != nil {
		t.Fatal(err)
	}
	if edmFixtureCount(s, "own", "CUST-100482") != 1 || !bytes.Equal(old.data, legacy) {
		t.Fatal("legacy startup salt or original bytes changed")
	}
	// An explicit empty snapshot replaces old state; it must not merge with it.
	empty := &edmRestorePersister{data: []byte(`{"version":1,"salt":"new-salt","datasets":{}}`)}
	if err := s.SetPersister(empty); err != nil {
		t.Fatal(err)
	}
	if len(s.Tenants()) != 0 || s.FingerprintSetForTenant("own") != nil || s.salt != "new-salt" || s.generation <= gen {
		t.Fatal("snapshot merged or generation did not change")
	}
	// Legacy data always uses the constructor salt, even after adopting another salt.
	if err := s.SetPersister(old); err != nil {
		t.Fatal(err)
	}
	if edmFixtureCount(s, "own", "CUST-100482") != 1 || s.salt != "legacy-salt" {
		t.Fatal("legacy snapshot inherited adopted salt")
	}
	missing := &edmRestorePersister{}
	if err := s.SetPersister(missing); err != nil {
		t.Fatal(err)
	}
	if !s.dirty || edmFixtureCount(s, "own", "CUST-100482") != 1 {
		t.Fatal("new empty writer lost current state")
	}
	if err := s.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPersister(nil); err != nil || s.persister != nil || edmFixtureCount(s, "own", "CUST-100482") != 1 {
		t.Fatal("clean detach changed live state")
	}
}

func TestEDMRestoreProductionStartup(t *testing.T) {
	if path := os.Getenv("DSSE_EDM_RESTORE_CHILD"); path != "" {
		rt := buildDLPRuntime(serverConfig{DLPFingerprintStorePath: path})
		if os.Getenv("DSSE_EDM_RESTORE_VALID") == "1" && edmFixtureCount(rt.fingerprints, "own", "CUST-100482") == 1 {
			os.Exit(0)
		}
		os.Exit(9)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "edm.json")
	s := newDLPFingerprintRuntimeStore("nondefault-salt")
	if err := s.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetDatasetDurable("own", "customer_record", []string{"CUST-100482"}); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{{"valid", valid, true}, {"empty", []byte{}, false}, {"null", []byte("null"), false}, {"broken", []byte("{bad"), false}, {"missing datasets", []byte(`{"version":1,"salt":"test"}`), false}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEDMRestoreProductionStartup$")
			cmd.Env = append(os.Environ(), "DSSE_EDM_RESTORE_CHILD="+path)
			if tc.valid {
				cmd.Env = append(cmd.Env, "DSSE_EDM_RESTORE_VALID=1")
			}
			out, err := cmd.CombinedOutput()
			if tc.valid {
				if err != nil {
					t.Fatalf("valid startup: %v %s", err, out)
				}
			} else {
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 || !strings.Contains(string(out), "load dlp fingerprint store") {
					t.Fatalf("invalid startup: %v %s", err, out)
				}
			}
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			after, e := os.ReadFile(path)
			if e != nil || !reflect.DeepEqual(after, tc.data) {
				t.Fatal("startup changed saved data")
			}
		})
	}
}
