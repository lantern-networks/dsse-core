package main

import (
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/dlp"
	"strings"
	"testing"
)

func TestLibraryReceiverSaveRetryAndRestart(t *testing.T) {
	for _, fail := range []string{"classifiers", "fingerprints"} {
		t.Run(fail, func(t *testing.T) {
			cp, edge := dlpStoresForTest("authority"), dlpStoresForTest("receiver")
			c, f := &allowlistSaveFixture{}, &allowlistSaveFixture{}
			if err := edge.classifiers.SetPersister(c); err != nil {
				t.Fatal(err)
			}
			if err := edge.fingerprints.SetPersister(f); err != nil {
				t.Fatal(err)
			}
			cp.classifiers.SetSpecs("own", []dlp.ClassifierSpec{{Name: "employee_id", Kind: "keyword", Keywords: []string{"EMPLOYEE"}}})
			cp.fingerprints.SetDataset("own", "employees", []string{"CUSTOMER123"})
			if fail == "classifiers" {
				c.err = errors.New("save failed")
			} else {
				f.err = errors.New("save failed")
			}
			if edge.Apply(cp.Snapshot()) == nil {
				t.Fatal("failed save accepted")
			}
			if len(edge.classifiers.SpecsForTenant("own")) != 0 || len(edge.fingerprints.DatasetsForTenant("own")) != 0 {
				t.Fatal("failed save published new scanner")
			}
			c.err = nil
			f.err = nil
			if err := edge.Apply(cp.Snapshot()); err != nil {
				t.Fatal(err)
			}
			reloadedC, reloadedF := newDLPClassifierRuntimeStore(), newDLPFingerprintRuntimeStore("different")
			if err := reloadedC.SetPersister(c); err != nil {
				t.Fatal(err)
			}
			if err := reloadedF.SetPersister(f); err != nil {
				t.Fatal(err)
			}
			hits := dlp.DetectWithOptions([]byte("EMPLOYEE CUSTOMER123"), "text/plain", dlp.Options{Classifiers: reloadedC.ClassifierSetForTenant("own"), Fingerprints: reloadedF.FingerprintSetForTenant("own")})
			if len(hits) != 2 {
				t.Fatalf("restored scan hits=%v", hits)
			}
			if strings.Contains(string(f.data), "CUSTOMER123") {
				t.Fatal("source value persisted")
			}
			cp.classifiers.SetSpecs("own", nil)
			cp.fingerprints.RemoveDataset("own", "employees")
			if err := edge.Apply(cp.Snapshot()); err != nil {
				t.Fatal(err)
			}
			if err := reloadedC.SetPersister(c); err != nil {
				t.Fatal(err)
			}
			if err := reloadedF.SetPersister(f); err != nil {
				t.Fatal(err)
			}
			if len(reloadedC.SpecsForTenant("own")) != 0 || len(reloadedF.DatasetsForTenant("own")) != 0 {
				t.Fatal("deleted definitions restored")
			}
		})
	}
}
func TestLibraryLegacyFingerprintSnapshot(t *testing.T) {
	s := newDLPFingerprintRuntimeStore("legacy")
	s.SetDataset("own", "employees", []string{"EMPLOYEE123"})
	raw, err := json.Marshal(map[string]any{"datasets": s.datasets})
	if err != nil {
		t.Fatal(err)
	}
	p := &allowlistSaveFixture{data: raw}
	r := newDLPFingerprintRuntimeStore("legacy")
	if err := r.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if len(dlp.DetectWithOptions([]byte("EMPLOYEE123"), "text/plain", dlp.Options{Fingerprints: r.FingerprintSetForTenant("own")})) != 1 {
		t.Fatal("legacy snapshot lost")
	}
	if _, err := r.SetDatasetDurable("other", "employees", []string{"OTHER123"}); err != nil {
		t.Fatal(err)
	}
	q := newDLPFingerprintRuntimeStore("new-startup-salt")
	if err := q.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if len(dlp.DetectWithOptions([]byte("EMPLOYEE123"), "text/plain", dlp.Options{Fingerprints: q.FingerprintSetForTenant("own")})) != 1 {
		t.Fatal("migrated salt lost")
	}
}
