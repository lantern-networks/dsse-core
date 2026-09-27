package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCarriedMachineCanReapplyPlanWithoutIssuingAuthority(t *testing.T) {
	work := t.TempDir()
	source := filepath.Join(work, "source")
	plan := installFromPlan(t, writePlan(t, work), source)
	for _, name := range []string{"cp-b", "edge-b"} {
		t.Run(name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "node.tar.gz")
			if err := carryPlanMachine(plan, source, archive, name); err != nil {
				t.Fatal(err)
			}
			dir := unpackCarry(t, archive)
			if _, err := os.Stat(filepath.Join(dir, authorityDirName, storeCAKeyFile)); !os.IsNotExist(err) {
				t.Fatal("signing authority must not travel")
			}
			before := map[string][]byte{}
			for _, file := range []string{storeMemberFile, storeMemberKeyFile, "deployment.env"} {
				before[file], _ = os.ReadFile(filepath.Join(dir, file))
			}
			for i := 0; i < 2; i++ {
				if err := applyPlanToThisMachine(plan, dir, name); err != nil {
					t.Fatal(err)
				}
			}
			for file, b := range before {
				a, _ := os.ReadFile(filepath.Join(dir, file))
				if !bytes.Equal(a, b) {
					t.Errorf("reapply replaced %s", file)
				}
			}
		})
	}
}

func TestCarriedMachineRejectsUnusableMemberBeforeChangingEnvironment(t *testing.T) {
	work := t.TempDir()
	source := filepath.Join(work, "source")
	plan := installFromPlan(t, writePlan(t, work), source)
	archive := filepath.Join(work, "node.tar.gz")
	if err := carryPlanMachine(plan, source, archive, "cp-b"); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"missing-key", "mismatched-key", "expired", "wrong-ca", "changed-peer"} {
		t.Run(fault, func(t *testing.T) {
			dir := unpackCarry(t, archive)
			switch fault {
			case "missing-key":
				if err := os.Remove(filepath.Join(dir, storeMemberKeyFile)); err != nil {
					t.Fatal(err)
				}
			case "mismatched-key":
				k, err := newKey()
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, storeMemberKeyFile), keyPEM(k), 0600); err != nil {
					t.Fatal(err)
				}
			case "expired":
				sa, err := loadStoreAuthority(source)
				if err != nil {
					t.Fatal(err)
				}
				old, err := firstCertificateIn(beforeFile(t, dir, storeMemberFile))
				if err != nil {
					t.Fatal(err)
				}
				c, k, err := issueStoreMember(sa, old.Subject.CommonName, old.DNSNames, time.Now().AddDate(-2, 0, 0), 1)
				if err != nil {
					t.Fatal(err)
				}
				if err = writeStoreMember(dir, c, k); err != nil {
					t.Fatal(err)
				}
			case "wrong-ca":
				sa, err := mintStoreAuthority("Other", time.Now(), 5)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, storeCAFile), certPEM(sa.Cert), 0644); err != nil {
					t.Fatal(err)
				}
			}
			// A pending plan change must not be committed before material is validated.
			envPath := filepath.Join(dir, "deployment.env")
			before := append(beforeFile(t, dir, "deployment.env"), []byte("\n# operator note\nDSSE_AGENT_PUBLISHER='Previous Publisher'\n")...)
			if err := os.WriteFile(envPath, before, 0600); err != nil {
				t.Fatal(err)
			}
			target := "cp-b"
			if fault == "changed-peer" {
				target = "cp-a"
			}
			err := applyPlanToThisMachine(plan, dir, target)
			if err == nil || !strings.Contains(err.Error(), "re-pack") {
				t.Fatalf("wanted recovery instruction, got %v", err)
			}
			if !bytes.Equal(before, beforeFile(t, dir, "deployment.env")) {
				t.Fatal("failed apply changed environment")
			}
		})
	}
}
func beforeFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
