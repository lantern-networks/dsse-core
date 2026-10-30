package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPlanReapplyRejectsUnsafeStoreAndRuntimePrivateKeys(t *testing.T) {
	plan := threeNodesOneRegionPlan()
	work := t.TempDir()
	planFile := filepath.Join(work, "plan.json")
	raw, _ := json.Marshal(plan)
	if err := os.WriteFile(planFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, "issuer")
	installFromPlan(t, planFile, dir)
	values, err := plan.MachineEnvironment(plan.foundingRegion().controlPlane().Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		key      string
		validate func() error
	}{
		{"store member", storeMemberKeyFile, func() error { return validateExistingStoreMember(dir, values, time.Now().UTC()) }},
		{"runtime transport", storeClientKeyFile, func() error { return validateRuntimeTransportMaterial(dir, values, time.Now().UTC()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.key)
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			if err := tc.validate(); err == nil {
				t.Fatal("accepted a group/world-readable private key")
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			realPath := path + ".real"
			if err := os.Rename(path, realPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(realPath, path); err != nil {
				t.Fatal(err)
			}
			if err := tc.validate(); err == nil {
				t.Fatal("accepted a symlinked private key")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(realPath, path); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := validateExistingStoreMember(dir, values, time.Now().UTC()); err == nil {
		t.Fatal("accepted a private key in a group/world-writable deployment directory")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeTransportPrivateKeyPublicationDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, storeClientKeyFile)
	if err := os.Symlink(outside, key); err != nil {
		t.Fatal(err)
	}
	if err := writeRuntimeTransportMaterial(dir, map[string][]byte{storeClientKeyFile: []byte("replacement")}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "unchanged" {
		t.Fatal("private-key publication followed an existing symlink")
	}
	info, err := os.Lstat(key)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("private-key publication did not leave a regular 0600 file")
	}
}
