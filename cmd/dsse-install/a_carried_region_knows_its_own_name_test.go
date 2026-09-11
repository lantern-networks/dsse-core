package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ A REGION CARRIED AS region-b ARRIVED CALLING ITSELF region-a (2026-08-28, measured standing up a second
// site).
//
//	dsse-install -carry cp-b.tar.gz -region region-b -holds-state -control-plane-only
//	→ DSSE_EDGE_REGION='region-a'
//
// It is the name devices use to CHOOSE a region and the name every record from there carries. A second site
// that started from this carry would have reported itself as the first one, and the region map devices are
// handed would have had two entries pointing at the same name — so a device "failing over" would have chosen
// the region it was already in.
//
// The installer's closing note tells an operator to change it by hand. It did not need to be told: the flag
// that packs the machine already says which region it is for, and discarding an answer the operator gave is
// the same defect as never asking.
func TestACarriedRegionIsNamedByTheFlagThatPackedIt(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "cp-b.tar.gz")
	if _, _, err := carryDeploymentFor(dir, dest,
		machineShape{holds: regionShapeStateBearingJoin}, "region-b", nil); err != nil {
		t.Fatalf("carry: %v", err)
	}
	env := fileFromTarball(t, dest, "deployment.env")
	if !strings.Contains(env, "DSSE_EDGE_REGION='region-b'") {
		t.Errorf("a machine carried for region-b is told it is somewhere else:\n%s",
			lineContaining(env, "DSSE_EDGE_REGION"))
	}
	if strings.Contains(env, "DSSE_EDGE_REGION='region-a'") {
		t.Error("the carried machine still carries the name of the region it was packed FROM")
	}
}

// ★ AND A CARRY THAT NAMES NO REGION CHANGES NOTHING. -control-plane-only alone packs another machine of THIS
// region, which is already correctly named; rewriting it would be inventing an answer nobody gave.
func TestACarryWithNoRegionLeavesTheNameAlone(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "cp-a.tar.gz")
	if _, _, err := carryDeploymentFor(dir, dest,
		machineShape{holds: regionShapeStateBearing}, "", nil); err != nil {
		t.Fatalf("carry: %v", err)
	}
	if env := fileFromTarball(t, dest, "deployment.env"); !strings.Contains(env, "DSSE_EDGE_REGION='region-a'") {
		t.Errorf("a machine of this region was renamed:\n%s", lineContaining(env, "DSSE_EDGE_REGION"))
	}
}

func fileFromTarball(t *testing.T, path, want string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			t.Fatalf("%s is not in %s", want, path)
		}
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(h.Name) == want {
			body, rerr := io.ReadAll(tr)
			if rerr != nil {
				t.Fatal(rerr)
			}
			return string(body)
		}
	}
}
