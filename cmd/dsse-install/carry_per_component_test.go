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

// ★★★ THE EDGE MACHINE HELD THE DATABASE SUPERUSER PASSWORD (2026-08-27, measured on a generated deployment).
// deployment.env is one file carrying every credential the region has, and the carry shipped it whole. Nothing
// on an Edge machine names any of these — not a service in its compose, not start-edge.sh — so what an Edge
// box holds today is the deployment's database and object store, readable by anything that reaches it.
//
// Every component is its own hardware and its own operating system. Nothing is handed to a machine because a
// different machine needs it.
func TestAnEdgeMachineIsNotGivenTheControlPlanesCredentials(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "edge.tar.gz")
	_, _, err := carryDeploymentFor(dir, dest, machineShape{holds: regionShapeEdgesOnly, edges: true}, "", nil)
	if err != nil {
		t.Fatalf("carry: %v", err)
	}
	env := fileFromCarry(t, dest, "deployment.env")

	for _, credential := range []string{
		"PG_PASSWORD", "PG_SUPERUSER_PASSWORD", "CLICKHOUSE_PASSWORD", "MINIO_ROOT_PASSWORD",
	} {
		for _, line := range strings.Split(env, "\n") {
			if strings.HasPrefix(line, credential+"=") {
				t.Errorf("an Edge machine is given %s, which nothing on it reads: %q", credential, line)
			}
		}
	}

	// ★ THE CONTROL, AND IT IS THE HALF THAT BREAKS THINGS. A filter that strips everything passes the
	// assertions above and produces a machine that cannot start. These four reach the Edge through
	// start-edge.sh rather than through the compose environment, which is exactly what a compose-only filter
	// would lose.
	for _, needed := range []string{
		"ADMIN_TOKEN", "CONNECTOR_SECRET", "WORKLOAD_SECRET", "AUDIT_INGEST_TOKEN", "EDGE_CP_TOKEN",
	} {
		if !strings.Contains(env, "\n"+needed+"=") && !strings.HasPrefix(env, needed+"=") {
			t.Errorf("an Edge machine is NOT given %s, which start-edge.sh passes to the Edge", needed)
		}
	}
}

// ★★★ AND THE FILES, NOT ONLY THE VALUES. An Edge machine has no business holding the control plane's
// management key, and a control-plane machine has no business holding the key its Edges sign intercepted
// traffic with.
func TestNeitherMachineIsGivenTheOthersKeys(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	edge := filepath.Join(t.TempDir(), "edge.tar.gz")
	cp := filepath.Join(t.TempDir(), "cp.tar.gz")
	edgeFiles, _, err := carryDeploymentFor(dir, edge, machineShape{holds: regionShapeEdgesOnly, edges: true}, "", nil)
	if err != nil {
		t.Fatalf("edge carry: %v", err)
	}
	cpFiles, _, err := carryDeploymentFor(dir, cp, machineShape{holds: regionShapeStateBearing, edges: false}, "", nil)
	if err != nil {
		t.Fatalf("control-plane carry: %v", err)
	}

	// What only the control plane's services mount.
	for _, f := range []string{"management.key", "haproxy.cfg", "haproxy-postgres.cfg", "device-ca-registry.json"} {
		if carrySetHas(edgeFiles, f) {
			t.Errorf("the Edge machine is given %s, which only the control plane's services mount", f)
		}
	}
	// What only the Edges mount. The interception key in particular: an Edge signs with it, and a machine that
	// runs no Edge has no reason to be able to.
	for _, f := range []string{
		"transport.key", "edge-identity.key", "device-ca.key",
		"lantern_dsse_interception_root_ca.key.pem",
	} {
		if carrySetHas(cpFiles, f) {
			t.Errorf("the control-plane machine is given %s, which only an Edge mounts", f)
		}
	}
	// ★ AND NEITHER GETS THE MINTING MATERIAL, which is the property the whole-directory carry already had and
	// must not lose on the way to being per-component.
	for _, a := range authorityFiles {
		if carrySetHas(edgeFiles, authorityDirName+"/"+a) || carrySetHas(cpFiles, authorityDirName+"/"+a) {
			t.Errorf("%s travelled to a machine", a)
		}
	}

	// ★★ THE CONTROL: each machine still gets what it does need, or "gave nothing" would pass every
	// assertion above.
	for _, f := range []string{"deployment.env", "docker-compose.yml", "deployment-anchor.pem", "start-edge.sh"} {
		if !carrySetHas(edgeFiles, f) {
			t.Errorf("the Edge machine is not given %s and cannot come up", f)
		}
	}
	for _, f := range []string{"deployment.env", "docker-compose.yml", "start-control-plane.sh", "management.key"} {
		if !carrySetHas(cpFiles, f) {
			t.Errorf("the control-plane machine is not given %s and cannot come up", f)
		}
	}
}

// ★★★ AND THE COMPOSE IN THE CARRY IS THE ONE THAT MACHINE WILL RUN. Packing the file set for an Edge machine
// beside a compose that defines the control plane produces a machine that starts services it has no material
// for — which is the whole-directory failure wearing a smaller directory.
func TestTheCarryHoldsTheComposeForTheMachineItIsFor(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "edge.tar.gz")
	if _, _, err := carryDeploymentFor(dir, dest, machineShape{holds: regionShapeEdgesOnly, edges: true}, "", nil); err != nil {
		t.Fatalf("carry: %v", err)
	}
	compose := fileFromCarry(t, dest, "docker-compose.yml")
	if !strings.Contains(compose, "dsse-edge-a:") {
		t.Fatal("the Edge machine's compose defines no Edge")
	}
	for _, notHere := range []string{"dsse-postgres-a:", "dsse-control-plane-a:", "dsse-console:"} {
		if strings.Contains(compose, "\n  "+notHere) {
			t.Errorf("the Edge machine's compose defines %s, which belongs to another machine", notHere)
		}
	}

	// ★ EVERY FILE THAT COMPOSE MOUNTS IS IN THE CARRY. This is the property that makes the two one thing:
	// the file set is DERIVED from this compose, so a service that gains a mount gains a carried file, and
	// nobody has to remember.
	names, _ := entriesOfCarry(t, dest)
	for _, m := range filesThisMachineReads(compose) {
		if !carrySetHas(names, m) && !carrySetHasPrefix(names, m+"/") {
			t.Errorf("this machine's compose mounts %q and the carry does not hold it", m)
		}
	}
}

func carrySetHasPrefix(names []string, prefix string) bool {
	for _, n := range names {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// fileFromCarry reads one file out of a carry, so the assertions are about what ARRIVES on the machine rather
// than about what was on the operator's disk.
func fileFromCarry(t *testing.T, path, want string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Name == want {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
	}
	t.Fatalf("the carry does not hold %q", want)
	return ""
}

// ★★★ AND WHAT THIS PROGRAM READS ON THAT MACHINE SURVIVES THE FILTER (2026-08-27, found by walking). The
// first split withheld DSSE_AGENT_PLANE_NAME from the Edge machine — nothing there NAMES it, which is true —
// and -verify then reported "this deployment does not say what its agent plane is called" on a deployment
// that says so perfectly. A machine that cannot state its own description cannot be checked.
func TestAMachineKeepsWhatItNeedsToStateWhatItIs(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, shape := range []machineShape{
		{holds: regionShapeEdgesOnly, edges: true},
		{holds: regionShapeStateBearing, edges: false},
	} {
		dest := filepath.Join(t.TempDir(), "m.tar.gz")
		if _, _, err := carryDeploymentFor(dir, dest, shape, "", nil); err != nil {
			t.Fatalf("carry: %v", err)
		}
		env := fileFromCarry(t, dest, "deployment.env")
		for _, k := range []string{"EDGE_HOST", "DSSE_AGENT_PLANE_NAME", "DSSE_RECOVERY_SNI", "DSSE_EDGE_REGION"} {
			if !strings.Contains(env, "\n"+k+"=") && !strings.HasPrefix(env, k+"=") {
				t.Errorf("shape %v is not told %s, so it cannot say what it is", shape, k)
			}
		}
		// ★ THE CONTROL: the credentials it does not read are still gone, or "keep everything" would pass.
		if shape.edges && strings.Contains(env, "\nPG_SUPERUSER_PASSWORD=") {
			t.Error("keeping the descriptions brought the database superuser password back with them")
		}
	}
}

// ★★★ THE PROCEDURE ATE ITSELF (2026-08-27, found by walking it on a second region's machine). -carry packs a
// machine what its services mount; nothing mounts root.crt, so it was withheld. -region decides whether a
// directory is a carried deployment or an empty one that would MINT A SECOND DEPLOYMENT by looking for
// root.crt — so the command the installer tells you to run refused the file the installer told you to make:
//
//	dsse-install: /opt/dsse/region-b holds no authorities, so installing a region here would MINT A SECOND
//	DEPLOYMENT. … Carry the deployment from the region that created it: dsse-install … -carry <file.tar.gz>
//
// Same shape as the deployment.env filter: dsse-install runs ON the receiving machine and is a reader too.
func TestACarriedMachineCanBeInstalledAsARegion(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, shape := range []machineShape{
		{holds: regionShapeEdgesOnly, edges: true},
		{holds: regionShapeStateBearingJoin, edges: false},
	} {
		dest := filepath.Join(t.TempDir(), "m.tar.gz")
		if _, _, err := carryDeploymentFor(dir, dest, shape, "", nil); err != nil {
			t.Fatalf("carry: %v", err)
		}
		landed := unpackCarry(t, dest)
		minted, err := alreadyMinted(landed)
		if err != nil {
			t.Fatal(err)
		}
		if !minted {
			t.Fatalf("shape %+v: a carried machine reads as an EMPTY directory, so -region refuses it as the "+
				"second deployment it is not", shape)
		}
		// ★ AND THE MINTING MATERIAL IS STILL NOT THERE. The point is that a receiving machine can be
		// RECOGNISED without being able to ISSUE.
		for _, a := range authorityFiles {
			if _, err := os.Stat(filepath.Join(landed, authorityDirName, a)); err == nil {
				t.Fatalf("%s travelled to a receiving machine", a)
			}
		}
	}
}

func unpackCarry(t *testing.T, path string) string {
	t.Helper()
	out := t.TempDir()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		target := filepath.Join(out, hdr.Name)
		if hdr.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		w, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, tr); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
	}
	return out
}
