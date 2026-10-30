package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/authrollout"
)

func TestAuthRolloutInstallerCensusAndIndividualCarries(t *testing.T) {
	for _, plan := range []*Plan{threeNodesOneRegionPlan(), threeRegionsMultiEdgePlan(), planOfRegions("region-a", "region-b", "region-c"), authRolloutCohostPlan(3), authRolloutCohostPlan(1)} {
		t.Run(plan.Profile, func(t *testing.T) {
			work := t.TempDir()
			file := filepath.Join(work, "plan.json")
			raw, _ := json.Marshal(plan)
			if e := os.WriteFile(file, raw, 0600); e != nil {
				t.Fatal(e)
			}
			source := filepath.Join(work, "issuer")
			installFromPlan(t, file, source)
			raw, e := os.ReadFile(filepath.Join(source, authCensusFile))
			if e != nil {
				t.Fatal(e)
			}
			var census authrollout.Manifest
			if e = json.Unmarshal(raw, &census); e != nil {
				t.Fatal(e)
			}
			if e = census.Validate(); e != nil {
				t.Fatal(e)
			}
			want := 0
			for _, machine := range plan.machines() {
				if machine.Holds.has("control-plane") {
					want++
				}
				if machine.Holds.has("edges") {
					want++
				}
			}
			if len(census.Members) != want {
				t.Fatalf("expected %d individual CP/Edge members, got %d", want, len(census.Members))
			}
			for _, machine := range plan.machines() {
				archive := filepath.Join(work, machine.Name+".tgz")
				if e := carryPlanMachine(plan, source, archive, machine.Name); e != nil {
					t.Fatal(e)
				}
				dir := unpackCarry(t, archive)
				for _, role := range []string{"cp", "edge"} {
					component := "control-plane"
					if role == "edge" {
						component = "edges"
					}
					files := authRoleFiles(role)
					if !machine.Holds.has(component) {
						if _, e := os.Stat(filepath.Join(dir, files[1])); !os.IsNotExist(e) {
							t.Fatal("carried another component's private key")
						}
						continue
					}
					pair, e := tls.LoadX509KeyPair(filepath.Join(dir, files[0]), filepath.Join(dir, files[1]))
					if e != nil {
						t.Fatal(e)
					}
					sum := sha256.Sum256(pair.Certificate[0])
					found := false
					for _, n := range census.Members {
						if n.ID == authMemberID(machine.Name, role) {
							found = n.CertificateSHA256 == hex.EncodeToString(sum[:])
						}
					}
					if !found {
						t.Fatal("carried identity did not match complete census")
					}
				}
				if e := applyPlanToThisMachine(plan, dir, machine.Name); e != nil {
					t.Fatal(e)
				}
				compose, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
				if !strings.Contains(string(compose), authCensusFile) {
					t.Fatal("runtime cannot read census")
				}
				if _, e := os.Stat(filepath.Join(dir, authorityDirName, "auth-rollout")); !os.IsNotExist(e) {
					t.Fatal("other members' keys travelled")
				}
			}
		})
	}
}

func TestAuthRolloutCarryRejectsAnotherMembersMaterial(t *testing.T) {
	plan := threeNodesOneRegionPlan()
	work := t.TempDir()
	file := filepath.Join(work, "plan.json")
	raw, _ := json.Marshal(plan)
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(work, "issuer")
	installFromPlan(t, file, source)
	raw, err := os.ReadFile(filepath.Join(source, authCensusFile))
	if err != nil {
		t.Fatal(err)
	}
	var census authrollout.Manifest
	if err = json.Unmarshal(raw, &census); err != nil {
		t.Fatal(err)
	}
	first, other := census.Members[0], census.Members[1]
	for _, suffix := range []string{".crt", ".key"} {
		from := filepath.Join(source, authorityDirName, "auth-rollout", authMemberStem(other.ID)+suffix)
		to := filepath.Join(source, authorityDirName, "auth-rollout", authMemberStem(first.ID)+suffix)
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(to, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = authRolloutMaterialFor(source, strings.TrimSuffix(first.ID, "/"+first.Role), first.Role); err == nil {
		t.Fatal("mismatched member material exported")
	}
}

func TestAuthRolloutExistingPrivateKeyMustRemainPrivate(t *testing.T) {
	plan := threeNodesOneRegionPlan()
	work := t.TempDir()
	planFile := filepath.Join(work, "plan.json")
	raw, _ := json.Marshal(plan)
	if err := os.WriteFile(planFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, "issuer")
	installFromPlan(t, planFile, dir)
	machine := plan.foundingRegion().controlPlane().Name
	key := filepath.Join(dir, "auth-rollout-cp.key")
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if err := prepareAuthRollout(plan, dir, machine); err == nil {
		t.Fatal("installer silently accepted a readable existing auth-rollout private key")
	}
	if err := os.Chmod(key, 0600); err != nil {
		t.Fatal(err)
	}
	realKey := key + ".real"
	if err := os.Rename(key, realKey); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realKey, key); err != nil {
		t.Fatal(err)
	}
	if err := prepareAuthRollout(plan, dir, machine); err == nil {
		t.Fatal("installer silently accepted a symlinked auth-rollout private key")
	}
}

func TestAuthRolloutMaterialRewriteKeepsPrivateMode(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "auth-rollout-cp.key")
	if err := os.WriteFile(key, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeAuthRolloutMaterial(dir, map[string][]byte{"auth-rollout-cp.key": []byte("new")}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(key)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("rewritten auth-rollout key mode = %#o, want 0600", info.Mode().Perm())
	}
}

func authRolloutCohostPlan(regions int) *Plan {
	ids := []string{"region-a", "region-b", "region-c"}
	p := planOfRegions(ids[:regions]...)
	for i := range p.Regions {
		p.Regions[i].Machines = p.Regions[i].Machines[:1]
		p.Regions[i].Machines[0].Holds = heldComponents{"control-plane", "edges"}
	}
	return p
}

func TestAuthRolloutStandaloneCLIAndUnknownInventory(t *testing.T) {
	dir := t.TempDir()
	if err := runStandalone(dir, "standalone.example", "", 1, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, authCensusFile))
	if err != nil {
		t.Fatal(err)
	}
	var m authrollout.Manifest
	if json.Unmarshal(before, &m) != nil || len(m.Members) != 2 {
		t.Fatal("standalone CP/Edge missing")
	}
	if err := runStandalone(dir, "", "", 1, false); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, authCensusFile))
	if string(after) != string(before) {
		t.Fatal("repair replaced census")
	}
	if err := regionInstall(dir, "another", machineShape{}); err == nil {
		t.Fatal("cloned standalone identity into another region")
	}
	if err := os.Remove(filepath.Join(dir, authCensusFile)); err != nil {
		t.Fatal(err)
	}
	if err := runStandalone(dir, "", "", 1, false); err == nil {
		t.Fatal("inferred unknown legacy inventory as single node")
	}
}

// Existing issuing directories have deployment authorities but no rollout census
// or individual reporter leaves. Upgrading must add only the new material, retain
// operator-entered version baselines, and carry only the destination's keys.
func TestAuthRolloutExistingIssuingDirectoryMigration(t *testing.T) {
	plan := threeRegionsMultiEdgePlan()
	work := t.TempDir()
	planFile := filepath.Join(work, "plan.json")
	raw, _ := json.Marshal(plan)
	if e := os.WriteFile(planFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(work, "issuer")
	installFromPlan(t, planFile, source)
	retained := map[string][]byte{}
	for _, name := range []string{"management-ca.crt", "management.crt", "management.key", "deployment-anchor.pem"} {
		b, e := os.ReadFile(filepath.Join(source, name))
		if e != nil {
			t.Fatal(e)
		}
		retained[name] = b
	}
	if e := os.Remove(filepath.Join(source, authCensusFile)); e != nil {
		t.Fatal(e)
	}
	if e := os.RemoveAll(filepath.Join(source, authorityDirName, "auth-rollout")); e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"cp", "edge"} {
		for _, name := range authRoleFiles(role) {
			if e := os.Remove(filepath.Join(source, name)); e != nil && !os.IsNotExist(e) {
				t.Fatal(e)
			}
		}
	}
	first := plan.machines()[0].Name
	if e := prepareAuthRollout(plan, source, first); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(source, authCensusFile))
	if e != nil {
		t.Fatal(e)
	}
	var census authrollout.Manifest
	if e = json.Unmarshal(raw, &census); e != nil {
		t.Fatal(e)
	}
	for i := range census.Members {
		if census.Members[i].Version != "awaiting-first-report" {
			t.Fatal("installer invented observed version")
		}
		census.Members[i].Version = "operator-inventoried-0.3.1"
	}
	raw, _ = json.Marshal(census)
	if e = os.WriteFile(filepath.Join(source, authCensusFile), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = prepareAuthRollout(plan, source, first); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(source, authCensusFile))
	if string(after) != string(raw) {
		t.Fatal("repair overwrote reviewed census or baseline")
	}
	for name, before := range retained {
		after, e := os.ReadFile(filepath.Join(source, name))
		if e != nil || string(after) != string(before) {
			t.Fatal("migration changed existing deployment identity", name)
		}
	}
	for _, machine := range plan.machines() {
		archive := filepath.Join(work, machine.Name+".tgz")
		if e = carryPlanMachine(plan, source, archive, machine.Name); e != nil {
			t.Fatal(e)
		}
		carried := unpackCarry(t, archive)
		if _, e = os.Stat(filepath.Join(carried, authorityDirName)); !os.IsNotExist(e) {
			t.Fatal("issuer authority travelled")
		}
		for _, role := range []string{"cp", "edge"} {
			component := "control-plane"
			if role == "edge" {
				component = "edges"
			}
			files := authRoleFiles(role)
			if !machine.Holds.has(component) {
				if _, e = os.Stat(filepath.Join(carried, files[1])); !os.IsNotExist(e) {
					t.Fatal("unrelated role key travelled")
				}
				continue
			}
			pair, e := tls.LoadX509KeyPair(filepath.Join(carried, files[0]), filepath.Join(carried, files[1]))
			if e != nil {
				t.Fatal(e)
			}
			pin := sha256.Sum256(pair.Certificate[0])
			found := false
			for _, member := range census.Members {
				if member.ID == authMemberID(machine.Name, role) {
					found = member.CertificateSHA256 == hex.EncodeToString(pin[:])
				}
			}
			if !found {
				t.Fatal("carried leaf differs from migration census")
			}
		}
	}
}
