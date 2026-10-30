package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
)

const authCensusFile = "auth-rollout-census.json"

func authMemberID(machine, role string) string { return machine + "/" + role }
func authMemberStem(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}
func authRoleFiles(role string) []string {
	return []string{"auth-rollout-" + role + ".crt", "auth-rollout-" + role + ".key"}
}

// All member keys stay under authority/, which never travels. A carry
// substitutes only the destination process's leaf and key.
func prepareAuthRollout(plan *Plan, dir, machine string) error {
	if plan == nil || len(plan.Regions) == 0 {
		return fmt.Errorf("authentication rollout requires the complete deployment plan")
	}
	path := filepath.Join(dir, authCensusFile)
	var census authrollout.Manifest
	raw, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(raw, &census); e != nil {
			return e
		}
		if e = census.Validate(); e != nil {
			return e
		}
		if census.Deployment != plan.Deployment {
			return fmt.Errorf("authentication census belongs to another deployment")
		}
		expected := map[string]bool{}
		for _, n := range census.Members {
			if !n.Retired {
				expected[n.ID] = true
			}
		}
		for _, m := range plan.machines() {
			for _, role := range []string{"cp", "edge"} {
				component := "control-plane"
				if role == "edge" {
					component = "edges"
				}
				if m.Holds.has(component) {
					id := authMemberID(m.Name, role)
					if !expected[id] {
						return fmt.Errorf("authentication census needs an explicit new generation for member %s", id)
					}
					delete(expected, id)
				}
			}
		}
		if len(expected) != 0 {
			return fmt.Errorf("removed authentication members must be explicitly retired")
		}
	} else if os.IsNotExist(e) {
		ca, e := readCertificate(filepath.Join(dir, "management-ca.crt"))
		if e != nil {
			return e
		}
		caKey, e := readECKey(authorityPathForReading(dir, "management-ca.key"))
		if e != nil {
			return fmt.Errorf("authentication census requires the issuing directory: %w", e)
		}
		materialDir := filepath.Join(dir, authorityDirName, "auth-rollout")
		if e = os.MkdirAll(materialDir, 0700); e != nil {
			return e
		}
		census = authrollout.Manifest{Deployment: plan.Deployment, Generation: 1}
		for _, m := range plan.machines() {
			for _, role := range []string{"cp", "edge"} {
				component := "control-plane"
				if role == "edge" {
					component = "edges"
				}
				if !m.Holds.has(component) {
					continue
				}
				id := authMemberID(m.Name, role)
				stem := filepath.Join(materialDir, authMemberStem(id))
				cert, key, e := issueStoreMember(&storeAuthority{Cert: ca, Key: caKey}, "dsse-auth-rollout-"+m.Name+"-"+role, nil, time.Now().UTC(), 1)
				if e != nil {
					return e
				}
				if e = os.WriteFile(stem+".crt", append(certPEM(cert), certPEM(ca)...), 0644); e != nil {
					return e
				}
				if e = os.WriteFile(stem+".key", keyPEM(key), 0600); e != nil {
					return e
				}
				sum := sha256.Sum256(cert.Raw)
				// Planned membership is not an observation of installed software.
				census.Members = append(census.Members, authrollout.Member{ID: id, Role: role, Version: "awaiting-first-report", CertificateSHA256: hex.EncodeToString(sum[:])})
			}
		}
		if e = census.Validate(); e != nil {
			return e
		}
		raw, _ = json.MarshalIndent(census, "", "  ")
		if e = writeContainerReadableFile(path, raw); e != nil {
			return e
		}
	} else {
		return e
	}
	for _, role := range []string{"cp", "edge"} {
		id := authMemberID(machine, role)
		var wanted *authrollout.Member
		for i := range census.Members {
			n := &census.Members[i]
			if n.ID == id && !n.Retired {
				wanted = n
				break
			}
		}
		if wanted == nil {
			continue
		}
		files := authRoleFiles(role)
		local := filepath.Join(dir, files[0])
		if cert, e := readCertificate(local); e == nil {
			sum := sha256.Sum256(cert.Raw)
			if hex.EncodeToString(sum[:]) == wanted.CertificateSHA256 {
				keyPath := filepath.Join(dir, files[1])
				if err := checkPrivateInstallerKey(keyPath); err != nil {
					return fmt.Errorf("inspect authentication member key: %w", err)
				}
				if _, err := tls.LoadX509KeyPair(local, keyPath); err != nil {
					return fmt.Errorf("authentication member key does not match its census identity: %w", err)
				}
				continue
			}
		}
		material, e := authRolloutMaterialFor(dir, machine, role)
		if e != nil {
			return e
		}
		if e = writeAuthRolloutMaterial(dir, material); e != nil {
			return e
		}
	}
	// The issuer needs placeholder paths so the normal carry walker can replace
	// a role the founding machine itself does not run. A carried directory has no
	// authority and must not acquire the unused role's key.
	for _, role := range []string{"cp", "edge"} {
		files := authRoleFiles(role)
		if _, e := os.Stat(filepath.Join(dir, files[0])); os.IsNotExist(e) {
			for _, n := range census.Members {
				if n.Role == role && !n.Retired {
					material, e := authRolloutMaterialFor(dir, strings.TrimSuffix(n.ID, "/"+role), role)
					if e != nil {
						break
					}
					if e = writeAuthRolloutMaterial(dir, material); e != nil {
						return e
					}
					break
				}
			}
		}
	}
	return nil
}
func writeAuthRolloutMaterial(dir string, material map[string][]byte) error {
	for name, b := range material {
		perm := os.FileMode(0644)
		if strings.HasSuffix(name, ".key") {
			perm = 0600
		}
		var e error
		if perm == 0644 {
			e = writeContainerReadableFile(filepath.Join(dir, name), b)
		} else {
			e = publishPrivateInstallerKey(filepath.Join(dir, name), b)
		}
		if e != nil {
			return e
		}
	}
	return nil
}
func authRolloutMaterialFor(dir, machine, role string) (map[string][]byte, error) {
	stem := filepath.Join(dir, authorityDirName, "auth-rollout", authMemberStem(authMemberID(machine, role)))
	out := map[string][]byte{}
	for _, suffix := range []string{".crt", ".key"} {
		b, e := os.ReadFile(stem + suffix)
		if e != nil {
			return nil, fmt.Errorf("authentication member identity missing for %s/%s; re-pack this machine from the original issuing directory: %w", machine, role, e)
		}
		out["auth-rollout-"+role+suffix] = b
	}
	pair, err := tls.X509KeyPair(out["auth-rollout-"+role+".crt"], out["auth-rollout-"+role+".key"])
	if err != nil || len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("authentication member certificate/key mismatch")
	}
	raw, err := os.ReadFile(filepath.Join(dir, authCensusFile))
	if err != nil {
		return nil, err
	}
	var census authrollout.Manifest
	if json.Unmarshal(raw, &census) != nil || census.Validate() != nil {
		return nil, fmt.Errorf("invalid authentication census")
	}
	sum := sha256.Sum256(pair.Certificate[0])
	for _, n := range census.Members {
		if !n.Retired && n.ID == authMemberID(machine, role) && n.Role == role && n.CertificateSHA256 == hex.EncodeToString(sum[:]) {
			return out, nil
		}
	}
	return nil, fmt.Errorf("authentication member material does not match census")
}
func composeAuthRollout(body, dir string) string {
	if _, e := os.Stat(filepath.Join(dir, authCensusFile)); e != nil {
		return body
	}
	for _, role := range []string{"cp", "edge"} {
		anchor := "      - \"./edge-identity.key:/deployment/edge-identity.key:ro\"\n"
		if role == "cp" {
			anchor = "      - \"./audit-ingest-authority.json:/deployment/audit-ingest-authority.json\"\n"
		}
		extra := "      - \"./" + authCensusFile + ":/deployment/" + authCensusFile + ":ro\"\n"
		for _, f := range authRoleFiles(role) {
			extra += "      - \"./" + f + ":/deployment/" + f + ":ro\"\n"
		}
		body = strings.ReplaceAll(body, anchor, anchor+extra)
	}
	return body
}

// The no-plan CLI creates one local CP/Edge pair. Existing inventories cannot
// safely be inferred from local files: upgrading or expanding them needs a plan.
func runStandalone(dir, hosts, org string, years int, force bool) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("-dir is required")
	}
	existing, err := alreadyMinted(dir)
	if err != nil {
		return err
	}
	if existing {
		raw, err := os.ReadFile(filepath.Join(dir, authCensusFile))
		if err != nil {
			return fmt.Errorf("existing deployments require -plan with the complete CP/Edge inventory before authentication upgrade: %w", err)
		}
		var m authrollout.Manifest
		if json.Unmarshal(raw, &m) != nil || m.Validate() != nil || len(m.Members) != 2 ||
			m.Members[0].ID != "standalone/cp" || m.Members[1].ID != "standalone/edge" {
			return fmt.Errorf("use -plan to repair this deployment's complete authentication inventory")
		}
		if force {
			return fmt.Errorf("use authority rotation, not -force, on an existing authentication census")
		}
	}
	if err := run(dir, hosts, org, years, force); err != nil {
		return err
	}
	ca, err := readCertificate(filepath.Join(dir, "management-ca.crt"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(ca.Raw)
	plan := &Plan{Deployment: "standalone-" + hex.EncodeToString(sum[:]), Regions: []PlanRegion{{ID: "local", Machines: []PlanMachine{{Name: "standalone", Holds: heldComponents{"control-plane", "edges"}}}}}}
	if err := prepareAuthRollout(plan, dir, "standalone"); err != nil {
		return err
	}
	if err := writeComposeFile(dir); err != nil {
		return err
	}
	return writeLaunchScripts(dir)
}
