package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ★★★ THE MOUNT LIST AND THE START SCRIPT HAVE TO AGREE, AND NOTHING MADE THEM (2026-08-27, written while
// replacing a whole-directory mount with an explicit one).
//
// While the whole directory was mounted, a start script could read anything and it was there. Scoping the
// mounts makes every read a claim on the mount list, and the two live in different files — so the failure
// mode is a node that starts, cannot find one file, and reports something unrelated. This is the check that
// makes the pair one thing.
//
// ★ It reads the GENERATED artefacts, not the templates: what the container is given is what compose says
// about a directory that actually exists.
func TestEveryFileAStartScriptReadsIsMountedForIt(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "the-deployment.example", "Example", 3, false); err != nil {
		t.Fatalf("mint: %v", err)
	}
	compose, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}

	// ★ PER SERVICE, NOT PER SCRIPT. The first version of this check keyed by entrypoint and therefore UNIONED
	// the mounts of every service running the same script — so removing one Edge's device-ca.key mount left the
	// other Edge's standing in for it and the check passed. Proven by removing one and watching it stay green.
	given := mountsByService(string(compose))
	if len(given) == 0 {
		t.Fatal("no service declares an entrypoint script — this check would pass by measuring nothing")
	}

	hereRef := regexp.MustCompile(`\$here/([A-Za-z0-9._/-]+)`)
	for svc, m := range given {
		script, mounts := m.entrypoint, m.mounts
		body, err := os.ReadFile(filepath.Join(dir, script))
		if err != nil {
			t.Fatalf("read %s: %v", script, err)
		}
		var missing []string
		for _, m := range hereRef.FindAllStringSubmatch(string(body), -1) {
			name := m[1]
			// A path INSIDE a mounted directory is covered by that directory.
			covered := false
			for _, mount := range mounts {
				if name == mount || strings.HasPrefix(name, mount+"/") {
					covered = true
					break
				}
			}
			// Written by the node into its own state, not read from the deployment directory.
			if strings.HasPrefix(name, "edge-state") || strings.HasPrefix(name, "cp-state") {
				covered = true
			}
			if !covered {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		missing = dedupeStrings(missing)
		if len(missing) > 0 {
			t.Fatalf("%s runs %s, which reads %v that this service is not given — it will start, fail to find "+
				"them, and report something else", svc, script, missing)
		}
	}
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
