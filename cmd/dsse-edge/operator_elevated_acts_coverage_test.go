package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ★★★ A TENANT-SCOPED PKI WRITE MUST BE CLASSIFIED, NOT LEFT OUT (2026-08-19, roadmap item B).
//
// The elevated list grew by exception: an act was added when somebody noticed it was destructive. So a route
// that nobody thought about was un-elevated BY DEFAULT and nothing anywhere said so — which is how POST and
// DELETE /admin/interception-roots/{tenant} came to sit outside the envelope while
// POST /admin/interception-intermediate/{tenant}, beside them and strictly smaller in blast radius, sat
// inside it. Replacing the intermediate changes what signs; replacing the ROOT changes the anchor every one of
// that organization's devices must already hold, and a device that does not hold it loses every HTTPS request
// it makes. That is not hypothetical — it happened on win-dev-1 the same day.
//
// So every write route that names an organization on the PKI surface appears in one list or the other, with a
// reason. Adding a route now forces the question instead of answering it by omission.
func TestEveryTenantScopedPKIWriteIsClassified(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "route_manifest.txt"))
	if err != nil {
		t.Fatalf("route manifest: %v", err)
	}
	// The PKI surface, by the prefixes the routes actually use. Read from the manifest rather than from the
	// mux so a route that exists and was never written down fails somewhere else, loudly, rather than here.
	pki := regexp.MustCompile(`^(POST|DELETE|PUT|PATCH) (/admin/(interception[a-z-]*|tenant-cas|device-client-cas|pki)/.*)$`)
	tenantSegment := regexp.MustCompile(`\{tenant[a-z_]*\}`)

	unclassified := []string{}
	checked := 0
	for _, line := range strings.Split(string(blob), "\n") {
		line = strings.TrimSpace(line)
		m := pki.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if !tenantSegment.MatchString(m[2]) {
			continue // node-wide material: not an act performed ON one organization
		}
		checked++
		// The manifest writes {tenant}; the classification writes * for one segment.
		path := tenantSegment.ReplaceAllString(m[2], "*")
		path = regexp.MustCompile(`\{[a-z_0-9]+\}`).ReplaceAllString(path, "*")
		if !operatorActIsClassified(m[1], path) {
			unclassified = append(unclassified, m[1]+" "+m[2])
		}
	}

	if checked == 0 {
		t.Fatal("no tenant-scoped PKI write routes were found in the manifest — this gate is reading the wrong " +
			"file or the wrong shape, and a gate that checks nothing passes for the wrong reason")
	}
	if len(unclassified) > 0 {
		t.Fatalf("these acts are performed on ONE organization's PKI and are in neither list:\n    %s\n"+
			"Add each to operatorElevatedActs (if it is irreversible or takes effect across that organization "+
			"at once) or to operatorDailyWorkActs (if it is the work the customer is paying for), with the "+
			"reason written down. Being in neither means an operator performs it under the standing delegation "+
			"because nobody decided.", strings.Join(unclassified, "\n    "))
	}
}

// ★★★ AND THE ORGANIZATION IS NOT ALWAYS IN THE PATH (2026-08-20).
//
// The gate above reads the route manifest and treats "acts on ONE organization's PKI" as "has a {tenant} path
// segment". That premise was true when it was written and stopped being true the same morning it was relied
// on: POST /admin/tenant-transport-authority and POST /admin/tenant-interception-authority name the
// organization in the body and in X-Operate-Tenant, so the gate could not see them, and an operator credential
// walked straight into another organization's PKI with no elevation — measured, on the running lab, the first
// time anybody held a credential that could cross organizations at all.
//
// So this reads the SOURCE for the thing that actually marks the act: a handler that calls
// adminTenantPKITargetAllowed has, by construction, decided it is acting on one named organization's PKI —
// however that name arrived. Where the previous gate asks about the URL, this one asks about the code.
func TestEveryHandlerThatTargetsOneOrganizationsPKIIsClassified(t *testing.T) {
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	route := regexp.MustCompile(`HandleFunc\("(GET|POST|PUT|PATCH|DELETE) (/[^"]*)"`)
	wildcard := regexp.MustCompile(`\{[a-zA-Z_0-9.]+\}`)

	unclassified, checked := []string{}, 0
	for _, file := range entries {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		blob, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		method, path := "", ""
		for _, line := range strings.Split(string(blob), "\n") {
			if m := route.FindStringSubmatch(line); m != nil {
				method, path = m[1], m[2]
			}
			if !strings.Contains(line, "adminTenantPKITargetAllowed(r,") || path == "" {
				continue
			}
			if method == "GET" {
				continue // reading another organization's PKI is refused by the same call, but it is not an act
			}
			checked++
			if !operatorActIsClassified(method, wildcard.ReplaceAllString(path, "*")) {
				unclassified = append(unclassified, method+" "+path+"  ("+file+")")
			}
		}
	}

	if checked == 0 {
		t.Fatal("no handler that targets one organization's PKI was found in the source — this gate is reading " +
			"for the wrong shape, and a gate that checks nothing passes for the wrong reason")
	}
	if len(unclassified) > 0 {
		t.Fatalf("these handlers act on ONE organization's PKI and are in neither list:\n    %s\n"+
			"The organization does not have to be in the URL for the act to cross into it.",
			strings.Join(unclassified, "\n    "))
	}
}
