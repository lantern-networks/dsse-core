package main

// what_this_machine_reads.go — the files and the values ONE machine needs, and nothing beyond them.
//
// ★★★ EVERY COMPONENT IS ITS OWN HARDWARE AND ITS OWN OPERATING SYSTEM, so no directory is shared between
// them and nothing may be handed to a machine because a DIFFERENT machine needs it. Until this existed the
// unit of installation was the region: one directory, rendered once, carried whole to every machine in it.
//
// ★★★ WHAT THAT COST, MEASURED ON A GENERATED DEPLOYMENT (2026-08-27). deployment.env is one file holding
// every credential the region has, and it is mounted into every service on every machine. Reading the compose
// for who actually NAMES each value:
//
//	PG_PASSWORD             dsse-control-plane-a, dsse-control-plane-b, dsse-postgres-init
//	PG_SUPERUSER_PASSWORD   dsse-postgres-a, dsse-postgres-init
//	CLICKHOUSE_PASSWORD     dsse-clickhouse, dsse-control-plane-a, dsse-control-plane-b
//	MINIO_ROOT_PASSWORD     dsse-archive, dsse-archive-init, dsse-control-plane-a, dsse-control-plane-b
//
// Not one of them is named by an Edge service or by start-edge.sh. Every Edge machine in every deployment
// nevertheless holds the deployment's database superuser password and its object store's root credential —
// read by nothing there, and reachable by anything that reaches that box.
//
// ★★ THE SET IS DERIVED, NEVER LISTED. A hand-kept list of "what an Edge needs" is a second description of
// the deployment that drifts from the first one silently, and the failure is a node that starts, cannot find
// one file, and reports something unrelated. The compose file for a machine already says exactly what its
// services mount and name; this reads that, and the start scripts those services run.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type serviceMaterial struct {
	entrypoint string
	mounts     []string
}

var (
	composeServiceDecl = regexp.MustCompile(`^  ([a-z0-9-]+):(?: &[a-z0-9-]+)?\s*$`)
	// ★★★ ANY DESTINATION AND EITHER LIST FORM (2026-08-27, both caught by reading what the first
	// per-component carry withheld, one after the other).
	//
	// The first pattern required the destination to be under /deployment, because that is where the Edges and
	// the control planes mount their material. The region doorway mounts haproxy-edge.cfg at
	// /usr/local/etc/haproxy/haproxy.cfg, the database door mounts haproxy-postgres.cfg, and ClickHouse mounts
	// clickhouse-init/ — so four files were reported as "not in it".
	//
	// The second required the block list form, `- "./x:/y"`. The doorway writes its volumes inline —
	// `volumes: ["./haproxy-edge.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro"]` — so haproxy-edge.cfg was STILL
	// withheld from both machines, which would have produced a region whose only door starts with no
	// configuration at all. Compose accepts both forms and this file is generated in both.
	//
	// What makes a file this machine's is that a service here mounts it. Where it lands inside the container,
	// and how the line is punctuated, are that service's business.
	composeMountDecl = regexp.MustCompile(`"\./([A-Za-z0-9._/-]+):/[^"]+"`)
	composeEntryDecl = regexp.MustCompile(`^\s+entrypoint: \["/deployment/([A-Za-z0-9._-]+)"\]\s*$`)
	shellVarRef      = regexp.MustCompile(`\$\{?([A-Z][A-Z0-9_]{2,})\b`)
)

// mountsByService maps each service that runs a start script to that script and the deployment-directory
// paths it is given. Services with no entrypoint are left out deliberately: this answers "does the script
// this service runs have what it reads", and a service with no script has no such question.
func mountsByService(compose string) map[string]serviceMaterial {
	mounts, entries := composeMountsAndEntrypoints(compose)
	out := map[string]serviceMaterial{}
	for svc, entry := range entries {
		out[svc] = serviceMaterial{entrypoint: entry, mounts: mounts[svc]}
	}
	return out
}

// composeMountsAndEntrypoints reads both, for every service — including the ones that run an image's own
// command rather than a start script.
//
// ★ THE HAPROXY DOORS AND THE STORES ARE SERVICES TOO. mountsByService leaves them out because they run no
// script, and a carry that inherited that would omit haproxy-edge.cfg and clickhouse-init/ — the machine
// would come up with a door that has no configuration.
func composeMountsAndEntrypoints(compose string) (map[string][]string, map[string]string) {
	mounts, entries := map[string][]string{}, map[string]string{}
	current := ""
	for _, l := range strings.Split(compose, "\n") {
		if m := composeServiceDecl.FindStringSubmatch(l); m != nil {
			current = m[1]
			continue
		}
		if current == "" {
			continue
		}
		// ★ A COMMENT IS NOT A MOUNT. The generated file explains itself at length, and a path quoted in prose
		// would otherwise become a file this machine is given.
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			for _, m := range composeMountDecl.FindAllStringSubmatch(l, -1) {
				mounts[current] = append(mounts[current], strings.TrimSuffix(m[1], "/"))
			}
		}
		if m := composeEntryDecl.FindStringSubmatch(l); m != nil {
			entries[current] = m[1]
		}
	}
	return mounts, entries
}

// filesThisMachineReads is every deployment-directory path the given compose mounts into any of its services.
func filesThisMachineReads(compose string) []string {
	mounts, _ := composeMountsAndEntrypoints(compose)
	seen := map[string]bool{}
	out := []string{}
	for _, list := range mounts {
		for _, m := range list {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

// valuesThisMachineReads is every environment variable this machine's compose names, plus every one named by
// the start scripts its services run.
//
// ★★★ THE SCRIPTS ARE HALF THE ANSWER. A value can reach a process two ways: compose puts it in the
// environment, or the start script sources deployment.env and passes it on a flag. start-edge.sh takes
// -admin-token, -connector-secret, -workload-attestation-secret and -audit-ingest-token that way, and a carry
// that read only the compose would strip four credentials the Edge cannot start without.
func valuesThisMachineReads(dir, compose string) map[string]bool {
	named := map[string]bool{}
	// ★ WHAT THIS PROGRAM READS ON THAT MACHINE. See installerReadsFromDeploymentEnv: filtering these out
	// leaves a deployment that cannot say what it is called, and the checks that ask report a defect that is
	// not there.
	for _, k := range installerReadsFromDeploymentEnv {
		named[k] = true
	}
	for _, m := range shellVarRef.FindAllStringSubmatch(compose, -1) {
		named[m[1]] = true
	}
	_, entries := composeMountsAndEntrypoints(compose)
	for _, script := range entries {
		body, err := os.ReadFile(filepath.Join(dir, script))
		if err != nil {
			continue
		}
		for _, m := range shellVarRef.FindAllStringSubmatch(string(body), -1) {
			named[m[1]] = true
		}
	}
	return named
}

// installerReadsFromDeploymentEnv are the values THIS PROGRAM reads out of a machine's deployment.env.
//
// ★★★ A THIRD READER, FOUND BY WALKING (2026-08-27). The filter asked "does a service or a start script on
// this machine name it", which is the right question for a credential and the wrong one for a description.
// dsse-install runs ON the machine too — -verify, -who-depends, -add-host and a repair all read this file —
// and the first walk after the split reported
//
//	FAIL the way back reaches the agent plane — this deployment does not say what its agent plane is called
//	     (DSSE_AGENT_PLANE_NAME is empty)
//
// on a deployment where it was called exactly what it should be. The check was right and the file it read had
// been filtered out from under it.
//
// ★ NONE OF THESE IS A CREDENTIAL. They are what the deployment calls itself: its host, its region, the names
// of its planes, the map of its regions. A machine keeping its own description costs nothing; a machine that
// cannot state its own description cannot be checked. ADMIN_TOKEN is not in this list — it is kept, on the
// machines that keep it, because a start script there names it.
var installerReadsFromDeploymentEnv = []string{
	"EDGE_HOST",
	"DSSE_EDGE_REGION",
	"DSSE_AGENT_PLANE_NAME",
	"DSSE_RECOVERY_SNI",
	"DSSE_REGION_ENDPOINTS",
	"DSSE_AUTHORITY_ORIGIN",
	"ADMIN_CONSOLE_ORIGIN",
	// ★★★ AND THE TWO DOORS' PEERS (2026-08-28). This program reads them when it renders a region's doorway,
	// and the carry withheld them because no compose SERVICE names them — so a machine that later re-rendered
	// its own door lost every route to the other regions and reported nothing. What a MACHINE reads is not
	// only what its containers read; this installer runs there too.
	"DSSE_CP_PEERS",
	"DSSE_CP_DATA_PEERS",
	"DSSE_PG_PEERS",
}

// installerReadsFromDeploymentDir are the FILES this program reads on a receiving machine.
//
// ★★★ THE PROCEDURE ATE ITSELF WITHOUT THESE (2026-08-27, found by walking it). The carry packs a machine
// what its services mount, and no service mounts root.crt — so it was withheld. -region decides whether a
// directory is a carried deployment or an empty one that would MINT A SECOND DEPLOYMENT by looking for
// exactly that file, and refused the machine the carry had just been used to make. The command the installer
// tells an operator to run rejected the file the installer told them to create.
//
// ★ RECOGNISED WITHOUT BEING ABLE TO ISSUE. root.crt is the deployment's root CERTIFICATE, and its key stays
// in authority/ on the minting machine. A receiving machine can therefore say which deployment it belongs to
// and cannot sign anything for it, which is the whole point of the split. The public halves beside it are
// what an operator compares out loud to check a carry arrived intact.
var installerReadsFromDeploymentDir = []string{
	"root.crt",
	"deployment-anchor.pem",
	"agent-policy-signing.pub",
	"bundle-signing.pub",
}

// deploymentEnvFor is deployment.env with only the assignments this machine reads, and the comments that
// explain them.
//
// ★ COMMENTS AND BLANK LINES SURVIVE. The file is written to be read by a person — most of it is the reason
// a value is what it is — and a filtered copy that keeps only assignments is a different document.
// ★★ AN ASSIGNMENT THAT IS DROPPED IS SAID SO, IN PLACE. A machine's operator opening this file and finding
// nothing where a credential used to be cannot tell "this component does not need it" from "the carry lost
// it". Withheld is not the same as missing, and only one of them is a fault.
func deploymentEnvFor(body string, reads map[string]bool) (string, []string) {
	assign := regexp.MustCompile(`^([A-Z][A-Z0-9_]*)=`)
	out, withheld := []string{}, []string{}
	for _, line := range strings.Split(body, "\n") {
		m := assign.FindStringSubmatch(line)
		if m == nil {
			out = append(out, line)
			continue
		}
		if reads[m[1]] {
			out = append(out, line)
			continue
		}
		withheld = append(withheld, m[1])
		out = append(out, "# "+m[1]+"= — withheld: no service or start script on this machine names it.")
	}
	sort.Strings(withheld)
	return strings.Join(out, "\n"), withheld
}
