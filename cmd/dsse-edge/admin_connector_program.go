package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/durablefile"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// admin_connector_program.go — the deployment holds the programs a customer runs on the machine inside their
// network, so the person who takes the profile takes the program in the same act.
//
// ★★★ THE SCREEN TOLD THEM TO RUN SOMETHING THEY HAD NO WAY TO GET (2026-08-26). "Add connector" hands over a
// profile and the line `dsse-connector-install --profile …`, and nothing in the product put that program on
// the customer's machine. The endpoint agent has a signed artifact lane for exactly this, and a connector
// cannot use it: that route is served inside the tunnel under mandatory mTLS, and a connector has no identity
// until it has enrolled — which is the thing the program it does not have would do.
//
// So it is carried by the same person, in the same visit to the same screen. That is not a workaround; it is
// what the connector's install actually is. A connector is placed by an administrator who is already holding
// a credential for this deployment, and the profile beside it is already a file they carry.
//
// ★ IT IS PUBLISHED, NOT BUILT HERE. The operator uploads the bytes for a platform and architecture and
// declares their digest; this stores them and hands the same digest to whoever downloads. It mints nothing
// and compiles nothing.
//
// ★★ WHAT THE DIGEST DOES AND DOES NOT PROVE, said plainly because the agent's lane next door proves more.
// There the bytes are named by a SIGNED manifest and a device verifies them twice before it runs anything,
// because a device installs unattended and must not be trickable. Here the same person supplies the bytes and
// the digest, so the digest is an INTEGRITY check on the carry — it catches a truncated upload, a corrupted
// download, and a file swapped in the customer's downloads folder — and it is not an authorisation of the
// bytes. What authorises them is that an operator of this deployment put them here. Adding a signing key
// would be machinery for a threat this path does not have: there is a human at both ends, and anyone who can
// publish here can already publish an agent release the whole fleet installs.

// connectorProgramMeta is the sidecar written beside the bytes. It is what the screen shows and what the
// person who downloads compares against.
type connectorProgramMeta struct {
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
	FileName    string `json:"file_name"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	Version     string `json:"version,omitempty"`
	PublishedAt string `json:"published_at"`
	PublishedBy string `json:"published_by,omitempty"`
}

// connectorProgramListing describes the resolved publication source, not a value
// trusted from the uploaded sidecar. The selected tenant is carried by the response.
type connectorProgramListing struct {
	connectorProgramMeta
	Source string `json:"source"`
}

// connectorProgramTarget is one platform/arch pair, normalised. Both halves are required: a program with no
// architecture is one somebody has to guess about, and the guess is made on the machine where it fails.
func connectorProgramTarget(platform, arch string) (string, error) {
	p, a := strings.ToLower(strings.TrimSpace(platform)), strings.ToLower(strings.TrimSpace(arch))
	if p == "" || a == "" {
		return "", fmt.Errorf("platform and arch are both required: a program stored without them is one " +
			"somebody has to guess about on the machine where the guess fails")
	}
	for _, s := range []string{p, a} {
		// The pair becomes a directory name. Kept to what a target name is actually made of rather than
		// escaped, so nothing here can be talked into writing outside the store.
		for _, r := range s {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' {
				return "", fmt.Errorf("%q is not a platform/architecture name", s)
			}
		}
		if s == "." || s == ".." {
			return "", fmt.Errorf("%q is not a platform/architecture name", s)
		}
	}
	return p + "-" + a, nil
}

// The store has two halves, and the difference between them is who the bytes belong to.
//
// ★★★ A PER-ORGANIZATION-ONLY STORE WOULD BE DARK FOR EVERY ORGANIZATION BUT ONE. This deployment can seed
// the program it is itself running, and it runs under one tenant's configuration — so seeding into a
// tenant's directory would give the first organization a working "Add connector" and every later one a
// screen that says there is nothing to put on the machine. That difference is invisible from the side that
// works, which is the family this tree keeps finding. The seeded program is not tenant material anyway:
// it is this deployment's own binary, identical for everyone it serves.
//
// So: `deployment/` is what this deployment carries, available to every organization it serves.
// `tenants/<id>/` is what an operator published FOR one organization, and it wins for that organization.
const (
	connectorProgramDeploymentScope = "deployment"
	connectorProgramTenantScope     = "tenants"
)

// connectorProgramDir is where one target's bytes and metadata live for one organization.
func connectorProgramDir(root, tenantID, target string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("this process has no connector-program directory, so it has nowhere to put the bytes")
	}
	tenant := strings.TrimSpace(tenantID)
	if tenant == "" || strings.ContainsAny(tenant, `/\`) {
		return "", fmt.Errorf("a connector program is stored for one organization, and this request names none")
	}
	return filepath.Join(root, connectorProgramTenantScope, tenant, target), nil
}

// connectorProgramDeploymentDir is where the program this deployment itself carries lives.
func connectorProgramDeploymentDir(root, target string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("this process has no connector-program directory, so it has nowhere to put the bytes")
	}
	return filepath.Join(root, connectorProgramDeploymentScope, target), nil
}

const (
	connectorProgramBytesName = "program"
	connectorProgramMetaName  = "program.json"
	// A connector program is a static binary or a small archive of two — tens of megabytes. The cap is
	// generous, finite, and small enough that the upload is read whole rather than staged by hand: an
	// unbounded upload is a way to fill the disk that holds this deployment's database, and that has already
	// happened here once from log files.
	connectorProgramMaxBytes = int64(64 << 20)
)

func readConnectorProgramMeta(dir string) (connectorProgramMeta, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, connectorProgramMetaName))
	if err != nil {
		return connectorProgramMeta{}, false
	}
	var m connectorProgramMeta
	if json.Unmarshal(raw, &m) != nil || strings.TrimSpace(m.SHA256) == "" {
		return connectorProgramMeta{}, false
	}
	return m, true
}

// listConnectorPrograms returns a complete effective catalogue or an error. Missing
// scope directories are valid on first use; unreadable stores and incomplete target
// records must not masquerade as an empty catalogue or a deployment fallback.
func listConnectorPrograms(root, tenantID string) ([]connectorProgramListing, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("connector-program storage is not configured")
	}
	byTarget := map[string]connectorProgramListing{}
	collect := func(dir, source string) error {
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			raw, err := os.ReadFile(filepath.Join(path, connectorProgramMetaName))
			if err != nil {
				return err
			}
			var m connectorProgramMeta
			if err := json.Unmarshal(raw, &m); err != nil {
				return err
			}
			target, err := connectorProgramTarget(m.Platform, m.Arch)
			digest, derr := hex.DecodeString(m.SHA256)
			if err != nil || target != e.Name() || derr != nil || len(digest) != sha256.Size ||
				m.Platform != strings.ToLower(strings.TrimSpace(m.Platform)) || m.Arch != strings.ToLower(strings.TrimSpace(m.Arch)) ||
				m.Size < 0 || m.Size > connectorProgramMaxBytes || m.FileName == "" || connectorProgramFileName(m.FileName, target) != m.FileName {
				return fmt.Errorf("invalid connector-program metadata")
			}
			info, err := os.Stat(filepath.Join(path, connectorProgramBytesName))
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() != m.Size {
				return fmt.Errorf("incomplete connector-program bytes")
			}
			byTarget[e.Name()] = connectorProgramListing{connectorProgramMeta: m, Source: source}
		}
		return nil
	}
	deployment, err := connectorProgramDeploymentDir(root, "x")
	if err != nil {
		return nil, err
	}
	if err := collect(filepath.Dir(deployment), "deployment"); err != nil {
		return nil, err
	}
	// Legacy unscoped reads can still see shared seed programs. A named tenant's
	// override directory must be readable before shared entries are offered.
	if strings.TrimSpace(tenantID) != "" {
		dir, err := connectorProgramDir(root, tenantID, "x")
		if err != nil {
			return nil, err
		}
		if err := collect(filepath.Dir(dir), "tenant"); err != nil {
			return nil, err
		}
	}
	out := make([]connectorProgramListing, 0, len(byTarget))
	for _, m := range byTarget {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Platform != out[j].Platform {
			return out[i].Platform < out[j].Platform
		}
		return out[i].Arch < out[j].Arch
	})
	return out, nil
}

// resolveConnectorProgram finds the directory a download should be served from: this organization's own copy
// if it published one, otherwise the deployment's.
func resolveConnectorProgram(root, tenantID, target string) (string, connectorProgramMeta, string, bool) {
	if dir, err := connectorProgramDir(root, tenantID, target); err == nil {
		if m, ok := readConnectorProgramMeta(dir); ok {
			return dir, m, "tenant", true
		}
	}
	if dir, err := connectorProgramDeploymentDir(root, target); err == nil {
		if m, ok := readConnectorProgramMeta(dir); ok {
			return dir, m, "deployment", true
		}
	}
	return "", connectorProgramMeta{}, "", false
}

func registerConnectorProgramRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	root string, isEnforcingEdge bool, writer *logs.Writer, outbox adminAuditOutboxDeadReader, evaluator decision.Evaluator) {

	// control-plane-only: the bytes live with the authority, the same way agent release artifacts do. An
	// enforcing Edge holds no copy and says where to write instead of accepting a write it would lose.
	mux.HandleFunc("PUT /admin/connector-program", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		if isEnforcingEdge {
			writeError(w, http.StatusConflict, fmt.Errorf("this edge holds no connector programs; publish to "+
				"the control plane instead"))
			return
		}
		target, terr := connectorProgramTarget(r.URL.Query().Get("platform"), r.URL.Query().Get("arch"))
		if terr != nil {
			writeError(w, http.StatusBadRequest, terr)
			return
		}
		declared := strings.ToLower(strings.TrimSpace(r.Header.Get("x-artifact-sha256")))
		if len(declared) != 64 {
			// ★ THE DIGEST IS DECLARED FIRST, so a truncated upload is REFUSED here rather than downloaded by
			// a customer and run. Without something to check against, this endpoint is a place to stage
			// anything and call it published — the argument the agent artifact route beside this one makes.
			writeError(w, http.StatusBadRequest, fmt.Errorf("x-artifact-sha256 must carry the sha256 of the "+
				"bytes being published: without it nothing here can tell a complete upload from a truncated one"))
			return
		}
		dir, derr := connectorProgramDir(root, adminTenantIDFromRequest(r), target)
		if derr != nil {
			writeError(w, http.StatusPreconditionFailed, derr)
			return
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// ★ READ IT, THEN WRITE IT ONCE. Staging a temporary file here by hand — create, write, flush, close,
		// chmod, replace — is durablefile.Write spelled out again, and every copy of that sequence is
		// individually reasonable right up to the day one of them misses a platform fix. The cap below is
		// what makes reading the whole body reasonable: a connector program is two static binaries, tens of
		// megabytes, published by an operator a handful of times per release.
		//
		// One byte past the cap, so an oversized body is DETECTED rather than silently truncated into
		// something that then fails the digest for a misleading reason.
		body, rerr := io.ReadAll(io.LimitReader(r.Body, connectorProgramMaxBytes+1))
		if rerr != nil {
			writeError(w, http.StatusInternalServerError, rerr)
			return
		}
		written := int64(len(body))
		if written > connectorProgramMaxBytes {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Errorf("a connector program larger than %d bytes is not stored here", connectorProgramMaxBytes))
			return
		}
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, declared) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("these bytes are not the ones declared: got %d "+
				"bytes sha256:%s, the request declares sha256:%s", written, got, declared))
			return
		}
		if err := durablefile.Write(filepath.Join(dir, connectorProgramBytesName), body, 0o640); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		platform, arch, _ := strings.Cut(target, "-")
		meta := connectorProgramMeta{
			Platform: platform, Arch: arch,
			FileName:    connectorProgramFileName(r.Header.Get("x-artifact-filename"), target),
			SHA256:      got,
			Size:        written,
			Version:     strings.TrimSpace(r.Header.Get("x-artifact-version")),
			PublishedAt: time.Now().UTC().Format(time.RFC3339),
			PublishedBy: actorOf(r).PrincipalID,
		}
		sidecar, _ := json.MarshalIndent(meta, "", "  ")
		// Metadata lands after the bytes. This is not an atomic pair: an interrupted
		// publish can leave a missing sidecar or an older sidecar beside new bytes.
		// Catalogue reads reject missing metadata and size mismatches; they do not
		// hash every file or establish serialization with concurrent publishers.
		if err := durablefile.Write(filepath.Join(dir, connectorProgramMetaName), sidecar, 0o640); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// Record the verified bytes and completed metadata, not the untrusted
		// request declaration. Publication and audit delivery remain separate writes.
		if writer != nil {
			now := time.Now().UTC()
			_ = appendAdminAudit(r.Context(), writer, outbox, connectorProgramPublishedAuditLog(r, adminTenantIDFromRequest(r), meta, evaluator, now), now)
		}
		writeJSON(w, http.StatusOK, meta)
	}))

	mux.HandleFunc("GET /admin/connector-programs", adminEndpoint("admin.connectors.read", func(w http.ResponseWriter, r *http.Request) {
		programs, err := listConnectorPrograms(root, adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("connector programs could not be verified; ask the deployment operator to check program storage and retry"))
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id": adminTenantIDFromRequest(r),
			"programs":  programs,
			"count":     len(programs),
			// ★ THE CONSEQUENCE, NOT THE COUNT. A screen showing "0" cannot be acted on by the person reading
			// it; this says what the zero means for the customer standing in front of a machine.
			"note": connectorProgramNote(len(programs)),
		})
	}))

	mux.HandleFunc("GET /admin/connector-program", adminEndpoint("admin.connectors.read", func(w http.ResponseWriter, r *http.Request) {
		target, terr := connectorProgramTarget(r.URL.Query().Get("platform"), r.URL.Query().Get("arch"))
		if terr != nil {
			writeError(w, http.StatusBadRequest, terr)
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		if strings.TrimSpace(tenantID) == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("this request names no organization"))
			return
		}
		dir, meta, source, ok := resolveConnectorProgram(root, tenantID, target)
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("this deployment holds no connector program for %s: "+
				"an operator publishes one with PUT /admin/connector-program", target))
			return
		}
		f, oerr := os.Open(filepath.Join(dir, connectorProgramBytesName))
		if oerr != nil {
			writeError(w, http.StatusNotFound, fmt.Errorf("the record for %s is here and its bytes are not", target))
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+meta.FileName+`"`)
		// The digest travels with the bytes, so whoever carries them can check what arrived without going
		// back to the screen that offered them.
		w.Header().Set("x-artifact-sha256", meta.SHA256)
		w.Header().Set("X-Dsse-Connector-Program-Tenant", tenantID)
		w.Header().Set("X-Dsse-Connector-Program-Source", source)
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, meta.FileName, time.Time{}, f)
	}))
}

func connectorProgramNote(n int) string {
	if n == 0 {
		return "This deployment holds no connector program, so an administrator adding a connector has " +
			"nothing to put on the machine. An operator publishes one per platform and architecture."
	}
	return "Carried to the machine by the person who carries the profile, and checked there against the digest shown."
}

// connectorProgramFileName is what the download is called. A name the publisher chose is kept when it is a
// plain file name; anything carrying a path is replaced rather than sanitised, because a name that had to be
// repaired is not a name to hand to somebody's shell.
func connectorProgramFileName(supplied, target string) string {
	s := strings.TrimSpace(supplied)
	if s != "" && !strings.ContainsAny(s, `/\`) && s != "." && s != ".." && len(s) <= 120 {
		return s
	}
	return "dsse-connector-" + target + ".tar.gz"
}

// resolveConnectorProgramDir makes the durable path the default path, the same rule -state-dir applies to
// every config store: an operator who named nothing still gets a lane that works, and one who named a
// directory keeps it.
//
// ★★★ A LANE NOTHING SETS IS A LANE THAT IS DARK. The connector installer spent its first day in a tree that
// built it nowhere, and a screen went on handing out the command it replaced. A flag with no default repeats
// that: every deployment the installer generates would answer "this process has no connector-program
// directory" to a customer standing in front of a machine.
func resolveConnectorProgramDir(explicit, stateDir string) string {
	if e := strings.TrimSpace(explicit); e != "" {
		return e
	}
	if sd := strings.TrimSpace(stateDir); sd != "" {
		return filepath.Join(sd, "connector-programs")
	}
	return ""
}

// seedConnectorProgramFromThisImage publishes, as the deployment's own, the connector programs this process
// is shipped beside — once, for the platform and architecture it is itself running on.
//
// ★★★ A LANE THAT ONLY curl CAN FILL IS A LANE NOBODY FILLS. That is the defect this whole change exists to
// undo: the connector's installer was written, built nowhere, and the screen went on handing out the command
// it replaced. An upload endpoint with no way to reach it repeats that shape one layer up — every generated
// deployment would answer "this deployment holds no connector program" to a customer standing in front of a
// machine, and nothing would say why.
//
// The deployment already carries these programs: they are in the same image as the process running this, put
// there by the same build. Handing them out is not a new supply chain, it is showing what is already here.
//
// ★ IT SEEDS ONLY WHAT IT CAN HONESTLY CLAIM. One target — this process's own GOOS/GOARCH — because that is
// the only pair whose bytes are on this disk. A customer's machine running something else needs an operator
// to publish for it, and the screen names the platform of every download so nobody carries the wrong one.
//
// ★ AND IT NEVER OVERWRITES. A deployment that has been given a program keeps it; this fills an empty slot
// and says so, or does nothing and says nothing.
func seedConnectorProgramFromThisImage(root string, binaries []string, goos, goarch string) {
	if strings.TrimSpace(root) == "" {
		return
	}
	target, err := connectorProgramTarget(goos, goarch)
	if err != nil {
		return
	}
	dir, derr := connectorProgramDeploymentDir(root, target)
	if derr != nil {
		return
	}
	// ★★★ AND IT REFRESHES ITS OWN COPY WHEN THE BUILD MOVES (2026-08-26, measured immediately after the
	// first seed). "Never overwrite" is right for a program an OPERATOR published — that is their choice —
	// and wrong for this half, which is not a choice at all: it is "the program this deployment runs". A
	// deployment that upgrades and keeps handing out the previous build gives every customer a connector
	// older than the Edge it is enrolling into, silently, for ever. Measured on the release lab: the fleet
	// was on 49868b0d and the screen was still offering the archive built from aab4a692.
	//
	// The operator's per-organization copy is in another directory and is never touched by this.
	stamp := buildVersion + "+" + buildCommit
	if existing, exists := readConnectorProgramMeta(dir); exists {
		if strings.TrimSpace(existing.Version) == stamp {
			return
		}
		log.Printf("connector programs: this deployment now runs %s and the program it hands out was built "+
			"from %q — replacing it, so a customer installs a connector of the same build as the Edge it "+
			"enrols into", stamp, existing.Version)
	}
	present := []string{}
	for _, b := range binaries {
		if st, serr := os.Stat(b); serr == nil && !st.IsDir() {
			present = append(present, b)
		}
	}
	// ★ THE INSTALLER IS THE ONE THAT MATTERS. A customer handed only dsse-connector is back to the command
	// line this change removed, so an archive missing it is not worth publishing as "the program".
	hasInstaller := false
	for _, b := range present {
		if filepath.Base(b) == "dsse-connector-install" {
			hasInstaller = true
		}
	}
	if !hasInstaller {
		log.Printf("connector programs: this image carries no dsse-connector-install, so there is nothing to "+
			"hand a customer for %s. \"Add connector\" will say so; publish one with PUT /admin/connector-program", target)
		return
	}
	archive, sum, aerr := connectorProgramArchive(present)
	if aerr != nil {
		log.Printf("connector programs: could not package this image's connector programs for %s: %v", target, aerr)
		return
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		log.Printf("connector programs: %v", err)
		return
	}
	name := "dsse-connector-" + target + ".tar.gz"
	if err := durablefile.Write(filepath.Join(dir, connectorProgramBytesName), archive, 0o640); err != nil {
		log.Printf("connector programs: %v", err)
		return
	}
	meta := connectorProgramMeta{
		Platform: goos, Arch: goarch, FileName: name, SHA256: sum, Size: int64(len(archive)),
		Version: stamp, PublishedAt: time.Now().UTC().Format(time.RFC3339),
		PublishedBy: "this deployment",
	}
	body, _ := json.MarshalIndent(meta, "", "  ")
	if err := durablefile.Write(filepath.Join(dir, connectorProgramMetaName), body, 0o640); err != nil {
		log.Printf("connector programs: %v", err)
		return
	}
	log.Printf("connector programs: published this deployment's own %s (%d bytes, sha256:%s) — \"Add connector\" "+
		"now hands a customer the program as well as the profile", name, len(archive), sum)
}

// connectorProgramArchive packages the binaries into a .tar.gz and returns it with its digest. Executable
// bits are set explicitly: an archive that unpacks into files nobody can run is a download that fails on the
// customer's machine, for a reason that is not visible there.
func connectorProgramArchive(paths []string) ([]byte, string, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, "", err
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: filepath.Base(p), Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg,
		}); err != nil {
			return nil, "", err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, "", err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, "", err
	}
	if err := gz.Close(); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

// connectorProgramsBesideThisBinary is where this image put the connector programs: next to the program
// reading this. Derived from the running executable rather than hard-coded, so it is true in the published
// image, in the release lab's image, and when somebody runs the tree from a build directory.
func connectorProgramsBesideThisBinary() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	dir := filepath.Dir(exe)
	return []string{
		filepath.Join(dir, "dsse-connector"),
		filepath.Join(dir, "dsse-connector-install"),
	}
}

// registerConnectorProgramFlag defines this surface's one flag HERE rather than in main.go — the same rule
// the agent-update surface next door follows, and the one the decomposition ratchet enforces.
func registerConnectorProgramFlag() *string {
	return flag.String("connector-program-dir", "",
		"where this deployment holds the connector PROGRAMS an administrator downloads from \"Add connector\" "+
			"and carries to the machine inside the customer's network. Empty and -state-dir set = "+
			"‹state-dir›/connector-programs, so the lane is not dark on a deployment that never named it")
}

// The artifact digest identifies public program content. The raw bytes,
// credentials, arbitrary request headers and storage paths never enter this row.
func connectorProgramPublishedAuditLog(r *http.Request, tenant string, meta connectorProgramMeta, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	record := model.AuditLog{
		ID: randomEdgeID("audit_connector_program_published_", now), TenantID: tenant,
		ActorUserID: auditActorPrincipal(r), EventType: "admin_connector_program_published",
		TargetType: stringPtr("connector_program"), TargetID: stringPtr(meta.Platform + "/" + meta.Arch),
		Action: stringPtr("publish"), Result: stringPtr("success"),
		EdgeRegionID: &evaluator.EdgeRegionID, EdgeClusterID: &evaluator.EdgeClusterID,
		Timestamp: now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{"publication_scope": "tenant_override", "platform": meta.Platform, "arch": meta.Arch,
			"version": meta.Version, "artifact_sha256": meta.SHA256, "artifact_size": meta.Size,
			"file_name": meta.FileName, "published_at": meta.PublishedAt},
	}
	if r != nil {
		if identity, ok := adminIdentityFromRequest(r); ok && strings.TrimSpace(tenant) != "" && !strings.EqualFold(strings.TrimSpace(tenant), strings.TrimSpace(identity.TenantID)) {
			stampOperatorActor(record.Metadata, identity)
		}
	}
	return record

}
