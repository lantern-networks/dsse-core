package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// steer_agent_update_artifact.go — where the update package itself comes from.
//
// ★ WHY THE EDGE SERVES IT. delivery=dsse requires an https artifact_url, and until now nothing in the product
// could be one: the manifest endpoint existed, the courier existed, the updater existed, and the bytes they
// were all about had no home. That left "host it yourself" as the only answer, which is a fine answer for a
// customer with a CDN and no answer at all for a deployment that has an Edge and nothing else.
//
// ★★ AND IT IS DELIBERATELY UNAUTHENTICATED, which is the part that deserves the argument.
//
// The updater holds no network identity, on purpose (updateplatform/source.go): giving the most privileged
// component on the endpoint a TLS client stack and access to the device key adds a privileged network surface
// in order to protect a document that already protects itself. The same reasoning covers the artifact. Its
// integrity is the SHA-256 in the signed manifest — checked when staged and AGAIN immediately before the
// installer is launched — so the channel proves nothing and is asked to prove nothing. A signed release served
// over https is what every vendor does, and requiring mTLS here would mean the one component that must never
// be tricked is also the one carrying credentials.
//
// What is NOT public: which version a device is offered. That stays on the manifest endpoint, keyed to the
// cert-proven identity. This endpoint hands over bytes whose digest is already published to the fleet.
//
// The bytes are verified against the manifest BEFORE they are served, so an Edge with a mismatched artifact
// fails here — loudly, on the machine where the release was staged — instead of on every device that stages a
// package it will then refuse.
func registerSteerAgentUpdateArtifactRoute(mux *http.ServeMux, config serverConfig) {
	mux.HandleFunc("GET /steer/agent-update-artifact", func(w http.ResponseWriter, r *http.Request) {
		// ★★ IT IS SERVED INSIDE THE TUNNEL NOW (2026-08-13, operator decision, from win-dev-1's §b46a53fa).
		//
		// The integrity argument below still holds — the digest is in the signed manifest and is checked twice —
		// but the CONFIDENTIALITY claim above it did not. "Which version a device is offered" stayed private per
		// device while the fleet's CURRENT build was retrievable by anyone who could reach the endpoint: an
		// unenrolled anonymous curl pulled 25,931,776 bytes on the lab. Whether a fleet is mid-rollout of a build
		// with public weaknesses is therefore not private either, and it is an unauthenticated 25MB egress
		// surface.
		//
		// ★ AND THE DEPLOYMENT COST WAS THE DECIDING ARGUMENT. The (T) listener REFUSES TO START in production
		// without mandatory mTLS — that is a premise, not a toggle — so an anonymous route can never live on it.
		// Corporate egress is effectively 443-only and 443 is one per address, so shipping the anonymous shape
		// meant a SECOND GLOBAL ADDRESS PER CUSTOMER. SNI-varied ClientAuth could dodge it only by relaxing the
		// guard that makes mTLS non-optional, which is not a fix.
		//
		// The stated reason the updater holds no network identity is fully preserved: the AGENT couriers these
		// bytes to disk, exactly as it already couriers the manifest and the plan, and the updater still only
		// reads a file. It is the agent that has a TLS stack and the device key, and it always did.
		if _, verified := transportDeviceIdentityFromRequest(r); !verified {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("a verified device transport identity is "+
				"required: this edge serves release bytes inside the tunnel, and the agent couriers them to "+
				"the updater"))
			return
		}
		if config.PublishedUpdates == nil {
			http.Error(w, "no agent updates are published by this edge", http.StatusNotFound)
			return
		}
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		arch := strings.TrimSpace(r.URL.Query().Get("arch"))
		if platform == "" || arch == "" {
			http.Error(w, "platform and arch query parameters are required", http.StatusBadRequest)
			return
		}
		u, ok := config.PublishedUpdates.forTarget(platform, arch)
		if !ok {
			http.Error(w, fmt.Sprintf("no agent update is published for %s/%s", platform, arch), http.StatusNotFound)
			return
		}

		// ★ The path is derived from the PUBLISHED MANIFEST, never from the request. platform, arch and version
		// all reach us as strings a caller controls; the only one that ends up in a filename is the version from
		// a manifest this Edge verified at load, and it is still checked for separators — a path is not a place
		// to be relaxed about an input that has been through one validation.
		name := artifactFileName(u.Manifest.Platform, u.Manifest.Arch, u.Manifest.Version)
		if name == "" {
			http.Error(w, "the published manifest names an artifact this edge will not serve", http.StatusInternalServerError)
			return
		}
		// The artifact is stored PER TENANT by the upload route, and this index is keyed only by platform/arch,
		// so the tenant comes from the published entry. The lookup falls back to the flat path, which is where
		// a manifest-directory deployment (no admin upload) still keeps its bytes — and, on a deployment whose
		// control planes share a shelf, to the shelf, so a node that never served the upload can still answer.
		path := publishedStoreOrEmpty(config.PublishedAgentUpdateStore).artifactPathFor(config.AgentUpdateArtifactDir, u.TenantID,
			u.Manifest.Platform, u.Manifest.Arch, u.Manifest.Version)
		if path == "" {
			path = filepath.Join(config.AgentUpdateArtifactDir, name)
		}

		f, err := os.Open(path)
		if err != nil {
			// Named at INFO on the Edge, because the operator who published the manifest is the only one who can
			// fix it, and every device will otherwise fail to stage with no explanation on this side.
			log.Printf("agent_update_artifact_missing platform=%s arch=%s version=%s path=%s: %v",
				platform, arch, u.Manifest.Version, path, err)
			http.Error(w, "the published manifest's artifact is not on this edge", http.StatusNotFound)
			return
		}
		defer f.Close()

		// ★ Verify before serving. An artifact whose digest does not match the manifest is a release mistake, and
		// it must fail on the machine that made it — not on every endpoint, each of which would download the
		// whole thing and then refuse it with a message about an untrusted package.
		//
		// ★ ONCE PER FILE, NOT ONCE PER REQUEST (2026-08-11, from a review). This route is deliberately
		// unauthenticated, and it used to hash the whole artifact on EVERY request — including a Range request
		// for one byte. Tens of megabytes of disk read per call, from anyone who can reach the port, in
		// parallel: the check that protects a release doubled as the cheapest way to exhaust an Edge.
		//
		// The result is cached against the file's identity (size and modification time), so a file REPLACED on
		// disk is re-verified rather than served on the strength of an old answer. That pairing is the point: a
		// cache keyed on the path alone would turn "verify before serving" into "verified once, long ago".
		// ★ THE FILE THAT IS VERIFIED IS THE FILE THAT IS SERVED (2026-08-11, third review). This used to hand
		// the PATH to the verifier, which opened it again — so an atomic replace between the two opens would
		// verify the new bytes and serve the old descriptor. The handle already open here is the only thing
		// that cannot be swapped underneath.
		size, verr := verifiedArtifactSizeFromFile(f, path, u.Manifest.ArtifactSHA256)
		if verr != nil {
			if errors.Is(verr, errArtifactDigestMismatch) {
				log.Printf("agent_update_artifact_DIGEST_MISMATCH platform=%s arch=%s version=%s path=%s "+
					"manifest=%s: %v — REFUSING to serve it; republish the manifest for these bytes",
					platform, arch, u.Manifest.Version, path, u.Manifest.ArtifactSHA256, verr)
				http.Error(w, "the artifact on this edge does not match the published manifest", http.StatusConflict)
				return
			}
			http.Error(w, "the artifact could not be read", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		// ★ SAY WHICH VERSION THESE BYTES ARE (2026-08-11, from a device that downloaded the wrong ones).
		//
		// This URL does not name a version — deliberately, so that nothing a caller controls selects a file. The
		// consequence is that a device whose manifest is one release behind (the courier refreshes every 15
		// minutes) downloads the CURRENT artifact, checks it against the OLD manifest, and refuses it with "the
		// downloaded artifact does not match the manifest".
		//
		// That sentence is what a substitution attack looks like. Attaching it to the ordinary minutes after a
		// release means an operator either investigates an attack that is not happening, or learns to ignore the
		// one message that would tell them about a real one. The header lets the endpoint say the true thing
		// instead: this Edge is serving X, this device holds a manifest for Y, refresh and try again.
		//
		// It is NOT authority — the digest in the signed manifest remains the only thing that decides whether
		// these bytes may run. A header is a hint for a human, and the check that protects the device is
		// unchanged.
		w.Header().Set(agentupdate.ArtifactVersionHeader, u.Manifest.Version)
		http.ServeContent(w, r, name, fileModTime(path), f)
	})
}

// errArtifactDigestMismatch separates "these are the wrong bytes" from "this disk did not cooperate": the
// first is a release mistake a person must fix, the second is a fault.
var errArtifactDigestMismatch = errors.New("the artifact does not match the published digest")

// verifiedArtifact remembers what was checked, and what it was checked about.
//
// ★ IDENTITY IS NOT size+mtime (2026-08-12, fourth review). A file replaced with one of the same length and
// the same timestamp — which a build tool, an rsync with -t, or anyone deliberate can produce — read as a
// cache hit, and this request's descriptor was served without ever being hashed. The inode and device pin it
// to the actual file: a replacement is a new inode, whatever its metadata says.
type verifiedArtifact struct {
	size    int64
	modTime time.Time
	inode   uint64
	device  uint64
	// ctime is the inode's change time, which an in-place rewrite moves and utimes cannot put back.
	//
	// ★ inode+mtime WAS STILL NOT ENOUGH (2026-08-12, fifth review). A replacement is a new inode, but an
	// OVERWRITE of the same file — rsync --inplace -t, a build writing over its output — keeps the inode and
	// can restore size and mtime. Every field matched and the old verification answered for new bytes. Devices
	// would still refuse them (the digest is checked on the endpoint), so the damage is a fleet that cannot
	// stage rather than one that runs the wrong code — and a fleet that cannot stage is still an outage.
	ctime  time.Time
	digest string
}

var (
	verifiedArtifactsMu sync.Mutex
	verifiedArtifacts   = map[string]verifiedArtifact{}
	// ★ ONE HASH AT A TIME PER FILE (2026-08-11, second review). Caching after the fact still let every
	// concurrent request on a COLD path observe a miss and read the same tens of megabytes at once — which is
	// the same unauthenticated I/O amplifier, narrowed to the moments right after a restart or a republish.
	// The second caller waits for the first rather than repeating its work.
	verifyingArtifacts = map[string]*sync.WaitGroup{}
)

// verifiedArtifactSizeFromFile hashes THIS descriptor the first time and, after that, only when the file it
// refers to is not the one that was hashed. The path is used solely as the cache key: identity comes from the
// open file, which nothing else can replace.
func verifiedArtifactSizeFromFile(f *os.File, path, wantDigest string) (int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	key := path
	verifiedArtifactsMu.Lock()
	cached, ok := verifiedArtifacts[key]
	verifiedArtifactsMu.Unlock()
	inode, device, ctime := fileIdentity(fi)
	if ok && cached.size == fi.Size() && cached.modTime.Equal(fi.ModTime()) &&
		cached.inode == inode && cached.device == device && cached.ctime.Equal(ctime) {
		if !strings.EqualFold(cached.digest, wantDigest) {
			return 0, fmt.Errorf("%w: file %s", errArtifactDigestMismatch, cached.digest)
		}
		return cached.size, nil
	}

	// Claim the hash, or wait for whoever already has it and then re-read the cache they filled.
	verifiedArtifactsMu.Lock()
	if wg, running := verifyingArtifacts[key]; running {
		verifiedArtifactsMu.Unlock()
		wg.Wait()
		return verifiedArtifactSizeFromFile(f, path, wantDigest)
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	verifyingArtifacts[key] = wg
	verifiedArtifactsMu.Unlock()
	defer func() {
		verifiedArtifactsMu.Lock()
		delete(verifyingArtifacts, key)
		verifiedArtifactsMu.Unlock()
		wg.Done()
	}()

	// Hashed from the START of the descriptor the caller will serve, and rewound afterwards so the caller finds
	// it where it left it.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	sum := sha256.New()
	size, err := io.Copy(sum, f)
	if err != nil {
		return 0, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	got := hex.EncodeToString(sum.Sum(nil))

	verifiedArtifactsMu.Lock()
	verifiedArtifacts[key] = verifiedArtifact{size: size, modTime: fi.ModTime(), inode: inode, device: device,
		ctime: ctime, digest: got}
	verifiedArtifactsMu.Unlock()

	if !strings.EqualFold(got, wantDigest) {
		return 0, fmt.Errorf("%w: file %s", errArtifactDigestMismatch, got)
	}
	return size, nil
}

// artifactFileName is the one place the layout is decided: <platform>-<arch>-<version>.<ext>. Returns "" for
// anything that could leave the directory or is not a shape we publish.
func artifactFileName(platform, arch, version string) string {
	ext := map[string]string{"darwin": "pkg", "windows": "msi"}[platform]
	if ext == "" {
		return ""
	}
	for _, part := range []string{platform, arch, version} {
		if part == "" || strings.ContainsAny(part, `/\`) || strings.Contains(part, "..") {
			return ""
		}
	}
	return fmt.Sprintf("%s-%s-%s.%s", platform, arch, version, ext)
}

func fileModTime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}
