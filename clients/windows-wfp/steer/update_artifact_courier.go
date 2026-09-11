// update_artifact_courier.go — the release package itself, carried inside the (T) tunnel.
//
// ★★ WHY THE AGENT CARRIES IT (2026-08-13, operator decision; macOS landed the same change in 23ba5e32).
// The updater used to fetch this itself, over plain https, from an endpoint that was deliberately anonymous.
// The INTEGRITY argument for that still holds — the digest is in the signed manifest, and the updater checks
// it when staging and again immediately before the installer runs — but two other things did not:
//
//   - Anyone who could reach the endpoint could retrieve the fleet's CURRENT build. Which device is offered
//     what stayed private; whether this fleet is mid-rollout of a version with public weaknesses did not.
//   - The (T) listener REFUSES TO START without mandatory mTLS (secure_transport.go: "mTLS device identity is
//     a system premise, not optional"). An anonymous route can therefore never live on it, so the artifact
//     needed a second listener — and on 443-only corporate egress that is a second global address per
//     customer, not a lab port number.
//
// The stated reason the updater holds no network identity is untouched. It still only reads a file. THIS
// process already holds the (T) transport and the device key, and always did, so nothing new is privileged.
//
// ★ AND THE BYTES GO WHERE THE UPDATER ALREADY LOOKS. updateplatform.Stage returns immediately when the
// staged file's digest already matches the manifest, so a couriered package needs no new code over there and
// no new trust: the same verification runs on the same bytes, at staging and again before launch, as before.
//
// Portable Go with no build tag, like update_courier.go: the decisions here — when to skip, what a version may
// be, what a failure keeps — are the content, and they must not go untested because the host was the wrong OS.
// The staged path is injected for the same reason.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// updateArtifactPath is the third steer route, and since 23ba5e32 it requires a verified transport identity
// exactly as the manifest and the plan do. A caller with no client certificate is answered 401.
const updateArtifactPath = "/steer/agent-update-artifact"

// maxArtifactBytes is the ceiling on a body whose length the Edge did not declare.
//
// It is NOT the ordinary bound — that is the Content-Length, checked below — and it exists only so a server
// that streams without end cannot fill the disk of a machine whose network this product is responsible for.
// An agent MSI is tens of megabytes; a gigabyte is three keystrokes of headroom and still a wall.
const maxArtifactBytes = 1 << 30

// artifactStageTimeout bounds one fetch. Long, because tens of megabytes over a home or hotel link is the
// ordinary case rather than the exception, and bounded because this runs in a goroutine that must come back.
const artifactStageTimeout = 30 * time.Minute

// artifactCourier fetches the release package over the (T) transport and leaves it where the updater looks.
//
// ★ A SEPARATE TYPE FROM signedDocCourier, and not for lack of trying to share. That type is built around
// properties this one must not have: a 1 MiB body bound, a whole-body read into memory, a JSON envelope check,
// and a destination fixed at construction. Here the body is a package, the destination is chosen by a header
// on the response, and there is nothing to parse. Sharing the shell would have meant making every one of those
// conditional, which is how the two couriers would have drifted in the dark.
type artifactCourier struct {
	client   *http.Client // wired to the (T) mTLS transport (transportHTTPClient)
	baseURL  string       // Edge base, e.g. https://<transport-host>
	platform string
	arch     string
	interval time.Duration
	logf     func(string, ...any)

	// stagedPath maps a version to the file the updater will look for. Injected because it is
	// updateplatform.StagedPath in the service and a temp directory in tests — and because that function is
	// where a version from the network meets rollbackstore.FileName, which is the validation this courier
	// deliberately does not reimplement.
	//
	// ★ THE NAME IS A CONTRACT, not a convenience. StagedPath asks rollbackstore for "dsse-agent-<version>.msi"
	// and looks nowhere else. A package written under any other name is one the updater never opens, so the
	// device would fetch tens of megabytes every pass and install nothing — silent, and indistinguishable from
	// a fleet that is simply up to date.
	stagedPath func(version string) (string, error)
}

// errArtifactNotPublished is the Edge saying this device has nothing to fetch. The normal answer for most
// devices most of the time, and returned as a value so the caller can stay quiet rather than log a fault.
var errArtifactNotPublished = errors.New("no artifact published for this device")

// refreshOnce fetches the artifact once and reconciles what is on disk.
//
// ★ NOTHING HERE DELETES A STAGED PACKAGE. The same rule the document couriers follow, for a different
// reason: a device may be holding a verified package while it waits days for its maintenance window, and a
// 404 — which an operator's mistyped directory produces as readily as a withdrawal — must not disarm it. The
// rollout plan's freeze is the signed way to stop a release, and it cannot be produced by a wrong file path.
func (a *artifactCourier) refreshOnce(ctx context.Context) error {
	base := strings.TrimRight(strings.TrimSpace(a.baseURL), "/")
	if base == "" {
		return errors.New("artifact courier: no Edge base URL")
	}
	url := fmt.Sprintf("%s%s?platform=%s&arch=%s", base, updateArtifactPath, a.platform, a.arch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("artifact courier: build request: %w", err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("artifact courier: fetch: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errArtifactNotPublished
	case resp.StatusCode == http.StatusUnauthorized:
		// ★ NAMED SEPARATELY BECAUSE IT IS THE NEW FAILURE, and it will be somebody's afternoon otherwise. Since
		// 23ba5e32 this route requires the transport identity; a 401 here means the request did not ride the (T)
		// tunnel, or this device's certificate is not one the Edge accepts. It is not a missing release, and the
		// repair is on the transport rather than in the publish lane.
		return fmt.Errorf("artifact courier: the edge refused this device's identity (HTTP 401) — release bytes "+
			"are served inside the (T) tunnel now, and this request did not present a certificate it accepts%s",
			agentupdate.DescribeHTTPErrorBody(resp.Body))
	case resp.StatusCode == http.StatusConflict:
		// The Edge verified its own artifact against the published manifest and refused to serve it. A release
		// mistake on the Edge, repaired there, and worth repeating here so it is visible from the device too.
		return fmt.Errorf("artifact courier: the edge is holding bytes that do not match its published manifest "+
			"(HTTP 409) — the release must be republished on the edge%s", agentupdate.DescribeHTTPErrorBody(resp.Body))
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("artifact courier: edge returned HTTP %d; keeping whatever is already staged%s",
			resp.StatusCode, agentupdate.DescribeHTTPErrorBody(resp.Body))
	}

	// ★ THE VERSION COMES FROM THE EDGE'S OWN HEADER, and this process parses no manifest. The header chooses
	// a FILENAME and nothing else; the updater then verifies the digest of whatever sits at that name against
	// the manifest it trusts with its own baked keys. A lying header therefore produces a file the updater
	// ignores, not a package it installs — which is why reading it here adds no authority.
	version := strings.TrimSpace(resp.Header.Get(agentupdate.ArtifactVersionHeader))
	if version == "" {
		return fmt.Errorf("artifact courier: the edge served a package without naming its version (%s), so there "+
			"is no name to stage it under; keeping whatever is already staged", agentupdate.ArtifactVersionHeader)
	}
	dst, err := a.stagedPath(version)
	if err != nil {
		// Refused, never repaired: a version that had to be sanitised to become a path is a version nobody
		// meant, and this one arrived from the network.
		return fmt.Errorf("artifact courier: the edge named version %q, which will not become a path on this "+
			"device: %w", version, err)
	}

	// ★ ALREADY STAGED IS THE COMMON CASE, and re-downloading it would be the expensive one. This loop runs on
	// the manifest's refresh interval, so without this check a device that is up to date pulls the whole
	// package every pass, forever — the fleet paying for its own idleness, and on the Edge's uplink.
	//
	// Size is a WEAK identity and is used only to skip work, never to approve bytes: the updater hashes the
	// file against the signed manifest regardless. A same-size file that is wrong is refused there, which is
	// the check that was always doing this job.
	if resp.ContentLength > 0 {
		if fi, serr := os.Stat(dst); serr == nil && fi.Size() == resp.ContentLength {
			return nil
		}
	}

	written, err := a.stage(dst, resp.Body, resp.ContentLength)
	if err != nil {
		return fmt.Errorf("artifact courier: %w", err)
	}
	a.logf("artifact courier: staged %s (%d bytes) for the updater", filepath.Base(dst), written)
	return nil
}

// stage streams the body to a temporary file beside dst and then replaces dst with it.
//
// ★ REPLACED, NOT DELETED-THEN-RENAMED, and this differs deliberately from courierWriteAtomic beside it. That
// function removes the destination first and documents the gap as acceptable, which it is for a MANIFEST: the
// updater reads an absent manifest as "nothing published" and does nothing. A package is not read that way.
// The updater hashes whatever it finds at the staged path, so a window in which that path holds nothing — or
// half a file — is a window in which a healthy device reports a package it will refuse.
//
// MEASURED ON THIS BOX (2026-08-13), because the neighbouring comment asserts the opposite: os.Rename onto an
// existing CLOSED file succeeds on Windows (it is MoveFileEx with MOVEFILE_REPLACE_EXISTING). It fails with
// "Access is denied" while another process holds the destination open — which is exactly the updater hashing
// it — and that failure is the RIGHT one: the temporary file is discarded and the previously staged package
// is left intact, so the next pass tries again against a file that was never damaged.
func (a *artifactCourier) stage(dst string, body io.Reader, declared int64) (int64, error) {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("create %s: %w", dir, err)
	}
	// Same directory as the destination: a rename across volumes is not atomic, and the staging root and the
	// system temp directory are not guaranteed to share one. Prefixed rather than suffixed so a reader looking
	// for dsse-agent-*.msi never matches a partial file.
	tmp, err := os.CreateTemp(dir, ".artifact-*.partial")
	if err != nil {
		return 0, fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Removed on every path that does not reach the rename. After a successful rename the name is gone and
	// this is a no-op.
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	// Bounded by what the Edge declared, plus one byte so an oversized body is DETECTED rather than silently
	// truncated into something that then fails the updater's digest check for a misleading reason. A body with
	// no declared length falls back to the ceiling.
	limit := declared
	if limit <= 0 {
		limit = maxArtifactBytes
	}
	written, err := io.Copy(tmp, io.LimitReader(body, limit+1))
	if err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}
	if written > limit {
		return 0, fmt.Errorf("the edge served more than the declared %d bytes; refusing it", limit)
	}
	if declared > 0 && written != declared {
		// A short read is a truncated transfer. Caught here rather than left for the updater, which would
		// report it as a digest mismatch — the sentence that is supposed to mean "artefacts are being
		// substituted, look tonight".
		return 0, fmt.Errorf("the edge declared %d bytes and sent %d; keeping whatever is already staged",
			declared, written)
	}
	// Sync before the rename, or the directory entry can reach disk ahead of the contents — the torn file this
	// whole function exists to prevent, appearing only on the box that lost power while updating.
	if err := tmp.Sync(); err != nil {
		return 0, fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return 0, fmt.Errorf("place %s: %w", dst, err)
	}
	return written, nil
}

// run polls until the context is cancelled. The first pass happens immediately, for the same reason the
// document couriers do it: a device that has just started is the one most likely to be behind.
func (a *artifactCourier) run(ctx context.Context) {
	tick := func() {
		c, cancel := context.WithTimeout(ctx, artifactStageTimeout)
		defer cancel()
		if err := a.refreshOnce(c); err != nil {
			if errors.Is(err, errArtifactNotPublished) {
				return // the quiet, normal case
			}
			a.logf("%v", err)
		}
	}
	tick()
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
