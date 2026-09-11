// staging.go — getting the artifact onto disk, verified, before anything is allowed to run it.
//
// agentupdate.Run does not fetch anything. It calls Execute, which expects the package to already be at
// StagedPath — so this is the step between "the manifest says 0.2.0" and "an installer may be launched", and
// it is the last place a wrong or tampered payload can be stopped for free.
//
// THE ORDERING IS THE SECURITY PROPERTY. The bytes are verified BEFORE they occupy the path Execute will hand
// to msiexec. Downloading straight to that path and verifying afterwards leaves a window — a crash, a power
// loss, a killed service — in which an unverified file is sitting exactly where a privileged install will look
// for it, and the next tick would find it "already staged". Same-directory temp then rename means the real
// name only ever appears on a file that has already passed.
//
// Verification reads the file back FROM DISK rather than hashing the stream on the way past. It is one extra
// pass over tens of megabytes and it answers the question that matters: not "did the right bytes arrive" but
// "are the right bytes what is now on disk". A truncated write, a full disk, or a filesystem that lost the
// tail would otherwise pass a stream check and fail an install.
package updateplatform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/datadir"
)

// stageTimeout bounds a single fetch. Generous because an agent MSI is tens of megabytes and endpoints are on
// home links, but bounded because this runs inside a service tick: a download that never finishes must
// not become a service that never ticks again.
const stageTimeout = 30 * time.Minute

// ErrDeliveryNotOurs is returned for a manifest whose payload someone else delivers.
//
// Under MDM delivery the management system already holds the package and DSSE never downloads it, so an
// updater that "helpfully" fetched it anyway would be a second, unmanaged download path for a privileged
// install — the exact thing the delivery mode exists to prevent.
var ErrDeliveryNotOurs = errors.New("updateplatform: this manifest is delivered by MDM; DSSE does not fetch it")

// Stage fetches the artifact for m, verifies it, and places it where Execute will look. It returns the staged
// path.
//
// It is idempotent and cheap on repeat: a tick loop calls this every time it is waiting for a maintenance
// window, so an already-staged, still-verifying package is returned without touching the network. That check
// re-verifies rather than trusting the file name, because a name is not a digest and the interval between
// staging and installing can be days.
func Stage(ctx context.Context, client *http.Client, m agentupdate.Manifest) (string, error) {
	if m.Delivery == agentupdate.DeliveryMDM {
		return "", ErrDeliveryNotOurs
	}
	if m.ArtifactURL == "" {
		return "", errors.New("updateplatform: manifest has no artifact URL")
	}
	dst, err := StagedPath(m.Version)
	if err != nil {
		return "", err
	}

	if err := verifyFile(dst, m); err == nil {
		return dst, nil
	}

	// Through datadir rather than a bare MkdirAll: %ProgramData% grants BUILTIN\Users write (measured on
	// win-dev-1), and a plain MkdirAll inherits it — into the directory holding the package msiexec is about to
	// run as SYSTEM. Whichever of the three components gets here first decides that, so all three go through
	// the same door. VerifyStaged still re-checks the digest at launch; that detects a substitution and this
	// prevents one, and neither should be the only half.
	if st, derr := datadir.Ensure(); derr != nil {
		return "", derr
	} else if d := st.Describe(); d != "" {
		log.Print(d)
	}
	if err := os.MkdirAll(StagedRoot(), 0o755); err != nil {
		return "", fmt.Errorf("updateplatform: create %s: %w", StagedRoot(), err)
	}
	tmp, err := os.CreateTemp(StagedRoot(), "staging-*.partial")
	if err != nil {
		return "", fmt.Errorf("updateplatform: create temp in %s: %w", StagedRoot(), err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if client == nil {
		client = &http.Client{}
	}
	ctx, cancel := context.WithTimeout(ctx, stageTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.ArtifactURL, nil)
	if err != nil {
		return "", fmt.Errorf("updateplatform: build request for %s: %w", m.ArtifactURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("updateplatform: fetch %s: %w", m.ArtifactURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// ★ THE BODY IS THE DIFFERENCE BETWEEN TWO 404s, and the endpoint is where somebody is standing when they
		// need it (2026-08-11, measured while deliberately breaking this path). An Edge that PREDATES the artifact
		// route answers with net/http's own "404 page not found"; an Edge that has the route but is missing the
		// file answers "the published manifest's artifact is not on this edge". Same status, different repair —
		// rebuild the Edge, or put the package where the manifest says it is.
		//
		// Dropping the body made those identical on the device, and I misread exactly that pair today: I recorded
		// a stale Edge as a successful test of a missing artifact. A status code alone is not a diagnosis.
		//
		// Bounded and whitespace-collapsed: this is an error message, and an origin that answers a megabyte of
		// HTML to a failed fetch must not get to write a megabyte into an endpoint's log.
		return "", fmt.Errorf("updateplatform: fetch %s: HTTP %d%s", m.ArtifactURL, resp.StatusCode,
			agentupdate.DescribeHTTPErrorBody(resp.Body))
	}

	// Bounded by the manifest's own declared size, plus one byte so an oversized body is DETECTED rather than
	// silently truncated into something that then fails a digest check for a misleading reason. Without the
	// bound, a server that streams forever fills the endpoint's disk — and this runs as SYSTEM on a machine
	// whose network is this product's responsibility.
	limit := m.ArtifactSize
	if limit <= 0 {
		return "", errors.New("updateplatform: manifest declares no artifact size; refusing an unbounded download")
	}
	written, err := io.Copy(tmp, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", fmt.Errorf("updateplatform: download %s: %w", m.ArtifactURL, err)
	}
	if written > limit {
		return "", fmt.Errorf("updateplatform: %s served more than the declared %d bytes", m.ArtifactURL, limit)
	}
	if err := tmp.Sync(); err != nil {
		return "", fmt.Errorf("updateplatform: sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("updateplatform: close %s: %w", tmpName, err)
	}

	// Verified while it is still called *.partial and therefore still un-runnable by Execute.
	if err := verifyFile(tmpName, m); err != nil {
		// ★ A STALE MANIFEST IS NOT AN ATTACK, and must not be reported in an attack's words. The artifact URL
		// carries no version, so a device whose courier has not refreshed downloads whatever the Edge publishes
		// NOW and checks it against the release it still holds. Measured on a live Mac fifteen minutes after a
		// publication: "the downloaded artifact does not match the manifest", which is exactly what a
		// substitution looks like, for the most ordinary reason there is.
		if served := strings.TrimSpace(resp.Header.Get(agentupdate.ArtifactVersionHeader)); served != "" &&
			!agentupdate.SameVersion(served, m.Version) {
			return "", fmt.Errorf("%w — this edge is serving %s and this device holds a manifest for %s, so these "+
				"are the wrong bytes rather than tampered ones; the manifest refreshes on its own and the next "+
				"attempt will match", err, served, m.Version)
		}
		return "", err
	}

	// os.Rename onto an existing name fails on Windows, and reaching here means whatever was there did not
	// verify, so removing it is the point rather than a risk.
	_ = os.Remove(dst)
	if err := os.Rename(tmpName, dst); err != nil {
		return "", fmt.Errorf("updateplatform: place %s: %w", dst, err)
	}
	return dst, nil
}

// verifyFile checks a file on disk against the manifest's digest and size.
func verifyFile(path string, m agentupdate.Manifest) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := agentupdate.VerifyArtifact(f, m); err != nil {
		return fmt.Errorf("updateplatform: %s does not match the manifest: %w", filepath.Base(path), err)
	}
	return nil
}

// ClearStaged removes a staged package. Call it once the version is installed, or when a manifest is
// superseded: a staged artifact is a privileged install waiting to happen, and leaving supplanted ones on
// disk widens the window in which one could be run by something other than this updater.
func ClearStaged(version string) error {
	p, err := StagedPath(version)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("updateplatform: remove staged %s: %w", p, err)
	}
	return nil
}

// VerifyStaged re-checks the staged package against the manifest and returns its path, and is meant to be
// called IMMEDIATELY before the installer is launched.
//
// ★ Why a second check, when Stage already verified these exact bytes. Because the two events can be days
// apart, and deliberately so: an artifact is staged as soon as it is applicable, and executed when the
// maintenance window opens, precisely so a two-hour night window is not spent downloading. Everything Stage
// established is a statement about the past by then.
//
// What sits in the gap is a file under %ProgramData%\DSSE\staged whose full path is derived from a public
// version string, which will shortly be handed to msiexec running as SYSTEM. The digest is the only thing that
// makes substitution in that window detectable, and checking it costs one pass over a file the installer is
// about to read anyway — against an install of somebody else's package with our privileges.
//
// It is NOT a replacement for the directory's permissions, and reading it as one would be the mistake: this
// detects, it does not prevent. Preventing is the ACL's job.
func VerifyStaged(m agentupdate.Manifest) (string, error) {
	p, err := StagedPath(m.Version)
	if err != nil {
		return "", err
	}
	if err := verifyFile(p, m); err != nil {
		return "", fmt.Errorf("refusing to launch the installer for %s: %w", m.Version, err)
	}
	return p, nil
}
