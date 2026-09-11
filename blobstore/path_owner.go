package blobstore

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Per-node state must not live on a shared mount, and this is how a node finds out that it does.
//
// ★ THE MEASURED FAILURE, TWICE (2026-08-12 and 2026-08-15). These stores are written by the node that holds
// them, and a reference topology gave several Edges the same bind-mounted path. The first time, an enrolment
// recorded by one node was erased by another saving an older snapshot, and a spent device identity could be
// spent again. The second time, two Edges shared the admin runtime state and the enrolled inventory, and
// config distribution simply STOPPED on one of them: it could not save what it had applied, so its generation
// never advanced, and the symptom was "this Edge is permanently behind" with nothing naming the cause. It
// took a manual comparison of generations across nodes to find it.
//
// SingleWriterFilePersister already refuses to overwrite a change it did not make, which turns the silent
// lost write into an error — but only for the one store it was applied to, and only once the damage is being
// attempted. Its own comment says it "cannot tell one bind-mounted path from another".
//
// This can, because it writes down WHO. Each node stamps <path>.owner with its own id and refreshes that
// stamp whenever it saves. A node starting up against a path another LIVE node owns refuses, naming both
// nodes and the path. A stamp that has gone stale — the previous owner is gone — is taken over, and that
// takeover is reported rather than done in silence, because "this node used to be somewhere else" is exactly
// the kind of fact that explains an incident three weeks later.
type pathOwnerStamp struct {
	NodeID      string `json:"node_id"`
	ClaimedAt   string `json:"claimed_at"`
	RefreshedAt string `json:"refreshed_at"`
}

// OwnershipStaleAfter is how long a stamp survives without a refresh before another node may take the path.
//
// Generous on purpose. Too short and a node that is merely idle — one whose stores have not changed, which is
// the normal state of a healthy deployment — loses its own path to a neighbour. Too long and recovering a
// genuinely dead node's path needs an operator. The cost of the two mistakes is not symmetric: wrongly
// stealing a live node's store is the very corruption this exists to prevent, while waiting is only slow.
const OwnershipStaleAfter = 30 * time.Minute

// ErrPathOwnedByAnotherNode reports that a live node already owns this path.
var ErrPathOwnedByAnotherNode = fmt.Errorf("this state path belongs to another node")

// ClaimPath takes ownership of a state path for nodeID, or refuses if another live node holds it.
//
// Returns the taken-over stamp (if any) so the caller can say so out loud. An unreadable or absent stamp is
// not an error: a first boot has no stamp, and a corrupt one is not evidence that somebody else is live.
func ClaimPath(path, nodeID string, now time.Time) (previous string, err error) {
	path = strings.TrimSpace(path)
	nodeID = strings.TrimSpace(nodeID)
	if path == "" || nodeID == "" {
		return "", nil // nothing to protect, or nobody to protect it for
	}
	stampPath := path + ".owner"
	if raw, rerr := os.ReadFile(stampPath); rerr == nil {
		var stamp pathOwnerStamp
		if json.Unmarshal(raw, &stamp) == nil && strings.TrimSpace(stamp.NodeID) != "" &&
			!strings.EqualFold(strings.TrimSpace(stamp.NodeID), nodeID) {
			refreshed, perr := time.Parse(time.RFC3339, strings.TrimSpace(stamp.RefreshedAt))
			if perr == nil && now.Sub(refreshed) < OwnershipStaleAfter {
				// ★ THE PATH IS DELIMITED BUT NOT ESCAPED (2026-08-16, measured on win-dev-1). This was %q, and on
				// Windows %q escapes the separators: an operator was handed
				// "C:\\Users\\...\\001\\enrolled_inventory.json" and could not paste it anywhere. The whole point of
				// naming the path is that somebody goes and looks at it. Quotes still delimit it, so a path with
				// spaces is still unambiguous; the node id keeps %q because it is an identifier, where escaping is
				// harmless and quoting is the only job.
				//
				// It also made the test unpassable on this platform for a reason that had nothing to do with the
				// behaviour under test: the assertion looks for the path it passed in, and no raw Windows path can
				// appear inside %q output.
				return "", fmt.Errorf("%w: \"%s\" is owned by node %q (last refreshed %s). Per-node state must not "+
					"be on a shared mount — two nodes writing one store lose each other's writes, and the symptom "+
					"is a node that silently stops applying config rather than an error",
					ErrPathOwnedByAnotherNode, path, stamp.NodeID, stamp.RefreshedAt)
			}
			previous = stamp.NodeID
		}
	}
	// A stamp that cannot be written is NOT a reason to fail. This is a diagnosis aid, and a diagnosis aid
	// that can stop the thing it diagnoses from starting is a worse bug than the one it finds — the path may
	// not exist yet on first boot, or may be created by the store itself at its first save. The only fatal
	// case is the one above: a live node already owns it.
	if werr := writeOwnerStamp(stampPath, pathOwnerStamp{
		NodeID:      nodeID,
		ClaimedAt:   now.UTC().Format(time.RFC3339),
		RefreshedAt: now.UTC().Format(time.RFC3339),
	}); werr != nil {
		log.Printf("state path %q: could not record this node's ownership stamp (%v). The store still works; "+
			"what is lost is the ability to NAME the other node if this path is ever shared.", path, werr)
	}
	return previous, nil
}

// RefreshPathOwnership re-stamps the path as still owned by nodeID. Best-effort: a failure here must never
// fail the save it accompanies, because the stamp is a diagnosis aid and the data is the point.
func RefreshPathOwnership(path, nodeID string, now time.Time) {
	path, nodeID = strings.TrimSpace(path), strings.TrimSpace(nodeID)
	if path == "" || nodeID == "" {
		return
	}
	stampPath := path + ".owner"
	claimed := now.UTC().Format(time.RFC3339)
	if raw, err := os.ReadFile(stampPath); err == nil {
		var stamp pathOwnerStamp
		if json.Unmarshal(raw, &stamp) == nil && strings.TrimSpace(stamp.ClaimedAt) != "" {
			claimed = stamp.ClaimedAt
		}
	}
	_ = writeOwnerStamp(stampPath, pathOwnerStamp{
		NodeID:      nodeID,
		ClaimedAt:   claimed,
		RefreshedAt: now.UTC().Format(time.RFC3339),
	})
}

func writeOwnerStamp(stampPath string, stamp pathOwnerStamp) error {
	data, err := json.Marshal(stamp)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(stampPath); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	tmp := stampPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, stampPath)
}

// OwnedFilePersister is a FilePersister that keeps its path's ownership stamp fresh as it writes.
type OwnedFilePersister struct {
	File   FilePersister
	NodeID string
	Now    func() time.Time
}

func (p OwnedFilePersister) Load() ([]byte, error) { return p.File.Load() }

func (p OwnedFilePersister) Save(data []byte) error {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	RefreshPathOwnership(p.File.Path, p.NodeID, now())
	return p.File.Save(data)
}
