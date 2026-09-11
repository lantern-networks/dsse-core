package agentupdate

// report.go — how an update outcome LEAVES the device.
//
// ★ WHY THIS EXISTS (2026-08-12). Every mechanism in this package worked on the lab Mac — the first real
// update, six failure modes, a rollback and its poison — and the control plane's fleet view said
// `total: 0`. The ingest route existed (`POST /devices/{id}/agent-updates`); nothing on either platform ever
// called it. An operator watching the Console had no way to tell a fleet that updated cleanly from one where
// the updater had never run, which is the same "absence reads as success" family this session keeps finding,
// on the one screen an operator would actually look at.
//
// ★ AND WHY IT IS AN OUTBOX RATHER THAN AN HTTP CALL. The updater holds NO network identity, deliberately: it
// runs as root, launches installers, and giving it the device's (T) client certificate would put the credential
// that proves this machine's identity inside the process most likely to be replaced mid-execution. So the
// updater writes what happened, and the component that already holds the identity and already beats on a timer
// — DsseSteer on Windows, the network extension on macOS — sends it. Neither side gains a capability it did
// not already have.
//
// ★ AND WHY A DIRECTORY OF EVENTS RATHER THAN "REPORT THE CURRENT STATE". A snapshot reported on a heartbeat
// loses every transition between two beats: a device that fails an update, retries and succeeds within fifteen
// minutes would report one success, and the failure — the thing worth knowing — never happened as far as the
// fleet is concerned. Completeness outranks tidiness here.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lantern-networks/dsse-core/durablefile"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Report statuses. These are the values the Edge's AgentUpdateEvent.UpdateStatus carries, so they are the
// vocabulary an operator ends up reading.
const (
	ReportInstalled  = "installed"   // the target version is running
	ReportFailed     = "failed"      // the attempt ended and the device is not on the target
	ReportRolledBack = "rolled_back" // a deliberate return to an earlier version, and it landed
	ReportRefused    = "refused"     // nothing was attempted, and WHY is the point of the record
)

// Report is one terminal update event, as the device saw it.
//
// DeviceID and TenantID are written by the updater from the runtime marker when it can read them, and the
// SENDER overrides them from its own verified client certificate. The sender's copy is authoritative: it is
// the one backed by a certificate the Edge checked, and a device that mis-identifies itself in a fleet report
// is worse than one that does not report.
type Report struct {
	ID             string `json:"id"`
	DeviceID       string `json:"device_id,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
	FromVersion    string `json:"from_version,omitempty"`
	TargetVersion  string `json:"target_version,omitempty"`
	RunningVersion string `json:"running_version,omitempty"`
	Status         string `json:"status"`
	// Kind separates an update from a rollback. Both record a target and both are confirmed the same way, and
	// "this device is on 0.2.4" means the release landed in one case and had to be undone in the other.
	Kind string `json:"kind,omitempty"`
	// Platform is what this endpoint IS (darwin | windows), so the control plane can tell which release applies
	// to it.
	//
	// ★ THE CP COULD NOT ANSWER "IS THIS MACHINE CURRENT" WITHOUT IT (2026-08-12). Its enrolment ledger carries
	// no platform and its device runtime store is an Edge's, so the per-device view had to say "this control
	// plane does not know this device's platform" — true, and useless to the operator reading the row. The
	// device knows; it costs one field to say so.
	Platform string `json:"platform,omitempty"`
	// Arch is what this endpoint RUNS ON (arm64 | amd64), and it is a separate fact from Platform.
	//
	// ★ THE EDGE WAS GUESSING IT FROM THE PLATFORM (2026-08-12, fourteenth review): macOS meant arm64 and
	// Windows meant amd64. Intel Macs and Windows-on-ARM exist, and for those the per-device view compared the
	// device against a release built for a different machine — reporting "no release is published" for one
	// that is, or worse, "up to date" against a version it can never run. A release target is keyed by
	// platform AND arch; only one of the two was coming from the device that knows.
	Arch           string `json:"arch,omitempty"`
	Channel        string `json:"channel,omitempty"`
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
	Reason         string `json:"reason,omitempty"`
	At             string `json:"at"`
	// DroppedBefore is how many earlier reports this device threw away to stay inside its cap, attached to the
	// first report that gets out afterwards. A device offline long enough to overflow must not come back with a
	// tidy history that silently begins in the middle.
	DroppedBefore int `json:"dropped_before,omitempty"`

	// Fingerprint is set on a REFUSAL and never crosses the wire. It travels from the code that decided the
	// refusal to the code that writes the outbox, so the suppression marker can be written by whoever actually
	// performs the durable append — the marker must never be written by someone who is not the one storing the
	// report. See AppendRefusal.
	Fingerprint string `json:"-"`

	// RejectedDigest is the sha256 of the document this refusal is ABOUT, when there is no version to name it
	// by — an unverifiable manifest supplies no version a device may believe.
	RejectedDigest string `json:"rejected_digest,omitempty"`
}

// reportSeq makes every id unique even when several outcomes are produced from ONE timestamp.
//
// ★ A TICK CAN PRODUCE TWO (2026-08-12, seventh review). now is captured once per pass and handed to every
// report it makes — so a pass that reconciles a completed update AND then refuses the next release built both
// from the same nanosecond: same id, same file name, and the second AppendReport renamed over the first. One
// of the two outcomes simply vanished, and the survivor would also be deduplicated by the Edge if it ever got
// there. The counter is process-local, which is enough: two processes writing the same nanosecond is already
// prevented by the device lock.
var reportSeq atomic.Uint64

// ★ THE ID IS THE ORDER, SO IT HAS TO SORT (2026-08-12, sixteenth review). Both fields were written with
// plain %d, so two reports from the same tick — identical nanosecond, consecutive counter — produced
// `…_9` and `…_10`, and every consumer of this directory sorts the names as TEXT: DrainReports ships in that
// order, pruneReports drops the "oldest" in that order, and the Edge's newest-wins tie-break inherits it. `_9`
// shipped last, so it arrived last, so it was recorded last, so it was served as the current outcome. On a
// device that failed and then rolled back within one pass, that is the wrong half of the story reaching the
// fleet view — and it survived one fix already, because the tie-break was corrected at the DATABASE while the
// order the records arrived in was still reversed.
//
// Fixed width makes lexicographic order and creation order the same thing. 19 digits covers UnixNano until
// 2262; 9 covers a counter that resets every process start.
func newReportID(now time.Time) string {
	return fmt.Sprintf("aue_%019d_%09d", now.UTC().UnixNano(), reportSeq.Add(1))
}

// reportIDOrder is (nanosecond, counter) parsed out of a report id, and ok=false for anything that is not one.
// It exists for the files an EARLIER build wrote with unpadded fields: those are already on devices, and a
// device that upgrades with a backlog must not ship them in the wrong order on the way out.
func reportIDOrder(name string) (int64, int64, bool) {
	// ★ IT WAS PARSING A FILENAME THAT DOES NOT EXIST (2026-08-12, seventeenth review). AppendReport writes
	// `<timestamp>-aue_<nano>_<seq>.json`, so splitting the whole name on "_" never yields "aue" first: the
	// function returned ok=false for every real file, the sort silently fell back to text, and the ordering
	// this was written to fix carried on happening for exactly the backlog it was written for. My test passed
	// because I hand-wrote the fixture — the same mistake, in the same session, for the third time. The
	// fixtures below are produced by AppendReport now.
	base := strings.TrimSuffix(name, ".json")
	if cut := strings.LastIndex(base, "-aue_"); cut >= 0 {
		base = base[cut+1:]
	}
	parts := strings.Split(base, "_")
	if len(parts) != 3 || parts[0] != "aue" {
		return 0, 0, false
	}
	nano, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	seq, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return nano, seq, true
}

// maxStoredReports bounds the directory on a device that cannot reach its Edge.
//
// A device offline for a month must not fill its disk with its own update history, and it must not silently
// forget that it did: when the cap is hit the OLDEST are dropped and the drop is recorded in the next report
// that goes out, so the gap is visible to the operator rather than inferred from a suspiciously tidy timeline.
const maxStoredReports = 200

// ReportsDir is where reports wait, beside the journal they came from.
func ReportsDir(journalPath string) string {
	return filepath.Join(filepath.Dir(journalPath), "reports")
}

// AppendReport records one terminal outcome. Best-effort by contract: a device that cannot write a report has
// still performed the update, and failing the update over its bookkeeping would be the worse trade.
func AppendReport(dir string, r Report) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("no reports directory")
	}
	if strings.TrimSpace(r.At) == "" {
		return fmt.Errorf("a report with no timestamp cannot be ordered")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create the reports directory: %w", err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// The name carries the timestamp so the drain is ordered by it without opening anything, and the id so two
	// events in the same second cannot collide.
	name := fmt.Sprintf("%s-%s.json", strings.ReplaceAll(r.At, ":", ""), sanitiseReportID(r.ID))
	// ★ THE SHARED DURABLE WRITE, NOT A SIXTH COPY OF IT (2026-08-14, thirty-first review #12). This staged its
	// own temporary file — create, write, flush, close, chmod, replace — which is durablefile.Write spelled out
	// by hand, down to setting the mode BEFORE the file becomes visible. Only the replace half had been
	// borrowed, so the package that exists to be the one implementation was being used as a helper by a copy of
	// itself.
	//
	// This is the write with the worst consequence, which is why it was the one singled out on 2026-08-12: the
	// CALLER acts on it. A successful AppendReport is what clears the pending marker, durably — lose this
	// directory entry to a power cut and the journal says the outcome was reported while the outbox holds
	// nothing, and nothing ever produces it again. Every property that makes that safe now comes from the same
	// place the other writers get it, rather than from a copy that has to be remembered separately.
	if werr := durablefile.Write(filepath.Join(dir, name), b, 0o600); werr != nil {
		return werr
	}
	pruneReports(dir)
	return nil
}

// DrainReports hands each stored report to send, oldest first, and deletes the ones it accepted.
//
// It STOPS at the first send error and keeps everything from there on. Order is the point: an operator reading
// "failed, then installed" learns something different from "installed, then failed", and a drain that skipped
// past a report the Edge refused would reorder the fleet's view of what happened on this device.
//
// A report whose file cannot be parsed is removed and counted: it is one lost event, and leaving it in place
// would block every later report behind it forever.
func DrainReports(dir string, send func(Report) error) (sent, corrupt int, err error) {
	names, lerr := reportFiles(dir)
	if lerr != nil {
		return 0, 0, lerr
	}
	dropped, droppedClaim, _ := ClaimDropped(dir)
	deliveredDrop := false
	defer func() { ReleaseDropped(dir, droppedClaim, deliveredDrop) }()
	for _, name := range names {
		path := filepath.Join(dir, name)
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return sent, corrupt, rerr
		}
		var r Report
		if jerr := json.Unmarshal(raw, &r); jerr != nil {
			corrupt++
			_ = os.Remove(path)
			continue
		}
		if dropped > 0 {
			r.DroppedBefore = dropped
		}
		if serr := send(r); serr != nil {
			return sent, corrupt, serr
		}
		if dropped > 0 {
			// Discarded only once a report CARRYING the count has actually been accepted.
			deliveredDrop = true
			dropped = 0
		}
		if rmErr := os.Remove(path); rmErr != nil {
			// Delivered but not removed: stop rather than risk sending it forever on every beat.
			return sent, corrupt, fmt.Errorf("report %s was delivered and could not be removed (%w): stopping so "+
				"it is not sent repeatedly", name, rmErr)
		}
		sent++
	}
	return sent, corrupt, nil
}

// PendingReports is how many are waiting, for a status line that would otherwise have to guess.
func PendingReports(dir string) int {
	names, err := reportFiles(dir)
	if err != nil {
		return 0
	}
	return len(names)
}

func reportFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") ||
			e.Name() == "dropped.json" || e.Name() == "dropped.json.claimed" || e.Name() == "dropped.lock" {
			continue
		}
		names = append(names, e.Name())
	}
	// Oldest first, by what the id MEANS rather than by how it renders. A plain string sort is correct for the
	// padded ids this build writes and wrong for the ones earlier builds left behind, and both are present on a
	// device that has just upgraded with a backlog.
	sort.Slice(names, func(i, j int) bool {
		ni, si, oki := reportIDOrder(names[i])
		nj, sj, okj := reportIDOrder(names[j])
		if !oki || !okj {
			return names[i] < names[j]
		}
		if ni != nj {
			return ni < nj
		}
		return si < sj
	})
	return names, nil
}

func pruneReports(dir string) {
	names, err := reportFiles(dir)
	if err != nil || len(names) <= maxStoredReports {
		return
	}
	dropped := 0
	for _, name := range names[:len(names)-maxStoredReports] {
		if rerr := os.Remove(filepath.Join(dir, name)); rerr == nil {
			dropped++
		}
	}
	if dropped > 0 {
		_ = addDropped(dir, dropped)
	}
}

// droppedPath holds the count of reports this device threw away. It is a separate file rather than a field in
// one of the reports because the reports it is counting are exactly the ones that are gone.
func droppedPath(dir string) string { return filepath.Join(dir, "dropped.json") }

// addDropped increases the ledger, under the SAME cross-process lock the sender takes.
//
// ★ THE UPDATER AND THE SENDER ARE DIFFERENT PROCESSES (2026-08-12, ninth review). This was a read-modify-write
// with nothing around it: a prune adding drops while the sender restored an undelivered claim (also an
// addition) meant one of the two increments was simply overwritten. The claim-by-rename fixed the CLAIM and
// left the arithmetic beside it unprotected.
//
// The lock is the same primitive the device update lock uses, on a file beside the ledger. Failing to take it
// does not skip the update — a ledger that under-counts is better than one that stops counting — but it is
// the only path here that proceeds without exclusion, and it says so.
func addDropped(dir string, n int) error {
	lock, err := lockLedger(dir)
	if err != nil {
		return err
	}
	defer lock.Release()
	return addDroppedLocked(dir, n)
}

// lockLedger takes the cross-process ledger lock, WAITING for it.
//
// ★ IT USED TO PROCEED WITHOUT ONE (2026-08-12, ninth review). LockDevice is non-blocking by design — the
// update path wants "somebody else is deciding right now, try again" rather than a queue behind a
// thirty-minute daemon. So `if err == nil { defer release }` meant that whenever another process held it, this
// went ahead unlocked: unprotected in precisely the contention the lock exists for, and protected only when
// nothing else was there.
//
// Here the right answer IS to wait. The ledger is a counter, the hold is microseconds, and the two processes
// that touch it (the updater's prune, the sender's restore) are not competing for a device — they are both
// adding to a number that must not lose an increment.
func lockLedger(dir string) (*DeviceLock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(ledgerLockWait)
	for {
		lock, err := LockDevice(droppedLockPath(dir))
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, ErrLocked) || time.Now().After(deadline) {
			return nil, fmt.Errorf("take the drop-ledger lock: %w", err)
		}
		time.Sleep(ledgerLockPoll)
	}
}

const (
	// ledgerLockWait bounds the wait so a stuck holder cannot hang a heartbeat. Generous next to a hold that is
	// a read, an add and a write.
	ledgerLockWait = 2 * time.Second
	ledgerLockPoll = 5 * time.Millisecond
)

func addDroppedLocked(dir string, n int) error {
	total := readDropped(dir) + n
	b, err := json.Marshal(map[string]int{"dropped": total})
	if err != nil {
		return err
	}
	return os.WriteFile(droppedPath(dir), b, 0o600)
}

// droppedLockPath guards every read-modify-write of the ledger. Beside it, and never removed: removing a lock
// file is how two processes end up locking two different inodes and both proceeding.
func droppedLockPath(dir string) string { return filepath.Join(dir, "dropped.lock") }

// ClaimDropped takes the current count and RENAMES the ledger out of the way in one step, so a producer that
// adds to it while a report is in flight cannot have its additions erased.
//
// ★ CLEARING BY DELETION LOST DROPS (2026-08-12, seventh review). The sender read the count, spent a network
// round trip, and then removed the whole file — so any drop recorded in between vanished with it. The other
// ordering re-reports drops already accounted for. Claiming by rename means the producer's next addition
// starts a NEW ledger, and the claimed one is either delivered (discarded) or returned (restored).
func ClaimDropped(dir string) (n int, claim string, err error) {
	// Held across the recover-and-rename pair, so a producer cannot add between them — and WAITED for, because
	// the contended case is the only one that needs it.
	lock, lerr := lockLedger(dir)
	if lerr != nil {
		return 0, "", lerr
	}
	defer lock.Release()
	// ★ RENAME FIRST, THEN READ THE CLAIM (2026-08-12, eighth review). Reading the count and renaming were two
	// operations, so a producer writing between them made the returned number disagree with the file that was
	// actually taken — under-reporting or double-reporting the same drops. The claim IS the count.
	//
	// An orphaned claim from a previous crash is folded back in first, so its drops are not lost and not
	// counted twice.
	recoverDroppedClaimLocked(dir)
	claim = droppedPath(dir) + ".claimed"
	if rerr := os.Rename(droppedPath(dir), claim); rerr != nil {
		if os.IsNotExist(rerr) {
			return 0, "", nil // nothing recorded; not an error
		}
		return 0, "", rerr
	}
	n = readDroppedFile(claim)
	if n == 0 {
		_ = os.Remove(claim)
		return 0, "", nil
	}
	return n, claim, nil
}

// recoverDroppedClaim folds a claim left behind by a crash back into the ledger.
//
// ★ A CLAIM IS NOT CRASH-SAFE ON ITS OWN. If the process dies between the rename and the delivery, the count
// sits in a file nothing reads — Go never looked at it again and the Swift sender DELETED it before claiming,
// so those drops were lost permanently. Recovering rather than deleting is the direction this whole lane
// commits to: a duplicate declaration is a smaller error than a silent gap.
func recoverDroppedClaimLocked(dir string) {
	claim := droppedPath(dir) + ".claimed"
	n := readDroppedFile(claim)
	if n <= 0 {
		_ = os.Remove(claim) // absent, empty or unreadable: nothing to fold in
		return
	}
	if err := addDroppedLocked(dir, n); err == nil {
		_ = os.Remove(claim)
	}
}

// ReleaseDropped discards a claim that was delivered, or puts it back when it was not.
//
// Putting it back ADDS to whatever the producer has recorded since, rather than overwriting: those are
// different drops and both happened.
func ReleaseDropped(dir, claim string, delivered bool) {
	if strings.TrimSpace(claim) == "" {
		return
	}
	if delivered {
		_ = os.Remove(claim)
		return
	}
	raw, err := os.ReadFile(claim)
	_ = os.Remove(claim)
	if err != nil {
		return
	}
	var v struct {
		Dropped int `json:"dropped"`
	}
	if json.Unmarshal(raw, &v) == nil && v.Dropped > 0 {
		// addDropped takes the lock: this runs in the SENDER, which is a different process from the one that
		// prunes, and both add.
		_ = addDropped(dir, v.Dropped)
	}
}

func readDropped(dir string) int { return readDroppedFile(droppedPath(dir)) }

func readDroppedFile(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var v struct {
		Dropped int `json:"dropped"`
	}
	if jerr := json.Unmarshal(raw, &v); jerr != nil {
		return 0
	}
	return v.Dropped
}

func sanitiseReportID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "report"
	}
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// DocumentDigest is the sha256 of a file, or "" when it cannot be read.
//
// ★ A REFUSAL OF AN UNVERIFIABLE DOCUMENT MUST NAME THE DOCUMENT (2026-08-12, eighth review). A manifest that
// does not verify supplies no version this device may believe, so the refusal had no version at all — and its
// fingerprint was then just "empty version + a generic error string". A SECOND substituted document produced
// the same fingerprint and was suppressed as a repeat, which is precisely the sequence worth seeing: somebody
// trying again with different bytes.
func DocumentDigest(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sum := sha256.New()
	if _, cerr := io.Copy(sum, f); cerr != nil {
		return ""
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// RefusalFingerprint identifies a standing refusal, so the same hold is reported ONCE rather than on every
// tick.
//
// ★ THE FAILURES THAT NEVER REACHED THE FLEET (2026-08-12, sixth review). Reports were queued only when the
// journal's failure counter moved — and the paths that matter most return BEFORE Run is called: an artifact
// that will not stage, a manifest that will not verify, a device that has been refused for a month. Those are
// exactly the devices an operator needs to see, and they were the ones still contributing `total: 0`.
//
// A fingerprint rather than a counter because these repeat every tick by nature. The status file records the
// last one reported; a DIFFERENT refusal is a new event, the same one is not.
func RefusalFingerprint(version, reason string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(version) + "\x00" + strings.TrimSpace(reason)))
	return hex.EncodeToString(sum[:8])
}

// RefusalAlreadyReported reports whether this exact refusal is the one already recorded.
func RefusalAlreadyReported(dir, fingerprint string) bool {
	prev, err := os.ReadFile(filepath.Join(dir, "last-refusal"))
	return err == nil && strings.TrimSpace(string(prev)) == fingerprint
}

// AppendRefusal queues a refusal ONCE per distinct reason — and in the order that cannot lose it.
//
// ★ THE MARKER USED TO GO FIRST (2026-08-12, seventh review). ShouldReportRefusal wrote "I have reported
// this" and the caller appended the report afterwards, so a crash — or an AppendReport failure — between the
// two left a device permanently silent about that refusal: every later tick matched the marker and suppressed
// it. Suppression is cheap to get wrong in exactly the direction this whole file exists to prevent.
//
// So the report is written FIRST and the marker only after the file is durably in place. The failure mode is
// now a duplicate report rather than a missing one, which is the trade this codebase makes every time:
// completeness outranks tidiness.
func AppendRefusal(dir string, r Report, fingerprint string) (queued bool, err error) {
	if strings.TrimSpace(fingerprint) == "" {
		fingerprint = r.Fingerprint
	}
	if strings.TrimSpace(fingerprint) == "" {
		return false, fmt.Errorf("a refusal with no fingerprint cannot be de-duplicated")
	}
	if RefusalAlreadyReported(dir, fingerprint) {
		return false, nil
	}
	if aerr := AppendReport(dir, r); aerr != nil {
		return false, aerr
	}
	if werr := os.WriteFile(filepath.Join(dir, "last-refusal"), []byte(fingerprint), 0o600); werr != nil {
		// Queued but not marked: the next tick reports it again. Noisy and honest, and the caller is told so
		// it can say which of the two happened.
		return true, fmt.Errorf("the refusal is queued and the suppression marker could not be written (%w): it "+
			"will be reported again next tick", werr)
	}
	return true, nil
}

// ClearRefusal forgets the last refusal, so the NEXT one is reported even if it is identical. Called when
// something has since progressed: a device that failed, updated, and later hits the same refusal again is
// reporting a new event, not repeating an old one.
func ClearRefusal(dir string) { _ = os.Remove(filepath.Join(dir, "last-refusal")) }

// ReportFromJournal builds the record for a journal that has just reached a terminal state.
//
// It is here rather than in each platform's updater so both send the same vocabulary: a fleet view that means
// one thing for Windows devices and another for Macs is not a fleet view.
func ReportFromJournal(j *Journal, status, reason string, now time.Time) Report {
	r := Report{
		ID:     newReportID(now),
		Status: status,
		Reason: reason,
		Kind:   "update",
		At:     now.UTC().Format(time.RFC3339),
	}
	if j != nil {
		r.FromVersion, r.TargetVersion = j.FromVersion, j.TargetVersion
		if j.IsRollback() {
			r.Kind = "rollback"
		}
	}
	return r
}

// ReportOutcome builds a report from the JOURNAL, which is the only place from_version actually lives.
//
// ★ THE PRODUCERS WERE BUILDING THESE BY HAND (2026-08-12, sixth review) and neither set FromVersion — so the
// field was populated only by tests, which is the shape of a feature that passes its own suite and tells an
// operator nothing. Both platforms call this instead.
func ReportOutcome(j *Journal, status, running, reason string, now time.Time) Report {
	r := ReportFromJournal(j, status, reason, now)
	r.RunningVersion = running
	r.Platform = runtime.GOOS
	r.Arch = runtime.GOARCH
	return r
}
