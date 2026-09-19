package enrolledinventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Durable persistence for the Enrolled Inventory ledger (W7). The admin runtime changes (enroll / disable /
// remove) were in-memory only — lost on an Edge restart, leaving only the static seed file. They now persist
// to a durable store: on boot the durable state is AUTHORITATIVE (it overlays the static seed), so a Console
// enroll/disable/remove survives a restart and a device admitted/revoked at runtime stays that way. With a
// shared (Postgres) persister it also survives a CP failover.

type stateFile struct {
	SchemaVersion string           `json:"schema_version"`
	Entries       map[string]Entry `json:"entries"`
	// Groups: the first-class device-group registry (key = group id). Optional/omitempty so an old snapshot
	// (no groups key) loads cleanly into an empty registry — backward compatible.
	Groups map[string]Group `json:"groups,omitempty"`
}

// enrolledInventoryStateSchemaVersion is bumped when a load has to DO something rather than just parse.
//
// ★ v2 EXISTS SO "MIGRATED" IS ANSWERABLE (2026-08-12, twenty-first review). v1 files predate
// Entry.DeviceEnrolledAt, and an absent marker there means "written before the field existed", not "no device
// has enrolled" — reading it as the latter hands every existing identity in the fleet one free enrolment to
// whoever holds a credential for its tenant. The two states are indistinguishable in the DATA, so the version
// is what distinguishes them, and without it a migration cannot tell whether it has already run.
const enrolledInventoryStateSchemaVersion = "enrolled_inventory_state.v2"

// enrolledInventoryStateSchemaVersionV1 is the version that predates the device-enrolment marker.
const enrolledInventoryStateSchemaVersionV1 = "enrolled_inventory_state.v1"

// migratedDeviceEnrolmentSentinel marks an identity that a v1 store carried. It is not a real timestamp
// because none was recorded; it says "assume enrolled" and is deliberately readable as what it is.
const migratedDeviceEnrolmentSentinel = "migrated:assumed-enrolled"

// seededDeviceEnrolmentSentinel is the same statement for an identity that arrived from the STATIC admission
// list rather than from a durable store. Distinct so the record says which route it came in by.
const seededDeviceEnrolmentSentinel = "seeded:assumed-enrolled"

// SetStatePath enables durable file persistence at path (historical behaviour). A back-compat convenience over
// SetPersister(blobstore.FilePersister{...}). Call once at boot, AFTER SeedFromStatic.
func (l *Ledger) SetStatePath(path string) {
	if l == nil {
		return
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	l.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or shared Postgres) and loads existing state
// (authoritative over the static seed already applied).
func (l *Ledger) SetPersister(p blobstore.Persister) {
	_ = l.SetPersisterChecked(p)
}

// SetPersisterChecked is SetPersister with the load failure RETURNED.
//
// ★ AN UNREADABLE LEDGER MUST NOT BE READ AS AN EMPTY ONE (2026-08-13, twenty-sixth review). loadLocked logs
// a read or parse failure and carries on with whatever is in memory — which is the static seed, or nothing.
// For an Edge that ISSUES certificates that is the worst possible reading: every identity in the fleet looks
// unenrolled, and the node is about to claim them and start handing out certificates in their names. A
// caller that is about to issue needs to be able to refuse.
func (l *Ledger) SetPersisterChecked(p blobstore.Persister) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.persister = p
	if p == nil {
		return nil
	}
	if err := l.loadLocked(); err != nil {
		// ★ A STORE THIS PROCESS COULD NOT READ MUST NOT BE OVERWRITTEN BY IT (2026-08-13, twenty-seventh
		// review). The persister is attached by the line above, so the next admin change or bundle merge would
		// Save the whole ledger — seed only — over a durable file whose contents were merely unreadable a
		// moment ago, and every enrolment marker and device group in it would be gone. The SingleWriter guard
		// cannot help: it arms on a successful Load, and there was not one, so its changed-underneath check is
		// skipped and the overwrite is unconditional and silent.
		//
		// So writes are latched off until somebody has actually read the file. An Edge that only enforces
		// keeps running on the static seed and the control plane's next bundle, which is what it is for.
		l.persistBlocked = err
		return err
	}
	l.persistBlocked = nil
	return nil
}

func (l *Ledger) loadLocked() error {
	if l.persister == nil {
		return nil
	}
	data, err := l.persister.Load()
	if err != nil {
		return ErrInventoryLoad
	}
	if len(data) == 0 {
		if l.snapshotKnown || l.persistBlocked != nil {
			return ErrInventoryLoad
		}
		return nil // first boot retains the static seed
	}
	f, err := decodeInventorySnapshot(data)
	if err != nil {
		return err
	}
	changed := !reflect.DeepEqual(l.entries, f.Entries) || !reflect.DeepEqual(l.groups, f.Groups)
	l.entries, l.groups = f.Entries, f.Groups
	l.snapshotKnown = true
	if changed {
		l.generation.Add(1)
	}
	return nil
}

// persistLocked atomically writes the current ledger to the durable store. Caller holds l.mu. Best-effort:
// write errors are logged, never fail the admin op. No-op when persistence is disabled.
//
// ★ persistCheckedLocked IS THE ONE TO USE WHERE THE WRITE IS THE SECURITY DECISION (2026-08-12, twenty-first
// review). "Best-effort, logged, never fails the op" is right for an admin edit and wrong for the record that
// a device has enrolled: a failure there returns a certificate and forgets that it did.
// ★ WHAT STILL USES IT, AND WHY (2026-08-13, thirty-first review #8). The security-bearing mutators no longer
// do: CreateGroup, UpdateGroup, DeleteGroup, SetGroup (the WAVE GROUP — which ring a device updates in) and the
// enrol path all return the error now, because each of them answers an administrator who is entitled to know
// whether the change lasted.
//
// The two that remain are ReplaceAll and ReplaceAllGroups, and the argument for them is different rather than
// weaker: they are the bulk apply of a control-plane-authored set, re-driven by the next pull. A lost write
// there is re-applied minutes later by the same mechanism that produced it, so failing the call would report an
// outage that does not exist. That is the whole distinction this seam was supposed to encode — and it is
// recorded here rather than left to be rediscovered, because the seam's previous justification covered
// everything and was wrong about most of it.
func (l *Ledger) persistLocked() { _ = l.persistCheckedLocked() }

// persistCheckedLocked is persistLocked with the error returned instead of only logged.
func (l *Ledger) persistCheckedLocked() error {
	if l == nil || l.persister == nil {
		return nil
	}
	if l.persistBlocked != nil {
		return fmt.Errorf("this process never read the enrolled inventory (%w), so it will not overwrite it: "+
			"the file holds enrolment markers and device groups this process cannot see", l.persistBlocked)
	}
	data, err := json.Marshal(stateFile{SchemaVersion: enrolledInventoryStateSchemaVersion, Entries: l.entries, Groups: l.groups})
	if err != nil {
		log.Printf("enrolled_inventory persist: marshal failed: %v", err)
		return err
	}
	if err := l.persister.Save(data); err != nil {
		// A completed synced in-place write is not a failure; an unconfirmed flush
		// is still rejected even when it carries that compatibility warning. Reporting a completed write
		// as failed would tell an operator their
		// change was lost when it was written; saying nothing would hide that an interrupted write could
		// truncate it. Both are worth exactly one accurate sentence.
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) && !errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			log.Printf("enrolled_inventory persist: saved, but NOT atomically — %v", err)
			l.snapshotKnown = true
			return nil
		}
		log.Printf("enrolled_inventory persist: save failed: %v", err)
		return err
	}
	l.snapshotKnown = true
	return nil
}

// ReloadFromStore re-reads the durable store and replaces this process's view with what it holds.
//
// ★★★ READING A SHARED STORE ONCE AT START-UP IS THE DEFECT THIS DEPLOYMENT KEEPS FINDING (2026-08-25, and
// the tenant CA registry says the same thing three findings earlier). Two control planes share one database
// precisely so that the standby holds what the leader authored — and the standby loaded the blob at boot and
// never looked again. Measured: a device enrolled while both were running appeared on the leader and not on
// the standby, and appeared on the standby the moment it was restarted. A standby that only learns by
// restarting is not warm; it is a cold copy with a fast start.
//
// ★★ IT IS FOR THE NODE THAT IS NOT WRITING. The leader takes the writes — the front door sends administration
// to whichever node holds leadership — so a leader re-reading could only overwrite itself with an older
// snapshot. The caller decides; this call does what it is told.
//
// Reports whether anything changed, so a caller can stay quiet on a settled deployment.
func (l *Ledger) ReloadFromStore() (changed bool, err error) {
	if l == nil {
		return false, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	before := l.generation.Load()
	if err := l.loadLocked(); err != nil {
		l.persistBlocked = err
		return false, err
	}
	l.persistBlocked = nil
	return before != l.generation.Load(), nil
}
