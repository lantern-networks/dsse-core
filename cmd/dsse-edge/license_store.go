package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/vendorlicense"
	"strings"
)

// The licence in force, and the highest serial ever accepted.
//
// The serial is the part that has to be durable independently of the licence itself. Rollback protection means
// refusing anything at or below what has already been seen, and an Edge that forgot its high-water mark on
// restart would happily accept last year's file with more seats on it. Keeping the number alongside the envelope
// means it survives even when the envelope is replaced.
type licenseStore struct {
	mu                 sync.RWMutex
	envelope           *vendorlicense.Envelope
	payload            *vendorlicense.Payload
	lastAcceptedSerial int64
	persister          blobstore.Persister
}

type licenseState struct {
	SchemaVersion      string                  `json:"schema_version"`
	Envelope           *vendorlicense.Envelope `json:"envelope,omitempty"`
	LastAcceptedSerial int64                   `json:"last_accepted_serial"`
	AppliedAt          string                  `json:"applied_at,omitempty"`
	AppliedBy          string                  `json:"applied_by,omitempty"`
}

const licenseStateSchema = "dsse.vendor_license_state.v1"

var errLicensePersistence = errors.New("license persistence failed")

func newLicenseStore() *licenseStore { return &licenseStore{} }

func (s *licenseStore) SetPersister(p blobstore.Persister) {
	if s == nil || p == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persister = p
	data, err := p.Load()
	if err != nil || len(data) == 0 {
		return
	}
	var st licenseState
	if err := json.Unmarshal(data, &st); err != nil {
		// Keep nothing rather than half a licence, but do NOT forget the serial silently — say so, because a
		// forgotten high-water mark is what lets an older file back in.
		log.Printf("vendor_license persist: load failed; the accepted-serial high-water mark may be lost: %v", err)
		return
	}
	s.envelope = st.Envelope
	s.lastAcceptedSerial = st.LastAcceptedSerial
}

// Apply verifies a licence and records it as the one in force. Verification is not optional and not skippable:
// an unverified licence is a number an attacker chose.
func (s *licenseStore) Apply(env vendorlicense.Envelope, accepted []*ecdsa.PublicKey, expectedMSSPID, by, now string) (vendorlicense.Payload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := vendorlicense.Verify(env, accepted, expectedMSSPID, s.lastAcceptedSerial)
	if err != nil {
		return vendorlicense.Payload{}, err
	}
	if s.persister != nil {
		data, mErr := json.Marshal(licenseState{
			SchemaVersion: licenseStateSchema, Envelope: &env,
			LastAcceptedSerial: p.Serial, AppliedAt: now, AppliedBy: by,
		})
		if mErr == nil {
			mErr = s.persister.Save(data)
		}
		if mErr != nil && (!errors.Is(mErr, blobstore.ErrSavedWithoutAtomicity) || errors.Is(mErr, blobstore.ErrDurabilityUnconfirmed)) {
			log.Printf("vendor_license persist: save failed: %v", mErr)
			return vendorlicense.Payload{}, errLicensePersistence
		}
		if mErr != nil {
			log.Printf("vendor_license persist: saved without atomic replacement: %v", mErr)
		}
	}
	// Do not consume the serial or change enrolment limits until storage confirms the save.
	s.envelope = &env
	s.payload = &p
	s.lastAcceptedSerial = p.Serial
	return p, nil
}

// ConfigGeneration is this store's term in the config bundle's version.
//
// ★★★ A BUNDLE WHOSE VERSION DOES NOT MOVE IS A BUNDLE NO EDGE PULLS (measured 2026-08-27). An Edge applies a
// bundle only when its generation is GREATER than the last one it applied — so after the licence was added to
// the bundle's contents, applying one on the control plane changed what the bundle said and not what it was
// numbered. Every Edge polled, saw the generation it already held, and skipped the whole payload: licence
// carried, licence never delivered, and enrolment held fleet-wide with nothing in any log.
//
// ★ THE TERM IS THE ACCEPTED SERIAL, which is already persisted and already monotonic — a licence's serial
// increases with every issue for this MSSP, and the store refuses anything at or below the highest it has
// taken. Deriving the term from it means the number survives a restart without a second field to keep in step.
// A term that reset on restart would make the SUM go down, and a sum that goes down is a fleet that never
// pulls again.
func (s *licenseStore) ConfigGeneration() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastAcceptedSerial <= 0 {
		return 0
	}
	return uint64(s.lastAcceptedSerial)
}

// Envelope returns the signed licence file this node holds, if any, so it can be CARRIED to the Edges.
//
// ★★★ THE ENVELOPE TRAVELS, NEVER THE VERDICT (2026-08-27). What the control plane publishes is the vendor's
// signed file exactly as it arrived, and each Edge verifies it with its OWN accepted keys and its own
// accepted-serial high-water mark. Sending "this licence is valid, trust me" would make the control plane an
// issuer of entitlement — a compromised or simply mistaken one could then raise a fleet's seat count with no
// vendor signature anywhere in the path, which is the whole thing the signature exists to prevent.
func (s *licenseStore) Envelope() (vendorlicense.Envelope, bool) {
	if s == nil {
		return vendorlicense.Envelope{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.envelope == nil {
		return vendorlicense.Envelope{}, false
	}
	return *s.envelope, true
}

// HoldsPayloadSHA reports whether the licence in force is this exact file.
//
// Used to make carrying it idempotent. Re-applying an envelope already held would be REFUSED — Verify checks
// the serial against the high-water mark and the stored licence's own serial is no longer above it — so an Edge
// polling a bundle would log a verification failure every poll while holding exactly the right licence.
func (s *licenseStore) HoldsPayloadSHA(sha string) bool {
	if s == nil || strings.TrimSpace(sha) == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.envelope != nil && strings.EqualFold(strings.TrimSpace(s.envelope.PayloadSHA256), strings.TrimSpace(sha))
}

// Current re-verifies the stored envelope against the CURRENT accepted keys rather than returning a payload
// parsed once at apply time.
//
// That is deliberate: a vendor key withdrawn after a compromise must stop a licence that was accepted under it,
// and a payload cached at apply time would keep working until someone restarted the process. Re-verification
// passes the serial that was accepted MINUS one, because the stored licence is allowed to be exactly what it
// already is — the rollback rule is about NEW files, not about re-reading the one in force.
func (s *licenseStore) Current(accepted []*ecdsa.PublicKey, expectedMSSPID string) (vendorlicense.Payload, bool) {
	p, ok, _ := s.CurrentWithReason(accepted, expectedMSSPID)
	return p, ok
}

// CurrentWithReason is Current plus WHY, when the answer is no.
//
// ★★ THE PRODUCT ALREADY KNEW AND THREW IT AWAY (2026-08-17, found on the lab). Verify returns a precise
// sentence for each way a licence can fail — "licence is addressed to X, not Y", "not signed by any accepted
// vendor key", "serial N does not advance past M". Current discarded all of them and answered a bare false,
// so the admin route could only say "a licence was accepted once and no longer verifies" and the Console
// guessed the cause: "usually a withdrawn vendor signing key".
//
// On this lab that guess was wrong, and expensively so. The licence verifies perfectly; it is addressed to
// an organization id the deployment has since been renamed away from. The three causes
// need three different responses — re-issue to the new holder, replace a withdrawn key, or investigate a
// rollback — and they were being reported as one. Meanwhile NO DEVICE COULD ENROL: measured with a freshly
// issued enrolment token, POST /enroll answered 403 "enrolment is not available for this tenant".
func (s *licenseStore) CurrentWithReason(accepted []*ecdsa.PublicKey, expectedMSSPID string) (vendorlicense.Payload, bool, error) {
	s.mu.RLock()
	env, serial := s.envelope, s.lastAcceptedSerial
	s.mu.RUnlock()
	if env == nil {
		return vendorlicense.Payload{}, false, nil
	}
	p, err := vendorlicense.Verify(*env, accepted, expectedMSSPID, serial-1)
	if err != nil {
		return vendorlicense.Payload{}, false, err
	}
	return p, true, nil
}

func (s *licenseStore) LastAcceptedSerial() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastAcceptedSerial
}

// parseLicenseEnvelope accepts what an operator actually has: the file the vendor sent, sealed or not.
//
// Both shapes are taken on purpose. A deployment that has not been issued a recipient key still receives plain
// signed envelopes, and making an operator choose the right menu item — with the wrong choice producing a
// mystifying error — would be a way to fail for no reason. Whichever it is, the signature is verified afterwards
// and identically: decryption proves only that a file was addressed here, never that the vendor issued it.
func parseLicenseEnvelope(raw []byte, recipient *ecdh.PrivateKey) (vendorlicense.Envelope, error) {
	if vendorlicense.LooksSealed(raw) {
		var sealed vendorlicense.SealedLicense
		if err := json.Unmarshal(raw, &sealed); err != nil {
			return vendorlicense.Envelope{}, fmt.Errorf("this does not look like a licence file: %w", err)
		}
		if recipient == nil {
			return vendorlicense.Envelope{}, fmt.Errorf("this licence is sealed, but no recipient key is configured on this Edge")
		}
		return vendorlicense.Open(sealed, recipient)
	}
	var env vendorlicense.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return vendorlicense.Envelope{}, fmt.Errorf("this does not look like a licence file: %w", err)
	}
	if env.Signature == "" || env.PayloadB64 == "" {
		return vendorlicense.Envelope{}, fmt.Errorf("this does not look like a licence file: it carries no signed payload")
	}
	return env, nil
}

// licenseChangeSummary describes what applying a licence WOULD do, so an operator sees the consequence before
// committing rather than discovering it afterwards.
type licenseChangeSummary struct {
	SeatsNow     int    `json:"seats_now"`
	SeatsAfter   int    `json:"seats_after"`
	SeatsDelta   int    `json:"seats_delta"`
	ExpiresAt    string `json:"expires_at"`
	IsEvaluation bool   `json:"is_evaluation"`
	AllocatedNow int    `json:"allocated_now"`
	// OverAllocatedAfter is how far the existing allocations would exceed the new pool. Non-zero means the
	// operator has to redistribute — and it is far better to know that before applying than after.
	OverAllocatedAfter int `json:"over_allocated_after"`
}

func summariseLicenceChange(current vendorlicense.Payload, haveCurrent bool, next vendorlicense.Payload,
	allocated int, at time.Time) licenseChangeSummary {
	s := licenseChangeSummary{
		SeatsAfter:   next.SeatsAt(at),
		ExpiresAt:    next.ExpiresAt,
		IsEvaluation: next.IsEvaluation,
		AllocatedNow: allocated,
	}
	if haveCurrent {
		s.SeatsNow = current.SeatsAt(at)
	}
	s.SeatsDelta = s.SeatsAfter - s.SeatsNow
	if allocated > s.SeatsAfter {
		s.OverAllocatedAfter = allocated - s.SeatsAfter
	}
	return s
}
