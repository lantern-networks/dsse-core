package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/durablefile"
)

// The set of certificates devices trust for the Edge connection, runtime-mutable and durable — B2 of the
// PKI redesign . Until this store, the set lived in a flag-file read at
// startup and the signed distribution was minted exactly once, so "withdraw the old one" was a file edit, a
// serial bump and a restart. Now adding is an admin action (always the safe direction: devices gain a
// certificate they can match, nobody loses one), and withdrawing is an admin action the caller gates on
// fleet coverage BEFORE it reaches here.
//
// The serial advances by one on every change and is persisted with the set: devices refuse a distribution
// whose serial does not advance (rollback protection), so a serial that failed to move reads as "the change
// did nothing" — the store makes that mistake unmakeable.
//
// Persistence is temp+rename in the store's own DIRECTORY. Never point this at a bind-mounted single file:
// rename onto one fails, which is the lesson recorded the hard way on 2026-07-30.
//
// THE SERIAL ONLY EVER GOES UP. Devices refuse a distribution that does not advance past the highest they
// have accepted — correct rollback protection that presents, to an operator, as the change having no
// effect. Losing this file used to re-seed the serial from the flag and could therefore hand the fleet a
// number it had already passed (review R7: the reference lab runs store serial 3 against a compose flag of
// 2, so carrying the compose file without the state directory would have done exactly that). On load the
// higher of the two is taken, and every change increments from there.
type transportTrustStore struct {
	mu   sync.Mutex
	path string
	pems string // concatenated certificate PEM blocks, in distribution order
	// announced is the interception-root list the last served bundle named, joined. It is not part of the
	// trust SET; it is part of what the bundle says, and devices adopt the whole document by serial.
	announced string
	serial    int64
	// recoveryNameSince is the serial at which the current announcement FIRST named a recovery SNI, kept so a
	// device that reports the name while reporting an older distribution can be told apart from one that is
	// simply behind. Reset when the name is withdrawn, because the next announcement of it is a new fact.
	recoveryNameSince int64
	// resign rebuilds the signed distribution for a candidate set and returns a commit that swaps it in.
	// Called BEFORE anything is persisted or exposed: a set that cannot be signed is not adopted at all.
	resign func(pems string, serial int64) (commit func(), err error)
	// shared is the deployment's own database, used INSTEAD of path when this node authors rather than
	// receives. See openSharedTransportTrustStore for why a control plane must not keep this on its own disk.
	shared blobstore.Persister
	// adoptedAuthored is the highest AUTHORED serial this node has taken from the control plane — a different
	// number from the one it SERVES, and the reason it has to be kept separately is in AdoptDistribution.
	adoptedAuthored int64
}

// where names the store in a message, so an operator reading a refusal knows which one it is talking about.
func (s *transportTrustStore) where() string {
	if s.shared != nil {
		return "the deployment's shared store"
	}
	return s.path
}

// readState returns the durable record, or os.ErrNotExist when there is none yet.
func (s *transportTrustStore) readState() ([]byte, error) {
	if s.shared != nil {
		raw, err := s.shared.Load()
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			return nil, os.ErrNotExist
		}
		return raw, nil
	}
	return os.ReadFile(s.path)
}

func (s *transportTrustStore) writeState(blob []byte) error {
	if s.shared != nil {
		return s.shared.Save(blob)
	}
	return durablefile.Write(s.path, blob, 0o600)
}

type transportTrustStoreState struct {
	SchemaVersion string `json:"schema_version"`
	Serial        int64  `json:"serial"`
	AnchorsPEM    string `json:"anchors_pem"`
	// AnnouncedInterception is what the bundle last told devices to look for, remembered so a restart does not
	// read "changed" and advance the serial on every boot. See AdvanceForAnnouncement.
	AnnouncedInterception string `json:"announced_interception,omitempty"`
	// RecoveryNameSince is the serial at which the announcement first named a recovery SNI. Persisted so the
	// contradiction it detects survives a restart, which is exactly when a stale reported field looks normal.
	RecoveryNameSince int64 `json:"recovery_name_since,omitempty"`
	// AdoptedAuthored is the highest serial this node has taken from the authority. Absent on a record written
	// before the two numbers were told apart, which reads as 0 and makes the next authored distribution arrive.
	AdoptedAuthored int64 `json:"adopted_authored_serial,omitempty"`
}

// openTransportTrustStore loads the durable set, seeding it from the flag-configured file and serial on
// first run. Once the store exists it is authoritative: the flag values are only the seed, and a drifted
// seed file is reported rather than silently re-applied.
func openTransportTrustStore(path, seedPEM string, seedSerial int64,
	resign func(string, int64) (func(), error)) (*transportTrustStore, error) {
	s := &transportTrustStore{path: strings.TrimSpace(path), resign: resign}
	return s.loadOrSeed(seedPEM, seedSerial)
}

// loadOrSeed is the same load for both backings: the durable record if there is one, otherwise the seed the
// flags carry. Shared by the file and database constructors so the two cannot come to differ — the rule that
// a serial only ever goes up is enforced in exactly one place.
func (s *transportTrustStore) loadOrSeed(seedPEM string, seedSerial int64) (*transportTrustStore, error) {
	raw, err := s.readState()
	switch {
	case err == nil:
		var st transportTrustStoreState
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("transport trust store %s is unreadable: %w", s.where(), err)
		}
		// Canonicalised on the way in as well as on the way out: a string written by an older build is in
		// whatever order that build happened to compute, and comparing it against a canonical one would read as
		// a change and advance the serial once per node for no reason.
		s.pems, s.serial, s.announced = st.AnchorsPEM, st.Serial, canonicalAnnouncement(st.AnnouncedInterception)
		s.recoveryNameSince = st.RecoveryNameSince
		// ★ A RECORD WRITTEN BEFORE THE TWO NUMBERS WERE TOLD APART SAYS NOTHING ABOUT WHAT IT ADOPTED, and
		// nothing is not the same as zero-adopted. Left at 0 it takes the authority's next distribution once —
		// the same one-time catch-up the move into the shared store makes, and for the same reason: the
		// alternative is a node that stays permanently ahead of the authority and ignores it for ever. The
		// window is one poll of this node's own control plane, over mTLS, on a signature-verified bundle.
		s.adoptedAuthored = st.AdoptedAuthored
		if st.Serial <= 0 {
			// A record with a set but no serial (hand-edited, or an older schema) would distribute serial 0
			// and be refused by every device as a rollback, reported as "the change did nothing".
			return nil, fmt.Errorf("transport trust store %s carries certificates with no serial — refusing to distribute a serial devices will reject", s.where())
		}
		if seedSerial > st.Serial {
			// The flag has moved ahead of the store — an operator raised it, or this node was rebuilt from a
			// compose file newer than the state it carries. Take the higher of the two: a serial may only go
			// up (below).
			logInfof("transport_trust store=%s serial %d is behind -trust-bundle-serial %d — adopting the higher", s.where(), st.Serial, seedSerial)
			s.serial = seedSerial
			// Persist the adopted floor NOW, or it lives only in memory: the file stays at the old serial until
			// some later Add/Withdraw happens to write it. Then a restart where the flag is no longer held at or
			// above this value (an operator drops the one-time bump, or the node is rebuilt from a steady-state
			// compose whose flag sits below the store — the reference lab deliberately does exactly this) reloads
			// the OLD serial and re-signs BELOW the fleet's high-water mark, so every device rejects it as a
			// replay and the fleet is stranded. This file's own contract is "the serial only ever goes up"; a
			// memory-only bump breaks it across a restart. Fail closed if it cannot be made durable.
			if err := s.persistLocked(); err != nil {
				return nil, fmt.Errorf("transport trust store %s: could not persist the adopted serial floor %d: %w", s.where(), seedSerial, err)
			}
		}
		if strings.TrimSpace(seedPEM) != "" && normalizePEM(seedPEM) != normalizePEM(st.AnchorsPEM) {
			logInfof("transport_trust store=%s differs from the seed file — the store is authoritative; the seed is only used on first run", s.where())
		}
	case os.IsNotExist(err):
		if len(parseAllCerts([]byte(seedPEM))) == 0 {
			return nil, fmt.Errorf("transport trust store %s does not exist and the seed contains no certificate", s.where())
		}
		if seedSerial <= 0 {
			return nil, fmt.Errorf("transport trust store %s does not exist and -trust-bundle-serial is not set — a first distribution needs a serial devices will accept", s.where())
		}
		s.pems, s.serial = seedPEM, seedSerial
		// ★ A NODE WITH NO HISTORY STILL REFUSES A REPLAY. On a first run the two numbers are the same: the
		// seed is the only distribution this node has ever been told about, so anything at or below it is a
		// replay and not an instruction. They diverge afterwards, as this node's own announcements advance
		// what it SERVES without the authority ever hearing about it.
		s.adoptedAuthored = seedSerial
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("read transport trust store %s: %w", s.where(), err)
	}
	if len(s.anchorsLocked()) == 0 {
		return nil, fmt.Errorf("transport trust store %s holds no certificate — refusing to serve an empty trust set", s.where())
	}
	return s, nil
}

func normalizePEM(p string) string {
	out := ""
	for _, c := range parseAllCerts([]byte(p)) {
		sum := sha256.Sum256(c.Raw)
		out += hex.EncodeToString(sum[:])
	}
	return out
}

func (s *transportTrustStore) anchorsLocked() []*x509.Certificate {
	return parseAllCerts([]byte(s.pems))
}

func (s *transportTrustStore) Current() (string, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pems, s.serial
}

func (s *transportTrustStore) Anchors() []*x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.anchorsLocked()
}

// adoptNewerFromDiskLocked reads what the FLEET has already distributed, before this node decides anything.
//
// ★★★ THE STORE WAS READ ONCE AT BOOT AND NEVER AGAIN (2026-08-20, measured on a four-Edge fleet). Each
// process kept its own copy and only ever wrote to the shared file. Live, in one fleet: the file was at serial
// 144, region-a served 138, region-b served 142, and three minutes of watching showed no convergence — one
// fleet distributing three different documents, decided by which Edge a device happened to reach.
//
// The refusal added the same day (persistLocked) turned that into something an administrator meets: adding a
// trust anchor through region-a's admin API answered 400 "another Edge has distributed something newer" —
// correct, honest, and with no way out, because nothing re-read the file. Whether the Console's button works
// depended on which Edge the load balancer picked, and it would never start working again.
//
// Adopting is not a decision. It is reading the decision the fleet already made and told devices about — the
// same argument CatchUpWithTheFleet makes for which authority a node serves. It can only move FORWARD: a lower
// or equal serial is ignored, an empty set is ignored, an unreadable file leaves this node exactly as it was
// (unreadable is not changed), and a set this node cannot sign is not adopted at all.
func (s *transportTrustStore) adoptNewerFromDiskLocked() {
	if s.path == "" && s.shared == nil {
		return
	}
	raw, err := s.readState()
	if err != nil {
		return
	}
	var onDisk transportTrustStoreState
	if json.Unmarshal(raw, &onDisk) != nil || onDisk.Serial <= s.serial {
		return
	}
	if len(parseAllCerts([]byte(onDisk.AnchorsPEM))) == 0 {
		return
	}
	commit := func() {}
	if s.resign != nil {
		c, err := s.resign(onDisk.AnchorsPEM, onDisk.Serial)
		if err != nil {
			log.Printf("transport trust: the fleet is at serial %d and this node holds %d, but its set cannot be "+
				"signed here (%v) — keeping this node's own distribution", onDisk.Serial, s.serial, err)
			return
		}
		commit = c
	}
	held := s.serial
	s.pems, s.serial = onDisk.AnchorsPEM, onDisk.Serial
	s.announced, s.recoveryNameSince = onDisk.AnnouncedInterception, onDisk.RecoveryNameSince
	commit()
	log.Printf("transport trust: adopted the fleet's distribution serial %d (this node was serving %d) — another "+
		"Edge distributed it and this node was behind, not deciding", onDisk.Serial, held)
}

// AdoptFleetDistribution lets a caller outside the store read the fleet's current view before it reasons about
// the set — the read paths and the admin gates run outside the store lock, and a node between recompute ticks
// is judging on what it last wrote.
//
// ★ Live: with the fleet at serial 149 and two anchors, a withdrawal aimed at the second one was refused 409
// "the last certificate cannot be withdrawn" — the gate ran on this node's own 148/one-anchor view, decided
// before the lock, and never reached the re-judgement inside WithdrawIf that would have seen the fleet's set.
// The store had already learned how to catch up; the caller was asking before it did.
// Snapshot is what this node is distributing, as the fleet's own document.
//
// Used by a control plane to publish it in the config bundle. The same shape the shared file holds, so the two
// paths cannot describe the distribution differently — which is the failure the serial exists to prevent.
func (s *transportTrustStore) Snapshot() transportTrustStoreState {
	if s == nil {
		return transportTrustStoreState{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return transportTrustStoreState{
		SchemaVersion:         "transport_trust_store.v1",
		Serial:                s.serial,
		AnchorsPEM:            s.pems,
		AnnouncedInterception: s.announced,
		RecoveryNameSince:     s.recoveryNameSince,
	}
}

// AdoptDistribution takes a distribution the CONTROL PLANE published, under exactly the rules the shared file
// already follows: forward only, never empty, and never a set this node cannot sign.
//
// ★★★ WHY IT IS THE SAME RULES AND NOT NEW ONES (2026-08-23). The fleet used to agree about these anchors by
// sharing one FILE — which works in a deployment where every Edge happens to mount the same directory, and is
// nothing at all in one where they do not. Both outages this file records came from that: two processes reading
// the file once at boot and writing the whole thing back, so one wrote the other's work away and the serial went
// backwards, and the fleet distributed three different documents at once.
//
// Carrying it in the signed config bundle removes the second writer instead of defending against it. The rules
// stay because they were never about the file: forward-only is what makes a device's adopted anchor safe, and
// "a set this node cannot sign is not adopted" is what stops an Edge announcing something it cannot serve.
func (s *transportTrustStore) AdoptDistribution(published transportTrustStoreState) (adopted bool) {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shared != nil {
		return false
	} // Only file receivers adopt CP distributions.
	// ★★★ WHAT THE AUTHORITY WROTE AND WHAT THIS NODE SERVES ARE TWO NUMBERS (2026-09-07, measured on a
	// three-region deployment: the leading control plane answered 200 "added, serial 4" and ninety seconds
	// later no Edge in any region had the certificate).
	//
	// An Edge advances the serial ITSELF whenever its announcement changes — which interception roots this
	// node names is a property of this node, and devices adopt the whole document by serial, so it must. The
	// authority does not see those advances. Its counter therefore runs behind the fleet's, and the next
	// certificate an operator adds is published at or below what the Edges already serve and discarded by all
	// of them as a replay. The Console says "Added — serial 4" and nothing anywhere disagrees.
	//
	// Compared against the highest AUTHORED serial this node has taken, then, rather than against the one it
	// happens to be serving. The rollback protection is unchanged — an authored distribution still has to be
	// newer than the last authored one — and what it stops being is a race with this node's own announcements.
	if published.Serial <= s.adoptedAuthored {
		return false
	}
	if len(parseAllCerts([]byte(published.AnchorsPEM))) == 0 {
		// An empty set is never adopted. Devices check these before they will talk to an Edge at all, so
		// applying an empty distribution strands every one of them at once.
		return false
	}
	// Served at a number devices will accept as newer than what they already hold from THIS node.
	serve := published.Serial
	if serve <= s.serial {
		serve = s.serial + 1
	}
	commit := func() {}
	if s.resign != nil {
		c, err := s.resign(published.AnchorsPEM, serve)
		if err != nil {
			log.Printf("transport trust: the control plane is distributing serial %d and this node holds %d, but "+
				"its set cannot be signed here (%v) — keeping this node's own distribution rather than "+
				"announcing something it cannot serve", published.Serial, s.serial, err)
			return false
		}
		commit = c
	}
	held := s.serial
	s.pems, s.serial, s.adoptedAuthored = published.AnchorsPEM, serve, published.Serial
	// ★ AN EMPTY ANNOUNCEMENT FROM THE AUTHORITY IS NOT AN INSTRUCTION TO STOP ANNOUNCING. A control plane
	// holds no interception key, so what it publishes here is usually empty, while each Edge names the roots
	// IT serves. Copying the empty one over wiped this node's announcement, its own recompute put it back a
	// moment later, and the serial advanced twice for a document that never changed — which is how the
	// authority came to be permanently a step behind the fleet in the first place.
	if strings.TrimSpace(published.AnnouncedInterception) != "" {
		s.announced, s.recoveryNameSince = published.AnnouncedInterception, published.RecoveryNameSince
	}
	commit()
	if err := s.persistLockedInner(); err != nil {
		// Live but not durable: this node is serving the fleet's distribution and would come back on its own
		// after a restart. Said rather than swallowed.
		log.Printf("transport trust: adopted the control plane's serial %d but could not write it down (%v)",
			published.Serial, err)
	}
	log.Printf("transport trust: adopted the control plane's authored distribution serial %d, serving it as %d "+
		"(this node was serving %d)", published.Serial, s.serial, held)
	return true
}

func (s *transportTrustStore) AdoptFleetDistribution() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adoptNewerFromDiskLocked()
}

// persistLocked writes this process's view — after checking that the view on disk is not newer.
//
// ★★★ TWO EDGES SHARE THIS FILE AND ONE WROTE THE OTHER'S WORK AWAY (2026-08-20, and it took the lab down).
//
// The store is deliberately shared: one fleet, one distribution, one serial. But each process read it at
// start-up, kept its own copy, and wrote the whole thing whenever it changed something — last writer wins. So
// a node that had not yet noticed a promotion persisted its older announcement over the newer one, and the
// file went BACKWARDS: serial 127 naming the authority every device had adopted became serial 126 naming the
// one that had just been retired on the control plane.
//
// Nothing was wrong until the next restart. Then both Edges read that file, found it announcing an authority
// neither of them holds any more, and refused to join the fleet — correctly, and the fleet was empty.
//
// A regression is refused here, and the caller rolls back. It is not a lock: two processes can still interleave
// a read and a write. What it removes is the silent direction — going backwards — which is the one that ends
// with a distribution nobody can serve.
func (s *transportTrustStore) persistLocked() error {
	if s.path != "" || s.shared != nil {
		raw, err := s.readState()
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read current trust distribution before saving: %w", err)
		}
		if err == nil {
			var onDisk transportTrustStoreState
			if err := json.Unmarshal(raw, &onDisk); err != nil {
				return fmt.Errorf("decode current trust distribution before saving: %w", err)
			}
			if onDisk.Serial > s.serial {
				return fmt.Errorf("the shared trust store is at serial %d and this node holds %d: another node "+
					"has distributed something newer, and writing this view would take the fleet backwards to a "+
					"set no device holds", onDisk.Serial, s.serial)
			}
		}
	}
	return s.persistLockedInner()
}

func (s *transportTrustStore) persistLockedInner() error {
	blob, err := json.MarshalIndent(transportTrustStoreState{
		SchemaVersion: "transport_trust_store.v1", Serial: s.serial, AnchorsPEM: s.pems,
		AnnouncedInterception: s.announced,
		RecoveryNameSince:     s.recoveryNameSince,
		AdoptedAuthored:       s.adoptedAuthored,
	}, "", "  ")
	if err != nil {
		return err
	}
	// ★ ONE DURABLE WRITE (2026-08-14, thirty-first review #12 and the sweep it opened). This staged its own
	// temporary file and finished on a bare os.Rename — no durable replace at all, on the store that holds
	// what this Edge will trust. The gate that was meant to have ended this family only matched copies that
	// fsync the directory, so the copies that never did were invisible to it and read as compliant.
	return s.writeState(blob)
}

// applyLocked signs the candidate set, persists it, and only then swaps the served distribution — in that
// order, so a failure at any step leaves both the disk and the wire on the previous good set.
func (s *transportTrustStore) applyLocked(newPEMs string) error {
	newSerial := s.serial + 1
	commit := func() {}
	if s.resign != nil {
		var err error
		commit, err = s.resign(newPEMs, newSerial)
		if err != nil {
			return fmt.Errorf("sign the updated trust distribution: %w", err)
		}
	}
	oldPEMs, oldSerial := s.pems, s.serial
	s.pems, s.serial = newPEMs, newSerial
	if err := s.persistLocked(); err != nil {
		s.pems, s.serial = oldPEMs, oldSerial
		return fmt.Errorf("persist the updated trust set: %w", err)
	}
	commit()
	return nil
}

// deviceTrustPoolFrom builds the pool a (T) handshake verifies device client certificates against.
//
// It is ONE function because it is the seam two different admin acts change from opposite sides — the
// tenant-CA registry and the device-trust store — and the composition ("the registry, cloned, plus the
// store") is the reason their ordering matters. Written once so a test can assert against the same
// composition production serves, rather than against a restatement of it that can drift into agreeing with
// whatever the code does.
func deviceTrustPoolFrom(registryPool *x509.CertPool, pems string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if registryPool != nil {
		pool = registryPool.Clone()
	}
	if !pool.AppendCertsFromPEM([]byte(pems)) && registryPool == nil {
		return nil, fmt.Errorf("no usable CA certificate in the device-trust set")
	}
	return pool, nil
}

// AdvanceForAnnouncement re-signs the SAME trust set under the next serial, because something else the bundle
// carries has changed and devices adopt by serial.
//
// ★★★ THE BUNDLE ANNOUNCES MORE THAN IT GATES ON (2026-08-19, reported from win-dev-1). The interception roots
// a device must look for ride in this document, and the serial only ever moved when the TRANSPORT anchors
// changed. So an organization moved onto its own interception root while the serial stayed at 12 — and an
// agent takes a new bundle only when the serial advances. That box held the bundle it adopted on 2026-08-03,
// naming a root nothing had signed under for days, and answered the readiness question from it: fifteen days
// of reporting ready about a question whose answer had changed.
//
// The serial is the adoption mechanism for EVERYTHING in the bundle, so it advances when anything in the
// bundle changes. Reapply deliberately does not move it — that path rebuilds a pool and distributes nothing —
// and this one deliberately does, because something WAS distributed.
//
// Reports whether it moved, so the caller can say why in one line rather than logging on every boot: the
// announcement is remembered across restarts, and an unchanged announcement is not a change.
func (s *transportTrustStore) AdvanceForAnnouncement(announced []string, reason string) (int64, bool, error) {
	return s.AdvanceForAnnouncementContext(captureCPWriteLease(context.Background()), announced, reason)
}
func (s *transportTrustStore) AdvanceForAnnouncementContext(ctx context.Context, announced []string, reason string) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var moved bool
	if handled, err := s.mutateSharedLocked(ctx, func(c *transportTrustStore) error {
		_, changed, err := c.AdvanceForAnnouncementContext(ctx, announced, reason)
		moved = changed
		return err
	}); handled {
		return s.serial, err == nil && moved, err
	}
	s.adoptNewerFromDiskLocked()
	// ★ THE ORDER IS NOT PART OF THE ANNOUNCEMENT (2026-08-20, caught the same hour it was introduced). This
	// compares joined strings, so two nodes in one fleet that compute the SAME set in different order each read
	// the other's write as a change and advance the serial — forever, with nothing actually changing, and every
	// advance throwing away the adoption evidence below it. Canonicalised here, in the one place the comparison
	// happens, rather than by asking every caller to sort.
	next := canonicalAnnouncement(strings.Join(announced, ","))
	if next == s.announced {
		return s.serial, false, nil
	}
	if s.resign == nil {
		s.announced = next
		return s.serial, false, s.persistLocked()
	}
	previous := s.announced
	s.announced = next
	// Remember when a recovery name first appeared, and forget it when it goes.
	hadName := strings.Contains(previous, "recovery-sni=") && !strings.Contains(previous, "recovery-sni=withdrawn")
	hasName := strings.Contains(next, "recovery-sni=") && !strings.Contains(next, "recovery-sni=withdrawn")
	switch {
	case hasName && !hadName:
		s.recoveryNameSince = s.serial + 1 // the serial this change is about to produce
	case !hasName:
		s.recoveryNameSince = 0
	}
	if err := s.applyLocked(s.pems); err != nil {
		s.announced = previous
		return s.serial, false, err
	}
	if _, staged := s.shared.(*transportTrustCandidate); !staged {
		log.Printf("trust_bundle serial advanced to %d because %s changed: %q -> %q (devices adopt by serial, so a "+
			"changed announcement that leaves the serial behind never reaches them)", s.serial, reason, previous, next)
	}
	return s.serial, true, nil
}

// Reapply re-runs the rebuild that a change to this store triggers, WITHOUT changing the store.
//
// ★ THE POOL A HANDSHAKE READS IS NOT THIS STORE (2026-08-16, measured live). It is rebuilt from this store's
// certificates PLUS a clone of the tenant-CA registry's pool, and only a change HERE rebuilds it. So removing
// a CA from the tenant registry left the live pool untouched, and removing it from this store first rebuilt
// the live pool from a registry clone that still contained it — the withdrawal defeated itself by ordering.
// Whoever changes the registry needs a way to say "rebuild now" that does not pretend to be a change to the
// trust set: the serial must not move, because devices read the serial to decide whether their distribution
// is stale, and nothing was distributed.
func (s *transportTrustStore) Reapply() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resign == nil {
		return nil
	}
	commit, err := s.resign(s.pems, s.serial)
	if err != nil {
		return fmt.Errorf("rebuild the served trust set: %w", err)
	}
	commit()
	return nil
}

// Add appends one certificate to the set. Exactly one per call — each addition is one auditable act.
func (s *transportTrustStore) Add(certPEM string) (*x509.Certificate, int64, error) {
	return s.AddContext(captureCPWriteLease(context.Background()), certPEM)
}
func (s *transportTrustStore) AddContext(ctx context.Context, certPEM string) (*x509.Certificate, int64, error) {
	certs := parseAllCerts([]byte(certPEM))
	if len(certs) != 1 {
		return nil, 0, fmt.Errorf("exactly one certificate is added at a time (got %d)", len(certs))
	}
	c := certs[0]
	// What goes into the distribution is what devices will TRUST, so it must be able to act as one: a leaf
	// or an expired certificate can be added, reported held by every device, and then counted as coverage
	// evidence for a withdrawal (review R10③).
	if !c.IsCA || !c.BasicConstraintsValid {
		return nil, 0, fmt.Errorf("only a CA certificate can be distributed as one devices trust (this one is an end-entity certificate)")
	}
	if now := time.Now(); now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return nil, 0, fmt.Errorf("this certificate is not currently valid (not_before=%s not_after=%s)",
			c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
	}
	sum := sha256.Sum256(c.Raw)
	fp := hex.EncodeToString(sum[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	if handled, err := s.mutateSharedLocked(ctx, func(candidate *transportTrustStore) error {
		_, _, err := candidate.AddContext(ctx, certPEM)
		return err
	}); handled {
		if err != nil {
			return nil, 0, err
		}
		return c, s.serial, nil
	}
	s.adoptNewerFromDiskLocked()
	for _, existing := range s.anchorsLocked() {
		es := sha256.Sum256(existing.Raw)
		if hex.EncodeToString(es[:]) == fp {
			return nil, 0, fmt.Errorf("this certificate is already distributed")
		}
	}
	block := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	if err := s.applyLocked(strings.TrimRight(s.pems, "\n") + "\n" + block); err != nil {
		return nil, 0, err
	}
	return c, s.serial, nil
}

// Withdraw removes the certificate with the given fingerprint. The LAST certificate can never be withdrawn
// here regardless of what the caller decided — an empty trust set strands everything at once.
func (s *transportTrustStore) Withdraw(sha string) (*x509.Certificate, int64, error) {
	return s.WithdrawIf(sha, nil)
}

// WithdrawIf re-evaluates the caller's gate INSIDE the store lock, against the set as it is at the moment
// of removal. The gate used to be decided on a snapshot taken before the lock was acquired, so two
// concurrent withdrawals could each be judged against a set that still contained the other's target: with
// {A,B,C} where A and B each verify the served chain and C covers the fleet, gate(A) passes on B and
// gate(B) passes on A, both proceed, and the surviving set verifies nothing (review R9). Sequentially the
// second is refused; concurrently it was not.
func (s *transportTrustStore) WithdrawIf(sha string, gate func(remaining []*x509.Certificate) (bool, string)) (*x509.Certificate, int64, error) {
	var checked func([]*x509.Certificate, *x509.Certificate, int64) (bool, string)
	if gate != nil {
		checked = func(c []*x509.Certificate, _ *x509.Certificate, _ int64) (bool, string) { return gate(c) }
	}
	return s.WithdrawIfContext(captureCPWriteLease(context.Background()), sha, checked)
}
func (s *transportTrustStore) WithdrawIfContext(ctx context.Context, sha string, gate func(remaining []*x509.Certificate, removed *x509.Certificate, serial int64) (bool, string)) (*x509.Certificate, int64, error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	s.mu.Lock()
	defer s.mu.Unlock()
	var removedShared *x509.Certificate
	if handled, err := s.mutateSharedLocked(ctx, func(candidate *transportTrustStore) error {
		var err error
		removedShared, _, err = candidate.WithdrawIfContext(ctx, sha, gate)
		return err
	}); handled {
		if err != nil {
			return nil, 0, err
		}
		return removedShared, s.serial, nil
	}
	s.adoptNewerFromDiskLocked()
	anchors := s.anchorsLocked()
	if len(anchors) < 2 {
		return nil, 0, fmt.Errorf("the last certificate cannot be withdrawn — devices would have nothing left to match the Edge against")
	}
	var removed *x509.Certificate
	kept := ""
	for _, c := range anchors {
		sum := sha256.Sum256(c.Raw)
		if hex.EncodeToString(sum[:]) == sha {
			removed = c
			continue
		}
		kept += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	if removed == nil {
		return nil, 0, fmt.Errorf("no distributed certificate has that fingerprint")
	}
	if gate != nil {
		remaining := make([]*x509.Certificate, 0, len(anchors)-1)
		for _, c := range anchors {
			sum := sha256.Sum256(c.Raw)
			if hex.EncodeToString(sum[:]) != sha {
				remaining = append(remaining, c)
			}
		}
		if ok, reason := gate(remaining, removed, s.serial); !ok {
			return nil, 0, fmt.Errorf("%s", reason)
		}
	}
	if err := s.applyLocked(kept); err != nil {
		return nil, 0, err
	}
	return removed, s.serial, nil
}

// deviceClientCAs is the runtime-mutable set of CAs that device client certificates are verified against
// (-device-client-ca-store) — the same store type doing the same job on the other side of the handshake:
// its resign hook rebuilds the verification pool instead of re-signing a distribution. nil = startup-fixed.
var deviceClientCAs *transportTrustStore

// transportTrust is the runtime-mutable set when -transport-trust-store is configured; nil means the flag
// file is the fixed set. Package-level, like the other runtime registries in this package, because the store
// is created where the signer lives (the bundle-serving setup) and read by admin routes registered earlier.
var transportTrust *transportTrustStore

// currentTrustAnchors is what every reader of "the certificates devices trust" goes through, so the report,
// the certificate map, the paths view and the expiry sweep can never disagree about the current set.
func currentTrustAnchors(config serverConfig) (string, int64) {
	if transportTrust != nil {
		return transportTrust.Current()
	}
	return config.TrustBundleCAPEM, config.TrustBundleSerial
}

// RecoveryNameSince is the serial at which the current announcement first named a recovery SNI, or 0 when it
// names none — and ALSO 0 on a deployment that was already announcing one before this was recorded, where
// the answer is unknown. Unknown disables the contradiction check rather than guessing a serial: seeding it
// with the current one would make every device that is merely behind look like it was lying. A device reporting that name and a serial below this one is reporting two things that cannot
// both be true.
func (s *transportTrustStore) RecoveryNameSince() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveryNameSince
}

// Announced is the announcement string the last served distribution carried, as remembered here. It is how a
// node that has just joined a SHARED fleet learns what the fleet has already promised devices.
func (s *transportTrustStore) Announced() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.announced
}

// canonicalAnnouncement is the announcement as a SET: order carries nothing, and two nodes in one fleet that
// compute the same set in different order must not read each other as a change.
func canonicalAnnouncement(joined string) string {
	parts := strings.Split(joined, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// openSharedTransportTrustStore is the same store kept in the deployment's own database instead of on one
// node's disk.
//
// ★★★ THE AUTHORITY IS ONE ROLE HELD BY DIFFERENT MACHINES AT DIFFERENT TIMES (2026-09-07, measured on a
// three-region deployment while making this set reach more than one region).
//
// Only the LEADING control plane serves the config bundle — the others refuse it outright, naming the leader.
// So "the control plane holds the distribution" is true of whichever node leads right now, and leadership
// moves. With the distribution on local disk, a node that has never led sits at the serial it booted with
// while the fleet is far past it; the moment it takes leadership, the next certificate an operator adds is
// numbered from ITS serial, lands below the fleet's high-water mark, and is discarded by every Edge as a
// replay. The Console says "Added — serial 3" and nothing anywhere disagrees.
//
// A serial that only ever goes up is the rule the whole distribution rests on. It can only hold if every node
// that might issue one counts from the same place, which on this deployment is the database every control
// plane already shares. Enforcement Edges keep their file: what they hold is a CACHE of what they were given,
// and a cache is per node by definition.
func openSharedTransportTrustStore(shared blobstore.Persister, carriedFrom, seedPEM string, seedSerial int64,
	resign func(string, int64) (func(), error)) (*transportTrustStore, error) {
	if shared == nil {
		return nil, fmt.Errorf("a shared transport trust store needs the deployment's database")
	}
	if p, ok := shared.(transportTrustUpdater); ok {
		return openTransactionalTransportTrustStore(shared, p, carriedFrom, seedPEM, seedSerial, resign)
	}
	// ★★★ THE MOVE MUST NOT TAKE THE AUTHORITY BACKWARDS (2026-09-07, measured the first time this ran on a
	// deployment that already had a distribution).
	//
	// A deployment upgrading into this has its live distribution on the nodes' own disks — and the shared
	// record does not exist yet, so a fresh seed starts at the flag's serial. Measured immediately after the
	// change: every control plane read serial 2 while every Edge in every region served 4, which is the exact
	// state this store exists to prevent. The next certificate an operator added would have been numbered 3
	// and discarded by the whole fleet as a replay.
	//
	// So the record a node carried forward is read too, and the HIGHER of the two wins — the same rule the
	// file already followed, applied to the move itself. It does not depend on which node starts first: a node
	// holding a lower record cannot pull the shared one down, and a node holding a higher one raises it.
	if carried := carriedForwardTrustState(carriedFrom); carried != nil {
		if raw, err := shared.Load(); err != nil || len(bytes.TrimSpace(raw)) == 0 {
			if err == nil {
				if blob, merr := json.MarshalIndent(carried, "", "  "); merr == nil {
					if serr := shared.Save(blob); serr == nil {
						logInfof("transport_trust carried serial %d forward from %s into the deployment's shared "+
							"store — the authority must not restart below what the fleet is already serving",
							carried.Serial, carriedFrom)
					}
				}
			}
		} else {
			var onRecord transportTrustStoreState
			if json.Unmarshal(raw, &onRecord) == nil && carried.Serial > onRecord.Serial {
				if blob, merr := json.MarshalIndent(carried, "", "  "); merr == nil {
					if serr := shared.Save(blob); serr == nil {
						logInfof("transport_trust the shared store held serial %d and this node carried %d "+
							"forward from %s — the higher wins, because a serial may only go up",
							onRecord.Serial, carried.Serial, carriedFrom)
					}
				}
			}
		}
	}
	s := &transportTrustStore{shared: shared, resign: resign}
	return s.loadOrSeed(seedPEM, seedSerial)
}

// carriedForwardTrustState reads the record a node kept on its own disk before this store moved into the
// deployment's database. nil when there is none, when it is unreadable, or when it carries no serial — a
// record that cannot be trusted to be a distribution must never raise the fleet's high-water mark.
func carriedForwardTrustState(path string) *transportTrustStoreState {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var st transportTrustStoreState
	if json.Unmarshal(raw, &st) != nil || st.Serial <= 0 {
		return nil
	}
	if len(parseAllCerts([]byte(st.AnchorsPEM))) == 0 {
		return nil
	}
	return &st
}
