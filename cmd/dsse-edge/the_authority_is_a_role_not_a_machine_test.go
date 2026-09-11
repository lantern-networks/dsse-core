package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// memoryPersister is the deployment's shared store, standing in for the database.
type memoryPersister struct{ blob []byte }

func (m *memoryPersister) Load() ([]byte, error) { return m.blob, nil }
func (m *memoryPersister) Save(b []byte) error   { m.blob = append([]byte(nil), b...); return nil }

// ★★★ THE AUTHORITY IS A ROLE HELD BY DIFFERENT MACHINES AT DIFFERENT TIMES (2026-09-07, measured on a
// three-region deployment).
//
// Only the LEADING control plane serves the config bundle — the others refuse it outright and name the
// leader. So "the control plane holds the distribution" is true of whichever node leads right now, and
// leadership moves. Kept on local disk, a node that has never led sits at the serial it booted with while the
// fleet is far past it: measured, one control plane held serial 2 while every Edge in every region served 4.
// The moment that node takes leadership, the next certificate an operator adds is numbered from ITS serial,
// lands below the fleet's high-water mark, and is discarded by every Edge as a replay — with the Console
// reporting it added and nothing anywhere disagreeing.
func TestTheAuthorityIsARoleNotAMachine(t *testing.T) {
	seed := string(mustCAPEM(t, "Seed Root CA"))
	shared := &memoryPersister{}

	first, err := openSharedTransportTrustStore(shared, "", seed, 1, nil)
	if err != nil {
		t.Fatalf("open on the node that leads first: %v", err)
	}
	added := string(mustCAPEM(t, "Added Root CA"))
	if _, _, err := first.Add(added); err != nil {
		t.Fatalf("add: %v", err)
	}
	_, advanced := first.Current()
	if advanced <= 1 {
		t.Fatalf("adding a certificate must advance the serial, got %d", advanced)
	}

	// Leadership moves. The node taking over was built from the same compose and booted with the same seed
	// serial — the only thing that can tell it where the fleet has got to is the shared store.
	second, err := openSharedTransportTrustStore(shared, "", seed, 1, nil)
	if err != nil {
		t.Fatalf("open on the node that takes leadership: %v", err)
	}
	pems, serial := second.Current()
	if serial != advanced {
		t.Errorf("the node taking leadership counts from %d, the fleet is at %d — the next certificate it "+
			"issues lands below the fleet's high-water mark and every Edge discards it as a replay",
			serial, advanced)
	}
	if !strings.Contains(pems, "CERTIFICATE") || len(parseAllCerts([]byte(pems))) != 2 {
		t.Errorf("the node taking leadership must hold what the fleet was told, got %d certificate(s)",
			len(parseAllCerts([]byte(pems))))
	}

	// And what it writes is what the other reads: one document, not two.
	var state transportTrustStoreState
	if err := json.Unmarshal(shared.blob, &state); err != nil {
		t.Fatalf("the shared record is unreadable: %v", err)
	}
	if state.Serial != advanced {
		t.Errorf("the shared record is at serial %d, the store says %d", state.Serial, advanced)
	}
}

// The control: the same sequence with each node keeping its own file, which is what the deployment did until
// this. It is not a hypothetical divergence — it was read off a running fleet.
func TestOnItsOwnDiskTheNodeTakingOverCountsFromTheWrongPlace(t *testing.T) {
	seed := string(mustCAPEM(t, "Seed Root CA"))
	leading := filepath.Join(t.TempDir(), "trust.json")
	standby := filepath.Join(t.TempDir(), "trust.json")

	first, err := openTransportTrustStore(leading, seed, 1, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := first.Add(string(mustCAPEM(t, "Added Root CA"))); err != nil {
		t.Fatalf("add: %v", err)
	}
	_, fleet := first.Current()

	second, err := openTransportTrustStore(standby, seed, 1, nil)
	if err != nil {
		t.Fatalf("open on the standby: %v", err)
	}
	if _, behind := second.Current(); behind >= fleet {
		t.Fatalf("this control is meant to demonstrate the divergence the shared store removes: the standby "+
			"read %d against the fleet's %d", behind, fleet)
	}
}

// ★★★ AND THE MOVE ITSELF MUST NOT TAKE THE AUTHORITY BACKWARDS (2026-09-07, measured the first time the
// shared store ran on a deployment that already had a distribution: every control plane read serial 2 while
// every Edge in every region served 4). The shared record does not exist yet on such a deployment, so a fresh
// seed starts at the flag's serial — below the fleet — and the next certificate an operator adds is numbered
// from there and discarded by everyone as a replay.
func TestTheMoveIntoTheSharedStoreOnlyEverRaisesTheSerial(t *testing.T) {
	seed := string(mustCAPEM(t, "Seed Root CA"))

	// What this node was serving before the move: two anchors at serial 9.
	onDisk := filepath.Join(t.TempDir(), "transport-trust.json")
	live, err := openTransportTrustStore(onDisk, seed, 9, nil)
	if err != nil {
		t.Fatalf("open the record this node carried: %v", err)
	}
	if _, _, err := live.Add(string(mustCAPEM(t, "Added Root CA"))); err != nil {
		t.Fatalf("add: %v", err)
	}
	_, fleet := live.Current()

	shared := &memoryPersister{}
	moved, err := openSharedTransportTrustStore(shared, onDisk, seed, 1, nil)
	if err != nil {
		t.Fatalf("open after the move: %v", err)
	}
	pems, serial := moved.Current()
	if serial != fleet {
		t.Errorf("the move restarted the authority at %d while the fleet is serving %d — every certificate "+
			"added from here lands below the high-water mark and is discarded as a replay", serial, fleet)
	}
	if len(parseAllCerts([]byte(pems))) != 2 {
		t.Errorf("the move must carry the set forward too, got %d certificate(s)", len(parseAllCerts([]byte(pems))))
	}

	// And a node whose own record is BEHIND cannot pull the shared one down — the move does not depend on
	// which node happens to start first.
	behindDisk := filepath.Join(t.TempDir(), "transport-trust.json")
	if _, err := openTransportTrustStore(behindDisk, seed, 2, nil); err != nil {
		t.Fatalf("open a node that never led: %v", err)
	}
	late, err := openSharedTransportTrustStore(shared, behindDisk, seed, 1, nil)
	if err != nil {
		t.Fatalf("open the node that starts later: %v", err)
	}
	if _, after := late.Current(); after != fleet {
		t.Errorf("a node carrying an older record took the shared store from %d to %d", fleet, after)
	}
}
