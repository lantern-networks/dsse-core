package wfpstate

import (
	"encoding/binary"
	"os"
	"regexp"
	"strings"
	"testing"
)

// --- the cross-language layout guard -------------------------------------------------------------------
//
// The Go decoder and the C header describe ONE memory layout. Nothing in the build makes them agree: the
// driver is compiled by the WDK on Windows and this package is compiled anywhere, so a field inserted into
// DSSE_STATS would leave the decoder reading the wrong bytes and reporting a plausible wrong answer about
// whether a machine has a network. This test re-derives the offsets from the header itself.

var cFieldRE = regexp.MustCompile(`^\s*(unsigned\s+int|unsigned\s+short|unsigned\s+char|int|short|char)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;`)

// parseCStructOffsets returns field name -> byte offset for a byte-packed (pshpack1) C struct in src.
func parseCStructOffsets(t *testing.T, src, structName string) (map[string]int, int) {
	t.Helper()
	start := strings.Index(src, "typedef struct _"+structName)
	if start < 0 {
		t.Fatalf("struct %s not found in the header", structName)
	}
	end := strings.Index(src[start:], "} "+structName+";")
	if end < 0 {
		t.Fatalf("end of struct %s not found", structName)
	}
	body := src[start : start+end]

	sizes := map[string]int{
		"unsigned int": 4, "int": 4,
		"unsigned short": 2, "short": 2,
		"unsigned char": 1, "char": 1,
	}
	offsets := map[string]int{}
	off := 0
	for _, line := range strings.Split(body, "\n") {
		// Strip block comments so a commented-out field is not counted.
		if i := strings.Index(line, "/*"); i >= 0 {
			line = line[:i]
		}
		m := cFieldRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		typ := strings.Join(strings.Fields(m[1]), " ")
		size, ok := sizes[typ]
		if !ok {
			t.Fatalf("unhandled C type %q in %s", typ, structName)
		}
		offsets[m[2]] = off
		off += size
	}
	return offsets, off
}

func TestWFPStatsLayoutMatchesTheDriverHeader(t *testing.T) {
	raw, err := os.ReadFile("../driver/dsse_wfp.h")
	if err != nil {
		t.Fatalf("read driver header: %v", err)
	}
	src := string(raw)

	offsets, size := parseCStructOffsets(t, src, "DSSE_STATS")
	// Guard the guard: if the parser silently matched nothing, every comparison below would vacuously pass.
	if len(offsets) < 14 {
		t.Fatalf("header parser found only %d fields in DSSE_STATS — the parser is broken, not the code", len(offsets))
	}

	for _, tc := range []struct {
		field string
		want  int
	}{
		{"PolicyArmed", OffPolicyArmed},
		{"PolicyProxyPid", OffPolicyProxyPID},
		{"PolicyLocalPort", OffPolicyLocalPort},
		{"PolicyObserveOnly", OffPolicyObserveOnly},
		{"OwnerPresent", OffOwnerPresent},
		{"OwnerDisarmOnExit", OffOwnerDisarmOnExit},
		{"Version", OffVersion},
	} {
		got, ok := offsets[tc.field]
		if !ok {
			t.Fatalf("DSSE_STATS has no field %s — the header and this decoder have diverged", tc.field)
		}
		if got != tc.want {
			t.Errorf("%s: header says offset %d, decoder uses %d", tc.field, got, tc.want)
		}
	}
	if size != StatsV3Size {
		t.Errorf("sizeof(DSSE_STATS) = %d in the header, decoder expects %d", size, StatsV3Size)
	}

	// The version constant must match too: a decoder that accepts an older driver would read the state block
	// out of uninitialised bytes.
	if !strings.Contains(src, "#define DSSE_STATS_VERSION 3") {
		t.Errorf("DSSE_STATS_VERSION in the header is not 3; this decoder requires %d", StatsVersion)
	}
}

// --- decoding ------------------------------------------------------------------------------------------

// statsBuf builds a DSSE_STATS v3 reply.
func statsBuf(version uint32, armed, observe, ownerPresent, disarmOnExit bool, pid uint32, port uint16) []byte {
	b := make([]byte, StatsV3Size)
	binary.LittleEndian.PutUint32(b[OffVersion:], version)
	put32 := func(off int, on bool) {
		if on {
			binary.LittleEndian.PutUint32(b[off:], 1)
		}
	}
	put32(OffPolicyArmed, armed)
	put32(OffOwnerPresent, ownerPresent)
	put32(OffOwnerDisarmOnExit, disarmOnExit)
	binary.LittleEndian.PutUint32(b[OffPolicyProxyPID:], pid)
	binary.LittleEndian.PutUint16(b[OffPolicyLocalPort:], port)
	if observe {
		binary.LittleEndian.PutUint16(b[OffPolicyObserveOnly:], 1)
	}
	return b
}

func TestParseWFPDriverStateRoundTrip(t *testing.T) {
	got, err := Parse(statsBuf(3, true, false, true, true, 4242, 51820))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := State{Armed: true, OwnerPresent: true, DisarmOnExit: true, ProxyPID: 4242, LocalPort: 51820}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got.BlackHole() {
		t.Fatalf("armed with an owner present is steering, not a black hole")
	}
}

// The whole point of the state block: tell "steering" apart from "refusing every connection".
func TestBlackHoleIsArmedWithNoOwner(t *testing.T) {
	s, err := Parse(statsBuf(3, true, false, false, true, 99, 51820))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !s.BlackHole() {
		t.Fatalf("armed with no owner must be a black hole: %+v", s)
	}
	if !strings.Contains(s.String(), "BLACK_HOLE") || !strings.Contains(s.String(), "refused") {
		t.Fatalf("the log line must name the situation, got %q", s.String())
	}
}

// Observe-only is armed but permits every flow. A watchdog that "recovered" it would tear down steering for
// no reason, so it must not read as a black hole.
func TestObserveOnlyIsNotABlackHole(t *testing.T) {
	s, err := Parse(statsBuf(3, true, true, false, true, 7, 51820))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.BlackHole() {
		t.Fatalf("observe-only must never read as a black hole: %+v", s)
	}
}

func TestDisarmedIsNotABlackHole(t *testing.T) {
	s, err := Parse(statsBuf(3, false, false, false, false, 0, 0))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.BlackHole() || s.Armed {
		t.Fatalf("not armed: %+v", s)
	}
}

// "Could not tell" must never decode to "not armed" — a zero value here would make a caller skip recovery on
// a box that is refusing every connection.
func TestUnreadableStatsAreAnErrorNotAZeroValue(t *testing.T) {
	for name, buf := range map[string][]byte{
		"empty":            {},
		"version only":     {3, 0, 0, 0},
		"truncated v3":     statsBuf(3, true, false, false, true, 1, 2)[:StatsV3Size-1],
		"pre-v3 driver":    statsBuf(2, true, false, false, true, 1, 2),
		"v0 (zero buffer)": make([]byte, StatsV3Size),
	} {
		if _, err := Parse(buf); err == nil {
			t.Errorf("%s: expected an error, got a decoded state", name)
		}
	}
}

// A driver NEWER than this agent must still be readable: the struct grows append-only, so refusing it would
// mean a driver upgrade blinds the watchdog that is supposed to survive upgrades.
func TestANewerDriverIsAccepted(t *testing.T) {
	buf := append(statsBuf(4, true, false, false, true, 5, 6), make([]byte, 16)...)
	s, err := Parse(buf)
	if err != nil {
		t.Fatalf("a newer driver must still decode: %v", err)
	}
	if !s.BlackHole() {
		t.Fatalf("state block must decode from a newer driver: %+v", s)
	}
}

// --- disarm verification -------------------------------------------------------------------------------

func TestVerifyDisarmed(t *testing.T) {
	ok := VerifyDisarmed(State{}, nil)
	if !ok.Verified {
		t.Fatalf("a disarmed driver must verify: %+v", ok)
	}

	stillArmed := VerifyDisarmed(State{Armed: true, LocalPort: 51820}, nil)
	if stillArmed.Verified {
		t.Fatalf("a still-armed driver must NOT verify")
	}
	if !strings.Contains(stillArmed.Reason, "still reports") {
		t.Fatalf("reason must say what is wrong, got %q", stillArmed.Reason)
	}

	// The case that matters most: the check itself failed. Treating that as success would restore the exact
	// false confidence the verification was added to remove.
	unknown := VerifyDisarmed(State{}, os.ErrNotExist)
	if unknown.Verified {
		t.Fatalf("an unreadable driver must not be reported as disarmed")
	}
	if !strings.Contains(unknown.Reason, "unknown") {
		t.Fatalf("reason must say it is unknown, got %q", unknown.Reason)
	}
}
