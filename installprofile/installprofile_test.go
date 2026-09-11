package installprofile

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// signProfile signs an InstallProfile into an Envelope JSON with a fresh dev signer, returning the envelope
// bytes and the pinned public key hex a consumer verifies against.
func signProfile(t *testing.T, p InstallProfile) (envJSON []byte, pubHex string) {
	t.Helper()
	if p.Kind == "" {
		p.Kind = ProfileKind // valid profiles carry the kind discriminator
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true) // dev-ephemeral key
	if err != nil || signer == nil {
		t.Fatalf("signer: %v", err)
	}
	env, err := signer.Sign(p, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal env: %v", err)
	}
	return b, signer.PublicKeyHex()
}

func TestLoad_ValidSigned_AppliesAndDefaults(t *testing.T) {
	bq := false
	in := InstallProfile{
		Version: 3, TenantID: "acme", GroupID: "developers",
		TransportURL: "https://edge.acme:18543",
		Enroll:       EnrollSpec{Mode: "mdm"},
		Backend:      BackendWFP,
		BypassApps:   []string{"example-app"},
		BlockQUIC:    &bq, // explicitly false — must be honored, not overwritten by default(true)
		Captive:      CaptiveSpec{TimeoutSec: 300},
	}
	env, pub := signProfile(t, in)

	got, verified, err := Load(env, pub)
	if err != nil || !verified {
		t.Fatalf("expected verified, got verified=%v err=%v", verified, err)
	}
	if got.TenantID != "acme" || got.GroupID != "developers" || got.TransportURL != "https://edge.acme:18543" {
		t.Fatalf("identity fields lost: %+v", got)
	}
	if got.Captive.TimeoutSec != 300 {
		t.Fatalf("captive timeout = %d, want 300", got.Captive.TimeoutSec)
	}
	if got.BlockQUIC == nil || *got.BlockQUIC != false {
		t.Fatalf("explicit block_quic=false was not honored: %+v", got.BlockQUIC)
	}
	if got.Posture != PostureFailClosed { // unset posture => fail-closed
		t.Fatalf("posture = %q, want fail-closed", got.Posture)
	}
	if got.StartMode != StartAuto || got.DNSListen != "127.0.0.1:53" {
		t.Fatalf("unset fields not defaulted: %+v", got)
	}
}

func TestLoad_Tampered_FallsBackToSafeDefaults(t *testing.T) {
	env, pub := signProfile(t, InstallProfile{TenantID: "acme", Posture: PostureFailOpen, AckFailOpen: true})
	// Flip a byte inside the base64 payload to simulate tampering.
	var e agentpolicy.Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	if len(e.PayloadB64) > 10 {
		b := []byte(e.PayloadB64)
		if b[5] == 'A' {
			b[5] = 'B'
		} else {
			b[5] = 'A'
		}
		e.PayloadB64 = string(b)
	}
	tampered, _ := json.Marshal(e)

	got, verified, err := Load(tampered, pub)
	if verified || err == nil {
		t.Fatalf("tampered profile must not verify: verified=%v err=%v", verified, err)
	}
	if got.Posture != PostureFailClosed || got.FailOpenEnabled() {
		t.Fatalf("tampered fail-open must fall back to fail-closed, got %+v", got)
	}
	if got.TransportURL != "" || len(got.BypassApps) != 0 {
		t.Fatalf("safe default must carry no transport/bypass: %+v", got)
	}
}

func TestLoad_WrongKey_FallsBack(t *testing.T) {
	env, _ := signProfile(t, InstallProfile{TenantID: "acme"})
	other, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	_, verified, lerr := Load(env, other.PublicKeyHex())
	if verified || lerr == nil {
		t.Fatalf("wrong pinned key must not verify")
	}
}

func TestLoad_UnsignedGarbage_FallsBack(t *testing.T) {
	_, pub := signProfile(t, InstallProfile{TenantID: "acme"})
	for _, bad := range [][]byte{[]byte(`{"not":"an envelope"}`), []byte("garbage"), []byte("")} {
		got, verified, err := Load(bad, pub)
		if verified || err == nil {
			t.Fatalf("garbage must not verify: %q", bad)
		}
		if got.Posture != PostureFailClosed {
			t.Fatalf("garbage must yield fail-closed default")
		}
	}
}

func TestLoad_WrongKind_FallsBack(t *testing.T) {
	// A validly-signed envelope of another kind (same signing key) must NOT be accepted as an install profile.
	env, pub := signProfile(t, InstallProfile{Kind: "dsse_agent_steer_policy.v1", TenantID: "acme", Posture: PostureFailOpen, AckFailOpen: true})
	got, verified, err := Load(env, pub)
	if verified || err == nil {
		t.Fatalf("wrong kind must not verify: verified=%v err=%v", verified, err)
	}
	if got.Posture != PostureFailClosed || got.FailOpenEnabled() {
		t.Fatalf("wrong kind must fall back to fail-closed, got %+v", got)
	}
}

func TestLoad_NoPinnedKey_FallsBack(t *testing.T) {
	env, _ := signProfile(t, InstallProfile{TenantID: "acme"})
	if _, verified, err := Load(env, ""); verified || err == nil {
		t.Fatalf("empty pinned key must fall back")
	}
}

func TestResolve_FailOpenRequiresBothSignals(t *testing.T) {
	cases := []struct {
		posture string
		ack     bool
		want    bool
	}{
		{PostureFailOpen, true, true},   // both => fail-open
		{PostureFailOpen, false, false}, // posture only => fail-closed
		{PostureFailClosed, true, false},
		{"", true, false},
	}
	for _, c := range cases {
		got := InstallProfile{Posture: c.posture, AckFailOpen: c.ack}.resolveEffective()
		if got.FailOpenEnabled() != c.want {
			t.Fatalf("posture=%q ack=%v => failOpen=%v, want %v", c.posture, c.ack, got.FailOpenEnabled(), c.want)
		}
	}
}

func TestResolve_CaptiveClamp(t *testing.T) {
	cases := map[int]int{0: 180, -5: 180, 10: 30, 30: 30, 300: 300, 3600: 3600, 99999: 3600}
	for in, want := range cases {
		got := InstallProfile{Captive: CaptiveSpec{TimeoutSec: in}}.resolveEffective().Captive.TimeoutSec
		if got != want {
			t.Fatalf("captive %d => %d, want %d", in, got, want)
		}
	}
}

func TestResolve_UnknownBackend_DefaultsWFP(t *testing.T) {
	if got := (InstallProfile{Backend: "nonsense"}).resolveEffective(); got.Backend != BackendWFP {
		t.Fatalf("unknown backend => %q, want wfp", got.Backend)
	}
}

// ★★★ A PROFILE THAT SAYS NOTHING KEEPS VIRTUAL MACHINES OFF THE NETWORK (2026-09-01). Every profile issued
// before this field existed says nothing, and on Windows a WSL2 distro was measured egressing to the public
// internet — with no administrator involved — while the agent reported that it was steering. So the absent
// case has to be the one that keeps the promise, and letting them out takes both keys, like fail-open.
func TestVirtualMachineEgressTakesTwoKeys(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      InstallProfile
		want    string
		wantAck bool
	}{
		{"an older profile says nothing", InstallProfile{}, VMEgressBlocked, false},
		{"allowed without the acknowledgement", InstallProfile{VMEgress: VMEgressAllowed}, VMEgressBlocked, false},
		{"the acknowledgement alone", InstallProfile{AckVMEgress: true}, VMEgressBlocked, false},
		{"both", InstallProfile{VMEgress: VMEgressAllowed, AckVMEgress: true}, VMEgressAllowed, true},
		{"a word neither side knows", InstallProfile{VMEgress: "maybe", AckVMEgress: true}, VMEgressBlocked, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.resolveEffective()
			if got.VMEgress != tc.want || got.AckVMEgress != tc.wantAck {
				t.Errorf("resolved to %q/ack=%v, want %q/ack=%v", got.VMEgress, got.AckVMEgress, tc.want, tc.wantAck)
			}
		})
	}
}
