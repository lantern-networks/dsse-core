package agenttuning

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

func sign(t *testing.T, p TuningPolicy) (envJSON []byte, pubHex string) {
	t.Helper()
	if p.Kind == "" {
		p.Kind = TuningKind
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil || signer == nil {
		t.Fatalf("signer: %v", err)
	}
	env, err := signer.Sign(p, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b, _ := json.Marshal(env)
	return b, signer.PublicKeyHex()
}

var baseline = CaptiveSettings{TimeoutSec: 180, ProbeIntervalSec: 3, DetectHosts: []string{"msftconnecttest.com"}}

func TestLoad_ValidTuning_AppliesAndClamps(t *testing.T) {
	env, pub := sign(t, TuningPolicy{TenantID: "acme", DeviceGroup: "dev", Captive: &CaptiveTuning{
		TimeoutSec: 300, ProbeIntervalSec: 5, DetectHosts: []string{"gstatic.com", " "},
	}})
	p, verified, err := Load(env, pub)
	if err != nil || !verified {
		t.Fatalf("expected verified: verified=%v err=%v", verified, err)
	}
	got := p.ApplyCaptive(baseline)
	if got.TimeoutSec != 300 || got.ProbeIntervalSec != 5 {
		t.Fatalf("tuning not applied: %+v", got)
	}
	if !reflect.DeepEqual(got.DetectHosts, []string{"gstatic.com"}) {
		t.Fatalf("hosts not cleaned/applied: %v", got.DetectHosts)
	}
}

func TestApplyCaptive_ClampsOutOfRange(t *testing.T) {
	cases := []struct {
		inTimeout, wantTimeout int
		inProbe, wantProbe     int
	}{
		{10, 30, 0, 3},         // timeout below min clamps; probe 0 keeps current
		{99999, 3600, 999, 60}, // both above max clamp
		{0, 180, 2, 2},         // timeout 0 keeps current; probe applied
	}
	for _, c := range cases {
		p := TuningPolicy{Captive: &CaptiveTuning{TimeoutSec: c.inTimeout, ProbeIntervalSec: c.inProbe}}
		got := p.ApplyCaptive(baseline)
		if got.TimeoutSec != c.wantTimeout || got.ProbeIntervalSec != c.wantProbe {
			t.Fatalf("in(t=%d p=%d) => (t=%d p=%d), want (t=%d p=%d)", c.inTimeout, c.inProbe, got.TimeoutSec, got.ProbeIntervalSec, c.wantTimeout, c.wantProbe)
		}
	}
}

func TestApplyCaptive_NilCaptive_NoChange(t *testing.T) {
	got := TuningPolicy{TenantID: "acme"}.ApplyCaptive(baseline)
	if !reflect.DeepEqual(got, baseline) {
		t.Fatalf("nil captive must not change settings: %+v", got)
	}
}

func TestLoad_Tampered_KeepsCurrent(t *testing.T) {
	env, pub := sign(t, TuningPolicy{TenantID: "acme", Captive: &CaptiveTuning{TimeoutSec: 300}})
	var e agentpolicy.Envelope
	_ = json.Unmarshal(env, &e)
	b := []byte(e.PayloadB64)
	if b[5] == 'A' {
		b[5] = 'B'
	} else {
		b[5] = 'A'
	}
	e.PayloadB64 = string(b)
	tampered, _ := json.Marshal(e)

	p, verified, err := Load(tampered, pub)
	if verified || err == nil {
		t.Fatalf("tampered must not verify")
	}
	// The zero policy is a no-op overlay — current settings unchanged.
	if got := p.ApplyCaptive(baseline); !reflect.DeepEqual(got, baseline) {
		t.Fatalf("tampered must keep current settings: %+v", got)
	}
}

func TestLoad_WrongKind_Rejected(t *testing.T) {
	env, pub := sign(t, TuningPolicy{Kind: "dsse_install_profile.v1", TenantID: "acme", Captive: &CaptiveTuning{TimeoutSec: 300}})
	if _, verified, err := Load(env, pub); verified || err == nil {
		t.Fatalf("wrong kind must be rejected")
	}
}

func TestLoad_WrongKey_Rejected(t *testing.T) {
	env, _ := sign(t, TuningPolicy{TenantID: "acme"})
	other, _ := agentpolicy.LoadOrGenerateSigner("", true)
	if _, verified, err := Load(env, other.PublicKeyHex()); verified || err == nil {
		t.Fatalf("wrong key must be rejected")
	}
}
