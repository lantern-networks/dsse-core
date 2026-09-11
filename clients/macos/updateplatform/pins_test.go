package updateplatform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	keyA = "1111111111111111111111111111111111111111111111111111111111111111"
	keyB = "2222222222222222222222222222222222222222222222222222222222222222"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent_config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadPinsReadsBothAuthorities(t *testing.T) {
	p := writeConfig(t, `{"update_signing_keys":["`+strings.ToUpper(keyA)+`"],"network_extension_agent_policy_signing_public_key":"`+keyB+`"}`)
	pins, err := LoadPins(p)
	if err != nil {
		t.Fatalf("LoadPins: %v", err)
	}
	// Case-normalized, so a config written in upper case is not silently a different key from the same one in
	// lower case — which would make the separation check below miss an overlap.
	if len(pins.Update) != 1 || pins.Update[0] != keyA {
		t.Errorf("update = %v, want [%s]", pins.Update, keyA)
	}
	if len(pins.Plan) != 1 || pins.Plan[0] != keyB {
		t.Errorf("plan = %v, want [%s]", pins.Plan, keyB)
	}
}

// ★ The defect this whole file exists for: a device with no keys must be distinguishable from a device that is
// pinned. Absent is a legitimate answer here (the caller decides what to do about it) but it must not be an
// ERROR-free path that looks like success with keys.
func TestLoadPinsAbsentIsEmptyNotAnError(t *testing.T) {
	pins, err := LoadPins(writeConfig(t, `{"edge_url":"https://e:9443"}`))
	if err != nil {
		t.Fatalf("a config without keys should load cleanly and report none: %v", err)
	}
	if len(pins.Update) != 0 || len(pins.Plan) != 0 {
		t.Errorf("want no keys, got %+v", pins)
	}
}

func TestLoadPinsRefusesSharedKey(t *testing.T) {
	_, err := LoadPins(writeConfig(t, `{"update_signing_keys":["`+keyA+`"],"network_extension_agent_policy_signing_public_key":"`+strings.ToUpper(keyA)+`"}`))
	if err == nil {
		t.Fatal("reusing one key for both authorities must be refused: the key that authorises running code " +
			"would also authorise the plan that lifts a freeze")
	}
	if !strings.Contains(err.Error(), "RUNNING CODE") {
		t.Errorf("the refusal must say why, got: %v", err)
	}
}

func TestLoadPinsRefusesMalformedKeys(t *testing.T) {
	for name, body := range map[string]string{
		"not hex":   `{"update_signing_keys":["zzzz"]}`,
		"truncated": `{"update_signing_keys":["1111"]}`,
		"too long":  `{"update_signing_keys":["` + keyA + keyA + `"]}`,
	} {
		if _, err := LoadPins(writeConfig(t, body)); err == nil {
			t.Errorf("[%s] must be refused — a device that verifies nothing while appearing configured is the "+
				"worst of the three states", name)
		}
	}
}

func TestLoadPinsSurfacesUnreadableAndUnparseable(t *testing.T) {
	if _, err := LoadPins(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a missing agent config must be an error, not silently zero keys")
	}
	if _, err := LoadPins(writeConfig(t, `{not json`)); err == nil {
		t.Error("an unparseable agent config must be an error, not silently zero keys")
	}
}

func TestLoadPinsDeduplicatesAndIgnoresBlanks(t *testing.T) {
	pins, err := LoadPins(writeConfig(t, `{"update_signing_keys":["`+keyA+`","  `+keyA+`  ",""]}`))
	if err != nil {
		t.Fatalf("LoadPins: %v", err)
	}
	if len(pins.Update) != 1 {
		t.Errorf("want the key once, got %v", pins.Update)
	}
}

// ★ The plan keys are the UNION of the provisioned pin and everything adopted from a signed trust bundle —
// the same set DsseSignedAgentPolicy verifies with ([pinnedPublicKeyHex] + alsoAccept). Anything narrower is a
// validator stricter than the verifier, which is how this went wrong twice: reading only the adopted set
// reported "no plan key" on a device that verifies policy every minute against its pin.
func TestPlanKeysAreTheUnionOfPinAndAdopted(t *testing.T) {
	dir := t.TempDir()
	pointer := filepath.Join(dir, "trust_anchor_pointer.json")
	cfg := filepath.Join(dir, "agent_config.json")
	if err := os.WriteFile(cfg, []byte(`{"update_signing_keys":["`+keyA+`"],"network_extension_agent_policy_signing_public_key":"`+keyB+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rotated := "3333333333333333333333333333333333333333333333333333333333333333"
	if err := os.WriteFile(pointer, []byte(`{"agent_policy_public_keys":["`+rotated+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, source := PlanKeys(pointer, cfg, nil)
	// Both, because a rotation is an OVERLAP: the new key is published and adopted while the old one is still
	// signing. Dropping either end of that turns a routine rotation into a fleet that cannot read its plan.
	if len(keys) != 2 || !containsAll(keys, keyB, rotated) {
		t.Fatalf("plan keys = %v, want both the pin %s and the adopted %s", keys, keyB, rotated)
	}
	if !strings.Contains(source, "pin") || !strings.Contains(source, "adopted") {
		t.Errorf("source = %q, must name both origins — they have different lifetimes and different fixes", source)
	}
}

// The ordinary state in a deployment that publishes nothing for adoption: the pin alone, and it must WORK.
// Reporting "no plan key" here was the live defect.
func TestPlanKeysWorkFromThePinAlone(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent_config.json")
	if err := os.WriteFile(cfg, []byte(`{"network_extension_agent_policy_signing_public_key":"`+keyB+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, source := PlanKeys(filepath.Join(dir, "absent.json"), cfg, nil)
	if len(keys) != 1 || keys[0] != keyB {
		t.Fatalf("plan keys = %v, want the provisioned pin", keys)
	}
	if !strings.Contains(source, "pin") {
		t.Errorf("source = %q, must say the key came from the pin", source)
	}
}

// ★ An ECDSA-P256 pin — what the config-signing key became in the HSM. Rejecting this shape is the bug that
// made the freeze unverifiable while the device was verifying policy with the very same key.
func TestPlanKeysAcceptAnECDSAP256Pin(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent_config.json")
	p256 := "045dfd4ea0551351709095846afc1e241b74ad4ab5fa91ed02905b6d2722cbd00e65571248acb788ece8d8801a8e5a643be2758096baa7babd79f4e5c4527e3315"
	if err := os.WriteFile(cfg, []byte(`{"network_extension_agent_policy_signing_public_key":"`+p256+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, source := PlanKeys(filepath.Join(dir, "absent.json"), cfg, nil)
	if len(keys) != 1 || keys[0] != p256 {
		t.Fatalf("plan keys = %v (source %q), want the P-256 pin accepted", keys, source)
	}
}

func TestPlanKeysReportsWhenThereIsNoKeyAnywhere(t *testing.T) {
	dir := t.TempDir()
	pointer := filepath.Join(dir, "trust_anchor_pointer.json")
	cfg := filepath.Join(dir, "agent_config.json")
	if err := os.WriteFile(pointer, []byte(`{"agent_policy_public_keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte(`{"update_signing_keys":["`+keyA+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, source := PlanKeys(pointer, cfg, nil)
	if len(keys) != 0 {
		t.Fatalf("want no keys, got %v", keys)
	}
	// ★ THIS TEST USED TO REQUIRE THE WORD "frozen" (2026-08-13). It pinned a claim the product does not make:
	// agentupdate.LoadRollout with no trusted keys accepts a bare plan UNVERIFIED, deliberately, so that a lab
	// Edge without a signer does not halt every machine the moment a plan appears. The message said the device
	// holds itself frozen; an operator reading it believed the fleet was fail-frozen while a couriered plan was
	// being accepted. The test agreed with the message, so nothing disagreed with either.
	if strings.Contains(strings.ToLower(source), "frozen") {
		t.Errorf("source = %q — this device does NOT freeze without a plan key, and saying so is the defect", source)
	}
	if !strings.Contains(source, "UNVERIFIED") {
		t.Errorf("source = %q, must say what actually happens: the plan is accepted unverified", source)
	}
}

// A pointer carrying a key shape this build cannot use must SAY so — it is a different situation from an empty
// one, and the only one of the two that is a defect.
func TestPlanKeysNameAnUnusableAdoptedKey(t *testing.T) {
	dir := t.TempDir()
	pointer := filepath.Join(dir, "trust_anchor_pointer.json")
	cfg := filepath.Join(dir, "agent_config.json")
	if err := os.WriteFile(pointer, []byte(`{"agent_policy_public_keys":["nonsense"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, source := PlanKeys(pointer, cfg, nil)
	if !strings.Contains(source, "cannot use") {
		t.Errorf("source = %q, must distinguish an unusable adopted key from none at all", source)
	}
}

func containsAll(xs []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, x := range xs {
			if x == w {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ★ The separation must survive ROTATION, not only provisioning. LoadPins refuses a config whose update key is
// also its plan key — one key signing both the release and the halt means the party a freeze exists to stop is
// the party who signs the freeze. Adopted keys arrive later through the trust bundle and rotate there, and
// nothing re-checked them.
func TestAnAdoptedPlanKeyThatIsAlsoTheUpdateKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	updateKey := strings.Repeat("ab", 32)
	planKey := strings.Repeat("cd", 32)

	cfg := filepath.Join(dir, "agent_config.json")
	if err := os.WriteFile(cfg, []byte(`{"update_signing_keys":["`+updateKey+`"],"agent_policy_public_keys":["`+planKey+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The trust bundle later adopts the UPDATE key as a plan key — a rotation, not an attack, and it must not
	// silently dissolve the separation.
	pointer := filepath.Join(dir, "trust_anchor.json")
	if err := os.WriteFile(pointer, []byte(`{"agent_policy_public_keys":["`+strings.ToUpper(updateKey)+`","`+planKey+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, src := PlanKeys(pointer, cfg, nil)
	for _, k := range keys {
		if strings.EqualFold(k, updateKey) {
			t.Fatalf("the update key was adopted as a plan key: %v", keys)
		}
	}
	if !strings.Contains(src, "REFUSED") {
		t.Errorf("the refusal must be said out loud, got %q", src)
	}
	if len(keys) == 0 {
		t.Error("the other adopted key must still be usable — dropping one bad key must not disarm the freeze entirely")
	}
}

// ★★ A DEVICE PINNED BY FLAG IS CONFIGURED, NOT UNKNOWN (2026-08-13, thirtieth review #8). The refusal of
// adopted plan keys is correct when this device cannot tell what its release key is. It fired whenever the
// CONFIG's update list was empty — which is also the state of a healthy device whose key came from
// --update-pin. That device had every rotation key dropped and was told its config could not be read, which
// was false, and then froze the next time the plan key rotated.
func TestAnUpdateKeySuppliedByFlagIsNotAnUnknownOne(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent_config.json")
	pointer := filepath.Join(dir, "trust_anchor_pointer.json")
	adopted := strings.Repeat("cc", 32)
	flagKey := strings.Repeat("aa", 32)

	// A config with NO update key — exactly what a device driven by --update-pin has — and an adopted plan key.
	if err := os.WriteFile(cfg, []byte(`{"edge_url":"http://e"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pointer, []byte(`{"agent_policy_public_keys":["`+adopted+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, source := PlanKeys(pointer, cfg, []string{flagKey})
	if len(keys) != 1 || keys[0] != adopted {
		t.Fatalf("the adopted plan key was dropped (%v) — this device freezes the next time the plan key "+
			"rotates: %s", keys, source)
	}
	if strings.Contains(source, "could not be read") {
		t.Fatalf("the diagnosis is untrue and sends the operator to the wrong file: %s", source)
	}
}

// ★ AND THE FLAG GOES THROUGH THE SEPARATION CHECK (the twenty-ninth review's #18, second half). LoadPins
// refuses a CONFIG whose update key is its plan key; a key supplied by flag bypassed that, so the one pairing
// the rule exists to prevent — the party a freeze stops also signing the freeze — was reachable from the
// command line.
func TestAFlagSuppliedUpdateKeyCannotAlsoBeThePlanKey(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent_config.json")
	pointer := filepath.Join(dir, "trust_anchor_pointer.json")
	shared := strings.Repeat("dd", 32)

	if err := os.WriteFile(cfg, []byte(`{"edge_url":"http://e"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pointer, []byte(`{"agent_policy_public_keys":["`+shared+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, source := PlanKeys(pointer, cfg, []string{shared})
	if len(keys) != 0 {
		t.Fatalf("the key that signs releases was accepted as the one that signs the halt: %v", keys)
	}
	if !strings.Contains(source, "REFUSED an adopted plan key") {
		t.Fatalf("the refusal must say what it refused and why: %s", source)
	}
}

// The genuinely unknown case still refuses: an unreadable config and no flag means the rule cannot be checked.
func TestAnUnreadableConfigWithNoFlagStillRefusesAdoptedKeys(t *testing.T) {
	dir := t.TempDir()
	pointer := filepath.Join(dir, "trust_anchor_pointer.json")
	if err := os.WriteFile(pointer, []byte(`{"agent_policy_public_keys":["`+strings.Repeat("ee", 32)+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, source := PlanKeys(pointer, filepath.Join(dir, "absent.json"), nil)
	if len(keys) != 0 {
		t.Fatalf("a check that cannot run must not pass: %v", keys)
	}
	if !strings.Contains(source, "REFUSED every adopted plan key") {
		t.Fatalf("got %s", source)
	}
}
