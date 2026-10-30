//go:build darwin

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

func rotationSigner(t *testing.T) *agentpolicy.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.NewSignerFromCrypto(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func writeRotationJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPassFollowsAdoptedPlanKeyWithoutDaemonRestart(t *testing.T) {
	u := passRig(t, "0.2.9")
	u.dryRun = true
	u.followPlanRotation = true
	u.configPath = filepath.Join(filepath.Dir(u.planPath), "agent_config.json")
	u.planPointerPath = filepath.Join(filepath.Dir(u.planPath), "trust_anchor_pointer.json")
	oldKey, newKey := rotationSigner(t), rotationSigner(t)
	u.planKeys = []string{oldKey.PublicKeyHex()}
	writeRotationJSON(t, u.configPath, map[string]any{
		"update_signing_keys":                               u.updateKeys,
		"network_extension_agent_policy_signing_public_key": oldKey.PublicKeyHex(),
	})
	now := time.Now().UTC()
	for _, signer := range []*agentpolicy.Signer{oldKey, newKey} {
		writeRotationJSON(t, u.planPointerPath, map[string]any{"agent_policy_public_keys": []string{signer.PublicKeyHex()}})
		env, err := signer.SignTyped(agentupdate.RolloutPlanEnvelopeType, agentupdate.RolloutPlan{
			SchemaVersion: agentupdate.RolloutPlanSchema, TargetVersion: "0.2.9", GeneratedAt: now.Format(time.RFC3339),
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		writeRotationJSON(t, u.planPath, env)
		got := u.pass(now)
		if got.action != "idle" || strings.Contains(strings.Join(got.notes, "\n"), "rollout frozen:") {
			t.Fatalf("valid plan after key adoption was not usable: %s", got.line())
		}
	}
}

func TestPassDoesNotDowngradeLostPlanTrustToUnsigned(t *testing.T) {
	u := passRig(t, "0.2.9")
	u.dryRun = true
	u.followPlanRotation = true
	u.configPath = filepath.Join(filepath.Dir(u.planPath), "missing-config.json")
	u.planPointerPath = filepath.Join(filepath.Dir(u.planPath), "missing-pointer.json")
	u.planKeys = []string{rotationSigner(t).PublicKeyHex()}
	now := time.Now().UTC()
	writeRotationJSON(t, u.planPath, agentupdate.RolloutPlan{
		SchemaVersion: agentupdate.RolloutPlanSchema, TargetVersion: "0.2.9", GeneratedAt: now.Format(time.RFC3339),
	})
	got := u.pass(now)
	if got.action != "blocked" || !strings.Contains(got.reason, "plan-signing") {
		t.Fatalf("missing trusted key material must block the pass: %s", got.line())
	}
	if len(u.planKeys) != 1 {
		t.Fatal("forgot previous pinned authority")
	}
}

func TestPlanRefreshKeepsExplicitPinOverride(t *testing.T) {
	u := passRig(t, "0.2.9")
	u.dryRun = true
	signer := rotationSigner(t)
	u.planKeys = []string{signer.PublicKeyHex()}
	// Explicit --plan-pin leaves followPlanRotation disabled. Neither a missing
	// config nor a subsequently adopted key may replace that chosen authority.
	u.configPath = filepath.Join(filepath.Dir(u.planPath), "missing-config.json")
	u.planPointerPath = filepath.Join(filepath.Dir(u.planPath), "trust_anchor_pointer.json")
	writeRotationJSON(t, u.planPointerPath, map[string]any{"agent_policy_public_keys": []string{rotationSigner(t).PublicKeyHex()}})
	now := time.Now().UTC()
	env, err := signer.SignTyped(agentupdate.RolloutPlanEnvelopeType, agentupdate.RolloutPlan{
		SchemaVersion: agentupdate.RolloutPlanSchema, TargetVersion: "0.2.9", GeneratedAt: now.Format(time.RFC3339),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	writeRotationJSON(t, u.planPath, env)
	got := u.pass(now)
	if got.action != "idle" || strings.Contains(strings.Join(got.notes, "\n"), "rollout frozen:") {
		t.Fatalf("explicit pin override was not honored: %s", got.line())
	}
	if len(u.planKeys) != 1 || u.planKeys[0] != signer.PublicKeyHex() {
		t.Fatal("explicit pin changed")
	}
}

func TestPlanRefreshRejectsReleaseKeyAsOnlyRotatedPlanKey(t *testing.T) {
	u := passRig(t, "0.2.9")
	u.followPlanRotation = true
	u.planKeys = []string{rotationSigner(t).PublicKeyHex()}
	u.configPath = filepath.Join(filepath.Dir(u.planPath), "agent_config.json")
	u.planPointerPath = filepath.Join(filepath.Dir(u.planPath), "trust_anchor_pointer.json")
	writeRotationJSON(t, u.configPath, map[string]any{"update_signing_keys": u.updateKeys})
	writeRotationJSON(t, u.planPointerPath, map[string]any{"agent_policy_public_keys": u.updateKeys})
	oldKey := u.planKeys[0]
	if err := u.refreshPlanTrust(); err == nil {
		t.Fatal("release key must not replace plan authority")
	}
	if len(u.planKeys) != 1 || u.planKeys[0] != oldKey {
		t.Fatal("lost pinned authority on failed rotation")
	}
}

func TestInitialProvisionedPlanKeyCollisionDoesNotBecomeUnverified(t *testing.T) {
	u := passRig(t, "0.2.9")
	u.followPlanRotation = true
	u.configPath = filepath.Join(filepath.Dir(u.planPath), "agent_config.json")
	u.planPointerPath = filepath.Join(filepath.Dir(u.planPath), "missing-pointer.json")
	writeRotationJSON(t, u.configPath, map[string]any{
		"update_signing_keys":                               u.updateKeys,
		"network_extension_agent_policy_signing_public_key": u.updateKeys[0],
	})
	if err := u.refreshPlanTrust(); err == nil {
		t.Fatal("a configured plan key rejected for collision must not become an unverified plan")
	}
}

func TestInitialAdoptedPlanKeyCollisionDoesNotBecomeUnverified(t *testing.T) {
	u := passRig(t, "0.2.9")
	u.followPlanRotation = true
	u.configPath = filepath.Join(filepath.Dir(u.planPath), "agent_config.json")
	u.planPointerPath = filepath.Join(filepath.Dir(u.planPath), "trust_anchor_pointer.json")
	writeRotationJSON(t, u.configPath, map[string]any{"update_signing_keys": u.updateKeys})
	writeRotationJSON(t, u.planPointerPath, map[string]any{"agent_policy_public_keys": u.updateKeys})
	if err := u.refreshPlanTrust(); err == nil {
		t.Fatal("a colliding adopted key must not silently opt out of plan verification")
	}
}

func TestExplicitPlanPinCollisionDoesNotBecomeUnverified(t *testing.T) {
	u := passRig(t, "0.2.9")
	u.dryRun = true
	u.followPlanRotation = false
	u.planKeys = append([]string(nil), u.updateKeys...)
	u.planSource = "--plan-pin"
	u.separateInitialPlanTrust()
	now := time.Now().UTC()
	writeRotationJSON(t, u.planPath, agentupdate.RolloutPlan{
		SchemaVersion: agentupdate.RolloutPlanSchema, TargetVersion: "0.2.9", GeneratedAt: now.Format(time.RFC3339),
	})
	got := u.pass(now)
	if got.action != "blocked" || !strings.Contains(got.reason, "plan-signing") {
		t.Fatalf("an explicit unusable plan pin must block, not verify no signature: %s", got.line())
	}
}

func TestUnconfiguredLegacyPlanMayRemainUnverified(t *testing.T) {
	u := passRig(t, "0.2.9")
	u.followPlanRotation = true
	u.configPath = filepath.Join(filepath.Dir(u.planPath), "agent_config.json")
	u.planPointerPath = filepath.Join(filepath.Dir(u.planPath), "missing-pointer.json")
	writeRotationJSON(t, u.configPath, map[string]any{"update_signing_keys": u.updateKeys})
	if err := u.refreshPlanTrust(); err != nil {
		t.Fatalf("no configured plan key is the legacy opt-out: %v", err)
	}
	if len(u.planKeys) != 0 {
		t.Fatal("unexpected plan key")
	}
}

func TestPartialPlanKeyCollisionRetainsDistinctAuthority(t *testing.T) {
	u := passRig(t, "0.2.9")
	u.followPlanRotation = true
	u.configPath = filepath.Join(filepath.Dir(u.planPath), "agent_config.json")
	u.planPointerPath = filepath.Join(filepath.Dir(u.planPath), "trust_anchor_pointer.json")
	other := rotationSigner(t).PublicKeyHex()
	writeRotationJSON(t, u.configPath, map[string]any{"update_signing_keys": u.updateKeys})
	writeRotationJSON(t, u.planPointerPath, map[string]any{"agent_policy_public_keys": []string{u.updateKeys[0], other}})
	if err := u.refreshPlanTrust(); err != nil {
		t.Fatalf("usable independent plan key was refused: %v", err)
	}
	if len(u.planKeys) != 1 || u.planKeys[0] != other {
		t.Fatalf("wrong usable plan keys: %v", u.planKeys)
	}
}

func TestPlanTrustDeclarationRecognizesJSONAliasesAndDuplicates(t *testing.T) {
	config := filepath.Join(t.TempDir(), "agent_config.json")
	pointer := filepath.Join(t.TempDir(), "trust_anchor_pointer.json")
	for _, raw := range []string{
		`{"Network_Extension_Agent_Policy_Signing_Public_Key":"configured"}`,
		`{"network_extension_agent_policy_signing_public_key":"","NETWORK_EXTENSION_AGENT_POLICY_SIGNING_PUBLIC_KEY":""}`,
	} {
		if err := os.WriteFile(config, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if !planSigningMaterialDeclared(config, pointer) {
			t.Fatalf("config declaration was mistaken for legacy opt-out: %s", raw)
		}
	}
	if err := os.WriteFile(config, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pointer, []byte(`{"Agent_Policy_Public_Keys":["configured"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if !planSigningMaterialDeclared(config, pointer) {
		t.Fatal("adopted-key alias was mistaken for legacy opt-out")
	}
}
