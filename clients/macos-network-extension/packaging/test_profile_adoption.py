"""Exercise generated installer adoption in a disposable directory only."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("build_macos_ne_pkg.sh").read_text()
FUNCTIONS = SCRIPT[SCRIPT.index("profile_adoption_refuse() {"):SCRIPT.index('adopt_artefacts_from_beside_the_package "${1:-}"')]
DERIVE_FUNCTION = SCRIPT[SCRIPT.index("dsse_profile_issued_at() {"):SCRIPT.index("# ★ STASH THIS PACKAGE AS ROLLBACK MATERIAL")]

def profile(tenant, revision):
    payload = json.dumps({"tenant_id": tenant, "revision": revision}).encode()
    return json.dumps({"payload_b64": base64.b64encode(payload).decode()})

class AdoptionTest(unittest.TestCase):
    def run_case(self, current, supplied, token=True, key=True, verifier_accepts=True, verifier_present=True):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        current_dir, sidecar, scripts = root / "current", root / "sidecar", root / "scripts"
        current_dir.mkdir(); sidecar.mkdir(); scripts.mkdir()
        (current_dir / "install_profile.json").write_text(current)
        (current_dir / "agent_config.json").write_text("existing-good-config")
        (current_dir / "interception-root.pem").write_text("existing-good-root")
        (current_dir / "enrolment_token.txt").write_text("existing-fixture-token")
        (current_dir / "device_identity_pointer.json").write_text("fixture-identity")
        (sidecar / "install_profile.json").write_text(supplied)
        if token: (sidecar / "enrolment_token.txt").write_text("new-fixture-token")
        if key: (sidecar / "profile_signing_key.txt").write_text("fixture-public-key")
        if verifier_present:
            verifier = scripts / "dsse-profileverify"
            verifier.write_text("#!/bin/sh\nexit %d\n" % (0 if verifier_accepts else 1))
            verifier.chmod(0o755)
        harness = 'set -e\nCONFIG_DIR="$1"\nCONFIG="$1/agent_config.json"\nsecurity() { exit 99; }\n' + FUNCTIONS + '\nadopt_artefacts_from_beside_the_package "$2/package.pkg"\n'
        result = subprocess.run(["/bin/bash", "-c", harness, str(scripts / "preinstall"), str(current_dir), str(sidecar)], capture_output=True, text=True)
        return result, current_dir

    def test_unreadable_current_preserves_existing_files(self):
        result, root = self.run_case("{broken", profile("tenant", 2))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((root / "install_profile.json").read_text(), "{broken")
        self.assertEqual((root / "device_identity_pointer.json").read_text(), "fixture-identity")
        self.assertFalse(list(root.glob("*.replaced-*")))

    def test_missing_key_is_rejected_before_moving_files(self):
        original = profile("tenant", 1)
        result, root = self.run_case(original, profile("tenant", 2), key=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((root / "install_profile.json").read_text(), original)
        self.assertFalse(list(root.glob("*.replaced-*")))

    def test_same_organization_retains_identity_and_token(self):
        result, root = self.run_case(profile("tenant", 1), profile("tenant", 2), token=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / "enrolment_token.txt").read_text(), "existing-fixture-token")
        self.assertEqual((root / "device_identity_pointer.json").read_text(), "fixture-identity")
        self.assertEqual((root / "install_profile.json").read_text(), profile("tenant", 2))

    def test_same_organization_uses_new_token_and_keeps_identity(self):
        result, root = self.run_case(profile("tenant", 1), profile("tenant", 2), token=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / "enrolment_token.txt").read_text(), "new-fixture-token")
        self.assertEqual((root / "device_identity_pointer.json").read_text(), "fixture-identity")

    def test_other_organization_requires_new_token(self):
        original = profile("tenant", 1)
        result, root = self.run_case(original, profile("other", 2), token=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((root / "install_profile.json").read_text(), original)
        self.assertFalse(list(root.glob("*.replaced-*")))

    def test_invalid_signature_preserves_existing_profile_config_and_root(self):
        original = profile("tenant", 1)
        result, root = self.run_case(original, profile("tenant", 2), verifier_accepts=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((root / "install_profile.json").read_text(), original)
        self.assertEqual((root / "agent_config.json").read_text(), "existing-good-config")
        self.assertEqual((root / "interception-root.pem").read_text(), "existing-good-root")
        self.assertFalse(list(root.glob("*.replaced-*")))

    def test_missing_verifier_preserves_existing_profile(self):
        original = profile("tenant", 1)
        result, root = self.run_case(original, profile("tenant", 2), verifier_present=False)
        # A missing packaged verifier is also a refusal, before adoption.
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((root / "install_profile.json").read_text(), original)


class DerivedConfigTest(unittest.TestCase):
    def test_postinstall_stops_before_startup_on_rejected_profile(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "bin").mkdir()
        (root / "install_profile.json").write_text(profile("tenant", 2))
        (root / "profile_signing_key.txt").write_text("fixture-public-key")
        (root / "enrolment_token.txt").write_text("fixture-token")
        (root / "agent_config.json").write_text("existing-good-config")
        verifier = root / "bin" / "dsse-profileverify"
        verifier.write_text("#!/bin/sh\nexit 1\n")
        verifier.chmod(0o755)
        postinstall = SCRIPT.split('cat > "$scripts/postinstall" <<\'POST\'\n', 1)[1].split("\nPOST\n", 1)[0]
        prefix = postinstall.split("\nderive_config_from_profile\n", 1)[0] + "\nderive_config_from_profile\n"
        prefix = prefix.replace('CONFIG_DIR="/Library/Application Support/Dsse"',
                                'CONFIG_DIR="' + str(root) + '"')
        # The real postinstall prefix includes set -eu, rollback stash and the exact startup gate.
        # No PackageKit or system operation is reached: no package path is passed to the stash.
        script = root / "postinstall-prefix"
        script.write_text(prefix + '\nprintf "STARTED" > "' + str(root / "started") + '"\n')
        result = subprocess.run(["/bin/sh", str(script)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "started").exists())
        self.assertEqual((root / "agent_config.json").read_text(), "existing-good-config")

    def run_failed_derivation(self, *, token=True):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "bin").mkdir()
        (root / "install_profile.json").write_text(profile("tenant", 2))
        (root / "profile_signing_key.txt").write_text("fixture-public-key")
        (root / "agent_config.json").write_text("existing-good-config")
        (root / "deployment-anchor.pem").write_text("existing-good-anchor")
        (root / "network_extension_steering_rules.json").write_text("existing-good-rules")
        if token:
            (root / "enrolment_token.txt").write_text("fixture-token")
        verifier = root / "bin" / "dsse-profileverify"
        verifier.write_text("#!/bin/sh\nexit 1\n")
        verifier.chmod(0o755)
        harness = ('set -e\nCONFIG_DIR="$1"\n' + DERIVE_FUNCTION
                   + '\nderive_config_from_profile\necho STARTED\n')
        result = subprocess.run(["/bin/bash", "-c", harness, "postinstall-test", str(root)],
                                capture_output=True, text=True)
        return result, root

    def test_rejected_signature_keeps_last_good_config_and_authorities(self):
        result, root = self.run_failed_derivation()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((root / "agent_config.json").read_text(), "existing-good-config")
        self.assertEqual((root / "deployment-anchor.pem").read_text(), "existing-good-anchor")
        self.assertEqual((root / "network_extension_steering_rules.json").read_text(), "existing-good-rules")
        self.assertFalse(list(root.glob("*.rederived-*")))
        self.assertNotIn("STARTED", result.stdout)

    def test_missing_token_keeps_last_good_config_and_authorities(self):
        result, root = self.run_failed_derivation(token=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((root / "agent_config.json").read_text(), "existing-good-config")
        self.assertEqual((root / "deployment-anchor.pem").read_text(), "existing-good-anchor")
        self.assertEqual((root / "network_extension_steering_rules.json").read_text(), "existing-good-rules")
        self.assertFalse(list(root.glob("*.rederived-*")))
        self.assertNotIn("STARTED", result.stdout)

    def test_verified_derivation_publishes_complete_config_then_allows_start(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "bin").mkdir()
        signed = {"issued_at": "2026-10-23T00:00:00Z", "organization": {"tenant_id": "tenant"},
                  "transport_url": "https://agent.example.test",
                  "deployment": {"anchor_pem": "new-fixture-anchor"}}
        (root / "install_profile.json").write_text(json.dumps({"payload_b64": base64.b64encode(
            json.dumps(signed).encode()).decode()}))
        (root / "profile_signing_key.txt").write_text("fixture-public-key")
        (root / "enrolment_token.txt").write_text("fixture-token")
        (root / "agent_config.json").write_text("existing-good-config")
        (root / "deployment-anchor.pem").write_text("existing-good-anchor")
        (root / "network_extension_steering_rules.json").write_text("existing-good-rules")
        (root / "bin" / "verified_payload.json").write_text(json.dumps(signed))
        verifier = root / "bin" / "dsse-profileverify"
        verifier.write_text('#!/bin/sh\ncat "$(dirname "$0")/verified_payload.json"\n')
        verifier.chmod(0o755)
        harness = ('set -e\nCONFIG_DIR="$1"\n' + DERIVE_FUNCTION
                   + '\nderive_config_from_profile\necho STARTED\n')
        result = subprocess.run(["/bin/bash", "-c", harness, "postinstall-test", str(root)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("STARTED", result.stdout)
        self.assertEqual(json.loads((root / "agent_config.json").read_text())["edge_url"],
                         "https://agent.example.test")
        self.assertEqual((root / "deployment-anchor.pem").read_text(), "new-fixture-anchor\n")
        self.assertEqual(json.loads((root / "network_extension_steering_rules.json").read_text())
                         ["tenant_id"], "tenant")
        self.assertEqual(json.loads((root / ".install_profile.verified.json").read_text()), signed)
        self.assertTrue((root / "derived_by.txt").is_file())
        self.assertFalse(list(root.glob(".derive.*")))
        backups = list(root.glob("agent_config.json.rederived-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "existing-good-config")
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)

    def test_invalid_verified_payload_keeps_existing_files_and_does_not_start(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "bin").mkdir()
        signed = {"issued_at": "2026-10-23T00:00:00Z", "organization": {"tenant_id": "tenant"},
                  "transport_url": "https://agent.example.test", "deployment": {
                      "exact_https_passthrough_endpoints": [{"hostname": "*.bad.example", "addresses": ["203.0.113.1"]}]}}
        (root / "install_profile.json").write_text(json.dumps({"payload_b64": base64.b64encode(
            json.dumps(signed).encode()).decode()}))
        (root / "profile_signing_key.txt").write_text("fixture-public-key")
        (root / "enrolment_token.txt").write_text("fixture-token")
        for name, value in (("agent_config.json", "good-config"),
                            ("deployment-anchor.pem", "good-anchor"),
                            ("network_extension_steering_rules.json", "good-rules")):
            (root / name).write_text(value)
        (root / "bin" / "verified_payload.json").write_text(json.dumps(signed))
        verifier = root / "bin" / "dsse-profileverify"
        verifier.write_text('#!/bin/sh\ncat "$(dirname "$0")/verified_payload.json"\n')
        verifier.chmod(0o755)
        harness = ('set -e\nCONFIG_DIR="$1"\n' + DERIVE_FUNCTION
                   + '\nderive_config_from_profile\necho STARTED\n')
        result = subprocess.run(["/bin/bash", "-c", harness, "postinstall-test", str(root)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("STARTED", result.stdout)
        self.assertEqual((root / "agent_config.json").read_text(), "good-config")
        self.assertEqual((root / "deployment-anchor.pem").read_text(), "good-anchor")
        self.assertEqual((root / "network_extension_steering_rules.json").read_text(), "good-rules")
        self.assertFalse(list(root.glob(".derive.*")))

if __name__ == "__main__":
    unittest.main()
