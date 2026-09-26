"""Exercise generated installer adoption in a disposable directory only."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("build_macos_ne_pkg.sh").read_text()
FUNCTIONS = SCRIPT[SCRIPT.index("profile_adoption_refuse() {"):SCRIPT.index('adopt_artefacts_from_beside_the_package "${1:-}"')]

def profile(tenant, revision):
    payload = json.dumps({"tenant_id": tenant, "revision": revision}).encode()
    return json.dumps({"payload_b64": base64.b64encode(payload).decode()})

class AdoptionTest(unittest.TestCase):
    def run_case(self, current, supplied, token=True, key=True):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        current_dir, sidecar = root / "current", root / "sidecar"
        current_dir.mkdir(); sidecar.mkdir()
        (current_dir / "install_profile.json").write_text(current)
        (current_dir / "enrolment_token.txt").write_text("existing-fixture-token")
        (current_dir / "device_identity_pointer.json").write_text("fixture-identity")
        (sidecar / "install_profile.json").write_text(supplied)
        if token: (sidecar / "enrolment_token.txt").write_text("new-fixture-token")
        if key: (sidecar / "profile_signing_key.txt").write_text("fixture-public-key")
        harness = 'set -e\nCONFIG_DIR="$1"\nCONFIG="$1/agent_config.json"\nsecurity() { exit 99; }\n' + FUNCTIONS + '\nadopt_artefacts_from_beside_the_package "$2/package.pkg"\n'
        result = subprocess.run(["/bin/bash", "-c", harness, "adoption-test", str(current_dir), str(sidecar)], capture_output=True, text=True)
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

if __name__ == "__main__":
    unittest.main()
