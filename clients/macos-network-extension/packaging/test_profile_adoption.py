"""Exercise generated installer adoption in a disposable directory only."""
import base64
import os
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


RETIRED_GATE = SCRIPT[SCRIPT.index("# ★ A MAC THAT WAS UNINSTALLED HAS NO IDENTITY AND A USED APPROVAL."):SCRIPT.index("refuse() {\n\techo \"\" >&2\n\techo \"REFUSING TO INSTALL: $1\"")]


class ReinstallAfterUninstallTest(unittest.TestCase):
    """A Mac that was uninstalled holds a configuration, no key, and a used approval the uninstaller retired."""

    def run_case(self, retired=True, token_here=False, token_beside=False, same_profile=True,
                 beside_token_text="fresh-token", profile_beside=True, empty_token_mode=None, extra_env=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        current_dir, sidecar, scripts = root / "current", root / "sidecar", root / "scripts"
        current_dir.mkdir(); sidecar.mkdir(); scripts.mkdir()
        (current_dir / "install_profile.json").write_text(profile("tenant", 1))
        (current_dir / "agent_config.json").write_text("existing-config")
        if retired: (current_dir / "enrolment_token.retired-20261115T000000Z.txt").write_text("used-token")
        if token_here: (current_dir / "enrolment_token.txt").write_text(token_here if isinstance(token_here, str) else "token-on-file")
        if empty_token_mode is not None:
            (current_dir / "enrolment_token.txt").write_text("")
            (current_dir / "enrolment_token.txt").chmod(empty_token_mode)
        if token_beside:
            (sidecar / "enrolment_token.txt").write_text(beside_token_text)
            if profile_beside:
                (sidecar / "install_profile.json").write_text(profile("tenant", 1 if same_profile else 2))
                (sidecar / "profile_signing_key.txt").write_text("fixture-public-key")
        verifier = scripts / "dsse-profileverify"
        verifier.write_text("#!/bin/sh\nexit 0\n"); verifier.chmod(0o755)
        harness = ('set -e\nCONFIG_DIR="$1"\nCONFIG="$1/agent_config.json"\nsecurity() { exit 99; }\n' + FUNCTIONS
                   + '\nadopt_artefacts_from_beside_the_package "$2/package.pkg"\n' + RETIRED_GATE + '\necho ARMED\n')
        env = dict(os.environ, **(extra_env or {}))
        result = subprocess.run(["/bin/bash", "-c", harness, str(scripts / "preinstall"), str(current_dir), str(sidecar)], capture_output=True, text=True, env=env)
        return result, current_dir

    def test_nothing_to_enrol_with_is_refused_before_anything_is_armed(self):
        result, root = self.run_case()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("REFUSING TO INSTALL: this Mac was uninstalled", result.stderr)
        self.assertNotIn("ARMED", result.stdout)
        self.assertEqual((root / "agent_config.json").read_text(), "existing-config")

    def test_a_fresh_token_beside_the_same_profile_is_taken(self):
        result, root = self.run_case(token_beside=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ARMED", result.stdout)
        self.assertEqual((root / "enrolment_token.txt").read_text(), "fresh-token")
        self.assertTrue((root / "enrolment_token.retired-20261115T000000Z.txt").exists())

    def test_a_fresh_token_with_a_reissued_profile_is_taken(self):
        result, root = self.run_case(token_beside=True, same_profile=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / "enrolment_token.txt").read_text(), "fresh-token")

    def test_an_upgrade_over_a_working_install_is_not_refused(self):
        result, _ = self.run_case(retired=False, token_here=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ARMED", result.stdout)

    def test_a_token_on_file_is_never_replaced_by_the_same_profiles_sidecar(self):
        result, root = self.run_case(retired=False, token_here=True, token_beside=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / "enrolment_token.txt").read_text(), "token-on-file")

    def test_the_used_token_left_beside_the_package_is_not_a_new_approval(self):
        for same in (True, False):
            with self.subTest(same_profile=same):
                result, root = self.run_case(token_beside=True, same_profile=same, beside_token_text="used-token\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("already used", result.stderr)
                self.assertNotIn("ARMED", result.stdout)
                self.assertFalse((root / "enrolment_token.txt").exists())

    def test_a_retired_token_already_on_file_is_refused(self):
        result, root = self.run_case(token_here="used-token\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("REFUSING TO INSTALL: this Mac was uninstalled", result.stderr)
        self.assertNotIn("ARMED", result.stdout)

    def test_a_fresh_token_on_its_own_is_taken(self):
        result, root = self.run_case(token_beside=True, profile_beside=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ARMED", result.stdout)
        self.assertEqual((root / "enrolment_token.txt").read_text(), "fresh-token")
        self.assertEqual((root / "install_profile.json").read_text(), profile("tenant", 1))

    def test_a_used_token_on_its_own_is_refused(self):
        result, root = self.run_case(token_beside=True, profile_beside=False, beside_token_text="used-token")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already used", result.stderr)

    def test_the_token_is_written_0600_over_an_empty_readable_file(self):
        for profile_beside in (True, False):
            with self.subTest(profile_beside=profile_beside):
                result, root = self.run_case(token_beside=True, profile_beside=profile_beside, empty_token_mode=0o644)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / "enrolment_token.txt").read_text(), "fresh-token")
                self.assertEqual((root / "enrolment_token.txt").stat().st_mode & 0o777, 0o600)

    def test_blanks_around_the_used_token_do_not_make_it_a_new_one(self):
        for text in (" used-token", "\tused-token\n", "used-token \n"):
            for profile_beside, same in ((False, True), (True, True), (True, False)):
                with self.subTest(text=text, profile_beside=profile_beside, same_profile=same):
                    result, root = self.run_case(token_beside=True, profile_beside=profile_beside, same_profile=same, beside_token_text=text)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("already used", result.stderr)
                    self.assertNotIn("ARMED", result.stdout)

    def test_what_is_stored_is_what_was_compared(self):
        for profile_beside, same in ((False, True), (True, True), (True, False)):
            with self.subTest(profile_beside=profile_beside, same_profile=same):
                result, root = self.run_case(token_beside=True, profile_beside=profile_beside, same_profile=same, beside_token_text="  fresh-token \t\n")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / "enrolment_token.txt").read_text(), "fresh-token")

    def test_a_fresh_token_replaces_a_retired_one_left_on_file(self):
        for profile_beside in (False, True):
            with self.subTest(profile_beside=profile_beside):
                result, root = self.run_case(token_here="used-token\n", token_beside=True, profile_beside=profile_beside)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("ARMED", result.stdout)
                self.assertEqual((root / "enrolment_token.txt").read_text().strip(), "fresh-token")

    def test_no_blank_of_any_kind_or_locale_makes_the_used_token_new(self):
        blanks = ["\u001c", "\u0085", "\u00a0", "\u2007", "\u202f", "\u3000", " ", "\t"]
        for locale in ("C", "en_US.UTF-8"):
            for blank in blanks:
                for profile_beside, same in ((False, True), (True, True), (True, False)):
                    with self.subTest(locale=locale, blank=repr(blank), profile_beside=profile_beside, same_profile=same):
                        result, root = self.run_case(token_beside=True, profile_beside=profile_beside, same_profile=same,
                                                     beside_token_text=blank + "used-token" + blank + "\n",
                                                     extra_env={"LC_ALL": locale, "LANG": locale})
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("already used", result.stderr)
                        self.assertNotIn("ARMED", result.stdout)
                        self.assertFalse((root / "enrolment_token.txt").exists())

    def test_a_token_with_a_blank_or_foreign_character_inside_it_is_refused(self):
        for text in ("fresh token", "fresh\u00a0token", "fr\u00e9sh-token", "fresh\ttoken"):
            for profile_beside in (False, True):
                with self.subTest(text=repr(text), profile_beside=profile_beside):
                    result, root = self.run_case(token_beside=True, profile_beside=profile_beside, beside_token_text=text)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("not a token the Console issues", result.stderr)
                    self.assertFalse((root / "enrolment_token.txt").exists())

    def test_what_is_stored_is_exactly_what_postinstall_enrols_with(self):
        for blank in ("\u3000", "\u00a0", " "):
            with self.subTest(blank=repr(blank)):
                result, root = self.run_case(token_beside=True, profile_beside=False, beside_token_text=blank + "fresh-token" + blank + "\n",
                                             extra_env={"LC_ALL": "C"})
                self.assertEqual(result.returncode, 0, result.stderr)
                stored = (root / "enrolment_token.txt").read_bytes()
                self.assertEqual(stored, b"fresh-token")
                self.assertEqual((root / "enrolment_token.txt").read_text(encoding="utf-8").strip().encode(), stored)
