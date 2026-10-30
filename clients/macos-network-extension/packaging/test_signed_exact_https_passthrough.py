"""Run the real PKG derivation on verified-profile fixtures without installing it."""

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE = Path(__file__).with_name("build_macos_ne_pkg.sh")


class SignedExactHTTPSPassthroughTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = PACKAGE.read_text()
        match = re.search(r"<<'DERIVE'\n(.*?)\nDERIVE\n", source, re.DOTALL)
        if not match:
            raise AssertionError("PKG profile derivation is missing")
        cls.derivation = match.group(1)
        cls.verifier_precedes_derivation = source.index('"$CONFIG_DIR/bin/dsse-profileverify"') < source.index("<<'DERIVE'")

    def derive(self, endpoints, passthrough_domains=None, posture=None, ack_failopen=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            body = {"organization": {"tenant_id": "tenant-fixture"},
                    "transport_url": "https://agent.example.test",
                    "deployment": {"exact_https_passthrough_endpoints": endpoints,
                                   "passthrough_domains": passthrough_domains or []},
                    "posture": posture, "ack_failopen": ack_failopen}
            (root / "verified.json").write_text(json.dumps(body))
            (root / "token.txt").write_text("one-time-fixture-token")
            (root / "pin.txt").write_text("00" * 32)
            result = subprocess.run(
                [sys.executable, "-", str(root / "verified.json"), str(root / "token.txt"),
                 str(root / "agent_config.json"), str(root), str(root / "pin.txt"),
                 str(root / "install_profile.json"), str(root)],
                input=self.derivation, text=True, capture_output=True, check=False,
            )
            config_path = root / "agent_config.json"
            config = json.loads(config_path.read_text()) if config_path.exists() else None
            return result.returncode, config

    def test_verified_profile_reaches_root_agent_config_without_broad_bypass(self):
        self.assertTrue(self.verifier_precedes_derivation)
        endpoint = {"hostname": "idp.example.test", "addresses": ["203.0.113.10"]}
        result, config = self.derive([endpoint])
        self.assertEqual(result, 0)
        self.assertEqual(config["network_extension_exact_https_passthrough_endpoints"], [endpoint])
        self.assertNotIn("network_extension_passthrough_domains", config)
        result, config = self.derive([])
        self.assertEqual(result, 0)
        self.assertNotIn("network_extension_exact_https_passthrough_endpoints", config)

    def test_invalid_signed_exception_does_not_create_a_config(self):
        for endpoints in (
            [{"hostname": "*.example.test", "addresses": ["203.0.113.10"]}],
            [{"hostname": "idp.example.test", "addresses": ["idp.example.test"]}],
            [{"hostname": "idp.example.test", "addresses": ["127.0.0.1"]}],
            [{"hostname": "idp.example.test", "addresses": []}],
            [{"hostname": "idp.example.test", "addresses": ["203.0.113.10"]},
             {"hostname": "idp.example.test", "addresses": ["203.0.113.11"]}],
        ):
            with self.subTest(endpoints=endpoints):
                result, config = self.derive(endpoints)
                self.assertNotEqual(result, 0)
                self.assertIsNone(config)
        result, config = self.derive(
            [{"hostname": "idp.example.test", "addresses": ["203.0.113.10"]}],
            passthrough_domains=["*.example.test"])
        self.assertNotEqual(result, 0)
        self.assertIsNone(config)

    def test_signed_posture_still_controls_fail_open_without_unread_config_key(self):
        result, config = self.derive([], posture="fail-open", ack_failopen=True)
        self.assertEqual(result, 0)
        self.assertNotIn("network_extension_posture", config)
        self.assertTrue(config["network_extension_lab_fail_open_when_region_blocked"])
        self.assertTrue(config["network_extension_fail_open_acknowledged"])
        result, config = self.derive([], posture="fail-open")
        self.assertEqual(result, 0)
        self.assertNotIn("network_extension_lab_fail_open_when_region_blocked", config)
        self.assertNotIn("network_extension_fail_open_acknowledged", config)


if __name__ == "__main__":
    unittest.main()
