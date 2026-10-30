"""Exercise the shipped profile generator's tenant selection with local public fixtures."""

import base64
import json
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("build_macos_interception_root_profile.sh").read_text()
PYTHON = SCRIPT.split('python3 - "$tenant" "$out" "$answer_file" <<\'PY\'\n', 1)[1].split("\nPY\n", 1)[0]


def public_pem(contents):
    return ("-----BEGIN CERTIFICATE-----\n" + base64.b64encode(contents).decode()
            + "\n-----END CERTIFICATE-----\n")


class InterceptionRootProfileTenantTest(unittest.TestCase):
    def run_generator(self, tenant):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        response = root / "response.json"
        output = root / "roots.mobileconfig"
        response.write_text(json.dumps({
            "per_tenant_issuers": [
                {"tenant": "Tenant_A", "root_pem": public_pem(b"public-root-A")},
                {"tenant": "tenant_a", "root_pem": public_pem(b"public-root-a")},
            ],
        }))
        result = subprocess.run(["python3", "-c", PYTHON, tenant, str(output), str(response)],
                                capture_output=True, text=True)
        return result, output

    def test_case_distinct_tenant_receives_only_its_own_root(self):
        result, output = self.run_generator("tenant_a")
        self.assertEqual(result.returncode, 0, result.stderr)
        profile = plistlib.loads(output.read_bytes())
        self.assertEqual([p["PayloadContent"] for p in profile["PayloadContent"]],
                         [b"public-root-a"])

    def test_no_exact_issuer_does_not_substitute_case_distinct_root(self):
        result, output = self.run_generator("TENANT_A")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
