import tempfile
import unittest
from pathlib import Path
from verify_generic_payload import unexpected_files


class GenericPayloadTests(unittest.TestCase):
    def test_product_signature_profiles_allowed_but_tenant_material_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "Applications/LanternDsseAgent.app/Contents"
            app.mkdir(parents=True)
            (app / "embedded.provisionprofile").write_bytes(b"Apple product signing profile")
            args = (root, "jp.co.lantern-networks.dsse.agent", "LanternDsseAgent", "DsseAppProxyProvider")
            self.assertEqual(unexpected_files(*args), [])
            for path in ("Library/Application Support/Dsse/install_profile.json",
                         "Library/Application Support/Dsse/agent_config.json",
                         "Library/Application Support/Dsse/deployment-anchor.pem",
                         "Library/Application Support/Dsse/profile_signing_key.txt",
                         "Library/Application Support/Dsse/update_signing_key.txt",
                         "Library/Application Support/Dsse/region_endpoints.json",
                         "Library/Application Support/Dsse/enrolment_token.txt",
                         "Applications/LanternDsseAgent.app/Contents/Resources/transport_ca.pem"):
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b"tenant fixture")
                self.assertEqual(unexpected_files(*args), [path])
                file.unlink()
            (app / "embedded.provisionprofile").unlink()
            (app / "embedded.provisionprofile").symlink_to("/tmp/runtime-profile")
            self.assertEqual(unexpected_files(*args), [str((app / "embedded.provisionprofile").relative_to(root))])


if __name__ == "__main__":
    unittest.main()
