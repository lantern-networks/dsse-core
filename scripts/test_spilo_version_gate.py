"""Exercise the image's actual version-check shell without building an image."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class SpiloVersionGate(unittest.TestCase):
    def test_each_required_tool_failure_fails_the_image_check(self):
        source = Path(__file__).with_name("build_spilo_source.sh").read_text()
        commands = re.findall(r"-c '([^']+)'", source)
        command = next(c for c in commands if "postgres --version" in c)
        with tempfile.TemporaryDirectory() as directory:
            for tool in ("postgres", "patroni", "wal-g"):
                path = Path(directory) / tool
                path.write_text('#!/bin/sh\ncase "$0" in\n'
                                '*/postgres) printf "%s\\n" "$PG_VERSION";;\n'
                                '*/patroni) printf "%s\\n" "$PATRONI_VERSION";;\n'
                                '*/wal-g) exit "$WALG_EXIT";;\nesac\n')
                path.chmod(0o755)
            baseline = {**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"],
                        "PG_VERSION": "postgres (PostgreSQL) 18.6",
                        "PATRONI_VERSION": "patroni 4.1.5", "WALG_EXIT": "0"}
            for overrides, ok in (({}, True), ({"PG_VERSION": "postgres (PostgreSQL) 17.0"}, False),
                                  ({"PATRONI_VERSION": "patroni 3.0.0"}, False), ({"WALG_EXIT": "1"}, False)):
                with self.subTest(overrides=overrides):
                    result = subprocess.run(["bash", "-c", command], env={**baseline, **overrides},
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.assertEqual(result.returncode == 0, ok)


if __name__ == "__main__":
    unittest.main()
