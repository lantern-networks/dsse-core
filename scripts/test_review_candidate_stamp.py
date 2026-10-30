"""The endpoint review builds must not inherit a private parent Git revision."""

import os
from pathlib import Path
import hashlib
import io
import json
import re
import subprocess
import tarfile
import tempfile
import unittest


OSS = Path(__file__).resolve().parents[1]
STAMP = OSS / "scripts" / "build_stamp.sh"
VERIFIER = OSS / "scripts" / "verify_source_content_id.go"


class ReviewCandidateStampTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "oss"
        (source / "scripts").mkdir(parents=True)
        (source / "scripts" / "build_stamp.sh").write_bytes(STAMP.read_bytes())
        (source / "VERSION").write_text("0.4.0\n")
        return source

    def stamp(self, source, content_id=None, locale=None):
        env = os.environ.copy()
        env.pop("DSSE_SOURCE_CONTENT_ID", None)
        if content_id is not None:
            env["DSSE_SOURCE_CONTENT_ID"] = content_id
        if locale is not None:
            env["LC_ALL"] = locale
        return subprocess.run(["sh", str(source / "scripts" / "build_stamp.sh")],
                              env=env, text=True, capture_output=True, check=False)

    def content_id(self, source):
        rows = []
        for path in sorted(source.rglob("*")):
            if path.is_file():
                rows.append({"mode": "100755" if path.stat().st_mode & 0o111 else "100644",
                             "path": path.relative_to(source).as_posix(),
                             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        return "source-" + hashlib.sha256(json.dumps(rows, sort_keys=True,
                                                       separators=(",", ":")).encode()).hexdigest()

    def verify(self, source, content_id):
        env = os.environ.copy()
        env["GOTOOLCHAIN"] = "go1.27.3"
        return subprocess.run(["go", "run", "-buildvcs=false", str(VERIFIER),
                               "-root", str(source), "-expected", content_id],
                              cwd=OSS, env=env, text=True, capture_output=True, check=False)

    def archive(self, source, archive, mode_override=None):
        with tarfile.open(archive, "w:gz") as tar:
            for path in sorted(source.rglob("*")):
                if not path.is_file():
                    continue
                name = path.relative_to(source).as_posix()
                data = path.read_bytes()
                info = tarfile.TarInfo(name)
                info.mode = mode_override.get(name, path.stat().st_mode & 0o777) if mode_override else path.stat().st_mode & 0o777
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return hashlib.sha256(archive.read_bytes()).hexdigest()

    def verify_archive(self, source, content_id, archive, archive_sha256):
        env = os.environ.copy()
        env["GOTOOLCHAIN"] = "go1.27.3"
        return subprocess.run(["go", "run", "-buildvcs=false", str(VERIFIER),
                               "-root", str(source), "-expected", content_id,
                               "-archive", str(archive), "-archive-sha256", archive_sha256],
                              cwd=OSS, env=env, text=True, capture_output=True, check=False)

    def test_explicit_content_identity_in_gitless_export(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fixture(Path(directory))
            content_id = "source-" + "a" * 64
            result = self.stamp(source, content_id)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("-X main.buildCommit=" + content_id, result.stdout)
            self.assertIn("-X main.buildDirty=false", result.stdout)
            self.assertNotIn("unknown", result.stdout)

    def test_gitless_export_under_private_git_parent_needs_content_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = self.fixture(root)
            result = self.stamp(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires DSSE_SOURCE_CONTENT_ID", result.stderr)

    def test_malformed_content_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fixture(Path(directory))
            for content_id in ("source-" + "a" * 63, "source-" + "A" * 64,
                               "private-" + "a" * 64, "source-" + "a" * 64 + "\nextra"):
                with self.subTest(content_id=content_id[:24]):
                    self.assertNotEqual(self.stamp(source, content_id).returncode, 0)

    def test_content_identity_uses_ascii_hex_in_available_locales(self):
        available = set(subprocess.run(["locale", "-a"], text=True, capture_output=True,
                                       check=True).stdout.splitlines())
        locales = ["C"] + [name for name in ("en_US.UTF-8", "ja_JP.UTF-8")
                             if name in available]
        with tempfile.TemporaryDirectory() as directory:
            source = self.fixture(Path(directory))
            for locale in locales:
                with self.subTest(locale=locale, valid=True):
                    result = self.stamp(source, "source-" + "0123456789abcdef" * 4, locale)
                    self.assertEqual(result.returncode, 0, result.stderr)
                for char in ("A", "B", "C", "D", "E", "F", "G", "é", "０", "-", "\t", "\n"):
                    with self.subTest(locale=locale, invalid=repr(char)):
                        result = self.stamp(source, "source-" + char + "a" * 63, locale)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("64 lowercase hexadecimal", result.stderr)

    def test_standalone_git_checkout_keeps_git_stamp(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fixture(Path(directory))
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "add", "VERSION", "scripts/build_stamp.sh"], check=True)
            subprocess.run(["git", "-C", str(source), "-c", "user.name=Fixture",
                            "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)
            result = self.stamp(source)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, r"-X main\.buildCommit=[0-9a-f]{7,}")
            self.assertIn("-X main.buildDirty=false", result.stdout)
            (source / "VERSION").write_text("0.4.0  \n")
            self.assertIn("-X main.buildDirty=true", self.stamp(source).stdout)

    def test_endpoint_package_builds_require_candidate_stamp_before_output(self):
        mac = (OSS / "clients/macos-network-extension/packaging/build_macos_ne_pkg.sh").read_text()
        windows = (OSS / "clients/windows-wfp/packaging/build-msi.ps1").read_text(encoding="utf-8-sig")
        self.assertLess(mac.index('source_stamp="$(sh "$tree/scripts/build_stamp.sh")"'),
                        mac.index('mkdir -p "$out"'))
        self.assertLess(mac.index('verify_source_content_id.go'), mac.index('mkdir -p "$out"'))
        self.assertIn("a content-ID candidate must build its app from this OSS source export", mac)
        self.assertIn("Gitless OSS export requires DSSE_SOURCE_CONTENT_ID", windows)
        self.assertRegex(windows, re.compile(r"source-\[0-9a-f\]\{64\}"))
        self.assertLess(windows.index('verify_source_content_id.go'), windows.index('New-Item -ItemType Directory'))
        self.assertLess(windows.index('DSSE_SOURCE_ARCHIVE_SHA256'), windows.index('New-Item -ItemType Directory'))
        self.assertIn('-archive $sourceArchive -archive-sha256 $sourceArchiveSha256', windows)
        for line in windows.splitlines():
            if re.match(r"\s*go build\b", line):
                self.assertIn("-buildvcs=false", line)

    def test_verifier_binds_identity_to_export_bytes_and_file_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fixture(Path(directory))
            content_id = self.content_id(source)
            result = self.verify(source, content_id)
            self.assertEqual(result.returncode, 0, result.stderr)
            (source / "VERSION").write_text("0.4.1\n")
            self.assertNotEqual(self.verify(source, content_id).returncode, 0)
            (source / "VERSION").write_text("0.4.0\n")
            (source / "VERSION").chmod(0o755)
            self.assertNotEqual(self.verify(source, content_id).returncode, 0)

    def test_windows_archive_verifier_preserves_modes_and_checks_exact_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.fixture(root)
            (source / "scripts" / "build_stamp.sh").chmod(0o755)
            content_id = self.content_id(source)
            archive = root / "source.tar.gz"
            digest = self.archive(source, archive)

            # On Windows, normal extracted files can all report 0666. The
            # authenticated archive remains the source of Unix mode truth.
            for path in source.rglob("*"):
                if path.is_file():
                    path.chmod(0o666)
            self.assertEqual(self.verify_archive(source, content_id, archive, digest).returncode, 0)
            self.assertNotEqual(self.verify(source, content_id).returncode, 0)
            self.assertNotEqual(self.verify_archive(source, content_id, archive, "0" * 64).returncode, 0)
            self.assertNotEqual(self.verify_archive(source, "source-" + "0" * 64, archive, digest).returncode, 0)

            (source / "VERSION").write_text("tampered\n")
            self.assertNotEqual(self.verify_archive(source, content_id, archive, digest).returncode, 0)
            (source / "VERSION").write_text("0.4.0\n")
            (source / "extra").write_text("unlisted")
            self.assertNotEqual(self.verify_archive(source, content_id, archive, digest).returncode, 0)
            (source / "extra").unlink()
            (source / "VERSION").unlink()
            self.assertNotEqual(self.verify_archive(source, content_id, archive, digest).returncode, 0)

    def test_windows_archive_verifier_refuses_wrong_canonical_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.fixture(root)
            content_id = self.content_id(source)
            archive = root / "source.tar.gz"
            digest = self.archive(source, archive, {"VERSION": 0o600})
            self.assertNotEqual(self.verify_archive(source, content_id, archive, digest).returncode, 0)


if __name__ == "__main__":
    unittest.main()
