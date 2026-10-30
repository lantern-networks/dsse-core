import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scan_release_images as gate


def image_report(image, platform, findings=None):
    operating_system, architecture = platform.split("/")
    return {"SchemaVersion": 2, "ArtifactName": image, "ArtifactType": "container_image",
            "Metadata": {"ImageConfig": {"os": operating_system, "architecture": architecture}},
            "Results": [{"Target": "test", "Class": "os-pkgs", "Type": "test",
                         "Vulnerabilities": findings or []}]}


class ImageGateTests(unittest.TestCase):
    def test_all_production_compose_and_dockerfiles_are_inventoried(self):
        compose = {path for path in (gate.ROOT / "cmd/dsse-install").glob("compose*.go")
                   if not path.name.endswith("_test.go")}
        dockerfiles = {path for path in gate.ROOT.rglob("Dockerfile*") if path.is_file()}
        self.assertEqual(set(gate.COMPOSE_FILES), compose)
        self.assertEqual(set(gate.DOCKERFILES) | gate.DERIVED_ONLY_DOCKERFILES
                         | gate.NON_DISTRIBUTED_DOCKERFILES, dockerfiles)

    def test_ci_runtime_images_are_inventoried_without_the_local_test_build(self):
        images = gate.source_images()
        ci_images = {role: image for role, image in images.items() if role.startswith("ci:")}
        self.assertTrue(any(image.startswith("clickhouse/clickhouse-server:")
                            for image in ci_images.values()))
        self.assertFalse(any(image == "dsse-postgres-tools:ci" for image in ci_images.values()))

    def test_new_ci_runtime_image_without_digest_fails_inventory(self):
        images = gate.ci_runtime_images("""      - run: |
          docker run --detach --name test \\
            --publish 127.0.0.1:9000:9000 example/new-image:latest
""")
        self.assertEqual(list(images.values()), ["example/new-image:latest"])
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(gate, "source_images", return_value=images), \
                 mock.patch.object(gate, "REQUIRED_BUILT", set()), \
                 mock.patch.object(sys, "argv", ["scan_release_images.py", "--report-dir", temp,
                                                 "--inventory-only"]):
                self.assertEqual(gate.main(), 1)
            summary = json.loads((Path(temp) / "summary.json").read_text())
            self.assertEqual(summary["unpinned"], images)

    def test_ci_docker_run_uses_image_before_container_command(self):
        digest = "a" * 64
        images = gate.ci_runtime_images("""      - run: |
          docker run --rm --env MODE=test example/runtime@sha256:""" + digest + """ sh -c true
""")
        self.assertEqual(list(images.values()), ["example/runtime@sha256:" + digest])

    def test_ci_local_tag_requires_its_source_build(self):
        with self.assertRaisesRegex(ValueError, "without building"):
            gate.ci_runtime_images("          docker run --rm dsse-postgres-tools:ci\n")

    def test_ci_service_images_keep_separate_roles(self):
        images = gate.ci_runtime_images("""        services:
          first:
            image: example/first:latest
          second:
            image: example/second:latest
""")
        self.assertEqual(len(images), 2)
        self.assertEqual(set(images.values()), {"example/first:latest", "example/second:latest"})

    def test_walg_exception_is_limited_to_verified_release_build(self):
        finding = {"VulnerabilityID": "CVE-2021-38599",
                   "PkgName": "github.com/wal-g/wal-g",
                   "InstalledVersion": "v0.0.0-20260820091616-3e493188db28+dirty",
                   "FixedVersion": "1.1"}
        target = {"Target": "usr/local/bin/wal-g"}
        self.assertTrue(gate.known_walg_version_false_positive("built:spilo", target, finding))
        self.assertFalse(gate.known_walg_version_false_positive("built:product", target, finding))
        self.assertFalse(gate.known_walg_version_false_positive("built:spilo", {"Target": "other"}, finding))
        self.assertFalse(gate.known_walg_version_false_positive(
            "built:spilo", target, {**finding, "InstalledVersion": "v0.0.0-unknown"}))

    def test_remediated_postgres_base_is_not_mistaken_for_the_final_image(self):
        images = gate.source_images()
        self.assertIn("deploy/spilo-4.1-p2.patch:BASE_IMAGE", images)
        self.assertFalse(any("egress-broker" in role for role in images))
        self.assertEqual(gate.REQUIRED_BUILT, {"product", "console", "spilo", "etcd", "postgres-tools"})
        self.assertTrue(images["deploy/spilo-4.1-p2.patch:BASE_IMAGE"].endswith(
            "@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11"))
        self.assertFalse(any("Dockerfile.postgres-tools" in role for role in images))
        self.assertIn("postgres-tools", gate.REQUIRED_BUILT)

    def test_distributed_installer_does_not_enable_experimental_broker(self):
        installer = gate.ROOT / "cmd/dsse-install"
        for path in installer.glob("*.go"):
            if path.name.endswith("_test.go"):
                continue
            source = path.read_text()
            self.assertNotIn("EGRESS_BROKER_URL", source, path.name)
            self.assertNotIn("swg-egress-browser-mimic", source, path.name)
        self.assertFalse(any("egress-broker" in role for role in gate.source_images()))

    def test_arm64_finding_cannot_hide_behind_clean_amd64_scan(self):
        image = "registry.example/dsse@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as temp:
            def scan(command, **_kwargs):
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, "Version: test", "")
                platform = command[command.index("--platform") + 1]
                output = Path(command[command.index("--output") + 1])
                findings = [{"VulnerabilityID": "CVE-test"}] if platform == "linux/arm64" else []
                output.write_text(json.dumps(image_report(image, platform, findings)))
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(gate, "source_images", return_value={"compose:product": image}), \
                 mock.patch.object(gate, "REQUIRED_BUILT", set()), \
                 mock.patch.object(gate, "REQUIRED_INSTALL_PROFILES", set()), \
                 mock.patch.object(gate.shutil, "which", return_value="/fake/trivy"), \
                 mock.patch.object(gate.subprocess, "run", side_effect=scan), \
                 mock.patch.object(sys, "argv", ["scan_release_images.py", "--report-dir", temp]):
                self.assertEqual(gate.main(), 1)
            summary = json.loads((Path(temp) / "summary.json").read_text())
            self.assertEqual(len(summary["scans"]), 2)
            self.assertFalse(summary["passed"])
            self.assertEqual(summary["scans"]["compose:product:linux/arm64"]["high_or_critical"], 1)

    def test_incomplete_wrong_image_or_platform_report_is_not_a_clean_scan(self):
        image = "registry.example/product@sha256:" + "a" * 64
        for case in ("empty", "wrong_image", "wrong_architecture", "invalid_results"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                def scan(command, **_kwargs):
                    if command[1:] == ["--version"]:
                        return subprocess.CompletedProcess(command, 0, "Version: test", "")
                    platform = command[command.index("--platform") + 1]
                    data = image_report(image, platform)
                    if case == "empty":
                        data = {}
                    elif case == "wrong_image":
                        data["ArtifactName"] = "different-image"
                    elif case == "wrong_architecture":
                        data["Metadata"]["ImageConfig"]["architecture"] = "different-arch"
                    else:
                        data["Results"] = [{"Vulnerabilities": "not-a-list"}]
                    Path(command[command.index("--output") + 1]).write_text(json.dumps(data))
                    return subprocess.CompletedProcess(command, 0, "", "")

                with mock.patch.object(gate, "source_images", return_value={"compose:product": image}), \
                     mock.patch.object(gate, "REQUIRED_BUILT", set()), \
                     mock.patch.object(gate, "REQUIRED_INSTALL_PROFILES", set()), \
                     mock.patch.object(gate.shutil, "which", return_value="/fake/trivy"), \
                     mock.patch.object(gate.subprocess, "run", side_effect=scan), \
                     mock.patch.object(sys, "argv", ["scan_release_images.py", "--report-dir", temp]):
                    self.assertEqual(gate.main(), 1)
                summary = json.loads((Path(temp) / "summary.json").read_text())
                self.assertFalse(summary["passed"])
                self.assertTrue(all(not result["ok"] for result in summary["scans"].values()))

    def test_prior_report_cannot_substitute_for_missing_scanner_output(self):
        image = "registry.example/product@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as temp:
            for platform in gate.scan_platforms("compose:product"):
                (Path(temp) / f"compose_product_{platform.replace('/', '_')}.json").write_text(
                    json.dumps(image_report(image, platform)))
            def scan(command, **_kwargs):
                return subprocess.CompletedProcess(command, 0, "Version: test", "")
            with mock.patch.object(gate, "source_images", return_value={"compose:product": image}), \
                 mock.patch.object(gate, "REQUIRED_BUILT", set()), \
                 mock.patch.object(gate, "REQUIRED_INSTALL_PROFILES", set()), \
                 mock.patch.object(gate.shutil, "which", return_value="/fake/trivy"), \
                 mock.patch.object(gate.subprocess, "run", side_effect=scan), \
                 mock.patch.object(sys, "argv", ["scan_release_images.py", "--report-dir", temp]):
                self.assertEqual(gate.main(), 1)
            self.assertFalse(json.loads((Path(temp) / "summary.json").read_text())["passed"])

    def test_built_product_requires_resolved_image_sbom(self):
        image = "registry.example/product@sha256:" + "a" * 64

        def scan(command, **_kwargs):
            if command[1:] == ["--version"]:
                return subprocess.CompletedProcess(command, 0, "Version: test", "")
            output = Path(command[command.index("--output") + 1])
            if command[command.index("--format") + 1] == "cyclonedx":
                output.write_text(json.dumps({
                    "bomFormat": "CycloneDX", "specVersion": "1.7",
                    "metadata": {"component": {"name": image, "bom-ref": image}},
                    "components": [{"bom-ref": "pkg:golang/..", "name": "..", "purl": "pkg:golang/.."}],
                }))
            else:
                output.write_text(json.dumps(image_report(image, command[command.index("--platform") + 1])))
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(gate, "source_images", return_value={}), \
                 mock.patch.object(gate, "REQUIRED_BUILT", {"product"}), \
                 mock.patch.object(gate, "REQUIRED_INSTALL_PROFILES", set()), \
                 mock.patch.object(gate.shutil, "which", return_value="/fake/trivy"), \
                 mock.patch.object(gate.subprocess, "run", side_effect=scan), \
                 mock.patch.object(sys, "argv", ["scan_release_images.py", "--report-dir", temp,
                                                 "--built-image", "product=" + image]):
                self.assertEqual(gate.main(), 1)
            result = json.loads((Path(temp) / "summary.json").read_text())["scans"]["built:product:linux/amd64"]
            self.assertEqual(result["blocking_high_or_critical"], 0)
            self.assertEqual(result["sbom_error"], "SBOM contains an unresolved local Go module")
            self.assertFalse(result["ok"])

    def test_image_sbom_checks_identity_and_inventory(self):
        image = "registry.example/product@sha256:" + "b" * 64
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.7",
                "metadata": {"component": {"name": image, "bom-ref": image}},
                "components": [{"bom-ref": "pkg:golang/stdlib@v1.27.3", "name": "stdlib",
                                "purl": "pkg:golang/stdlib@v1.27.3"}]}
        self.assertIsNone(gate.validate_image_sbom(sbom, image))
        self.assertEqual(gate.validate_image_sbom({**sbom, "components": []}, image),
                         "SBOM has no components")
        self.assertEqual(gate.validate_image_sbom(sbom, image + "-other"),
                         "SBOM image identity mismatch")
        self.assertEqual(gate.validate_image_sbom({**sbom, "components": [
            {"bom-ref": "source", "name": "source",
             "purl": "pkg:golang/example.com/../source"}]}, image),
            "SBOM contains an unresolved local Go module")
        self.assertEqual(gate.validate_image_sbom({**sbom, "dependencies": [
            {"ref": "missing", "dependsOn": []}]}, image),
            "SBOM dependency references an unknown component")
        self.assertEqual(gate.validate_image_sbom([], image), "not a CycloneDX SBOM")
        self.assertEqual(gate.validate_image_sbom({**sbom, "components": [
            {"bom-ref": "bad", "name": "bad", "purl": 7}]}, image),
            "SBOM component purl is invalid")

    def test_inventory_with_missing_first_party_image_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(gate, "source_images", return_value={}), \
                 mock.patch.object(gate, "REQUIRED_BUILT", {"spilo"}), \
                 mock.patch.object(sys, "argv", ["scan_release_images.py", "--report-dir", temp,
                                                 "--inventory-only"]):
                self.assertEqual(gate.main(), 1)

    def test_scanned_image_must_match_the_installer_default(self):
        pinned = "registry.example/etcd@sha256:" + "a" * 64
        other = "registry.example/etcd@sha256:" + "b" * 64
        source = {"compose.go:DSSE_ETCD_IMAGE": pinned}
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(gate, "source_images", return_value=source), \
                 mock.patch.object(gate, "REQUIRED_BUILT", {"etcd"}), \
                 mock.patch.object(sys, "argv", ["scan_release_images.py", "--report-dir", temp,
                                                 "--inventory-only", "--built-image", "etcd=" + other]):
                self.assertEqual(gate.main(), 1)
            summary = json.loads((Path(temp) / "summary.json").read_text())
            self.assertEqual(summary["mismatched_compose_roles"], {"compose.go:DSSE_ETCD_IMAGE": "etcd"})

    def test_spilo_18_digest_cannot_pass_with_postgres_16_setting(self):
        self.assertFalse(gate.postgres_major_is_18("PGVERSION: 16"))
        self.assertTrue(gate.postgres_major_is_18("PGVERSION: 18"))
        self.assertTrue(gate.postgres_major_is_18("PGVERSION: ${DSSE_POSTGRES_MAJOR:-18}"))
        pinned = "registry.example/spilo@sha256:" + "a" * 64
        source = {"compose.go:DSSE_POSTGRES_IMAGE": pinned,
                  "compose_postgres_tls.go:DSSE_POSTGRES_IMAGE": pinned}
        with tempfile.TemporaryDirectory() as temp:
            old_compose = Path(temp) / "compose.go"
            old_compose.write_text("PGVERSION: 16\n")
            with mock.patch.object(gate, "source_images", return_value=source), \
                 mock.patch.object(gate, "COMPOSE_FILES", (old_compose,)), \
                 mock.patch.object(gate, "REQUIRED_BUILT", {"spilo"}), \
                 mock.patch.object(sys, "argv", ["scan_release_images.py", "--report-dir", temp,
                                                 "--inventory-only", "--built-image", "spilo=" + pinned]):
                self.assertEqual(gate.main(), 1)
            summary = json.loads((Path(temp) / "summary.json").read_text())
            self.assertTrue(summary["postgres_version_mismatch"])

    def test_current_compose_has_no_legacy_image_fallback_and_release_defaults_are_pending(self):
        refs = gate.source_images()
        required = gate.compose_required_image_bindings()
        self.assertLessEqual(set(gate.COMPOSE_BUILT_ROLES), set(required))
        self.assertFalse(set(gate.COMPOSE_BUILT_ROLES) & set(refs))
        self.assertTrue(gate.postgres_major_is_18(gate.COMPOSE_FILES[0].read_text()))
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(sys, "argv", ["scan_release_images.py", "--report-dir", temp,
                                                 "--inventory-only"]):
                self.assertEqual(gate.main(), 1)
            summary = json.loads((Path(temp) / "summary.json").read_text())
            self.assertEqual(set(summary["required_only_compose_roles"]), set(gate.COMPOSE_BUILT_ROLES))
            self.assertEqual(summary["unbound_compose_roles"], [])

    def test_release_plan_images_must_match_every_scanned_role(self):
        built = {role: f"registry.example/{role}@sha256:" + "a" * 64
                 for role in gate.REQUIRED_BUILT}
        with tempfile.TemporaryDirectory() as temp:
            paths = []
            for profile in sorted(gate.REQUIRED_INSTALL_PROFILES):
                path = Path(temp) / f"{profile}.json"
                path.write_text(json.dumps({
                    "profile": profile, "image_revision": "source-reviewed",
                    "service_image": built["product"], "console_image": built["console"],
                    "data_layer": {"etcd_image": built["etcd"],
                                   "postgres_image": built["spilo"],
                                   "postgres_tools_image": built["postgres-tools"],
                                   "postgres_major": 18},
                }))
                paths.append(path)
            self.assertEqual(gate.inspect_install_plans(paths, built), ([], {}))
            changed = json.loads(paths[0].read_text())
            changed["service_image"] = "registry.example/product@sha256:" + "b" * 64
            changed["data_layer"]["postgres_major"] = 16
            paths[0].write_text(json.dumps(changed))
            missing, issues = gate.inspect_install_plans(paths, built)
            self.assertEqual(missing, [])
            self.assertEqual(issues[changed["profile"]], ["postgres_major", "product"])
            self.assertNotIn(changed["service_image"], json.dumps(issues))
            self.assertEqual(gate.inspect_install_plans(paths[:1], built)[0], [paths[1].stem])

    def test_invalid_private_plan_is_reported_without_echoing_contents(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plan.json"
            path.write_text('{"profile": ["sensitive-marker"]}')
            _, issues = gate.inspect_install_plans([path], {})
            self.assertEqual(issues, {"plan-1": ["unsupported_profile"]})
            self.assertNotIn("sensitive-marker", json.dumps(issues))

    def test_full_gate_does_not_start_scanning_without_both_completed_plans(self):
        built = {role: f"registry.example/{role}@sha256:" + "c" * 64
                 for role in gate.REQUIRED_BUILT}
        refs = {key: built[role] for key, role in gate.COMPOSE_BUILT_ROLES.items()}
        with tempfile.TemporaryDirectory() as temp:
            args = ["scan_release_images.py", "--report-dir", temp]
            for role, image in built.items():
                args.extend(["--built-image", f"{role}={image}"])
            with mock.patch.object(gate, "source_images", return_value=refs), \
                 mock.patch.object(gate.shutil, "which", side_effect=AssertionError("scan started")), \
                 mock.patch.object(sys, "argv", args):
                self.assertEqual(gate.main(), 1)
            summary = json.loads((Path(temp) / "summary.json").read_text())
            self.assertEqual(set(summary["missing_install_profiles"]), gate.REQUIRED_INSTALL_PROFILES)
            self.assertEqual(summary["scans"], {})

    def test_required_compose_image_is_satisfied_by_completed_plans(self):
        image = "registry.example/etcd@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as temp:
            paths = []
            for profile in sorted(gate.REQUIRED_INSTALL_PROFILES):
                path = Path(temp) / f"{profile}.json"
                path.write_text(json.dumps({
                    "profile": profile, "image_revision": "source-reviewed",
                    "service_image": image, "console_image": image,
                    "data_layer": {"etcd_image": image, "postgres_image": image,
                                   "postgres_tools_image": image, "postgres_major": 18},
                }))
                paths.extend(["--install-plan", str(path)])

            def scan(command, **_kwargs):
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, "Version: test", "")
                output = Path(command[command.index("--output") + 1])
                if command[command.index("--format") + 1] == "cyclonedx":
                    output.write_text(json.dumps({
                        "bomFormat": "CycloneDX", "specVersion": "1.7",
                        "metadata": {"component": {"name": image, "bom-ref": image}},
                        "components": [{"bom-ref": "component", "name": "etcd"}],
                    }))
                else:
                    output.write_text(json.dumps(image_report(image, command[command.index("--platform") + 1])))
                return subprocess.CompletedProcess(command, 0, "", "")

            args = ["scan_release_images.py", "--report-dir", temp,
                    "--built-image", "etcd=" + image, *paths]
            with mock.patch.object(gate, "source_images", return_value={}), \
                 mock.patch.object(gate, "REQUIRED_BUILT", {"etcd"}), \
                 mock.patch.object(gate, "COMPOSE_BUILT_ROLES", {"compose.go:DSSE_ETCD_IMAGE": "etcd"}), \
                 mock.patch.object(gate, "compose_required_image_bindings",
                                   return_value={"compose.go:DSSE_ETCD_IMAGE": "DSSE_ETCD_IMAGE"}), \
                 mock.patch.object(gate.shutil, "which", return_value="/fake/trivy"), \
                 mock.patch.object(gate.subprocess, "run", side_effect=scan), \
                 mock.patch.object(sys, "argv", args):
                self.assertEqual(gate.main(), 0)
            summary = json.loads((Path(temp) / "summary.json").read_text())
            self.assertTrue(summary["passed"])
            self.assertEqual(summary["required_only_compose_roles"], ["compose.go:DSSE_ETCD_IMAGE"])
            self.assertTrue(summary["required_only_satisfied_by_plans"])
            self.assertEqual(len(summary["scans"]), 2)


if __name__ == "__main__":
    unittest.main()
