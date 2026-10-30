#!/usr/bin/env python3
"""Fail-closed image inventory and vulnerability gate for a 0.4.0 candidate.

Runs only against immutable image references. Built first-party images must be
supplied after they are pushed to a registry and their manifest digests are known.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = tuple(sorted(path for path in (ROOT / "cmd/dsse-install").glob("compose*.go")
                             if not path.name.endswith("_test.go")))
# The PostgreSQL base contains the obsolete gosu binary. The derived
# postgres-tools image removes it; scan that mandatory final image instead.
DERIVED_ONLY_DOCKERFILES = {ROOT / "deploy/Dockerfile.postgres-tools"}
NON_DISTRIBUTED_DOCKERFILES = set((ROOT / "egress-broker").glob("Dockerfile*"))
DOCKERFILES = tuple(sorted(path for path in ROOT.rglob("Dockerfile*")
                           if path.is_file() and path not in DERIVED_ONLY_DOCKERFILES
                           and path not in NON_DISTRIBUTED_DOCKERFILES))
REQUIRED_BUILT = {"product", "console", "spilo", "etcd", "postgres-tools"}
REQUIRED_INSTALL_PROFILES = {"one-region-three-nodes", "three-regions-multi-edge"}
COMPOSE_BUILT_ROLES = {
    "compose.go:DSSE_ETCD_IMAGE": "etcd",
    "compose.go:DSSE_POSTGRES_IMAGE": "spilo",
    "compose_postgres_tls.go:DSSE_POSTGRES_IMAGE": "spilo",
    "compose.go:DSSE_PSQL_IMAGE": "postgres-tools",
}
PIN = re.compile(r"@sha256:[0-9a-f]{64}$")
CI_LOCAL_BUILT_IMAGES = {"dsse-postgres-tools:ci": "deploy/Dockerfile.postgres-tools"}
DOCKER_RUN_VALUE_FLAGS = {"--env", "--publish", "--name", "--platform", "--volume",
                          "--network", "--user", "--workdir", "--entrypoint", "-e",
                          "-p", "-v", "-w", "-u"}
DOCKER_RUN_SWITCHES = {"--detach", "--rm", "--init", "--privileged", "-d", "-i", "-t", "-it"}


def ci_runtime_images(source):
    """Inventory literal images started by CI, including multiline docker run.

    The locally built PostgreSQL tools tag is represented by the mandatory
    built:postgres-tools scan. Any other new tag must pass the digest gate.
    """
    result = {}
    lines = source.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^\s+image:\s+(\S+)", line)
        if match:
            result[f"ci:service:{index + 1}"] = match.group(1)
        if not re.search(r"\bdocker run\b", line) or line.lstrip().startswith("#"):
            continue
        command = line.strip()
        end = index
        while command.endswith("\\"):
            end += 1
            if end >= len(lines):
                raise ValueError(f"Unterminated CI docker run at line {index + 1}")
            command = command[:-1].rstrip() + " " + lines[end].strip()
        tokens = shlex.split(command)
        run = tokens.index("docker") + 1
        if run >= len(tokens) or tokens[run] != "run":
            raise ValueError(f"Unsupported CI docker run at line {index + 1}")
        position = run + 1
        while position < len(tokens) and tokens[position].startswith("-"):
            flag = tokens[position]
            if flag in DOCKER_RUN_VALUE_FLAGS:
                position += 2
            elif flag in DOCKER_RUN_SWITCHES or (flag.startswith("--") and "=" in flag):
                position += 1
            else:
                raise ValueError(f"Unrecognized CI docker run option at line {index + 1}")
        if position >= len(tokens):
            raise ValueError(f"Missing CI docker run image at line {index + 1}")
        image = tokens[position]
        local_dockerfile = CI_LOCAL_BUILT_IMAGES.get(image)
        if local_dockerfile:
            build = f"docker build -f {local_dockerfile} -t {image}"
            if build not in source:
                raise ValueError(f"CI runs {image} without building {local_dockerfile}")
        else:
            result[f"ci:docker-run:{index + 1}"] = image
    return result


def known_walg_version_false_positive(role, result, finding):
    """The pinned WAL-G 3.0.9 source contains the 2021 fix, but its dirty
    Go build pseudo-version sorts below 1.1 in Trivy's generic version check.
    No other WAL-G CVE, build, package, target, or role gets an exception.
    """
    return (role == "built:spilo"
            and result.get("Target", "").endswith("/wal-g")
            and finding.get("VulnerabilityID") == "CVE-2021-38599"
            and finding.get("PkgName") == "github.com/wal-g/wal-g"
            and finding.get("InstalledVersion") == "v0.0.0-20260820091616-3e493188db28+dirty"
            and finding.get("FixedVersion") == "1.1")


def source_images():
    result = {}
    for path in COMPOSE_FILES:
        for key, image in re.findall(r"\$\{(DSSE_\w+_IMAGE):-([^}]+)\}", path.read_text()):
            result[f"{path.name}:{key}"] = image
    for path in DOCKERFILES:
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if line.startswith("FROM "):
                image = line.split(" AS ")[0].split(" as ")[0].split()[-1]
                if not image.startswith("$"):
                    result[f"{path.relative_to(ROOT)}:{i}"] = image
    # Spilo is patched from a fixed upstream commit at build time. Its Ubuntu
    # base is an actual release image input and must be inventoried and scanned.
    spilo_patch = ROOT / "deploy/spilo-4.1-p2.patch"
    base = re.search(r"^\+ARG BASE_IMAGE=(\S+)$", spilo_patch.read_text(), re.M)
    if not base:
        raise ValueError("Spilo patch is missing its pinned base image")
    result["deploy/spilo-4.1-p2.patch:BASE_IMAGE"] = base.group(1)
    ci = ROOT / ".github/workflows/ci.yml"
    result.update(ci_runtime_images(ci.read_text()))
    return result


def compose_required_image_bindings():
    """Report image roles that require an operator-supplied reference.

    These have no default image to inventory. They keep Compose fail-closed,
    but cannot stand in for the final scanned release defaults.
    """
    result = {}
    for path in COMPOSE_FILES:
        for key in re.findall(r"\$\{(DSSE_\w+_IMAGE):\?[^}]+\}", path.read_text()):
            result[f"{path.name}:{key}"] = key
    return result


def postgres_major_is_18(source):
    match = re.search(r"PGVERSION:\s*(?:\$\{DSSE_POSTGRES_MAJOR:-(\d+)\}|(\d+)\b)", source)
    return bool(match and (match.group(1) or match.group(2)) == "18")


def inspect_install_plans(paths, built):
    """Bind both supported installation plans to the exact scanned images.

    Return only field names and profile identifiers; plans can be private and
    their contents must never be copied into a scan report or CLI output.
    """
    seen = set()
    issues = {}
    for number, path in enumerate(paths, 1):
        label = f"plan-{number}"
        try:
            data = json.loads(path.read_text())
        except (OSError, UnicodeError, ValueError):
            issues[label] = ["unreadable_or_invalid_json"]
            continue
        if (not isinstance(data, dict) or not isinstance(data.get("profile"), str)
                or data["profile"] not in REQUIRED_INSTALL_PROFILES):
            issues[label] = ["unsupported_profile"]
            continue
        profile = data["profile"]
        if profile in seen:
            issues[label] = ["duplicate_profile"]
            continue
        seen.add(profile)
        cohort = data.get("data_layer")
        if not isinstance(cohort, dict):
            cohort = {}
        fields = {
            "product": data.get("service_image"),
            "console": data.get("console_image"),
            "etcd": cohort.get("etcd_image"),
            "spilo": cohort.get("postgres_image"),
            "postgres-tools": cohort.get("postgres_tools_image"),
        }
        bad = [role for role, image in fields.items()
               if not isinstance(image, str) or not PIN.search(image)
               or (role in built and image != built[role])]
        if type(cohort.get("postgres_major")) is not int or cohort["postgres_major"] != 18:
            bad.append("postgres_major")
        revision = data.get("image_revision")
        if (not isinstance(revision, str) or not re.fullmatch(r"\S+", revision)
                or revision == "unknown"):
            bad.append("image_revision")
        if bad:
            issues[profile] = sorted(bad)
    return sorted(REQUIRED_INSTALL_PROFILES - seen), issues


def scan_platforms(role):
    return ("linux/amd64", "linux/arm64")


def validate_image_sbom(data, image):
    """Reject incomplete inventories and unresolved local Go module replacements.

    A local ``replace => ..`` is a build input, not a publishable package
    identity. Trivy currently emits it as ``pkg:golang/..`` for the broker.
    Keep the image gate closed until the final build identifies that source.
    """
    if (not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX"
            or not data.get("specVersion")):
        return "not a CycloneDX SBOM"
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        return "SBOM metadata is invalid"
    image_component = metadata.get("component") or {}
    if not isinstance(image_component, dict):
        return "SBOM image identity is invalid"
    if image_component.get("name") != image:
        return "SBOM image identity mismatch"
    if not isinstance(image_component.get("bom-ref"), str) or not image_component["bom-ref"]:
        return "SBOM image reference is missing"
    components = data.get("components")
    if not isinstance(components, list) or not components:
        return "SBOM has no components"
    refs = set()
    for component in components:
        if not isinstance(component, dict):
            return "SBOM contains an invalid component"
        ref = component.get("bom-ref")
        if not isinstance(ref, str) or not ref or ref in refs:
            return "SBOM has missing or duplicate component references"
        refs.add(ref)
        purl = component.get("purl") or ""
        if not isinstance(purl, str):
            return "SBOM component purl is invalid"
        if (component.get("name") in {".", ".."}
                or (purl.startswith("pkg:golang/")
                    and any(part in {".", ".."} for part in purl.split("?", 1)[0].split("/")))):
            return "SBOM contains an unresolved local Go module"
    refs.add(image_component["bom-ref"])
    for dependency in data.get("dependencies") or []:
        if not isinstance(dependency, dict):
            return "SBOM dependency is invalid"
        depends_on = dependency.get("dependsOn") or []
        if (not isinstance(depends_on, list)
                or not isinstance(dependency.get("ref"), str)
                or dependency["ref"] not in refs
                or any(not isinstance(ref, str) or ref not in refs for ref in depends_on)):
            return "SBOM dependency references an unknown component"
    return None


def validate_image_report(data, image, platform):
    """Bind a complete Trivy JSON report to the requested image and platform."""
    if (not isinstance(data, dict) or data.get("SchemaVersion") != 2
            or data.get("ArtifactType") != "container_image"):
        return "not a supported container image report"
    if data.get("ArtifactName") != image:
        return "image report identity mismatch"
    metadata = data.get("Metadata")
    config = metadata.get("ImageConfig") if isinstance(metadata, dict) else None
    operating_system, architecture = platform.split("/")
    if (not isinstance(config, dict) or config.get("os") != operating_system
            or config.get("architecture") != architecture):
        return "image report platform mismatch"
    results = data.get("Results")
    if not isinstance(results, list):
        return "image report results are missing or invalid"
    for result in results:
        if (not isinstance(result, dict) or not isinstance(result.get("Target"), str)
                or not result["Target"]):
            return "image report result is invalid"
        findings = result.get("Vulnerabilities")
        if findings is None:
            continue  # Trivy omits this field for a clean result.
        if not isinstance(findings, list) or any(
                not isinstance(finding, dict)
                or not isinstance(finding.get("VulnerabilityID"), str)
                or not finding["VulnerabilityID"] for finding in findings):
            return "image report findings are invalid"
    return None


def run_fresh_report(trivy, image, platform, output, report_format, severity=None):
    # A previous clean file must never make an unsuccessful new run pass.
    # Use a fresh path and preserve a new report even when the scanner fails.
    with tempfile.TemporaryDirectory(prefix=".scan-", dir=output.parent) as temporary:
        fresh = Path(temporary) / output.name
        command = [trivy, "image", "--image-src", "remote", "--platform", platform,
                   "--scanners", "vuln", "--format", report_format, "--output", str(fresh)]
        if severity:
            command.extend(["--severity", severity])
        run = subprocess.run([*command, image], capture_output=True, text=True)
        written = fresh.is_file()
        if written:
            os.chmod(fresh, 0o600)
            os.replace(fresh, output)
        return run, written


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report-dir", required=True, type=Path)
    p.add_argument("--built-image", action="append", default=[], metavar="ROLE=IMAGE@sha256:...")
    p.add_argument("--install-plan", action="append", default=[], type=Path,
                   help="completed installation plan; supply each supported profile once for a full scan")
    p.add_argument("--inventory-only", action="store_true", help="check references without downloading or scanning")
    args = p.parse_args()
    refs = source_images()
    built = {}
    for item in args.built_image:
        role, sep, image = item.partition("=")
        if not sep or role not in REQUIRED_BUILT or role in built:
            p.error("--built-image requires a unique required ROLE=IMAGE reference")
        built[role] = image
    refs.update({f"built:{key}": value for key, value in built.items()})
    missing = sorted(REQUIRED_BUILT - built.keys())
    unpinned = {key: value for key, value in refs.items() if not PIN.search(value)}
    required_bindings = compose_required_image_bindings()
    required_only = sorted(compose for compose, role in COMPOSE_BUILT_ROLES.items()
                           if role in REQUIRED_BUILT and compose not in refs
                           and compose in required_bindings)
    unbound = sorted(compose for compose, role in COMPOSE_BUILT_ROLES.items()
                     if role in REQUIRED_BUILT and compose not in refs
                     and compose not in required_bindings)
    mismatched = {
        compose: role for compose, role in COMPOSE_BUILT_ROLES.items()
        if role in built and compose in refs and refs[compose] != built[role]
    }
    postgres_version_mismatch = ("spilo" in built and
                                 not postgres_major_is_18(COMPOSE_FILES[0].read_text()))
    missing_profiles, plan_issues = inspect_install_plans(args.install_plan, built)
    # A required Compose image is bound by the completed installation plans.
    # Requiring a literal Compose default here would make this gate impossible
    # to pass even when both supported profiles select the scanned digests.
    required_only_satisfied_by_plans = not missing_profiles and not plan_issues
    report_dir = args.report_dir.resolve()
    report_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(report_dir, 0o700)
    summary = {"checked_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
               "references": refs, "missing_built_roles": missing,
               "unpinned": unpinned, "mismatched_compose_roles": mismatched,
               "required_only_compose_roles": required_only,
               "required_only_satisfied_by_plans": required_only_satisfied_by_plans,
               "unbound_compose_roles": unbound,
               "postgres_version_mismatch": postgres_version_mismatch,
               "missing_install_profiles": missing_profiles,
               "install_plan_issues": plan_issues,
               "scans": {}, "passed": False}
    if (not args.inventory_only and not missing and not unpinned and not mismatched
            and required_only_satisfied_by_plans and not unbound and not postgres_version_mismatch):
        trivy = shutil.which("trivy")
        if not trivy:
            p.error("trivy is required to scan release images")
        summary["scanner_version"] = subprocess.run([trivy, "--version"], capture_output=True,
                                                       text=True, check=True).stdout.strip()
        for role, image in refs.items():
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", role)
            for platform in scan_platforms(role):
                output = report_dir / f"{safe}_{platform.replace('/', '_')}.json"
                scan_key = f"{role}:{platform}"
                run, written = run_fresh_report(trivy, image, platform, output, "json", "HIGH,CRITICAL")
                if run.returncode or not written:
                    summary["scans"][scan_key] = {"ok": False, "error": "scanner failed",
                                                  "exit_code": run.returncode, "platform": platform}
                    continue
                try:
                    data = json.loads(output.read_text())
                    report_error = validate_image_report(data, image, platform)
                except (OSError, UnicodeError, ValueError):
                    report_error = "image report cannot be parsed"
                if report_error:
                    summary["scans"][scan_key] = {"ok": False, "error": report_error,
                                                  "report": output.name, "platform": platform}
                    continue
                findings = [(result, v) for result in data.get("Results", [])
                            for v in result.get("Vulnerabilities") or []]
                accepted = [(result, v) for result, v in findings
                            if known_walg_version_false_positive(role, result, v)]
                blocking = len(findings) - len(accepted)
                sbom_error = None
                sbom_output = None
                if role.startswith("built:"):
                    sbom_output = report_dir / f"{safe}_{platform.replace('/', '_')}.cdx.json"
                    sbom_run, sbom_written = run_fresh_report(
                        trivy, image, platform, sbom_output, "cyclonedx")
                    if sbom_run.returncode or not sbom_written:
                        sbom_error = "SBOM scanner failed"
                    else:
                        os.chmod(sbom_output, 0o600)
                        try:
                            sbom_error = validate_image_sbom(json.loads(sbom_output.read_text()), image)
                        except (OSError, ValueError):
                            sbom_error = "SBOM cannot be parsed"
                summary["scans"][scan_key] = {"ok": blocking == 0 and sbom_error is None,
                                               "high_or_critical": len(findings),
                                               "accepted_version_false_positive": len(accepted),
                                               "blocking_high_or_critical": blocking,
                                               "report": output.name, "platform": platform}
                if sbom_output is not None:
                    summary["scans"][scan_key]["sbom_report"] = sbom_output.name if sbom_written else None
                    summary["scans"][scan_key]["sbom_error"] = sbom_error
        expected_scans = sum(len(scan_platforms(role)) for role in refs)
        summary["passed"] = all(v["ok"] for v in summary["scans"].values()) and len(summary["scans"]) == expected_scans
    path = report_dir / "summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    os.chmod(path, 0o600)
    print(json.dumps({"passed": summary["passed"], "missing_built_roles": missing,
                      "unpinned_roles": list(unpinned), "mismatched_compose_roles": mismatched,
                      "required_only_compose_roles": required_only,
                      "required_only_satisfied_by_plans": required_only_satisfied_by_plans,
                      "unbound_compose_roles": unbound,
                      "postgres_version_mismatch": postgres_version_mismatch,
                      "missing_install_profiles": missing_profiles,
                      "install_plan_issues": plan_issues,
                      "scanned": len(summary["scans"])}))
    return 0 if summary["passed"] or (args.inventory_only and not unpinned and not missing and
                                       not mismatched and required_only_satisfied_by_plans and not unbound and
                                       not postgres_version_mismatch) else 1


if __name__ == "__main__":
    sys.exit(main())
