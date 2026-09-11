#!/usr/bin/env python3
"""Reject runtime provisioning material in the deployment- and tenant-independent PKG payload."""

import argparse
from pathlib import Path


def unexpected_files(root, app_id, app_exec, extension_exec):
    app = f"Applications/{app_exec}.app/Contents"
    extension = f"{app}/Library/SystemExtensions/{app_id}.networkextension.systemextension/Contents"
    allowed = {
        f"Library/LaunchAgents/{app_id}.plist",
        f"Library/LaunchAgents/{app_id}.trust-environment.plist",
        f"Library/LaunchDaemons/{app_id}.updater.plist",
        f"{app}/Resources/lantern-symbol.png",
        f"{app}/Resources/lantern.icns",
    }
    for name in ("dsse-updater", "dsse-profileverify", "dsse-verify-install",
                 "dsse-uninstall", "set-gui-trust-environment"):
        allowed.add(f"Library/Application Support/Dsse/bin/{name}")
    for bundle, executable in ((app, app_exec), (extension, extension_exec)):
        for name in ("Info.plist", "_CodeSignature/CodeResources", "embedded.provisionprofile",
                     f"MacOS/{executable}"):
            allowed.add(f"{bundle}/{name}")
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")
                  if p.is_symlink() or (not p.is_dir() and str(p.relative_to(root)) not in allowed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--app-id", default="jp.co.lantern-networks.dsse.agent")
    parser.add_argument("--app-exec", default="LanternDsseAgent")
    parser.add_argument("--extension-exec", default="DsseAppProxyProvider")
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error("payload root must be an existing directory")
    unexpected = unexpected_files(args.root, args.app_id, args.app_exec, args.extension_exec)
    if unexpected:
        parser.exit(1, "Generic PKG refused: unexpected payload files (configuration belongs outside the PKG):\n"
                    + "\n".join(unexpected) + "\n")
    print("Generic PKG payload: product files only; deployment and tenant provisioning inputs are external.")


if __name__ == "__main__":
    main()
