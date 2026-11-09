# Moving from 0.4.0

0.4.1 keeps the 0.4.0 plan format, layouts, package names and enrolment files.

## Servers

0.4.1 is accepted for fresh installations. Install a deployment with the 0.4.1
installer and the images in [the release README](README.md#server-container-images),
following [Deployment](../../deployment.md) from `-order`. The 0.4.1 `-order` includes
`-activate-auth` for every plan; run each step on the machine it names.

## Windows endpoints

On a device enrolled with 0.4.0, install the 0.4.1 MSI with the organization's current
`install_profile.json` as `CONFIG` and `profile_signing_key.txt` as `PIN`, and without
`TOKEN`. The enrolment is kept. The updater restarts with the profile's update keys and
publisher, and the certificates 0.4.0 trusted for provisioning are recorded so that a
later uninstall removes them. Then run `verify-windows-install.ps1` from the 0.4.1
source as [Windows agent](../../windows-agent.md) describes.

## macOS endpoints

Install the 0.4.1 package as [macOS agent](../../macos-agent.md) describes, after
checking its signature as in [Checking the packages](README.md#checking-the-packages).
