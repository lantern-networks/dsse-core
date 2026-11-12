# Moving from 0.4.1

0.4.2 keeps the 0.4.1 plan format, layouts, package names and enrolment files.

## Servers

0.4.2 is accepted for fresh installations. Install a deployment with the 0.4.2
installer and the published `release-manifest.json`, following
[Deployment](../../deployment.md#run-the-order-with--up):

```sh
A='-up -deployment dsse.example.com -address 10.20.1.10 -admin-email admin@example.com
   -dir /opt/dsse/region-a -release-manifest release-manifest.json'
dsse-install $A -print-names | sudo tee -a /etc/hosts   # or create the same records in DNS
dsse-install $A
```

The steps `-order` prints are unchanged and remain the reference; `-up` runs them. A plan
written for 0.4.1 works as it is. With `-release-manifest`, the plan no longer has to
name the images, `agent_publisher` or `data_layer.postgres_major`.

## Windows endpoints

On a device enrolled with 0.4.1, install the 0.4.2 MSI with the organization's current
`install_profile.json` as `CONFIG` and `profile_signing_key.txt` as `PIN`, and without
`TOKEN`, as [Windows agent](../../windows-agent.md) describes.

## macOS endpoints

Install the 0.4.2 package as [macOS agent](../../macos-agent.md) describes, after
checking its signature as in [Checking the packages](README.md#checking-the-packages).
