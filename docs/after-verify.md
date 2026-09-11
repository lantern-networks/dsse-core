# First use after deployment verification

A successful `dsse-install -verify` checks infrastructure. Finish the steps below to make
the deployment usable by an administrator and a customer endpoint.

## 1. Trust the deployment and sign in

On the administrator's computer, configure the generated DNS names and install the
verified `deployment-anchor.pem` as described under [Certificates](deployment.md#certificates).
Open `https://console.<region>.<deployment>/console.html` using the actual generated name.

Use the email and password from `-bootstrap-admin`. Add the printed **second-factor
secret** to an authenticator and enter its current TOTP code when prompted. Keep recovery
codes separately. An API token is for API calls, not the Console password or second factor.
Confirm that the Console header shows the operator context and the expected deployment.

If the browser refuses TLS, first check its trust store and the certificate hostname.
Do not bypass the warning. For a direct diagnostic, authenticate both the name and chain:

```sh
openssl s_client -connect <address>:443 -servername <generated-hostname> \
  -verify_hostname <generated-hostname> -verify_return_error \
  -CAfile deployment-anchor.pem </dev/null
```

The command must complete certificate verification successfully. Use the anchor obtained
through your trusted setup channel, not one fetched from the address being checked.
An issuer's display name or a publicly trusted chain alone does not prove deployment identity.

## 2. Create the customer organization

Follow [Organizations](organizations.md) to create a customer, enable the required operator
delegation, configure its transport, device, and interception authorities, and review its
initial policy. The operator organization `tenant_default` is not a customer enrolment target.

If the Console is to distribute endpoint installers, publish the signed package through
[Agent Releases](agent-updates.md) first. Otherwise supply the compatible signed package
alongside the configuration archive. A new deployment does not contain a published endpoint
release merely because its services started.

## 3. Verify a device's setup material

Obtain a fresh configuration archive **for that customer organization** and extract it
into an empty directory. It should contain a profile, profile-signing public key, one-time
enrolment token, and the intended platform's installer (if published).

```sh
dsse-profileverify -profile install_profile.json -pin profile_signing_key.txt
```

Obtain the signing pin through the trusted administrator handoff; a key supplied by an
untrusted party beside a profile cannot authenticate that party. Confirm the organization,
transport names, posture, device CA pin, and organization's interception root in the
verified output. Decoding `payload_b64` alone is not signature verification.

## 4. Install and test on the endpoint

Make sure the regional transport and recovery URLs in the verified profile resolve on
the device. Organization-specific SNI names and dial addresses are different: use the
profile's values, not guessed names. Follow [Windows](windows-agent.md) or
[macOS](macos-agent.md), including the local verification script.

Before considering first setup complete, establish that:

- the Console shows the device in the intended customer organization;
- a recent endpoint report and the local verifier show active steering;
- an allowed HTTPS request succeeds with certificate verification in the browser **and**
  the command-line programs this device uses;
- a deliberately denied test destination is blocked and its decision is visible in the Console;
- if private access is required, an installed [connector](connector.md) makes the intended
  application reachable from the endpoint, while policy still denies unauthorized access.

Read every failed or unanswered verifier result. These startup checks do not replace
certificate-rotation, sleep/wake, restart, and region-loss tests on the release build.
