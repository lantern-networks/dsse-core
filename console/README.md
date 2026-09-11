# Admin Console

The Console is a separate application served by `dsse-console`. It uses the control
plane's admin API over TLS and provides administrator sign-in, MFA, and organization-scoped
management. Edges enforce the resulting configuration.

## Start and sign in

The installer generates the Console service with the rest of the deployment. Follow
[Deployment](../docs/deployment.md), then [First use](../docs/after-verify.md).
Open the generated `https://console.<region>.<deployment>/console.html` URL after installing
the deployment trust anchor on the administrator's machine. Use the named administrator
created by `dsse-install -bootstrap-admin`, including its second factor.

Do not substitute a plain static-file server for this deployment: it omits the Console
server's authentication and routing behavior. Do not accept a browser certificate exception
as proof that the Console belongs to the intended deployment.

## Build

Build the image from the repository root using [Building](../docs/building.md).
Its assets are included in `dsse-console:release`; rebuild that image when changing them.

The interface supports English and Japanese. The tenant context displayed in the header
selects the organization being administered. See [Organizations](../docs/organizations.md)
for the first customer setup and [Agent updates](../docs/agent-updates.md) for package publication.

## TLS and origins

Use the generated deployment names and configuration. Browser API requests need both a
trusted TLS chain and the configured Console origin. If a request is blocked, check the
certificate, the API destination, and the allowed origin; do not disable these checks.
Third-party browser assets are documented in [vendor/README.md](vendor/README.md).
