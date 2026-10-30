# Live Keycloak browser verification

`TestKeycloakLiveBrowserHarness` runs the production clientless broker and
federated grant gate against an isolated Keycloak. It creates three separate
broker instances with separate pending state and grant stores in one Go process,
on loopback ports 18181–18183. This verifies broker behavior; it does not verify
public TLS, replicated storage, AWS node failure, or an OS agent's policy path.

Prepare two Keycloak realms, `dsse-momiji` and `dsse-kaede`, reachable at
`http://localhost:18080`. Each confidential `dsse-edge` client must use
Authorization Code and PKCE S256, with direct grants and service accounts disabled.
Allow only these exact redirect URIs:

```
http://localhost:18181/clientless/auth/callback
http://localhost:18182/clientless/auth/callback
http://localhost:18183/clientless/auth/callback
```

Configure password assurance ACR `1` and password plus TOTP ACR `2`. In Keycloak
26.8.0 the Conditional LoA authenticator keys are `loa-condition-level` and
`loa-max-age`; set the stronger level's age to `0` to require another OTP on the
next step-up. TOTP does not demonstrate phishing resistance. See the
[Keycloak step-up documentation](https://www.keycloak.org/docs/26.8.0/server_admin/#_step-up-flow).

Place `momiji-idp-connection.private.json` and
`kaede-idp-connection.private.json` in a private state directory. Use the DSSE
IdP connection API representation, with IDs `keycloak-momiji`/`keycloak-kaede`,
the corresponding realm issuer, endpoints, client secret, PKCE, and email-domain
restrictions. The harness assigns fixture tenant IDs `tenant_momiji` and
`tenant_kaede`. Keep secrets outside Git.

```sh
DSSE_KEYCLOAK_STATE_DIR=/absolute/private/state \
  go test ./cmd/dsse-edge -run '^TestKeycloakLiveBrowserHarness$' -count=1 -timeout 17m
```

Wait for `browser-harness-ready.json`, which records the run ID and scope.
Use a real browser to visit `/acceptance/start?tenant=momiji&acr=1` and then
`acr=2` on each loopback port; repeat for `tenant=kaede`. Check the actual
`/acceptance/status` grant tuples and gate flags after each ceremony. Baseline
must not release MFA. Other device, unbound flow, and wrong provider flags must
remain false.

Record negative cases with unchanged grant counts: invalid OTP; replay of a
consumed callback; `tamper=device`; `downgrade=true` on an ACR 2 start; an
unauthorized email domain; and `callback_owner=C` on port 18181. The latter
modifies the actual authorization request's redirect URI to deliver the callback
to the wrong broker, whose pending state must not recognize it. These fault
controls exist only in the opt-in loopback harness.

POST `/acceptance/revoke` on each port and confirm the gates close. POST
`/acceptance/finish` to stop the harness before its 15-minute deadline. A passing
Go harness result only confirms it started and finished; browser observations
must be checked independently and associated with the run ID. Ordinary unit
tests skip this harness.
