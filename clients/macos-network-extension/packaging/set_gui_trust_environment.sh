#!/bin/sh
# Run in each logged-in user's launchd session. Existing Node processes keep
# their startup trust store; this supplies the bundle to newly launched apps.
set -eu
bundle="${1:-/Library/Application Support/Dsse/trusted_ca_bundle.pem}"
[ -r "$bundle" ] || exit 0
for variable in SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS AWS_CA_BUNDLE; do
    current="$(launchctl getenv "$variable" 2>/dev/null || true)"
    # Respect an operator's explicit alternative. Reassert only our own setting.
    if [ -z "$current" ] || [ "$current" = "$bundle" ]; then
        launchctl setenv "$variable" "$bundle"
    fi
done
