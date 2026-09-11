# Vendored third-party assets

These files are bundled so the Admin Console (a static, separate-host app) works fully
offline — no CDN or external calls — which is required since it talks only to the tenant
Edge/control-plane admin API over TLS.

- **qrcode.min.js** — qrcodejs QR Code generator. Source: https://github.com/davidshimjs/qrcodejs
  License: MIT (David Shim). Used to render the TOTP enrollment QR on the activation page.
