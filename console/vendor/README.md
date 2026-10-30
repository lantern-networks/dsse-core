# Vendored third-party assets

These files are bundled so the Admin Console (a static, separate-host app) works fully
offline — no CDN or external calls — which is required since it talks only to the tenant
Edge/control-plane admin API over TLS.

- **qr.js** — `qr` 0.7.2 QR generator by Paul Miller, used to render the TOTP enrollment QR locally as SVG. Source: https://www.npmjs.com/package/qr/v/0.7.2
  npm tarball integrity: `sha512-yovYRuacJBJkG9fWSwcB2bKZhr58c04DpOXguDU+rAAoJZdi6/J3DtlomkKqdd1MutIptIK+kigWmT7LKz8y7A==`.
  `index.js` is copied unchanged as `qr.js`; SHA256: `3e3d38c37ecc5691b1edcc5b0dd6882b78280dc7f2130168bd7df074d1b21e47`.
  License: MIT OR Apache-2.0; notices are in `qr.LICENSE` and `qr.LICENSE-MIT`. No runtime dependencies or external calls.
