# Upstream trust for operating-system services

Linux public Web PKI bundles do not necessarily contain the vendor authorities used
by operating-system services. The Go SWG egress path supplements its upstream TLS
trust for these exact destinations:

| Destination | Additional root |
|---|---|
| `init.ess.apple.com` | Apple Root CA - G3 |
| `pds-init.ess.apple.com` | Apple Root CA |
| `msedge.api.cdp.microsoft.com` | Microsoft Root Certificate Authority 2011 |
| `watson.events.data.microsoft.com` | Microsoft Root Certificate Authority 2011 |
| `tsfe.trafficshaping.dsp.mp.microsoft.com` | Microsoft Root Certificate Authority 2011 |

This affects upstream authentication only. Routing, authorization and DLP still
apply. Certificate signatures, validity, server authentication usage and hostname
verification use the standard Go TLS verifier. Existing system and organizational
anchors are preserved. No root is installed in the system trust store, learned
from a server, or applied to other destinations. Custom TLS dialers and non-Go
transports retain their own trust handling.

## Certificate provenance and maintenance

The public root certificates are embedded in the binary; there is no runtime
download. DER SHA-256 fingerprints are pinned in `vendor.go`. Changes to roots or
destination scope require a reviewed source update and a new build. Root expiry
remains a verification failure; this package does not add revocation checking to
Go's existing upstream verifier.

- [Apple PKI repository](https://www.apple.com/certificateauthority/):
  [Apple Root CA](https://www.apple.com/appleca/AppleIncRootCertificate.cer) and
  [Apple Root CA - G3](https://www.apple.com/certificateauthority/AppleRootCA-G3.cer).
  Their SHA-256 values are also published in Apple's
  [operating-system root certificate list](https://support.apple.com/en-us/126047).
- [Microsoft PKI repository](https://www.microsoft.com/pkiops/docs/repository.htm):
  [Microsoft Root Certificate Authority 2011](https://www.microsoft.com/pki/certs/MicRooCerAut2011_2011_03_22.crt).
  Its repository SHA-1 identifier is `8f43288ad272f3103b6fb1428485ea3014c0bcfe`;
  the embedded certificate is pinned with SHA-256, not SHA-1.

Additional private OS service authorities and origins requiring a missing
intermediate are outside this destination list. A certificate refusal is not
automatically converted into an inspection bypass.
