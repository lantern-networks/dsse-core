# Third-party components in the egress broker

The broker links `libcurl-impersonate` through cgo so that decrypted flows are re-originated with a real
browser's TLS and HTTP/2 fingerprint. That library is not a Go module, so **every Go dependency scan is blind to
it** — `go list -deps`, `go-licenses`, an SBOM built from `go.mod`. This file is what those tools cannot produce.

## What is, and is not, distributed

| | contains the third-party binaries? |
|---|---|
| This repository | **No.** `cgo-*/`, `cli*/` and the built broker are gitignored; `build.sh` downloads them at build time from the pinned upstream release |
| The `dsse-egress-broker` container image | **Yes.** `libcurl-impersonate.so*` and the `curl_*` CLI binaries are copied in by `Dockerfile.runtime*` |

The runtime images carry both the checked-in notices and the upstream `LICENSE*` files
from the verified native-library archive. Release v2.2.2 includes these upstream notices;
the older v2.0.0 archive did not.

The archive checksums are fixed in `engine-checksums.sha256`. The shared library and CLI
version output identify their native dependencies; Go module scanning cannot inventory
those components. Retain the upstream release source and build information alongside
any distributed native binary.

## Components

Pinned engine: `lexiforest/curl-impersonate` **v2.2.2**, reporting `libcurl/8.21.0-IMPERSONATE`.

| Component | Licence | Text |
|---|---|---|
| curl-impersonate (lexiforest fork) | MIT, © curl_cffi developers | `third-party-licenses/curl-impersonate.LICENSE` |
| curl / libcurl | curl licence (MIT/X derivate) | `third-party-licenses/curl.COPYING` |
| BoringSSL | Apache-2.0, with notices covering earlier OpenSSL/ISC/MIT-licensed portions | `third-party-licenses/boringssl.LICENSE` |
| nghttp2 | MIT | `third-party-licenses/nghttp2.COPYING` |
| nghttp3 | MIT | upstream `LICENSE_NGHTTP3` |
| ngtcp2 | MIT | upstream `LICENSE_NGTCP2` |
| zlib | zlib licence | `third-party-licenses/zlib.LICENSE` |
| brotli | MIT | `third-party-licenses/brotli.LICENSE` |
| zstd | BSD-3-Clause | `third-party-licenses/zstd.LICENSE` |
| **libidn2** | **GPL-2.0-or-later OR LGPL-3.0-or-later** (library), dual at the recipient's election | `third-party-licenses/libidn2.COPYING.LESSER` |

## libidn2 — the one that is not permissive

Upstream states it plainly: *"The source code for the C library (libidn2.a or libidn.so) are dual-licensed under
the terms of either the GNU General Public License version 2.0 or later … or the GNU Lesser General Public
License version 3.0 or later … or both in parallel."* The command-line tool and tests are GPL-3.0-or-later; the
broker ships only the library, statically linked into `libcurl-impersonate.so`.

**This project elects the LGPL-3.0-or-later arm.** The election matters and is not a formality: GPL-2.0-only is
incompatible with Apache-2.0, while LGPL-3.0-or-later expressly permits combination with Apache-2.0 material.
Taking the LGPL arm is what makes the OSS licence decision (Apache-2.0) and this component consistent.

**What that requires of anyone distributing the image**, per LGPLv3 §4 — review these before distributing the image:

1. Ship the LGPL notice and licence text with the binary. `third-party-licenses/` in the image is that.
2. State prominently that libidn2 is used and covered by the LGPL. This file, and the notice in the image.
3. Leave the recipient able to relink a modified libidn2. Satisfied by the build being reproducible from public
   inputs: `build.sh` pins the engine version, the upstream release is public, and everything else linked into
   that object is permissive. A recipient who wants a different libidn2 rebuilds curl-impersonate at the pinned
   version and drops the result in.

**Apache-2.0 for this repository's own source is unaffected.** LGPL obligations attach to the distributed
binary that contains libidn2, not to code that calls curl through cgo.

## Keeping this true

Before distributing a runtime image, check that it carries `third-party-licenses/` and
that the inventory matches its actual native components. Retain the corresponding
source and build information needed by the applicable licences.

**Bumping `ENGINE_VERSION` requires reviewing this inventory and the archive checksums.** A new engine release can add or drop a dependency, and the
method above is the way to re-establish the set: `strings` the new object, compare against the table.
