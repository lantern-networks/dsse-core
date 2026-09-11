# amd64 runtime image for the egress broker. Same shape as Dockerfile.runtime; separate because the engine
# artifacts are per-architecture (cgo-amd64/ + cli-amd64/, fetched by the README's amd64 build steps).
FROM --platform=linux/amd64 debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
COPY .build-inspection-root.pem /tmp/build-inspection-root.pem
RUN mkdir -p /etc/ssl/certs \
 && cat /tmp/build-inspection-root.pem >> /etc/ssl/certs/ca-certificates.crt \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && update-ca-certificates && rm -rf /var/lib/apt/lists/* /tmp/build-inspection-root.pem
COPY egress-broker-amd64 /usr/local/bin/egress-broker
COPY cgo-amd64/libcurl-impersonate.so* /usr/local/lib/
COPY cli-amd64/ /usr/local/bin/
# ★ THE LICENCES SHIP WITH THE BINARIES (2026-08-14). The upstream curl-impersonate release tarballs carry no
# licence file of any kind, so an image built from them conveys curl, BoringSSL, zlib, brotli, nghttp2, zstd and
# libidn2 with nothing stating their terms. libidn2 is the one that is not permissive — LGPL-3.0-or-later, as
# elected in THIRD-PARTY.md — and its notice has to travel with the object it is linked into.
COPY third-party-licenses/ /usr/share/doc/dsse-egress-broker/third-party-licenses/
COPY THIRD-PARTY.md /usr/share/doc/dsse-egress-broker/
COPY cgo-amd64/LICENSE* /usr/share/doc/dsse-egress-broker/upstream-licenses/
RUN ldconfig
ENV EGRESS_IMPERSONATE_BIN=curl_chrome146 EGRESS_BROKER_LISTEN=:8088
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/egress-broker"]
