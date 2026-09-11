# Build the DSSE binaries (static, no cgo).
#
# ★ dsse-edge IS THE PRODUCT EDGE, and it is also the control plane: the same binary, told which it is by
# -control-plane. There is no separate control-plane binary — dsse-cp was a reduced reference that is not what
# a deployment runs, and it was retired on 2026-08-23 with the decision that the published binary is the
# product one. Splitting the roles into two binaries is a separate, later change.
FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /src
# ★★★ THE NESTED MODULE'S go.mod HAS TO ARRIVE FIRST (2026-08-23, found by building this tree on its own).
# go.mod carries `replace ... => ./egress-broker`, so `go mod download` opens that path — and the usual
# copy-the-manifests-first layer-caching trick copies only the top-level pair. The build died on
#
#   reading egress-broker/go.mod: open /src/egress-broker/go.mod: no such file or directory
#
# which is not a missing dependency, it is a file the Dockerfile chose not to copy yet. Nothing in the
# monorepo build hits this, because there the whole tree is already on disk.
COPY go.mod go.sum ./
COPY egress-broker/go.mod egress-broker/go.sum ./egress-broker/
RUN go mod download
COPY . .
# ★★★ dsse-connector-install SHIPS WITH dsse-connector, and it was written without being added here
# (2026-08-26). An installer nothing builds is an installer nobody can run: the customer was still left with
# the one long command line it exists to replace. This is the same defect as 2026-08-23, when the published
# installer required twelve flags of which ten were not in the published Edge — the published tree could not
# install itself. The pair below is what a machine inside the customer's network needs: the program, and the
# thing that puts it there so it comes back after a reboot.
# ★★★ AND THE BUILD SAYS WHICH BUILD IT IS (2026-09-04, found by standing this tree up from a clone and
# running -verify: 27 checks passed and the 28th was
#
#	all 3 node(s) report an UNSTAMPED build, so they cannot be shown to be the same one
#
# "Every node runs the same build" is a real question — a deployment half on one build and half on another
# looks healthy from either side — and it can only be answered if the binaries say what they are. The
# internal build has always passed -ldflags; this one did not, so anything built from the published tree
# could never answer it. DSSE_REVISION defaults to "unknown", which is honest: a tree built without being
# told still reports something, and reports it identically on every node built the same way.
ARG DSSE_REVISION=unknown
RUN LD="-X main.buildVersion=$(sh scripts/build_stamp.sh --version) -X main.buildCommit=${DSSE_REVISION} -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.buildDirty=false" \
 && CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o /out/dsse-edge ./cmd/dsse-edge \
 && CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o /out/dsse-connector ./cmd/dsse-connector \
 && CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o /out/dsse-connector-install ./cmd/dsse-connector-install \
 && CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o /out/dsse-install ./cmd/dsse-install \
 && CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o /out/dsse-signupdate ./cmd/dsse-signupdate

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates
# ★★★ AND dsse-signupdate, FOR THE SAME REASON (2026-08-28). A control plane holds the update-signing key only
# when it has a token; the key has no on-disk fallback by design, so on every other deployment the ONLY way to
# publish a release is to sign the manifest away from the nodes and publish the envelope. The Console says so on
# its own release screen — and the program that does it was built by nothing, so the instruction ended at a
# command not found on the machine where the key already is.
COPY --from=build /out/dsse-edge /out/dsse-connector /out/dsse-connector-install /out/dsse-install /out/dsse-signupdate /usr/local/bin/
# ★★★ THE MIGRATIONS SHIP WITH THE BINARY THAT RUNS THEM (2026-08-23). Until the Edge became the published
# binary this was invisible: the LOADER was published and the 45 .sql files it reads were in the product tree.
# A published deployment would have had a control plane that requires -migration-dir and nothing to point it
# at — it refuses to start, which is the good direction, on a file nobody could have supplied.
COPY --from=build /src/migrations /app/migrations
COPY --from=build /src/schemas /app/schemas
COPY --from=build /src/samples /app/samples
