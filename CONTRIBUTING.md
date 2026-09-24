# Contributing to dsse-core

Thanks for your interest in contributing. `dsse-core` contains the Secure Service Edge
(SSE/ZTNA) services, Admin Console, endpoint agents, and Go packages. We welcome bug
reports, fixes, tests, documentation, and well-scoped features.

## Developer Certificate of Origin (DCO)

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/).
Sign off every commit to certify you wrote the patch or otherwise have the right to submit it under the
project's license:

```sh
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer. Commits without a sign-off cannot
be merged.

## License

This project is licensed under **Apache-2.0** (see [`LICENSE`](LICENSE)). By contributing, you agree
your contributions are licensed under the same terms.

## Building and testing

```sh
go build ./...
go vet ./...
go test ./...

# the Windows steering agent cross-compiles:
GOOS=windows GOARCH=amd64 go build ./clients/windows-wfp/steer/

# the macOS network extension (needs a Swift 6 toolchain):
cd clients/macos-network-extension && swift build && swift test
```

The [CI workflow](.github/workflows/ci.yml) is the reference for platform-specific checks.
On non-Windows hosts, the blanket host build can report a missing `main` for Windows-only
service packages; CI handles those separately and also cross-builds the module for Windows.
Do not treat unrelated build errors as that exception. The nested
[egress broker](egress-broker/README.md) has separate native dependencies and checks.

For documentation-only changes, verify local links, example paths, and commands against
the relevant source. Update the [documentation index](docs/README.md) when adding a guide.
Use fictional names and addresses; never include credentials or private deployment details.
Keep release claims consistent with the experimental status and distinguish implemented
behavior from the results of a specific test. See [Verification](docs/verification.md).

## Integration and release checks

Keep pull requests independently reviewable, with one logical fix or a small set
of inseparable changes. Explain the user-visible problem, expected behavior,
dependencies, verification results and remaining limitations. Keep public claims
separate from unpublished deployment details.

A change may be integrated when:

- Its scope and dependencies have been reviewed, and required checks pass for the
  proposed revision. Document unavailable or skipped checks and their effect on
  acceptance; a skip is not a pass. Identify which checks ran locally or on hosted CI.
- A behavior change has appropriate regression coverage. For an affected user
  workflow, check the real interface and relevant saved state, permissions and
  audit records; do not substitute a rendering or HTTP-only test for browser evidence.
- No unresolved material defect in the changed behavior is being hidden by the
  summary, and the change does not depend on unmerged code without stating it.
- Documentation-only changes have valid links and accurate claims; they do not
  require repeating unrelated runtime acceptance checks. DCO requirements still apply.

Integration into `main` is separate from publishing a release. Release checks cover
the complete candidate, including installation and upgrade instructions, applicable
platforms and signed packages, independent control-plane/Edge traffic and change
propagation, failure and PKI checks, and sustained operation. A merged fix does not
waive these checks or change the project's experimental status. Unverified release
conditions remain open until there is evidence or an explicit documented scope decision.

Update [maintenance progress](docs/maintenance.md) for meaningful integrated fixes,
changed blockers or schedule changes. At release time, provide user-facing changes,
known limitations and upgrade guidance. Avoid accumulating unrelated completed fixes
in a single long-lived pull request.

## Guidelines

- Keep changes focused; one logical change per pull request.
- Add or update tests for behavior changes. The library packages aim to stay well-tested; please don't
  regress that.
- Keep the data plane fail-closed: the reference edge/control-plane must never serve over plaintext, and
  detection/observation must not auto-bypass enforcement.
- Match the surrounding code style and keep comments accurate.
- Do not commit secrets, real certificates/keys, or build artifacts.

## Reporting security issues

Please do **not** file public issues for vulnerabilities — see [`SECURITY.md`](SECURITY.md).
