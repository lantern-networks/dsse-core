<#
.SYNOPSIS
  Build the Lantern DSSE Agent MSI (roadmap M8.3): compile the user-mode exes, then `wix build` the MSI.

.DESCRIPTION
  Reproduces the M8.3 skeleton MSI. Optionally seals the exes with the signing-agnostic wrapper (sign.ps1)
  before packaging. The MSI itself and the staged exes go under <tree>\outputs\windows (gitignored).

  Prerequisites:
    - Go (windows/amd64 build)
    - WiX v5 as a dotnet global tool:  dotnet tool install --global wix --version 5.0.2
      (WiX v6/v7 add the OSMF EULA gate; v5 does not. See README.)
    - Windows SDK signtool (only when -Sign)

.EXAMPLE
  pwsh build-msi.ps1
  pwsh build-msi.ps1 -Version 0.2.0 -Sign -SignBackend test
#>
[CmdletBinding()]
param(
  # Default from the nearest VERSION file walking upward — the single source of truth shared with the macOS
  # build scripts and the Go -ldflags stamp (scripts/build_stamp.sh). Hardcoding it here let Windows and macOS
  # drift apart. Walks upward rather than using a fixed depth because this tree is ALSO mirrored to the public
  # dsse-core repo, where the root sits at a different level; there it finds that repo's own VERSION.
  #
  # ★ RESOLVE IT FIRST (2026-08-22). $PSScriptRoot is only absolute when the script is invoked by an absolute
  # path. Run with a RELATIVE -File argument it is that relative string, and Split-Path then walks off the top
  # of it long before reaching the repo root — so the walk found no
  # VERSION at all and the package was stamped 0.0.0-unversioned. WiX only WARNS about an invalid package
  # version, so nothing fails and a garbage version ships. An upward walk is only meaningful on a full path.
  # ★★★ AND IT IS NOT RESOLVED HERE ANY MORE (2026-09-04, found by the Windows session running this from a
  # copy of the published tree). A param() default is evaluated BEFORE the script scope exists, in the
  # CALLER's scope — where $PSScriptRoot is empty. The walk above therefore started from `(Get-Location)`,
  # so the version came out right when the shell happened to be sitting in this directory and
  # "0.0.0-unversioned" from anywhere else, INCLUDING when the script was invoked by its absolute path.
  # The refusal below then told the operator to do the one thing they had already done.
  #
  # Empty here, resolved in the body, where $PSScriptRoot is the real thing.
  [string] $Version = "",
  [ValidateSet('x64','arm64')][string] $Arch = "x64",
  [switch] $Sign,
  [ValidateSet('test','trustedsigning','evtoken')][string] $SignBackend = 'test',
  [string] $DriverSys = "",  # DsseWfp .sys to embed; default outputs\windows\dsse-wfp.sys (dev/test-signed)
  [string] $Profile = "",    # a CP-signed L1 profile.json to bundle (per-tenant "provisioned" MSI). Empty = generic MSI.
  [string] $Pin = "",        # L1 Ed25519 key, baked into both profile verifiers and passed to DsseSteer. Also supported without -Profile.
  # The TRANSPORT CA this device verifies the EDGE with — a PEM, laid down as %ProgramData%\DSSE\transport_ca.pem.
  #
  # ★ NOTHING PROVISIONED IT AND EVERY PATH NOW REQUIRES IT (2026-08-12, traced on win-dev-1). The install
  # profile carries `transport_anchor`, a FINGERPRINT, whose own comment says "else obtained at enroll" — and
  # the enrol response returns the DEVICE-ISSUING CA, which is a different PKI and cannot verify a server. So a
  # freshly installed box had no anchor by any route. Once the twentieth review correctly stopped the agent
  # persisting an identity it could not prove, that box stopped being able to ENROL at all: it stands aside,
  # for the right reason, forever, because nothing in the product ever produces the file it is waiting for.
  #
  # This is the "anchor the device was born with" the agent's own comments describe. Adopted anchors from a
  # signed trust bundle supersede it the moment the fleet rotates; this is only the starting point.
  [string] $TransportCA = "",
  # The update-manifest signing key(s) DsseUpdater verifies against, comma-separated hex. Each one is either a
  # 64-char Ed25519 key or a 130-char uncompressed ECDSA-P256 point starting 04 — the same two shapes -PlanPin
  # takes, because the same function decides both (agentpolicy.isAcceptedPublicKeyHex, reached from
  # agentupdate.OpenWithKey via VerifyAnyWithKey).
  #
  # Comma-separated is how a key ROTATION is carried out, and it is the only way: ship a build pinning the old
  # key AND the new one, wait for the fleet to hold both, and only then start signing with the new one. Doing
  # it in the other order strands every device, and the update lane cannot rescue them — a new pin arrives in
  # an MSI, and the MSI arrives through the lane that is refusing to verify (2026-08-13).
  #
  # A SEPARATE key from -Pin, and the separation is the point rather than tidiness: -Pin signs configuration,
  # this one signs the authority to run code. One key doing both means a compromise of the config-signing path
  # is a compromise of the code-execution path, which is the property the update key exists to deny.
  #
  # Empty is a supported and meaningful state, not an oversight: the service installs and idles, reporting that
  # this device can never update. That is the correct shape for a generic MSI, where the deployment has not yet
  # decided who may publish code to it.
  [string] $UpdatePin = "",
  # The key the ROLLOUT PLAN is verified against: the agent-policy key, NOT the update key.
  #
  # Different powers, and this is the second half of the separation -UpdatePin exists for. The plan says WHEN
  # this device may install and whether the fleet is HALTED; the manifest says WHAT it runs. An Edge holds the
  # plan key and must never hold the other, so a compromised traffic node can stall a rollout and cannot
  # publish code.
  #
  # Empty is supported and visibly degraded rather than silently: the updater accepts the plan unverified and
  # prints UNVERIFIED on every status line. That matters more here than it looks — an unverified plan means the
  # FREEZE is only as strong as the file's permissions, so a deployment that wanted withdrawal to be
  # tamper-evident and left this blank has not got it.
  [string] $PlanPin = "",
  # Who must have BUILT a package before DsseUpdater installs it as SYSTEM: `subject:<Authenticode Subject O=>`
  # or `thumbprint:<leaf certificate SHA-256>`.
  #
  # ★ THE THIRD AUTHORITY, AND THE ONE WINDOWS DID NOT HAVE (2026-08-14). -Pin signs configuration,
  # -UpdatePin says WHICH VERSION may run, and until now nothing said WHO BUILT THE BYTES. A manifest signer can
  # name the digest of anything it likes, so the digest check that stands between a download and `msiexec /i` as
  # SYSTEM is one the attacker's own manifest writes. macOS has asked this since 0.3.0 (update_publisher_team_id);
  # this is the same question, in the identity Windows has: the Authenticode signature the EV certificate already
  # puts on every release.
  #
  # `subject:` is the durable form and the one to use — a Subject O= survives certificate renewals, the way an
  # Apple Team ID does. `thumbprint:` pins one certificate exactly and STOPS THE FLEET UPDATING the day that
  # certificate is reissued, which for an EV certificate on a hardware token is a scheduled event.
  #
  # Empty is supported and visibly degraded, like -PlanPin: the updater installs and says on every status line
  # that packages are accepted on the manifest signature alone. It is NOT a silent default — an unset publisher
  # is the state this parameter exists to make visible.
  [string] $UpdatePublisher = "",
  # Destinations the agent must NOT steer, comma-separated `host` or `host:port`.
  #
  # ★ THIS EXISTS BECAUSE THE MSI SILENTLY DROPPED A DESIGN DECISION (2026-08-14). The hand-deployed agent ran
  # with `--bypass-dest <edge>:8088,203.0.113.10` and the MSI had no way to carry it, so every MSI-managed box
  # steered its own management path. The rule is explicit that this must
  # not happen: an edge that is down otherwise takes the recovery route down with it, and an
  # existing configuration IS the specification.
  #
  # Measured cost: `ssh mac` died on win-dev-1 because the destination WAS the edge, so the edge dialled
  # itself — the same hairpin, identical down to the 21-byte SSH banner. The only expressible workaround was a
  # CP steer-exclusion for ssh.exe, which is app-based and therefore exempts SSH to EVERY host rather than to
  # the one that needs it.
  #
  # Empty is the right default: most devices have no destination that must skip the tunnel, and a bypass is an
  # enforcement hole that should be named deliberately rather than inherited.
  # The organization's install bundle, as saved from GET /admin/tenant-install-bundle/{tenant}.
  #
  # ★ ONE ANSWER, NOT THREE DOWNLOADS (docs/pki_trust_model.md section 8.2). The Edge returns the transport anchors,
  # that organization's interception root, and the signed trust bundle it starts from TOGETHER, precisely
  # because "an installer assembled from parts fetched at different moments is how a package pins one
  # organization's transport anchor beside another's interception root". This parameter takes the whole answer
  # so the package cannot be built from a mismatched set.
  #
  # It is also what ends the manual procedure. Until now the interception root was installed by a person
  # following docs/handoff_windows_interception_root_changed_to_hsm.ja.md — a runbook whose own history is two
  # corrections, one of which shipped a stale fingerprint that would have broken every HTTPS site on a machine
  # that followed it.
  #
  #   curl.exe -sk -H "Authorization: Bearer $T" -H "X-Operate-Tenant: $TENANT" `
  #     https://<edge>:9443/admin/tenant-install-bundle/$TENANT | Out-File -Encoding ascii bundle.json
  #   build-msi.ps1 -TenantBundle .\bundle.json ...
  [string] $TenantBundle = "",
  [string] $BypassDest = "",
  [switch] $DriverAttested   # the DsseWfp .sys/.cat is MS attestation-signed: relax the compat gate (Secure Boot / HVCI OK). Default = test-signed (those become blocks).
)
$ErrorActionPreference = 'Stop'

# The same key reaches the signed binaries and the service command line. Validate
# before using it in linker flags or WiX definitions; never infer it from PlanPin.
if ($Pin) {
  $Pin = $Pin.Trim().ToLowerInvariant()
  if ($Pin -notmatch '^[0-9a-f]{64}$') {
    throw "-Pin must be the 64-character hex Ed25519 public key that verifies the L1 install profile"
  }
}

# The sentinel above is a value no package may carry. It exists so the default can be evaluated without
# throwing, not so a build can proceed on it: WiX downgrades an invalid package version to a warning, so
# without this the only symptom is three warnings in a wall of build output and an MSI that upgrade logic
# cannot order. Fail here instead, where the message can say what to do.
if (-not $Version) {
  $d = (Resolve-Path -LiteralPath $PSScriptRoot).Path
  while ($d -and -not $Version) {
    $c = Join-Path $d "VERSION"
    if (Test-Path $c) { $Version = (Get-Content $c -Raw).Trim() }
    $up = Split-Path $d -Parent; if ($up -eq $d) { break }; $d = $up
  }
}
if (-not $Version) {
  throw "no VERSION file was found in or above $PSScriptRoot, so this package would be stamped with nothing. " +
        "Pass -Version explicitly, or build from a tree that carries VERSION at its root."
}

$pkg  = $PSScriptRoot
$oss  = (Resolve-Path "$pkg\..\..\..").Path                 # the module root
# ★★★ OUTPUT GOES INSIDE THE TREE (2026-09-04, Windows session). This was $oss\..\.. — two levels ABOVE the
# module root — which is the monorepo root here and, for somebody who unpacked this tree on its own, two
# directories above whatever they unpacked into: a build run from ~/Downloads/dsse-core wrote to ~/outputs.
# The tree is the unit that ships, so it is also the unit that holds what a build produces.
$repo = $oss
$stage = Join-Path $repo "outputs\windows\stage"
$outDir = Join-Path $repo "outputs\windows"
$msi = Join-Path $outDir "DsseAgent.msi"
New-Item -ItemType Directory -Force -Path $stage, $outDir | Out-Null

$wix = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
if (-not (Test-Path $wix)) { $wix = "wix" }                 # fall back to PATH
$env:DOTNET_ROOT = Join-Path $env:USERPROFILE ".dotnet"

# ★ CHECK THE SIGNING PREREQUISITES BEFORE BUILDING ANYTHING (2026-08-17).
#
# `-Sign -SignBackend evtoken` with no DSSE_EV_THUMBPRINT compiled nine executables, staged the driver and the
# transport CA, ran every gate, and THEN threw from sign.ps1 on a missing environment variable. Nothing was
# lost but time, and time is the wrong thing to spend here: a signing round is scheduled around the operator
# being present to type the token PIN, and a build that dies at the signing step is a round they were standing
# by for. The same argument as one signtool invocation instead of nine.
#
# It only re-states what sign.ps1 requires, so it can drift. That is why it is a warning-free duplicate of one
# specific condition rather than a copy of the backend logic: sign.ps1 remains the authority and still throws.
if ($Sign) {
  switch ($SignBackend) {
    'evtoken' {
      if (-not $env:DSSE_EV_THUMBPRINT -and -not $env:DSSE_EV_SUBJECT) {
        throw ("-Sign -SignBackend evtoken needs the certificate named BEFORE the build starts: set " +
               "`$env:DSSE_EV_THUMBPRINT (or DSSE_EV_SUBJECT). Refusing now rather than after compiling " +
               "everything, because a signing round costs the operator a PIN entry per prompt.")
      }
    }
    'trustedsigning' {
      if (-not $env:DSSE_TS_DLIB -or -not $env:DSSE_TS_METADATA) {
        throw "-Sign -SignBackend trustedsigning needs `$env:DSSE_TS_DLIB and `$env:DSSE_TS_METADATA set before the build starts."
      }
    }
  }
}

Write-Host "== building exes (windows/$Arch) -> $stage =="
$goarch = if ($Arch -eq 'x64') { 'amd64' } else { $Arch }
$env:GOOS = 'windows'; $env:GOARCH = $goarch
Push-Location $oss
try {
  # Bake the L1 trust anchor pin (-ldflags) into the binaries that verify the profile — DsseSteer (runtime, at
  # --config-store startup) and profileapply (install time) — so it lives inside the signed binary, never a store
  # value (review S1).
  # Conditional -ldflags via array splat: an EMPTY string arg is dropped by PowerShell, which would turn
  # `go build -ldflags "" -o X` into `go build -ldflags -o X` (‑o becomes the ldflags value, X a bogus package).
  # Build identity, stamped the same way every other Go artifact in this repo is (scripts/build_stamp.sh).
  # Without it the agent reports an unstamped "0.0.0-dev" and a fleet's version distribution is unreadable —
  # which is the state it shipped in until 2026-08-05, when it reported the literal "wfp-steer" instead.
  # Computed here rather than shelling out to the sh script, because this runs on Windows.
  # ★★★ THE FALLBACK HAD TO BE REACHABLE (2026-09-04, Windows session, on a tree unpacked from an archive).
# `2>$null` and `if (-not …)` look like a fallback and are not one: under $ErrorActionPreference='Stop' a
# native command's failure is raised as a NativeCommandError and the build dies on this line, whatever git's
# complaint was — "not a repository" for an unpacked archive, "Needed a single revision" for a fresh `git
# init`. Anyone given this tree as a tarball was stopped here with a git error and no way to read it as one.
$stampCommit = "unknown"
try {
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $c = & git -C $oss rev-parse --short HEAD 2>$null
  $ErrorActionPreference = $prev
  if ($LASTEXITCODE -eq 0 -and $c) { $stampCommit = "$c".Trim() }
} catch { $stampCommit = "unknown" }
  git -C $oss diff --quiet 2>$null; $stampDirty = if ($LASTEXITCODE -ne 0) { "true" } else { "false" }
  $stamp = "-X main.buildVersion=$Version -X main.buildCommit=$stampCommit -X main.buildDate=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) -X main.buildDirty=$stampDirty"
  if ($Pin) { $stamp = "$stamp -X main.trustAnchorPin=$Pin" }
  $ldArgs = @("-ldflags", $stamp)

  # ---- Windows version resources -------------------------------------------------------------------------
  # ★ EVERY SHIPPED EXE HAD AN EMPTY PROPERTIES DIALOG until 2026-09-09. CompanyName, ProductName and
  # FileVersion were all blank — measured with Get-Item(...).VersionInfo on the installed binaries — because Go
  # writes no version resource and nothing here supplied one. A signed product that will not name its publisher
  # or its version makes every software inventory report nothing, and forces an administrator to open the
  # Authenticode signature to learn what they are looking at.
  #
  # The generator is the same tool that embeds the icon, so a binary can carry both. Each .syso is written into
  # its own package directory just before `go build`, which picks up *_windows_<arch>.syso automatically, and is
  # REMOVED afterwards: leaving generated objects in the tree is what makes a later build report .dirty.
  #
  # ★ These strings are deployment-independent by construction — publisher and version, nothing about any
  # organization, edge, key or tenant — which is the constraint the signed artifacts are held to.
  $verTool = Join-Path $stage "icontosyso.exe"
  go build -o $verTool ./clients/windows-wfp/packaging/cmd/icontosyso; if ($LASTEXITCODE) { throw "go build icontosyso" }
  $sysoWritten = @()
  $sysoParked  = @()
  function Add-VersionResource($pkgDir, $exeName, $description, $iconPath) {
    $syso = Join-Path $pkgDir "zz_version_windows_$goarch.syso"
    $args = @("-out", $syso, "-version", $Version, "-description", $description, "-original-name", $exeName, "-arch", $goarch)
    if ($iconPath -and (Test-Path $iconPath)) { $args += @("-in", $iconPath) }
    & $verTool @args | Out-Null
    if ($LASTEXITCODE) { throw "version resource for $exeName" }
    $script:sysoWritten += $syso
  }
  $ossRoot = $oss
  Add-VersionResource (Join-Path $ossRoot "clients/windows-wfp/steer")                      "dsse-steer.exe"         "DSSE steering agent"            $null
  Add-VersionResource (Join-Path $ossRoot "clients/windows-wfp/watchdog")                   "dsse-watchdog.exe"      "DSSE network recovery watchdog" $null
  Add-VersionResource (Join-Path $ossRoot "clients/windows-wfp/updater")                    "dsse-updater.exe"       "DSSE agent updater"             $null
  Add-VersionResource (Join-Path $ossRoot "clients/windows-wfp/compat/cmd/compatcheck")     "compatcheck.exe"        "DSSE compatibility check"       $null
  Add-VersionResource (Join-Path $ossRoot "clients/windows-wfp/packaging/cmd/driversvc")    "driversvc.exe"          "DSSE driver service helper"     $null
  Add-VersionResource (Join-Path $ossRoot "clients/windows-wfp/packaging/cmd/profileapply") "profileapply.exe"       "DSSE profile and trust apply"    $null
  # ★ THE STEP-UP WINDOW TAKES ONE .syso CARRYING BOTH, because a binary may hold exactly one .rsrc section.
  # Measured: generating a version .syso beside the committed icon one makes the Go linker refuse outright with
  # "too many .rsrc sections". So here the icon is regenerated from brand/lantern.ico TOGETHER with the version
  # into a single object, and the committed rsrc_windows_<arch>.syso is parked for the duration of the build and
  # put back in the finally block. It stays in the tree as the inspectable artefact it was written to be; it
  # just stops being a second resource section while a build is running.
  $swDir  = Join-Path $ossRoot "clients/windows-wfp/stepupwindow"
  $swIcon = Join-Path $swDir "brand/lantern.ico"
  $swOld  = Join-Path $swDir "rsrc_windows_$goarch.syso"
  if (Test-Path $swOld) { Move-Item $swOld "$swOld.parked" -Force; $script:sysoParked += ,@("$swOld.parked", $swOld) }
  Add-VersionResource $swDir "dsse-stepup-window.exe" "DSSE step-up credential window" $swIcon
  Write-Host "== version resources: 7 generated (publisher + version only; no deployment or tenant data) =="

  go build @ldArgs -o (Join-Path $stage "dsse-steer.exe")  ./clients/windows-wfp/steer;              if ($LASTEXITCODE) { throw "go build steer" }
  # dsse-tray.exe is deliberately NOT built or shipped (2026-08-05). The status endpoint it reads is an
  # unauthenticated loopback listener that any local process can read — it discloses posture, i.e. exactly when
  # enforcement is degraded — so it is off by default, which meant the MSI shipped a tray that could not work.
  # It returns when the ACL'd named-pipe transport lands (status_server.go's stated follow-up). Source is kept.
  go build -o (Join-Path $stage "dsse-stepup-window.exe") ./clients/windows-wfp/stepupwindow;    if ($LASTEXITCODE) { throw "go build stepup-window" }
  # dsse-watchdog.exe: the process that puts this box back on the network if the WFP redirect is left armed
  # with no agent behind it. It is stamped like the agent because a watchdog whose version nobody knows is one
  # nobody can reason about after an incident.
  go build @ldArgs -o (Join-Path $stage "dsse-watchdog.exe") ./clients/windows-wfp/watchdog;     if ($LASTEXITCODE) { throw "go build watchdog" }
  # dsse-updater.exe: decides when this device installs a new agent build. Stamped like the agent and the
  # watchdog, and for a sharper reason than either — after a bad rollout the first question is which version
  # each device was running, and the second is which updater decided to install it.
  go build @ldArgs -o (Join-Path $stage "dsse-updater.exe") ./clients/windows-wfp/updater;       if ($LASTEXITCODE) { throw "go build updater" }
  go build -o (Join-Path $stage "compatcheck.exe") ./clients/windows-wfp/compat/cmd/compatcheck;    if ($LASTEXITCODE) { throw "go build compatcheck" }
  go build -o (Join-Path $stage "driversvc.exe")   ./clients/windows-wfp/packaging/cmd/driversvc;   if ($LASTEXITCODE) { throw "go build driversvc" }
  go build @ldArgs -o (Join-Path $stage "profileapply.exe") ./clients/windows-wfp/packaging/cmd/profileapply; if ($LASTEXITCODE) { throw "go build profileapply" }
} finally {
  # ★ REMOVE THE GENERATED .syso FILES, AND DO IT IN finally SO A FAILED BUILD DOES NOT LEAVE THEM BEHIND.
  # They are build inputs, not source: left in the tree, `git diff --quiet` above sees a dirty worktree and the
  # NEXT build stamps every binary .dirty — which is precisely the state that disqualified this box's agent
  # from the release gate on 2026-09-08. A generator that tidies up only on success is a generator that
  # eventually poisons a release build.
  foreach ($s in $sysoWritten) { if ($s -and (Test-Path $s)) { Remove-Item $s -Force -ErrorAction SilentlyContinue } }
  # Put the parked committed .syso back. In finally for the same reason as the removals above: a build that
  # fails after parking it must not leave the tree missing a committed file.
  foreach ($p in $sysoParked) { if (Test-Path $p[0]) { Move-Item $p[0] $p[1] -Force -ErrorAction SilentlyContinue } }
  Pop-Location
}

# Stage the DsseWfp kernel driver (.sys). Production supplies a Microsoft attestation-signed .sys via -DriverSys;
# the default is the dev/test-signed build under outputs\windows (needs testsigning + the cert trusted to load).
if (-not $DriverSys) {
  if ($Arch -eq 'arm64') {
    # The Go user-mode exes cross-compile to ARM64 (verified), but the DsseWfp kernel driver has no ARM64
    # build yet (needs the WDK ARM64 toolchain; see driver/BUILD.md). Refuse to stage the x64 .sys into an
    # ARM64 package — that would silently ship a driver that cannot load. Pass -DriverSys <arm64 .sys> once one exists.
    throw "ARM64 MSI needs an ARM64-built DsseWfp .sys: pass -DriverSys <arm64 .sys>. The kernel driver has no ARM64 build yet; the Go exes DO cross-compile to ARM64."
  }
  $DriverSys = Join-Path $outDir "dsse-wfp.sys"   # x64 dev/test default
}
if (-not (Test-Path $DriverSys)) { throw "DsseWfp driver .sys not found: $DriverSys (build it per driver/BUILD.md, or pass -DriverSys)" }
Copy-Item $DriverSys (Join-Path $stage "dsse-wfp.sys") -Force
Write-Host "== staged driver: $DriverSys =="

# -DriverAttested and -DriverSys are separate flags, and only the second one changes what ships. Passing the
# first alone tells the compat gate to let Secure Boot / HVCI machines through while still staging the
# test-signed driver — an install that succeeds and then cannot load, which is the worst of the two failures
# because the gate exists to prevent exactly it. Read the signature off the file rather than trusting the flag.
if ($DriverAttested) {
  $ds = Get-AuthenticodeSignature (Join-Path $stage "dsse-wfp.sys")
  if ($ds.Status -ne 'Valid' -or $ds.SignerCertificate.Subject -notmatch 'Windows Hardware Compatibility Publisher') {
    throw "-DriverAttested was passed but $DriverSys is not attestation-signed (status=$($ds.Status), signer=$($ds.SignerCertificate.Subject)). Pass -DriverSys <the .sys returned by Partner Center>, or drop -DriverAttested so the gate keeps blocking Secure Boot machines."
  }
  Write-Host "== driver signature: $($ds.SignerCertificate.Subject) =="
}

# Provisioned (per-tenant) MSI: bundle the signed profile + require its baked pin.
$wixDefines = @()
if ($Pin) {
  $wixDefines += @("-d", "ConfigPin=$Pin")
} else {
  Write-Host "== no -Pin: this MSI supplies no L1 profile verification key. For an existing enrolled device, build with its current profile signing key before replacing DsseSteer. =="
}
if ($TenantBundle) {
  if (-not (Test-Path $TenantBundle)) { throw "tenant install bundle not found: $TenantBundle" }
  try { $b = Get-Content $TenantBundle -Raw | ConvertFrom-Json }
  catch { throw "-TenantBundle is not readable JSON: $TenantBundle ($_)" }

  # ★ REFUSE AN INCOMPLETE BUNDLE. The Edge says so itself, and the handoff is explicit: "complete=false は
  # 素材が足りない — その場合は入れずに Edge 側を先に直すこと". A package built from a partial answer is a
  # device that looks provisioned and cannot verify what it is shown.
  if ($b.complete -ne $true) {
    throw "-TenantBundle reports complete=$($b.complete) for tenant '$($b.tenant_id)': the Edge does not have " +
          "everything an installer must embed. Fix the Edge side first — a package built from a partial answer " +
          "produces a device that looks provisioned and cannot verify interception. note: $($b.note)"
  }
  if (-not $b.transport_ca_pem)      { throw "-TenantBundle carries no transport_ca_pem" }
  if (-not $b.interception_root_pem) { throw "-TenantBundle carries no interception_root_pem" }

  # ★ THE WHOLE POINT IS THAT THESE COME FROM ONE ANSWER, so refuse to have half of it overridden by hand.
  # Mixing is the exact failure section 8.2 names: one organization's transport anchor beside another's interception
  # root, in a package that builds cleanly.
  if ($TransportCA) {
    throw "-TenantBundle and -TransportCA are mutually exclusive. The bundle carries the transport anchor for " +
          "'$($b.tenant_id)' already, and taking one half from a file fetched at another moment is how a package " +
          "pins one organization's transport anchor beside another's interception root (pki_trust_model.md 8.2)."
  }

  $TransportCA = Join-Path $stage "transport_ca.from-bundle.pem"
  Set-Content -Path $TransportCA -Value $b.transport_ca_pem -Encoding ascii

  $rootPath = Join-Path $stage "interception_root.pem"
  Set-Content -Path $rootPath -Value $b.interception_root_pem -Encoding ascii
  try { $rc = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $rootPath }
  catch { throw "the bundle's interception_root_pem is not a readable certificate ($_)" }
  $rootSha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($rc.GetRawCertData())).Replace('-','').ToLower()
  $wixDefines += @("-d", "InterceptionRoot=1")

  # `interception_root_is_own=false` means the deployment's SHARED anchor is being embedded rather than one
  # belonging to this organization. That is a supported state and not an error — but it is the difference
  # between "this package trusts my organization's authority" and "this package trusts the deployment's", and
  # a build should not be the quiet place that happens.
  $own = if ($b.interception_root_is_own) { "the organization's OWN root" }
         else { "★ the deployment's SHARED root (interception_root_is_own=false) — this package does NOT pin an authority unique to '$($b.tenant_id)'" }
  Write-Host "== tenant install bundle: $($b.tenant_id) ($($b.schema_version)) =="
  Write-Host "==   transport anchor    -> %ProgramData%\DSSE\transport_ca.pem =="
  Write-Host "==   interception root   -> %ProgramData%\DSSE\interception_root.pem, installed into LocalMachine\Root at install time =="
  Write-Host "==   $($rc.Subject) =="
  Write-Host "==   sha256 $rootSha =="
  Write-Host "==   $own =="
}

if ($TransportCA) {
  if (-not (Test-Path $TransportCA)) { throw "transport CA not found: $TransportCA" }
  # Parsed, not just copied: a file that is not a certificate produces a device that fails every handshake and
  # reports a trust problem, which is a long way from the build that shipped it.
  try { $null = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $TransportCA }
  catch { throw "-TransportCA is not a readable certificate: $TransportCA ($_)" }
  Copy-Item $TransportCA (Join-Path $stage "transport_ca.pem") -Force
  $wixDefines += @("-d", "TransportCA=1")
  Write-Host "== staged transport CA: $TransportCA -> %ProgramData%\DSSE\transport_ca.pem =="
}

if ($Profile) {
  if (-not (Test-Path $Profile)) { throw "profile not found: $Profile" }
  if (-not $Pin) { throw "-Pin (trust anchor pubkey hex) is required with -Profile" }
  # ★ A PROVISIONED PACKAGE THAT NAMES A TRANSPORT AND NO ANCHOR BUILDS A DEVICE THAT CANNOT ENROL. Said here
  # rather than refused, because a profile with no transport is a legitimate shape and this script does not
  # parse the profile it is handed. The consequence is specific enough to act on.
  if (-not $TransportCA) {
    Write-Host "== ★ no -TransportCA with -Profile: if that profile names a transport, this device will have no"
    Write-Host "==   anchor to verify the Edge with. It will stand aside at enrolment rather than persist an"
    Write-Host "==   identity it cannot prove, and nothing else provisions that file. =="
  }
  Copy-Item $Profile (Join-Path $stage "profile.json") -Force
  $wixDefines += @("-d", "Profile=1")
  Write-Host "== staged profile: $Profile (provisioned MSI) =="
}
if ($UpdatePin) {
  # Rejected here rather than at install time. A pin that is not hex is a typo, and a typo discovered on the
  # endpoint presents as "every manifest is untrusted" — which by design means "something is substituting
  # artefacts, look tonight". Catching it at build turns a security alarm back into a build error.
  # ★ THE SAME DRIFT -PlanPin HAD, LEFT BEHIND IN THE OTHER HALF (2026-08-14, found by trying to pin the key
  # the control plane actually signs with). On 2026-08-12 this rule was corrected for -PlanPin: the verifier
  # takes an Ed25519 key OR an uncompressed ECDSA-P256 point, because a PKCS#11 token holds the second kind.
  # -UpdatePin kept demanding exactly 64 hex characters — and update manifests go through the very same
  # acceptance rule (agentupdate.OpenWithKey -> agentpolicy.VerifyAnyWithKey -> isAcceptedPublicKeyHex).
  #
  # What it cost: the CP moved its update key into an HSM and started signing with P-256, and the fleet's
  # devices could not be given a build that pinned it — not because anything refused the key, but because the
  # PACKAGING SCRIPT did. The device was left refusing every manifest, which is the correct behaviour for an
  # unverifiable document and reads exactly like an attack. A rotation cannot be performed through the update
  # lane, so this one line held the deployment at a version it could not leave.
  #
  # Shape first, per key, so a typo gets a sentence about hex rather than a Go build.
  foreach ($k in ($UpdatePin -split ',')) {
    if ($k -notmatch '^([0-9a-fA-F]{64}|04[0-9a-fA-F]{128})$') {
      throw "-UpdatePin entries must each be a 64-char hex Ed25519 key or a 130-char uncompressed ECDSA-P256 " +
            "point starting 04, comma-separated. Got $($k.Length) chars: $k"
    }
  }
  # ★ AND THEN THE VERIFIER'S OWN ANSWER, NOT AN IMITATION OF IT — the reasoning is -PlanPin's below, and it
  # applies with more force here: length alone accepts `04` followed by 128 zeros, and this is the key that
  # authorises RUNNING CODE. A build that passes and a device that then refuses every release is the failure
  # this whole block exists to move earlier.
  Push-Location $oss
  try {
    foreach ($k in ($UpdatePin -split ',')) {
      go run ./cmd/dsse-keycheck --agent-policy-key $k
      if ($LASTEXITCODE) { throw "-UpdatePin entry is not a key a device would accept (see above): $k" }
    }
  } finally { Pop-Location }
  if ($Pin -and ($UpdatePin -split ',' | Where-Object { $_ -ieq $Pin })) {
    # Refused rather than warned. Sharing the key collapses the boundary the update key exists to create: an
    # attacker who could sign configuration could then sign CODE, and the MSI would carry the collapse.
    throw "-UpdatePin must not contain -Pin: the update-signing key authorises code execution and the config-signing key must not"
  }
  $wixDefines += @("-d", "UpdatePin=$UpdatePin")
  Write-Host "== update manifests will be verified against $(($UpdatePin -split ',').Count) key(s) =="
} else {
  Write-Host "== no -UpdatePin: DsseUpdater installs but this device can never update (generic MSI) =="
}
if ($UpdatePublisher) {
  # ★ VALIDATED HERE BECAUSE THE ENDPOINT DELIBERATELY WILL NOT. A malformed publisher requirement cannot refuse
  # on the device: it travels INSIDE the MSI, so refusing would make the only repair path the one being refused —
  # the self-deadlock this product has already built twice. The device therefore degrades to "install, and say
  # loudly that nothing is being checked", and this block is what keeps that degradation rare. A typo caught here
  # is a build error; the same typo shipped is a fleet that believes it is protected and is not.
  #
  # The forms are the endpoint's, and only the two strong ones: `publisher:` matches a display name as a
  # SUBSTRING and `signed:` binds no signer at all. Both are reasonable for a steer-exclusion and neither is an
  # identity to run code as SYSTEM on. See updateplatform/publisher.go, which refuses them by name.
  $upLower = $UpdatePublisher.ToLowerInvariant()
  if ($upLower.StartsWith("thumbprint:")) {
    $hash = ($UpdatePublisher.Substring(11) -replace '[:\s]', '')
    if ($hash -notmatch '^[0-9a-fA-F]{64}$') {
      throw "-UpdatePublisher thumbprint must be a leaf certificate SHA-256: 64 hex characters (colons and " +
            "spaces are stripped). Got $($hash.Length): $hash. Note that older Windows dialogs show the SHA-1 " +
            "thumbprint, which is 40."
    }
    Write-Host "== packages must be signed by the certificate $hash — a RENEWAL of it will stop this fleet updating =="
  } elseif ($upLower.StartsWith("subject:")) {
    if (-not $UpdatePublisher.Substring(8).Trim()) {
      throw "-UpdatePublisher subject: names no organisation"
    }
    Write-Host "== packages must be signed by Subject O=$($UpdatePublisher.Substring(8).Trim()) =="
  } elseif ($upLower.StartsWith("publisher:") -or $upLower.StartsWith("signed:")) {
    throw "-UpdatePublisher must not use the loose exclusion forms: `publisher:` matches a display name as a " +
          "substring (a similarly-named company's certificate satisfies it) and `signed:` means signed by " +
          "anybody. This requirement decides whether code runs as SYSTEM. Use subject:<Subject O=> or " +
          "thumbprint:<leaf SHA-256>."
  } else {
    throw "-UpdatePublisher must be subject:<Authenticode Subject O=> or thumbprint:<leaf certificate SHA-256>. Got: $UpdatePublisher"
  }
  # The certificate this build is actually signed with is cross-checked AFTER signing, further down: the exes
  # are not signed yet at this point in the script, so a probe here would report NotSigned on every build,
  # including the ones that are about to be signed correctly. That is the "the check ran before the thing it
  # checks" shape, and it was written that way once before this comment replaced it.
  if (-not $Sign) {
    Write-Host "== ★ -UpdatePublisher is set and -Sign is not: this MSI's binaries will be UNSIGNED, so every " +
               "device carrying this requirement will refuse the package that delivered it. Development only. =="
  }
  $wixDefines += @("-d", "UpdatePublisher=$UpdatePublisher")
} else {
  Write-Host "== no -UpdatePublisher: packages install on the manifest signature ALONE — anyone able to sign a manifest can run code as SYSTEM on these devices =="
}
if ($PlanPin) {
  # ★ THE VERIFIER ACCEPTS TWO SHAPES AND THIS ACCEPTED ONE (2026-08-12, found by trying the lab's real key).
  # agentpolicy.AcceptedPublicKeyHex — the single place that decides — takes a 32-byte Ed25519 key OR a 65-byte
  # uncompressed ECDSA-P256 point, because a PKCS#11 token holds the second kind and the reference Edge signs
  # with one. This required exactly 64 hex characters, so the agent-policy key an operator is handed by the
  # Edge's own startup line ("anchor this in the device trusted keyring", 130 chars) could not be built into a
  # package at all.
  #
  # The build refusing a key the device would have accepted is the same drift as the help string that called it
  # the wrong kind — one step earlier, and louder, which is why it was worth trying rather than assuming.
  #
  # Shape first, so a typo gets a sentence about hex rather than a Go build.
  if ($PlanPin -notmatch '^([0-9a-fA-F]{64}|04[0-9a-fA-F]{128})$') {
    throw "-PlanPin must be a 64-char hex Ed25519 public key or a 130-char uncompressed ECDSA-P256 point " +
          "starting 04 (the Edge prints its agent-policy public_key at startup). Got $($PlanPin.Length) chars: $PlanPin"
  }
  # ★ AND THEN THE VERIFIER'S OWN ANSWER, NOT AN IMITATION OF IT (2026-08-12, twenty-fourth review). Length
  # alone accepts `04` followed by 128 zeros, which is not a point on P-256: the build would pass, the MSI
  # would ship, and the device would refuse the key at runtime — the same drift as the 64-char rule, in the
  # other direction. The reasoning for staying loose was right as far as it went ("a second implementation of
  # the check is a second thing to disagree with") and the conclusion was wrong: do not implement it twice,
  # CALL it. dsse-keycheck is a door to agentpolicy.AcceptedPublicKeyHex and contains no judgement of its own.
  Push-Location $oss
  try {
    go run ./cmd/dsse-keycheck --agent-policy-key $PlanPin
    if ($LASTEXITCODE) { throw "-PlanPin is not a key a device would accept (see above)" }
  } finally { Pop-Location }
  # Refused rather than warned, for the reason -UpdatePin is refused against -Pin: one key holding both powers
  # means whoever can decide WHEN a fleet updates can also decide WHAT it runs. An Edge holds this key.
  if ($UpdatePin -and ($UpdatePin -split ',' | Where-Object { $_ -ieq $PlanPin })) {
    throw "-PlanPin must not appear in -UpdatePin: an Edge holds the plan key, and it must never be able to sign code"
  }
  $wixDefines += @("-d", "PlanPin=$PlanPin")
  Write-Host "== the rollout plan will be VERIFIED (freeze is tamper-evident) =="
} else {
  # Said explicitly because the degradation is invisible otherwise: everything still works, and the halt
  # becomes only as strong as the file's permissions.
  Write-Host "== no -PlanPin: the rollout plan is accepted UNVERIFIED — the freeze is only as strong as the DACL on %ProgramData%\DSSE =="
}
if ($BypassDest) {
  # Shape-checked here rather than discovered on the endpoint. A malformed entry does not fail the agent — it
  # simply never matches — so the hole the operator believed they had punched would silently not be there, and
  # the symptom (SSH still dying) looks identical to not having configured it at all.
  foreach ($d in ($BypassDest -split ',')) {
    $e = $d.Trim()
    if ($e -eq "") { throw "-BypassDest has an empty entry: '$BypassDest'" }
    if ($e -notmatch '^[A-Za-z0-9\.\-\[\]:]+$') { throw "-BypassDest entry '$e' is not a host or host:port" }
    if ($e -match '\s') { throw "-BypassDest entry '$e' contains whitespace" }
  }
  $wixDefines += @("-d", "BypassDest=$BypassDest")
  # Said out loud, every build: a bypass is enforcement deliberately switched off for a destination, and the
  # package should not be the quiet place that happens.
  Write-Host "== ★ NOT steering: $BypassDest — these destinations bypass the tunnel on every device this MSI installs =="
} else {
  Write-Host "== no -BypassDest: every destination is steered. If this box's own edge is reachable only through the tunnel, its management path is inside the thing it manages =="
}
if ($DriverAttested) {
  $wixDefines += @("-d", "DriverAttested=1")
  Write-Host "== compat gate: production (attestation-signed driver) — Secure Boot / HVCI allowed =="
} else {
  # ★ SAYS WHAT THE GATE IS, NOT WHAT THE DRIVER IS (2026-09-07). This asserted "test-signed driver", which
  # is a claim about the file and can be false — measured: an operator passed -DriverSys with a genuinely
  # attestation-signed .sys, read this line, and concluded the warning was wrong. It was not wrong about the
  # thing it governs. -DriverAttested is what sets the gate, deliberately separate from -DriverSys so that
  # letting Secure Boot machines through cannot be done by accident while staging a driver they will refuse;
  # and it reads the signature off the file rather than trusting the flag. The line now describes the gate,
  # which is the only thing this branch actually knows.
  Write-Host "== compat gate: blocking (no -DriverAttested) — Secure Boot / HVCI will BLOCK install; pass -DriverAttested to have the signature read off the staged driver =="
}

if ($Sign) {
  Write-Host "== signing exes (backend=$SignBackend) =="
  $env:DSSE_SIGN_BACKEND = $SignBackend
  # ★ ONLY WHAT THE PACKAGE SHIPS (2026-08-14). This signed every exe in stage, and stage holds two that the
  # WXS never packages — dsse-tray.exe and profilegen.exe are built here and deliberately left out of the MSI.
  # On the evtoken backend each signature costs the operator a PIN entry, so two of every ten were being spent
  # on bytes no device ever receives. The authority is the WXS itself rather than a list kept in step by hand:
  # a File the package adds later is signed automatically, and one it drops stops being signed.
  $packaged = Select-String -Path (Join-Path $pkg "DsseAgent.wxs") -Pattern 'Source="([^"]+\.exe)"' -AllMatches |
    ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
  if (-not $packaged) { throw "no File Source=*.exe found in DsseAgent.wxs — refusing to guess what to sign" }
  $toSign = @()
  foreach ($name in $packaged) {
    $p = Join-Path $stage $name
    # Fail rather than skip: a packaged file missing from stage means the MSI is about to be built around a
    # binary that is not there, and discovering that at install time is far worse than here.
    if (-not (Test-Path $p)) { throw "DsseAgent.wxs packages $name but it is not in $stage" }
    $toSign += $p
  }
  $skipped = (Get-ChildItem "$stage\*.exe").Name | Where-Object { $packaged -notcontains $_ }
  if ($skipped) { Write-Host "== not signing (built but not packaged): $($skipped -join ', ') ==" }
  & (Join-Path $pkg "sign.ps1") -Files $toSign

  # ★ DOES THIS BUILD SATISFY THE REQUIREMENT IT IS SHIPPING? Asked here, where the signature exists.
  #
  # This is the one mistake in this lane that produces a fleet which cannot update, and it is silent: every
  # other gate in this script would be green, the MSI would install by hand, and only the NEXT unattended update
  # would refuse — on every device at once, with a message about signatures, which reads as an attack. The MSI
  # is signed a few lines below by the same sign.ps1 and therefore the same certificate, so the exes answer for
  # it.
  if ($UpdatePublisher) {
    $probe = Join-Path $stage "dsse-updater.exe"
    $sig = Get-AuthenticodeSignature $probe
    if ($sig.Status -ne 'Valid') {
      throw "-UpdatePublisher is set but $probe is not validly signed after signing ($($sig.Status)). A device " +
            "carrying this requirement would refuse this very package."
    }
    # ★★★ AN ORGANISATION NAME MAY CONTAIN A COMMA, AND THIS COMPANY'S DOES (2026-08-29, found by signing with
    # our own EV certificate for the first time through this gate).
    #
    # Splitting the whole Subject on ",\s*" splits INSIDE a quoted value. O="LANTERN NETWORKS, INC." became
    # "LANTERN NETWORKS", so the gate reported the signer's organisation as a name that is not the signer's
    # organisation, and `-UpdatePublisher subject:LANTERN NETWORKS, INC.` — the true, legal name, the one an
    # operator would read off the certificate — could never match. The only ways through were to pin a truncated
    # name, which is a requirement that says something false, or to abandon the durable form for a thumbprint
    # that dies at the next renewal.
    #
    # X500DistinguishedName.Decode splits on RDN boundaries rather than on commas, so a value carrying one
    # survives. Quotes are stripped afterwards because the decoded form keeps them around a value that needed
    # them, and the pinned text an operator types will not have them.
    $rdns = $sig.SignerCertificate.SubjectName.Decode(
              [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines) -split "`r?`n"
    $o = (($rdns | Where-Object { $_.Trim() -like 'O=*' } | Select-Object -First 1) -replace '^\s*O=', '').Trim()
    $o = ($o -replace '^"', '' -replace '"$', '')
    $t = $sig.SignerCertificate.GetCertHashString('SHA256').ToLowerInvariant()
    Write-Host "== this build's signer: Subject O=$o thumbprint=$t =="
    if ($upLower.StartsWith("subject:") -and ($UpdatePublisher.Substring(8).Trim() -ine $o)) {
      throw "-UpdatePublisher pins Subject O=$($UpdatePublisher.Substring(8).Trim()) and this build is signed by " +
            "O=$o. A device carrying this MSI would refuse the package that delivered the requirement, and every " +
            "one after it. Fix the value, or sign with the certificate you are pinning."
    }
    if ($upLower.StartsWith("thumbprint:") -and ((($UpdatePublisher.Substring(11) -replace '[:\s]', '').ToLowerInvariant()) -ne $t)) {
      throw "-UpdatePublisher pins a certificate this build is not signed with (signer above). Same consequence: " +
            "the fleet would refuse this package and every one after it."
    }
    Write-Host "== -UpdatePublisher matches this build's own signature =="
  }
}

Write-Host "== wix build -> $msi =="
Push-Location $pkg
try {
  & $wix build DsseAgent.wxs -arch $Arch -b $stage -d Version=$Version @wixDefines -o $msi
  if ($LASTEXITCODE) { throw "wix build failed ($LASTEXITCODE)" }
} finally { Pop-Location }

if ($Sign) {
  Write-Host "== signing MSI (backend=$SignBackend) =="
  & (Join-Path $pkg "sign.ps1") -Files $msi
}

Write-Host ("MSI: {0} ({1:N2} MB)" -f $msi, ((Get-Item $msi).Length / 1MB))
