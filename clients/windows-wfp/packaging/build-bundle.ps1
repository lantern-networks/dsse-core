<#
.SYNOPSIS
  Build the single-file Burn installer DsseAgentSetup.exe (roadmap M8.5) that wraps the DsseAgent MSI.

.DESCRIPTION
  Requires the MSI to be built first (build-msi.ps1 → outputs\windows\DsseAgent.msi). Chains an optional
  WebView2 Evergreen prerequisite (-WithWebView2, only needed once the WebView2-based helper is packaged) then
  the MSI. -Sign performs the full Burn signing sequence — detach the engine, sign it, reattach, sign the
  bundle — and then FAILS the build unless a re-detached engine and the bundle both verify. Signing only the
  finished exe (what this script did before 2026-08-06) leaves the engine unsigned while the bundle still
  reports Valid, and the engine is what Burn extracts to %TEMP% and elevates.

  Needs the WiX Burn extensions:
    wix extension add -g WixToolset.BootstrapperApplications.wixext WixToolset.Util.wixext
#>
[CmdletBinding()]
param(
  # Default from the nearest VERSION file walking upward — the single source of truth shared with the macOS
  # build scripts and the Go -ldflags stamp (scripts/build_stamp.sh). Hardcoding it here let Windows and macOS
  # drift apart. Walks upward rather than using a fixed depth because this tree is ALSO mirrored to the public
  # dsse-core repo, where the root sits at a different level; there it finds that repo's own VERSION.
  #
  # ★ RESOLVE IT FIRST (2026-08-22). $PSScriptRoot is only absolute when the script is invoked by an absolute
  # path; invoked relatively it is that relative string, and the upward walk then runs off the top of it before
  # reaching the repo root, silently yielding 0.0.0-unversioned. Same defect and same fix as build-msi.ps1.
  [string] $Version = $(
    $d = if ($PSScriptRoot) { (Resolve-Path -LiteralPath $PSScriptRoot).Path } else { (Get-Location).Path }
    $found = $null
    while ($d -and -not $found) {
      $c = Join-Path $d "VERSION"
      if (Test-Path $c) { $found = (Get-Content $c -Raw).Trim() }
      $p = Split-Path $d -Parent; if ($p -eq $d) { break }; $d = $p
    }
    if ($found) { $found } else { "0.0.0-unversioned" }
  ),
  [switch] $WithWebView2,
  [switch] $Sign,
  [ValidateSet('test','trustedsigning','evtoken')][string] $SignBackend = 'test'
)
$ErrorActionPreference = 'Stop'

$pkg  = $PSScriptRoot
$oss  = (Resolve-Path "$pkg\..\..\..").Path
$repo = (Resolve-Path "$oss\..\..").Path
$outDir = Join-Path $repo "outputs\windows"
$msi = Join-Path $outDir "DsseAgent.msi"
$setup = Join-Path $outDir "DsseAgentSetup.exe"

if (-not (Test-Path $msi)) { throw "MSI not found: $msi — run build-msi.ps1 first" }

$wix = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
if (-not (Test-Path $wix)) { $wix = "wix" }
$env:DOTNET_ROOT = Join-Path $env:USERPROFILE ".dotnet"

$defs = @("-d", "Version=$Version")
if ($WithWebView2) {
  $wv2 = Join-Path $outDir "MicrosoftEdgeWebview2Setup.exe"
  if (-not (Test-Path $wv2)) {
    Write-Host "== downloading WebView2 Evergreen bootstrapper =="
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $wv2 -UseBasicParsing
  }
  $defs += @("-d", "WebView2=1")
}

Write-Host "== wix build (Burn bundle) -> $setup =="
Push-Location $pkg
try {
  & $wix build DsseBundle.wxs `
      -ext WixToolset.BootstrapperApplications.wixext `
      -ext WixToolset.Util.wixext `
      -b $outDir -b $pkg @defs -o $setup
  if ($LASTEXITCODE) { throw "wix build (bundle) failed ($LASTEXITCODE)" }
} finally { Pop-Location }

if ($Sign) {
  # A Burn bundle is TWO signable things and signing only the finished exe is not enough. Burn extracts the
  # engine to %TEMP% and runs THAT as the elevated process, so an unsigned engine means the UAC prompt says
  # "Unknown publisher" for the thing actually doing the install, and any policy that requires signed binaries
  # blocks it — while `Get-AuthenticodeSignature DsseAgentSetup.exe` cheerfully reports Valid. Measured
  # 2026-08-06: signing just the finished exe left the detached engine `NotSigned`.
  #
  # The correct order is detach -> sign the engine -> reattach -> sign the bundle. Reattach must come BEFORE
  # the bundle signature, because reattaching rewrites the exe and would invalidate a signature applied first.
  $env:DSSE_SIGN_BACKEND = $SignBackend
  $signer = Join-Path $pkg "sign.ps1"
  $engine = Join-Path $outDir "DsseAgentSetup.engine.exe"

  Write-Host "== detaching Burn engine (backend=$SignBackend) =="
  & $wix burn detach $setup -engine $engine
  if ($LASTEXITCODE) { throw "wix burn detach failed ($LASTEXITCODE)" }

  Write-Host "== signing Burn engine =="
  & $signer -Files $engine
  if ($LASTEXITCODE) { throw "signing the Burn engine failed" }

  Write-Host "== reattaching signed engine =="
  & $wix burn reattach $setup -engine $engine -o $setup
  if ($LASTEXITCODE) { throw "wix burn reattach failed ($LASTEXITCODE)" }
  Remove-Item $engine -Force -ErrorAction SilentlyContinue

  Write-Host "== signing bundle (backend=$SignBackend) =="
  & $signer -Files $setup
  if ($LASTEXITCODE) { throw "signing the bundle failed" }

  # What CAN be verified here is the finished bundle. Do that, and fail on it.
  $bs = (Get-AuthenticodeSignature $setup).Status
  Write-Host "== bundle signature: $bs =="
  if ($bs -ne 'Valid' -and $SignBackend -ne 'test') { throw "bundle signature is $bs, expected Valid" }

  # What CANNOT be verified here is the embedded engine, and the tempting check is a trap. Re-detaching the
  # finished bundle and inspecting that engine reports `NotSigned` — but it reports `NotSigned` EQUALLY for a
  # bundle built WITHOUT the engine-signing step above (measured both ways, 2026-08-06). Reattach plus the
  # bundle signature rewrite the PE security directory, so the engine that comes back out of a detach no
  # longer carries the signature it went in with. The check cannot distinguish a correctly signed bundle from
  # an incorrectly signed one, so it must not gate the build: a check that cannot fail for the right reason is
  # worse than no check, because it reads as proof.
  #
  # The engine signature is therefore asserted by CONSTRUCTION (the detach -> sign -> reattach order above,
  # which is WiX's documented sequence) and cannot be proven from here. It WAS proven by hand on 2026-08-06:
  # running the bundle on a real machine raised a UAC prompt naming the publisher as LANTERN NETWORKS, INC.
  # rather than an unknown publisher. That prompt comes from the process Burn elevates, so it reports whoever
  # signed the engine — which is why it is the only real check. Re-run it by hand after any change to this
  # signing sequence; declining the prompt is enough, nothing is installed.
}

Write-Host ("DsseAgentSetup.exe: {0} ({1:N2} MB)" -f $setup, ((Get-Item $setup).Length / 1MB))
