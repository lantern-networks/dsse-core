<#
.SYNOPSIS
  Build the CAB submitted to Microsoft's Hardware Dev Center for attestation signing.

.DESCRIPTION
  Attestation signing is how this driver stops being test-signed. The submission is a CAB
  holding the driver package, signed with the EV certificate; Partner Center returns a
  Microsoft-signed catalog. Until that round trip completes the driver only loads on a
  machine in `bcdedit /set testsigning on`, which is fine for a lab and disqualifying
  everywhere else.

  WHAT GOES IN, AND WHY IT IS ONLY TWO FILES.
  Microsoft is changing the policy on files in a driver package that the INF does not
  reference (https://aka.ms/UnreferencedInfFiles). dsse-wfp.inf references exactly one
  payload file, dsse-wfp.sys, so the CAB carries the INF and that .sys and nothing else.
  In particular NO SYMBOLS: the comment at the top of dsse-wfp.inf still says a submission
  holds "the .sys, its symbols, and an INF", which was true when it was written and is the
  thing this policy change is about. Symbols belong in a symbol store, not in the package.

  THE TEST SIGNATURE IS REMOVED BEFORE PACKING.
  The built .sys carries `CN=Dsse Test Driver`, a self-signed cert from a CA nobody trusts.
  It contributes nothing to the submission and is one more thing validation can have an
  opinion about, so the staged copy is stripped. The original in outputs/ is untouched.

  ONE PIN ENTRY.
  Only the CAB is signed, not the files inside it — attestation validates the CAB
  signature. Each EV token operation costs a human typing a PIN, so this is deliberately
  one operation and not three.

.EXAMPLE
  $env:DSSE_EV_THUMBPRINT = '<sha1>'
  pwsh build-attestation-cab.ps1 -Backend evtoken

.EXAMPLE
  # Dry run: build and inspect the CAB without touching the token.
  pwsh build-attestation-cab.ps1 -Backend none
#>
[CmdletBinding()]
param(
  # Where the built driver is. Defaults to the tree's own output directory.
  [string] $SysPath,
  [string] $InfPath,
  [string] $OutDir,

  # 'evtoken' signs the CAB with the EV certificate. 'none' builds it and stops, which is
  # the right mode for checking layout without spending a PIN entry.
  [ValidateSet('evtoken', 'test', 'trustedsigning', 'none')]
  [string] $Backend = 'evtoken',

  # InfVerif is a submission gate on Microsoft's side. Skipping it locally only moves the
  # failure to somewhere slower.
  [switch] $SkipInfVerif,

  # Overwrite an existing SIGNED cab. Without this the script refuses, because rebuilding
  # over a signed artefact costs a human another PIN entry and the loss is silent — which
  # is exactly how the first signed cab was destroyed by a -Backend none re-run.
  [switch] $Force
)

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here '..\..\..\..\..')).Path

if (-not $SysPath) { $SysPath = Join-Path $repo 'outputs\windows\dsse-wfp.sys' }
if (-not $InfPath) { $InfPath = Join-Path $here '..\driver\dsse-wfp.inf' }
if (-not $OutDir)  { $OutDir  = Join-Path $repo 'outputs\windows\attestation' }

foreach ($p in @($SysPath, $InfPath)) {
  if (-not (Test-Path $p)) { throw "not found: $p" }
}
$SysPath = (Resolve-Path $SysPath).Path
$InfPath = (Resolve-Path $InfPath).Path

# The folder name inside the CAB. Microsoft unpacks the CAB and expects the driver package
# to sit in a directory rather than at the root.
$pkgName = 'dsse-wfp'
$stage   = Join-Path $OutDir "stage\$pkgName"
$cabPath = Join-Path $OutDir 'dsse-wfp-attestation.cab'

Write-Host "repo   : $repo"
Write-Host "sys    : $SysPath"
Write-Host "inf    : $InfPath"
Write-Host "out    : $OutDir"
Write-Host ''

# ------------------------------------------- do not destroy a signed cab
if ((Test-Path $cabPath) -and -not $Force) {
  $existing = Get-AuthenticodeSignature $cabPath
  if ($existing.Status -eq 'Valid') {
    throw @"
$cabPath is already signed and would be overwritten.

  signer: $($existing.SignerCertificate.Subject)

Rebuilding costs another PIN entry. If that is what you want, pass -Force.
If you only meant to inspect the layout, the signed cab is the thing to inspect.
"@
  }
}

# ---------------------------------------------------------------- stage
if (Test-Path (Join-Path $OutDir 'stage')) { Remove-Item (Join-Path $OutDir 'stage') -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

Copy-Item $SysPath (Join-Path $stage 'dsse-wfp.sys') -Force
Copy-Item $InfPath (Join-Path $stage 'dsse-wfp.inf') -Force

# ------------------------------------------------- resolve the SDK tools
function Resolve-KitTool([string] $name) {
  $roots = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
    "${env:ProgramFiles}\Windows Kits\10\bin",
    "${env:ProgramFiles(x86)}\Windows Kits\10\Tools"
  ) | Where-Object { Test-Path $_ }
  foreach ($r in $roots) {
    $hit = Get-ChildItem -Path $r -Recurse -Filter $name -ErrorAction SilentlyContinue |
           Where-Object { $_.FullName -match '\\x64\\' } |
           Sort-Object FullName -Descending | Select-Object -First 1
    if ($hit) { return $hit.FullName }
  }
  return $null
}

$signtool = Resolve-KitTool 'signtool.exe'
if (-not $signtool) { throw 'signtool.exe not found under the Windows Kits — install the Windows SDK/WDK.' }

# --------------------------------------- strip the test signature, if any
$staged = Join-Path $stage 'dsse-wfp.sys'
$sig = Get-AuthenticodeSignature $staged
if ($sig.Status -ne 'NotSigned') {
  Write-Host "removing embedded signature from the staged copy: $($sig.SignerCertificate.Subject)"
  & $signtool remove /s $staged | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "signtool remove failed ($LASTEXITCODE)" }
  $after = (Get-AuthenticodeSignature $staged).Status
  if ($after -ne 'NotSigned') { throw "the staged .sys is still signed ($after)" }
  Write-Host 'staged .sys is now unsigned. The original in outputs/ is untouched.'
} else {
  Write-Host 'staged .sys carries no embedded signature.'
}

# ------------------------------------------------------------- InfVerif
if (-not $SkipInfVerif) {
  $infverif = Resolve-KitTool 'infverif.exe'
  if ($infverif) {
    Write-Host ''
    Write-Host "InfVerif: $infverif"
    # /v = verbose, /w = treat the driver as a non-PnP/universal candidate check set.
    & $infverif /v (Join-Path $stage 'dsse-wfp.inf')
    if ($LASTEXITCODE -ne 0) {
      throw "InfVerif rejected dsse-wfp.inf ($LASTEXITCODE). Fix it here rather than finding out on submission."
    }
    Write-Host 'InfVerif: pass'
  } else {
    Write-Warning 'infverif.exe not found — the INF is going up unchecked. Install the WDK to close this gap.'
  }
}

# ----------------------------------------------------------------- pack
# makecab needs a DDF. .Set DestinationDir is what preserves the folder inside the CAB;
# without it every file lands at the root and the submission is rejected for layout.
$ddf = Join-Path $OutDir 'dsse-wfp.ddf'
@"
.OPTION EXPLICIT
.Set CabinetNameTemplate=$(Split-Path $cabPath -Leaf)
.Set DiskDirectory1=$OutDir
.Set MaxDiskSize=0
.Set Cabinet=on
.Set Compress=on
.Set CompressionType=MSZIP
.Set DestinationDir=$pkgName
"$stage\dsse-wfp.inf"
"$stage\dsse-wfp.sys"
"@ | Set-Content -Path $ddf -Encoding ASCII

if (Test-Path $cabPath) { Remove-Item $cabPath -Force }

Write-Host ''
Write-Host 'makecab...'
# makecab writes setup.inf and setup.rpt to the CURRENT directory, not to DiskDirectory1.
# Run it from $OutDir so those land beside the cab instead of in whatever directory the
# caller happened to be in — which, the first time this ran, was the repository root.
Push-Location $OutDir
try {
  & makecab.exe /f $ddf | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "makecab failed ($LASTEXITCODE)" }
} finally {
  Pop-Location
}
Remove-Item (Join-Path $OutDir 'setup.inf'), (Join-Path $OutDir 'setup.rpt') -ErrorAction SilentlyContinue
if (-not (Test-Path $cabPath)) { throw "makecab reported success but $cabPath is not there" }

Write-Host "cab: $cabPath ($([math]::Round((Get-Item $cabPath).Length / 1KB, 1)) KB)"

# ----------------------------------------------------------------- sign
if ($Backend -eq 'none') {
  Write-Host ''
  Write-Host 'Backend=none: built but NOT signed. An unsigned CAB will be rejected at submission.'
  Write-Host "Re-run with -Backend evtoken when you are ready to spend a PIN entry."
  return
}

Write-Host ''
Write-Host "signing the CAB (backend: $Backend). This asks for the token PIN once."
& (Join-Path $here 'sign.ps1') -Files $cabPath -Backend $Backend -Verify
if ($LASTEXITCODE -ne 0) { throw "signing failed ($LASTEXITCODE)" }

$final = Get-AuthenticodeSignature $cabPath
Write-Host ''
Write-Host '--- ready to submit ---'
Write-Host "file   : $cabPath"
Write-Host "status : $($final.Status)"
Write-Host "signer : $($final.SignerCertificate.Subject)"
Write-Host "digest : $($final.SignerCertificate.SignatureAlgorithm.FriendlyName)"
Write-Host ''
Write-Host 'Submit at https://partner.microsoft.com/dashboard/hardware/driver/New'
Write-Host 'If it is refused at Package Acceptance or Validation, capture the exact message:'
Write-Host 'the EV certificate is ECC P-384, and whether Partner Center accepts that is the'
Write-Host 'open question this submission answers.'
