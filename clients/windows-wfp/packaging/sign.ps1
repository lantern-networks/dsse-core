<#
.SYNOPSIS
  DSSE code-signing wrapper — one script, swappable signing identity backend.

.DESCRIPTION
  The signing IDENTITY is a swap, not a
  rearchitecture. All packaging/install E2E is built + verified with the free `test` backend now; switching to
  Azure Trusted Signing (`trustedsigning`) or an EV token/HSM (`evtoken`) at release changes ONLY this seal
  step — no MSI/Burn rework. Signs one or more Authenticode targets (.exe/.dll/.msi/.cat where applicable).

  Backend is chosen by -Backend or $env:DSSE_SIGN_BACKEND (default: test).

  test           Self-signed code-signing cert in CurrentUser\My (created/reused by subject). Free, for dev.
                 NOT trusted by default — good for proving the pipeline, not for distribution. No timestamp.
  trustedsigning Azure Trusted Signing via signtool /dlib. Needs the Trusted Signing dlib + a metadata json:
                   $env:DSSE_TS_DLIB      = path to Azure.CodeSigning.Dlib.dll
                   $env:DSSE_TS_METADATA  = path to metadata json (Endpoint, CodeSigningAccountName, CertificateProfileName)
                   $env:DSSE_TS_TSA       = RFC3161 TSA (default http://timestamp.acs.microsoft.com)
  evtoken        EV certificate on a token / cloud HSM CSP, selected by thumbprint (or subject):
                   $env:DSSE_EV_THUMBPRINT = SHA1 thumbprint of the EV cert   (or $env:DSSE_EV_SUBJECT)
                   $env:DSSE_EV_TSA        = RFC3161 TSA (default http://ts.ssl.com — the CA we chose, SSL.com;
                                             any RFC3161 TSA works, but the issuing CA's own is the safe default)

.EXAMPLE
  pwsh sign.ps1 -Files .\dsse-steer.exe,.\dsse-tray.exe            # test backend (default)
  $env:DSSE_SIGN_BACKEND='evtoken'; pwsh sign.ps1 -Files .\DsseAgent.msi
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string[]] $Files,
  [ValidateSet('test', 'trustedsigning', 'evtoken')]
  [string] $Backend = $(if ($env:DSSE_SIGN_BACKEND) { $env:DSSE_SIGN_BACKEND } else { 'test' }),
  [string] $TestSubject = 'CN=DSSE Test Signing (DO NOT DISTRIBUTE)',
  [switch] $Verify
)

$ErrorActionPreference = 'Stop'

function Resolve-SignTool {
  # Newest signtool.exe under the Windows Kits, preferring x64.
  $roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "${env:ProgramFiles}\Windows Kits\10\bin")
  $found = foreach ($r in $roots) {
    if (Test-Path $r) {
      Get-ChildItem -Path $r -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' }
    }
  }
  $st = $found | Sort-Object { $_.Directory.Parent.Name } -Descending | Select-Object -First 1
  if (-not $st) { throw "signtool.exe not found under Windows Kits — install the Windows SDK/WDK." }
  return $st.FullName
}

function Get-TestCertThumbprint([string] $subject) {
  $existing = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $subject } | Sort-Object NotAfter -Descending | Select-Object -First 1
  if ($existing) { return $existing.Thumbprint }
  Write-Host "test backend: creating self-signed code-signing cert '$subject' in CurrentUser\My"
  $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
    -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears(2)
  return $c.Thumbprint
}

# --- build the signtool argument vector for the chosen backend ---
$signtool = Resolve-SignTool
Write-Host "signtool: $signtool"
Write-Host "backend : $Backend"

function Get-SignArgs([string] $file) {
  switch ($Backend) {
    'test' {
      $thumb = Get-TestCertThumbprint $TestSubject
      # No timestamp: a self-signed test cert has no trusted TSA chain; test signatures are not for distribution.
      return @('sign', '/v', '/fd', 'SHA256', '/sha1', $thumb, $file)
    }
    'trustedsigning' {
      if (-not $env:DSSE_TS_DLIB -or -not (Test-Path $env:DSSE_TS_DLIB)) { throw "trustedsigning: set DSSE_TS_DLIB to Azure.CodeSigning.Dlib.dll" }
      if (-not $env:DSSE_TS_METADATA -or -not (Test-Path $env:DSSE_TS_METADATA)) { throw "trustedsigning: set DSSE_TS_METADATA to the metadata json" }
      $tsa = if ($env:DSSE_TS_TSA) { $env:DSSE_TS_TSA } else { 'http://timestamp.acs.microsoft.com' }
      return @('sign', '/v', '/fd', 'SHA256', '/tr', $tsa, '/td', 'SHA256', '/dlib', $env:DSSE_TS_DLIB, '/dmdf', $env:DSSE_TS_METADATA, $file)
    }
    'evtoken' {
      # Default to SSL.com's TSA (the CA we chose for the EV cert). Any RFC3161 TSA is valid — override with
      # $env:DSSE_EV_TSA — but defaulting to the issuing CA's own timestamp server is the least-surprise choice.
      $tsa = if ($env:DSSE_EV_TSA) { $env:DSSE_EV_TSA } else { 'http://ts.ssl.com' }
      if ($env:DSSE_EV_THUMBPRINT) {
        return @('sign', '/v', '/fd', 'SHA256', '/sha1', $env:DSSE_EV_THUMBPRINT, '/tr', $tsa, '/td', 'SHA256', $file)
      } elseif ($env:DSSE_EV_SUBJECT) {
        return @('sign', '/v', '/fd', 'SHA256', '/n', $env:DSSE_EV_SUBJECT, '/tr', $tsa, '/td', 'SHA256', $file)
      }
      throw "evtoken: set DSSE_EV_THUMBPRINT (or DSSE_EV_SUBJECT)"
    }
  }
}

$failures = 0

# ★ ONE signtool INVOCATION FOR ALL FILES, AND THE REASON IS THE OPERATOR'S HANDS (2026-08-14).
#
# This looped, one signtool process per file. On the `evtoken` backend every process is a fresh private-key
# session, so the YubiKey asks for its PIN AGAIN — nine exes plus the MSI is ten PIN entries for one build, and
# the operator types every one of them. Measured that day: three signed builds in an hour, roughly thirty
# entries, because the earlier ones were wasted on packages that then failed to install.
#
# signtool takes a list. A single process is one key session, so the token has the opportunity to cache — and
# whether it does is the CSP's business rather than something this script should be re-litigating per file.
# It is also simply fewer round trips to the TSA's rate limiter.
#
# The per-file REPORTING is kept: Get-AuthenticodeSignature and `signtool verify` read the file and need no key,
# so they cost nothing and are the half that proves what actually happened. A batch that says "10 files signed"
# without naming them is the kind of summary that hides one unsigned binary.
$missing = @()
$present = @()
foreach ($file in $Files) {
  if (Test-Path $file) { $present += $file } else { Write-Error "not found: $file"; $missing += $file }
}
$failures += $missing.Count

if ($present.Count -gt 0) {
  Write-Host "`n--- signing $($present.Count) file(s) in one signtool invocation ---"
  foreach ($f in $present) { Write-Host "      $f" }
  # Get-SignArgs puts the file last; build the argument list once and append every file to it.
  $argv = @(Get-SignArgs $present[0])
  $argv = $argv[0..($argv.Count - 2)] + $present
  & $signtool @argv
  if ($LASTEXITCODE -ne 0) {
    Write-Error "signtool failed ($LASTEXITCODE) for the batch"
    $failures++
  }
  # Report every file individually whatever the batch said, because "the command succeeded" and "this binary is
  # signed" are different claims and only the second one matters at install time.
  foreach ($file in $present) {
    $sig = Get-AuthenticodeSignature -FilePath $file
    Write-Host ("  {0}" -f (Split-Path $file -Leaf))
    Write-Host ("    signer : {0}" -f $sig.SignerCertificate.Subject)
    Write-Host ("    status : {0}" -f $sig.Status)   # 'Valid' needs the signer chain trusted (test cert => UnknownError/NotTrusted is expected)
    if ($sig.Status -ne 'Valid' -and $Backend -ne 'test') {
      Write-Error "not signed after the batch: $file"
      $failures++
    }
    if ($Verify -and $Backend -ne 'test') {
      & $signtool 'verify' '/pa' '/v' $file
      if ($LASTEXITCODE -ne 0) { Write-Error "verify failed for $file"; $failures++ }
    }
  }
}

if ($failures -gt 0) { Write-Error "$failures file(s) failed"; exit 1 }
Write-Host "`nAll files signed via '$Backend' backend."
