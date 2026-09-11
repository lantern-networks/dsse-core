<#
.SYNOPSIS
  Did the install actually produce a steering device? Run after installing DsseAgent.msi.

.DESCRIPTION
  .\verify-windows-install.ps1 [-ExpectInterceptionCA <substring>] [-Probe <url>]

  WHY THIS EXISTS (2026-09-04, written from the first walk of this lane from the published tree).
  The MSI returned exit 0, four services appeared, the driver loaded, the device enrolled, and the agent
  reported enforcement=healthy (filters=6/6). Every indicator an installer can check was green. On that same
  box `curl https://example.com` failed with "unable to get local issuer certificate" - because the profile
  carried no interception root, so nothing on the machine could verify the authority that was inspecting it.

  Nothing in the Windows lane would have told anyone. macOS has verify_macos_install.sh; this side had four
  build scripts and no way to ask a finished machine whether it works. The person who installed it could only
  find out by reading the agent log, running openssl by hand, and enumerating the certificate store - which is
  what was done to discover the defect, and is not something a reader of the published tree can be asked to do.

  So the last checks here are the ones the ENDPOINT performs: real TLS to a real host, and look at who signed
  it - measured against the root THE PROFILE ANNOUNCES, not against a name.

  AND BOTH TRUST PATHS ARE ASKED, because on Windows they disagree. Programs that use the OS certificate store
  (Edge, Chrome, Git built against schannel, Invoke-WebRequest) and programs that carry their own CA bundle
  (curl, openssl, python-requests, node) can give opposite answers on the same machine at the same second.
  Measured on win-dev-1: OS path 200, curl "SSL certificate problem". Asking only one would have reported a
  healthy device.

  Exit 0 only if the device is genuinely steering. Every check prints what it observed, because a verifier
  that only says PASS/FAIL is a verifier nobody can debug.
#>
param(
  [string] $ExpectInterceptionCA = $env:DSSE_EXPECT_INTERCEPTION_CA,
  [string] $Probe = "https://example.com",
  # After `msiexec /x`: say what the uninstall left behind, why, and when it is safe to remove.
  [switch] $AfterUninstall
)

$ErrorActionPreference = 'Continue'
$script:fail = 0
$script:unanswered = 0
$script:unansweredList = @()
function ok   { param($m) Write-Host ("  ok   " + $m) }
function bad  { param($m) Write-Host ("  FAIL " + $m); $script:fail++ }
function note { param($m) Write-Host ("       " + $m) }
# A THIRD STATE, because "could not be measured" is neither. Folding it into the passing side makes a
# verifier that reports green for a question it never asked - which is the shape this whole lane keeps
# producing. Counted separately and named in the summary, so a PASS says what it did NOT answer.
function na   { param($m) Write-Host ("  n/a  " + $m); $script:unanswered++; $script:unansweredList += $m }

$progFiles = Join-Path $env:ProgramFiles "DSSE"
$progData  = Join-Path $env:ProgramData  "DSSE"
$icRoot    = Join-Path $progData "interception-root.pem"

if ($AfterUninstall) {
  # WHY THIS MODE EXISTS (2026-09-04). `msiexec /x` returned 0, removed all four services, and left the
  # deployment's root trusted machine-wide plus the device identity, its sealed private key, the profile and
  # the signing key on disk - with no line in the uninstall log saying a certificate removal had even been
  # attempted. The uninstall is deliberately not allowed to fail, so it also says nothing; that silence is
  # what this mode replaces. The macOS uninstaller says what it left and why, and this is the same sentence.
  Write-Host "== after uninstall: what is left on this machine =="

  $svc = Get-Service DsseSteer,DsseWfp,DsseWatchdog,DsseUpdater -ErrorAction SilentlyContinue
  if ($svc) { foreach ($s in $svc) { bad "$($s.Name) still exists ($($s.Status)) - the uninstall did not complete" } }
  else { ok "all four services are gone" }
  if (Test-Path $progFiles) { note "$progFiles still exists: $((Get-ChildItem $progFiles -ErrorAction SilentlyContinue).Count) item(s) - usually just logs" }

  # MATCHED BY FINGERPRINT, NEVER BY SUBJECT. A torn-down deployment and the one that replaced it can hold
  # roots with the SAME name and different keys - measured on the macOS side, two same-subject roots in one
  # keychain, one of them from a deployment that no longer existed and valid until 2036. Removing by name
  # takes the wrong one and the machine keeps trusting the dead authority.
  # KEYED BY FINGERPRINT, NOT BY FILE. One certificate is routinely carried by more than one artefact - a
  # deployment whose step-up portal runs on its own transport certificate writes the same root as both
  # step_up_portal_ca.pem and transport_ca.pem. Listing per file printed it twice and printed the removal
  # command twice, which reads as two problems and invites running a destructive command a second time.
  $left = @{}
  foreach ($pem in 'interception-root.pem','step_up_portal_ca.pem','transport_ca.pem','trust_anchors_adopted.pem') {
    $p = Join-Path $progData $pem
    if (-not (Test-Path $p)) { continue }
    $raw = Get-Content $p -Raw
    foreach ($blk in ([regex]::Matches($raw, '(?s)-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----'))) {
      try {
        $der = [Convert]::FromBase64String(($blk.Groups[1].Value -replace '\s',''))
        $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2(,$der)
        $inStore = Get-ChildItem Cert:\LocalMachine\Root,Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
                   Where-Object { $_.Thumbprint -eq $c.Thumbprint }
        if ($inStore) {
          if ($left.ContainsKey($c.Thumbprint)) { $left[$c.Thumbprint].Files += $pem }
          else { $left[$c.Thumbprint] = [pscustomobject]@{ Cert = $c; Files = @($pem) } }
        }
      } catch { }
    }
  }
  foreach ($k in $left.Keys) {
    $e = $left[$k]
    bad "still TRUSTED: $($e.Cert.Subject)"
    note "  fingerprint $k, carried by $($e.Files -join ' and '), valid until $($e.Cert.NotAfter.ToString('yyyy-MM-dd'))"
  }
  if ($left.Count -eq 0) { ok "no certificate this install carried is still in a trust store" }

  if (Test-Path (Join-Path $progData "enroll\device.key.dpapi")) {
    bad "the device identity is still on disk: $progData\enroll"
    note "  device.key.dpapi is sealed to this machine's SYSTEM account, so it is not portable - but the"
    note "  identity it proves is still enrolled at the deployment until an administrator removes the device"
  }
  foreach ($f in 'install-profile.json','profile_signing_key.txt') {
    if (Test-Path (Join-Path $progData $f)) { note "$f is still in $progData" }
  }

  Write-Host ""
  Write-Host "what to do, and what NOT to do:"
  note "at the Console: Devices > this device > Remove device. The machine cannot revoke its own enrolment."
  if ($left.Count -gt 0) {
    note "take each certificate BY FINGERPRINT - never by subject, another deployment can share the name:"
    foreach ($k in $left.Keys) {
      Write-Host ("       Get-ChildItem Cert:\LocalMachine\Root | Where-Object { `$_.Thumbprint -eq '" + $k + "' } | Remove-Item")
    }
  }
  note "then: Remove-Item -Recurse `"`$env:ProgramData\DSSE`""
  note "DO NOT remove a CA bundle other programs were pointed at while this agent was running: shells and"
  note "daemons started before the uninstall still hold that path, and taking it removes TLS from them"
  note "entirely. After a reboot nothing holds it and it can go."

  Write-Host ""
  if ($script:unanswered -gt 0) { foreach ($u in $script:unansweredList) { Write-Host ("  not answered: " + $u) } }
  if ($script:fail -eq 0) { Write-Host "verify-windows-install: PASS - the uninstall left nothing behind."; exit 0 }
  Write-Host "verify-windows-install: $($script:fail) thing(s) remain after an uninstall that returned 0."
  exit 1
}

Write-Host "== 1. installed files =="
foreach ($f in 'dsse-steer.exe','dsse-watchdog.exe','dsse-updater.exe','profileapply.exe','dsse-wfp.sys') {
  $p = Join-Path $progFiles $f
  if (Test-Path $p) { ok "$f" } else { bad "$f is missing from $progFiles" }
}
foreach ($f in 'install-profile.json','transport_ca.pem') {
  $p = Join-Path $progData $f
  if (Test-Path $p) { ok "$f" } else { bad "$f is missing from $progData - provisioning did not complete" }
}
if (Test-Path $icRoot) { ok "interception-root.pem" } else { note "no interception-root.pem - see section 6" }

Write-Host "== 2. code identity =="
foreach ($f in 'dsse-steer.exe','dsse-wfp.sys') {
  $p = Join-Path $progFiles $f
  if (-not (Test-Path $p)) { continue }
  $sig = Get-AuthenticodeSignature $p
  if ($sig.Status -eq 'Valid') { ok "$f signed by $($sig.SignerCertificate.Subject)" }
  else { note "$f signature status: $($sig.Status) - unsigned builds run, but nothing vouches for them" }
}
# The driver's signer decides whether this machine can load it at all. A self-signed TEST driver - which is
# what clients/windows-wfp/driver/BUILD.md produces - requires Secure Boot OFF. That is a property of the
# machine, not of the install, so it is measured here rather than assumed.
$sysPath = Join-Path $progFiles "dsse-wfp.sys"
if (Test-Path $sysPath) {
  $dsig = Get-AuthenticodeSignature $sysPath
  $attested = $dsig.SignerCertificate.Subject -match 'Windows Hardware Compatibility Publisher'
  $sb = $null
  try { $sb = Confirm-SecureBootUEFI } catch { }
  if ($attested) { ok "driver is attestation-signed by Microsoft - it loads with Secure Boot on" }
  elseif ($sb -eq $true) {
    bad "driver is NOT attestation-signed and Secure Boot is ON - this driver cannot load on this machine"
    note "a driver built from driver/BUILD.md is test-signed; attestation needs an EV certificate and a Partner Center submission"
  }
  else { na "whether this driver can load was not established: it is not attestation-signed and the Secure Boot state could not be read" }
}

Write-Host "== 3. the driver and the services =="
foreach ($svc in 'DsseWfp','DsseSteer') {
  $s = Get-Service $svc -ErrorAction SilentlyContinue
  if (-not $s) { bad "$svc does not exist"; continue }
  if ($s.Status -eq 'Running') { ok "$svc is $($s.Status) (start=$($s.StartType))" }
  else { bad "$svc is $($s.Status) (start=$($s.StartType)) - the device is not steering" }
}
foreach ($svc in 'DsseWatchdog','DsseUpdater') {
  $s = Get-Service $svc -ErrorAction SilentlyContinue
  if ($s) { note "$svc is $($s.Status) (start=$($s.StartType))" } else { note "$svc does not exist" }
}

Write-Host "== 4. the device's own record of the install =="
$enrolled = Join-Path $progData "enroll\enrolled.json"
if (Test-Path $enrolled) {
  try {
    $e = Get-Content $enrolled -Raw | ConvertFrom-Json
    ok "enrolled as '$($e.device_id)' in organization '$($e.tenant)' (group '$($e.group)') at $($e.enrolled_at)"
  } catch { bad "enrolled.json is present but unreadable: $($_.Exception.Message)" }
}
else {
  bad "no enrolled.json - this device has an install but no identity, so it cannot open the tunnel"
  note "the agent enrols on its FIRST START. If DsseSteer has never run, start it and re-run this."
}
foreach ($f in 'device.crt','device.key.dpapi') {
  $p = Join-Path $progData "enroll\$f"
  if (Test-Path $p) { ok "enroll\$f" } else { bad "enroll\$f is missing - the identity is incomplete" }
}

Write-Host "== 4b. can this device ever be updated? =="
# An agent that cannot accept a signed update is a machine that will hold today's defects forever, and nothing
# else in the install reports it.
$profilePath = Join-Path $progData "install-profile.json"
$payload = $null
if (Test-Path $profilePath) {
  try {
    $env0 = Get-Content $profilePath -Raw | ConvertFrom-Json
    $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env0.payload_b64)) | ConvertFrom-Json
  } catch { na "install-profile.json could not be decoded, so nothing it carries was checked: $($_.Exception.Message)" }
}
if ($payload) {
  $keys = @($payload.deployment.update_signing_keys) | Where-Object { $_ }
  if ($keys.Count -gt 0) { ok "$($keys.Count) update-signing key(s) - a signed update can be accepted" }
  else { bad "no update-signing keys in the profile - this device can never be updated" }
  if ($payload.deployment.update_publisher_team_id) { ok "update publisher team '$($payload.deployment.update_publisher_team_id)'" }
  else { note "no update publisher team - packages install on the manifest signature alone" }
}
else { na "the update path was not judged - there is no decodable profile to read it from" }

Write-Host "== 5. steering is configured AND armed =="
if ($payload) {
  ok "profile v$($payload.version) posture=$($payload.posture) transport=$($payload.transport_url)"
  $eps = @($payload.transport_endpoints) | Where-Object { $_ }
  if ($eps.Count -gt 0) { note "$($eps.Count) door(s): $($eps -join ', ')" }
  # The profile says what the machine SHOULD do. Below is what it IS doing; they are different questions and
  # this tree has shipped installs where they disagreed.
  if ($payload.start_mode -eq 'auto') {
    $s = Get-Service DsseSteer -ErrorAction SilentlyContinue
    if ($s -and $s.StartType -ne 'Automatic') {
      bad "profile says start_mode=auto but DsseSteer start type is $($s.StartType) - the device will not steer after a reboot"
    }
    else { ok "start_mode=auto matches the service start type" }
  }
}
else { na "what this device was CONFIGURED to do was not checked - the profile could not be read, so the machine's state could not be compared against it" }
$log = Join-Path $progFiles "dsse-steer.log"
if (Test-Path $log) {
  $tail = Get-Content $log -Tail 400 -ErrorAction SilentlyContinue
  $hb = $tail | Select-String 'heartbeat sent' | Select-Object -Last 1
  # AND HOW OLD IT IS. A verifier that reads the last heartbeat without asking when it was written reports a
  # stopped agent as healthy - the log still holds the line the agent wrote just before it stopped. Measured
  # on win-dev-1 while writing this file: the box was disarmed and this check said ok. That is the same shape
  # this whole lane keeps producing - a photograph taken once that nobody retakes.
  if ($hb) {
    $ts = $null
    if ($hb.Line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
      try { $ts = [datetime]::ParseExact($matches[1], 'yyyy-MM-dd HH:mm:ss', $null) } catch { }
    }
    if ($ts) {
      $age = ((Get-Date) - $ts).TotalSeconds
      if ($age -le 120) { ok ("last heartbeat {0:N0}s ago: " -f $age) + $hb.Line.Substring([Math]::Max(0, $hb.Line.IndexOf('heartbeat'))) }
      else { bad ("the last heartbeat is {0:N0}s old - the agent has stopped talking to the deployment" -f $age) }
    }
    else { note ("a heartbeat line exists but its timestamp could not be read: " + $hb.Line) }
  }
  else { bad "no heartbeat in the recent log - the agent is not talking to the deployment" }
  $reg = $tail | Select-String 'steering through region' | Select-Object -Last 1
  if ($reg) { note $reg.Line.Substring([Math]::Max(0, $reg.Line.IndexOf('steering through region'))) }
}
else { bad "no agent log at $log" }

Write-Host "== 6. the endpoint test - is traffic actually steered and inspected? =="
# MEASURED AGAINST THE ROOT THE PROFILE ANNOUNCES, NOT AGAINST A NAME. Every organization with its own
# interception authority is issued under its OWN name, so a name match reports "not inspected" on a device that
# is inspecting perfectly. The question asked is whether the chain the server PRESENTS leads to the root the
# profile carries - which needs no name and no trust store, so it cannot be fooled by a root this machine
# happens to trust either.
$leafIssuer = $null
$chainRoot = $null
# THE INTERMEDIATES COME FROM THE HANDSHAKE, NOT FROM THIS MACHINE. The first version built the chain from
# the leaf alone. The issuing CAs are sent by the server and are in no store here, so X509Chain had nothing
# to build THROUGH: it returned a one-element chain whose "root" was the leaf, and this check reported "not
# inspected" on a device that was inspecting perfectly. That is the exact failure its own comment warns
# about - a verifier that fails on the product working correctly sends the next person to fix a device that
# is not broken. Measured on win-dev-1 the first time this ran against an organization that owns its
# interception authority.
#
# schannel validates using what the server sent; a standalone Build cannot see it. The certificates ARE
# reachable, in the validation callback's ChainPolicy.ExtraStore, so they are taken from there and the chain
# is built with them. Warming the OS cache with a prior request does not help - measured, still one element.
$leafIssuer = $null
$chainRoot = $null
$chainLen = 0
$global:dsseServed = $null
try {
  $u = [Uri]$Probe
  $tcp = New-Object Net.Sockets.TcpClient($u.Host, 443)
  $cb = { param($sndr, $cert, $chain, $errors) $global:dsseServed = @($chain.ChainPolicy.ExtraStore); return $true }
  $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, $cb)
  $ssl.AuthenticateAsClient($u.Host)
  $leaf = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
  $leafIssuer = $leaf.Issuer
  $ch = New-Object Security.Cryptography.X509Certificates.X509Chain
  $ch.ChainPolicy.RevocationMode = 'NoCheck'
  if ($global:dsseServed) { foreach ($x in $global:dsseServed) { [void]$ch.ChainPolicy.ExtraStore.Add($x) } }
  [void]$ch.Build($leaf)
  $chainLen = $ch.ChainElements.Count
  if ($chainLen -gt 0) { $chainRoot = $ch.ChainElements[$chainLen - 1].Certificate }
  $ssl.Close()
  $tcp.Close()
} catch { bad "could not complete TLS to $Probe : $($_.Exception.Message)" }
if ($chainLen -eq 1) { na "the chain could not be built past the leaf, so where it leads was not established" }

if ($leafIssuer) {
  note "$Probe leaf issued by: $leafIssuer"
  $rootPem = $null
  if ($payload -and $payload.deployment.interception_root_pem) { $rootPem = $payload.deployment.interception_root_pem }
  elseif (Test-Path $icRoot) { $rootPem = Get-Content $icRoot -Raw }
  if ($rootPem) {
    $b64 = (($rootPem -split '-----')[2]) -replace '\s', ''
    $announced = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String($b64))
    if ($chainRoot -and $chainRoot.Thumbprint -eq $announced.Thumbprint) {
      ok "the presented chain leads to the interception root this deployment announced ($($announced.Thumbprint))"
    }
    else {
      bad "the presented chain does NOT lead to the announced interception root - this traffic is not inspected by this deployment"
      note "announced: $($announced.Subject) $($announced.Thumbprint)"
      if ($chainRoot) { note "presented chain ends at: $($chainRoot.Subject) $($chainRoot.Thumbprint)" }
    }
  }
  elseif ($ExpectInterceptionCA) {
    if ($leafIssuer -match [Regex]::Escape($ExpectInterceptionCA)) { ok "issuer matches the expected substring '$ExpectInterceptionCA'" }
    else { bad "issuer does not match '$ExpectInterceptionCA' - traffic is NOT inspected" }
  }
  else {
    # This is the state that shipped on 2026-09-04 and that nothing reported.
    bad "this device has NO announced interception root, so it cannot verify the authority inspecting it"
    note "the profile carries no deployment.interception_root_pem and no $icRoot is present"
    note "if this traffic IS being inspected, every program that carries its own CA bundle is now broken (see 6b)"
  }
}

Write-Host "== 6b. both trust paths, because on Windows they disagree =="
# The OS store and a program's own CA bundle are different trust decisions. A device can be perfectly usable in
# a browser and completely broken for curl, pip, npm and every build script on the machine - and nothing on the
# machine reports it. Measured on win-dev-1, 2026-09-04: OS path 200, curl "SSL certificate problem".
$osOk = $false
try {
  $r = Invoke-WebRequest -Uri $Probe -TimeoutSec 15 -UseBasicParsing
  $osOk = ($r.StatusCode -eq 200)
} catch { }
if ($osOk) { ok "OS certificate store path (browsers, schannel): $Probe -> 200" }
else { bad "OS certificate store path cannot reach $Probe - browsers on this machine are broken" }

$curl = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
if ($curl) {
  $code = (& $curl -sS -o NUL -w '%{http_code}' --max-time 15 $Probe 2>&1 | Select-Object -Last 1)
  if ("$code" -eq '200') { ok "own-CA-bundle path (curl): $Probe -> 200" }
  else {
    bad "own-CA-bundle path (curl) cannot verify $Probe -> $code"
    note "programs that do not use the OS store - curl, openssl, python-requests, node - are broken on this device"
    note "nothing in this install provisions a CA bundle for them"
  }
}
else { na "the own-CA-bundle path was not asked - no curl.exe on PATH. A device can pass every other check here and still be broken for every program that does not use the OS store" }

Write-Host "== 7. plain reachability =="
$code = '000'
try {
  $r = Invoke-WebRequest -Uri $Probe -TimeoutSec 15 -UseBasicParsing
  $code = "$($r.StatusCode)"
} catch { }
if ($code -eq '200') { ok "$Probe -> $code" } else { bad "$Probe -> $code (the device cannot browse)" }

Write-Host ""
# A PASS SAYS WHAT IT DID NOT ANSWER. A check that could not run is not a check that passed, and a verifier
# that hides the difference reports green for questions it never asked.
if ($script:unanswered -gt 0) {
  Write-Host ""
  Write-Host "$($script:unanswered) question(s) were NOT answered on this machine:"
  foreach ($u in $script:unansweredList) { Write-Host ("  - " + $u) }
}
if ($script:fail -eq 0) {
  if ($script:unanswered -eq 0) {
    Write-Host "verify-windows-install: PASS - the device is installed, enrolled, and STEERING."
  }
  else {
    Write-Host "verify-windows-install: PASS for what was asked - $($script:unanswered) question(s) above were not."
    Write-Host "A device is ready only for the things that were checked."
  }
  exit 0
}
Write-Host "verify-windows-install: $($script:fail) check(s) FAILED - the install is NOT complete."
Write-Host "A green MSI and four running services prove the files are in place; they do not prove the device works."
exit 1
