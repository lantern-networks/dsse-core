# dsse-wfp driver: build / sign / load

The kernel-mode WFP callout backend driver. The shared contract is `dsse_wfp.h` (kept byte-for-byte in
sync with the Go side, `../steer/capture_wfp*.go`).

> ## What this page can and cannot get you
>
> **A driver built by following this page loads only on a machine with Secure Boot turned OFF.** Everything
> here is free and self-contained, and it ends at a test-signed `.sys`. Windows will not load a test-signed
> kernel driver on a default installation.
>
> Going further is not a longer version of this page. A kernel driver that loads on a stock Windows needs an
> **attestation signature from Microsoft**, which needs an **EV code-signing certificate associated with the signing account**
> and a **Partner Center account** — an organizational identity and a submission process, not a build step.
> `build-msi.ps1 -Sign` signs the *package*; it cannot make the driver loadable.
>
> So: this tree builds a driver you can develop and test with. Whoever ships an agent to machines they do not
> control brings their own attestation-signed `.sys` and passes it with `-DriverSys`.
>
> The Windows steering agent has a second backend — the standard Windows Filtering Platform rules the service
> installs without a driver (`--inbound-backend firewall`). What the callout driver adds is per-flow capture;
> what it costs is the paragraph above.

## Toolchain (all free)

- VS Build Tools 2022 (C++ workload + Windows SDK 10.0.22621):
  `winget install Microsoft.VisualStudio.2022.BuildTools --override "... --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.Windows11SDK.22621"`
- WDK 10.0.22621: `winget install Microsoft.WindowsWDK.10.0.22621`

## WDK Build Tools troubleshooting

1. **WDK VS integration is not supported on Build Tools** (the VSIX installer exits 2003). Workaround:
   extract `WDK.vsix` manually and merge the kernel toolset into the Build Tools VCTargets:
   - Unzip `C:\Program Files (x86)\Windows Kits\10\Vsix\VS2022\10.0.22621.0\WDK.vsix`
   - `robocopy "<extracted>\$MSBuild\Microsoft\VC\v170" "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Microsoft\VC\v170" /E`
   - This registers the `WindowsKernelModeDriver10.0` toolset.
2. **WOW64 redirection**: if the repo is under `C:\WINDOWS\system32\...`, 32-bit MSBuild redirects
   system32 -> SysWOW64 and reports "project not found" (MSB1009). **Use 64-bit MSBuild**:
   `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe`
3. **Spectre libs not installed** -> `/p:SpectreMitigation=false`.
4. **km includes / arch macros** must be set explicitly in the vcxproj (Build Tools integration is
   incomplete): `Include\...\km;km\crt;shared`, `_AMD64_;AMD64;_WIN64;_KERNEL_MODE;NTDDI_VERSION=0x0A000000`,
   and `/utf-8` (sources are UTF-8).
5. **The link -> .sys step does not run under MSBuild** (the WDK link target is missing from the Build
   Tools integration). The compile succeeds (produces `driver.obj`), so **link manually with link.exe**:
   ```
   link /DRIVER /INTEGRITYCHECK /DEBUG /PDB:dsse-wfp.pdb /OUT:dsse-wfp.sys /ENTRY:GsDriverEntry /SUBSYSTEM:NATIVE,10.0 /NODEFAULTLIB /MACHINE:X64 /RELEASE ^
     /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\km\x64" ^
     ntoskrnl.lib hal.lib fwpkclnt.lib ndis.lib wdmsec.lib BufferOverflowFastFailK.lib  <obj>\driver.obj
   ```
   (`wdmsec.lib` is required for `WdmlibIoCreateDeviceSecure`, used to create the control device with an ACL.)
   (`/DEBUG /PDB:` produces the symbol file. It is not needed to LOAD the driver, but a Partner Center
   attestation submission carries the .pdb — Microsoft's automated crash analysis wants it — so a build without
   retain it with the driver submission artifacts.)
   (`/INTEGRITYCHECK` is required by `PsSetCreateProcessNotifyRoutineEx`, used for the process-creation
   notification that lets signature-form steer exclusions reach short-lived processes. Without it the driver
   still loads and steers, but the registration fails with STATUS_ACCESS_DENIED and userspace silently falls
   back to learning from steered flows — so a missing flag costs one steered flow per binary, not an outage.)

## Build

```
& "<...BuildTools>\MSBuild\Current\Bin\amd64\MSBuild.exe" dsse-wfp.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false
# this produces driver.obj; then run the link.exe step above to produce the .sys
```

The output `.sys` goes to `outputs/windows/` (gitignored, not committed).

## Test-signing (free, self-signed)

```
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Dsse Test Driver" -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature -KeyExportPolicy Exportable
signtool sign /v /fd SHA256 /sha1 $cert.Thumbprint dsse-wfp.sys
```

## Load (requires Secure Boot OFF, admin, manual)

> Test-machine requirements:
> - **Ordering**: while Secure Boot is ON, `bcdedit /set testsigning on` is itself rejected
>   ("The value is protected by Secure Boot policy"). So two reboots are mandatory: disable Secure Boot
>   (reboot #1, UEFI) -> after Windows boots, enable testsigning -> reboot #2.
> - **BitLocker**: if the OS volume is BitLocker-protected, changing Secure Boot prompts for the
>   recovery key. Have the key ready and suspend protection first:
>   `Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 3` (auto-resumes after the given reboots).
> - Importing the certificate into Root + TrustedPublisher makes the `.sys` signature `Valid` even with
>   Secure Boot ON (that is about the chain, separate from whether it can load).

1. **Trust the test certificate** (public part only): `Import-Certificate -FilePath <.cer> -CertStoreLocation Cert:\LocalMachine\Root`, and likewise `\TrustedPublisher`. (No load / reboot needed, so do this first.)
2. **Suspend BitLocker** (after noting the recovery key): `Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 3`.
3. **Disable Secure Boot** in UEFI (test-signing is mutually exclusive with Secure Boot) -> reboot #1.
4. After Windows boots: `bcdedit /set testsigning on` -> reboot #2.
5. Register + load the service:
   ```
   sc.exe create DsseWfp type= kernel binPath= C:\...\outputs\windows\dsse-wfp.sys
   sc.exe start DsseWfp
   ```
6. Run the steering agent (`../steer`, built as `dsse-wfp-steer.exe`):
   ```
   dsse-wfp-steer.exe --mode redirect --steer-all --steer-generic --backend wfp --edge-url https://<edge> --bypass-app automation
   ```
   Confirm it opens `\\.\DsseWfp`, pushes policy, and connections are redirected.
7. Teardown: `sc.exe stop DsseWfp; sc.exe delete DsseWfp`, `bcdedit /set testsigning off`, re-enable
   Secure Boot in UEFI, BitLocker auto-resumes (`Resume-BitLocker` to resume immediately).

## Driver ABI

`DSSE_POLICY_VERSION 2` includes the verified exact application-ID bypass table
(`bypassByExactAppId`). The service verifies a signer's identity and passes exact NT
application IDs to the driver. Keep `dsse_wfp.h` and `capture_wfp_policy.go` in sync;
`TestWFPPolicyABISize` checks the shared layout.

A driver build or signature check does not prove runtime capture. Validate loading and
redirection on a dedicated test device under the security configuration you intend to support.
