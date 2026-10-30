package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lantern-networks/dsse-core/deploymentcrl"
)

// writeDeploymentCRLServices creates issuer-host service definitions, but does
// not activate them. The renewal timer signs as the issuer directory owner,
// while a separate DynamicUser HTTP service has no key mount and listens on loopback.
// The operator's external HTTP frontends must route every declared origin to
// a current copy of this keyless publisher before -start-node can pass.
// Exec commands use systemd's ":" prefix to keep environment-like text in
// operator-supplied paths literal; quotes alone do not disable ${VAR} expansion.

func writeDeploymentCRLServices(dir string, rootFingerprint string, origins []string) error {
	return writeDeploymentCRLServicesAt(dir, rootFingerprint, origins,
		"/var/lib/dsse-deployment-crl", "/usr/local/bin/dsse-deployment-crl", "/etc/systemd/system", 0)
}

// The private deployment tree is deliberately owned by the human installer.
// The renewer drops to that owner instead of allowing a root process to consume
// mutable source keys. Only public issuer certificates enter the root-owned
// stage used by the keyless publisher. The original authority and ledger remain
// the sole signing/revocation state. Injected paths/UID allow a rootless local
// regression test without weakening the production root ownership contract.
func writeDeploymentCRLServicesAt(dir string, rootFingerprint string, origins []string, stageBase, bin, unitDir string, stageUID int) error {
	if len(rootFingerprint) != 64 || strings.Trim(rootFingerprint, "0123456789abcdef") != "" || len(origins) == 0 {
		return fmt.Errorf("deployment CRL service needs an issued root and public origins")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	stageBase, err = filepath.Abs(stageBase)
	if err != nil {
		return err
	}
	if stageUID < 0 || strings.ContainsAny(absolute+stageBase+bin+unitDir, "\r\n\x00") {
		return fmt.Errorf("deployment CRL service path contains unsupported control characters")
	}
	for _, origin := range origins {
		if strings.Contains(origin, ",") {
			return fmt.Errorf("deployment CRL origin cannot contain a comma")
		}
	}
	id := rootFingerprint[:12]
	base := "dsse-crl-" + id
	renewService, timer, publishService := base+"-renew.service", base+"-renew.timer", base+"-publish.service"
	stage := filepath.Join(stageBase, rootFingerprint)
	// The deployment directory may be 0700, as the documented founding-node
	// procedure creates it. The issuer-owner signer keeps using its original
	// authority and ledger. The publisher receives only staged public issuer
	// certificates and live signed DER files, never the issuer keys.
	runtimeDir := "/run/" + base
	publicFiles := []string{
		"root.crt", "management-ca.crt", "console-server-ca.crt", "transport-ca.crt", "device-ca.crt",
		"lantern_dsse_interception_root_ca.pem",
	}
	var publicBinds strings.Builder
	for _, name := range publicFiles {
		fmt.Fprintf(&publicBinds, "BindReadOnlyPaths=%s:%s\n",
			systemdArg(filepath.Join(stage, name)), systemdArg(filepath.Join(runtimeDir, name)))
	}
	fmt.Fprintf(&publicBinds, "BindReadOnlyPaths=%s:%s\n",
		systemdArg(filepath.Join(absolute, "deployment-crl")), systemdArg(filepath.Join(runtimeDir, "deployment-crl")))
	publishCommand := strings.Join([]string{
		systemdArg(bin), "-dir", systemdArg(runtimeDir), "-mode serve -origins",
		systemdArg(strings.Join(origins, ",")), "-listen 127.0.0.1:18081",
	}, " ")
	renewUnit := fmt.Sprintf(`[Unit]
Description=DSSE deployment CRL signer for %s
ConditionPathExists=%s

[Service]
Type=oneshot
User=DSSE_ISSUER_UID
UMask=0077
ExecStart=:%s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=%s %s
RestrictAddressFamilies=AF_UNIX
`, id, systemdArg(filepath.Join(absolute, "root.crt")),
		systemdArg(bin)+" -dir "+systemdArg(absolute)+" -mode renew",
		systemdArg(filepath.Join(absolute, "authority")), systemdArg(filepath.Join(absolute, "deployment-crl")))
	timerBody := fmt.Sprintf(`[Unit]
Description=Renew signed DSSE deployment CRLs for %s

[Timer]
OnBootSec=1min
OnCalendar=hourly
Persistent=true
Unit=%s

[Install]
WantedBy=timers.target
`, id, renewService)
	publishUnit := fmt.Sprintf(`[Unit]
Description=Keyless DSSE deployment CRL HTTP publisher for %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
RuntimeDirectory=%s
RuntimeDirectoryMode=0700
%s
ExecStart=:%s
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectControlGroups=yes
InaccessiblePaths=%s
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
`, id, base, publicBinds.String(), publishCommand, systemdArg(filepath.Join(absolute, "authority")))
	installBody := deploymentCRLActivationScript(absolute, stageBase, stage, bin, unitDir, stageUID, publicFiles,
		[]string{renewService, timer, publishService})
	for _, item := range []struct {
		name, body string
		mode       os.FileMode
	}{
		{renewService, renewUnit, 0o644},
		{timer, timerBody, 0o644},
		{publishService, publishUnit, 0o644},
		{"install-deployment-crl-services.sh", installBody, 0o755},
	} {
		if err := os.WriteFile(filepath.Join(absolute, item.name), []byte(item.body), item.mode); err != nil {
			return err
		}
	}
	return nil
}

// The operator-owned authority and ledger remain the only signing state. The
// signer runs as that owner; root activation stages public certificates only.
func deploymentCRLActivationScript(source, stageBase, stage, bin, unitDir string, stageUID int, publicFiles, units []string) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\nset -eu\numask 077\n")
	fmt.Fprintf(&b, "source=%s\nstage_base=%s\nstage=%s\nbin=%s\nunit_dir=%s\nstage_uid=%d\n",
		shellQuote(source), shellQuote(stageBase), shellQuote(stage), shellQuote(bin), shellQuote(unitDir), stageUID)
	b.WriteString("test \"$(id -u)\" -eq \"$stage_uid\" || { echo 'Run activation as the service administrator' >&2; exit 1; }\n")
	b.WriteString("test -d \"$source\" && test ! -L \"$source\" && test \"$(stat -c %a \"$source\")\" -eq 700 || exit 1\n")
	b.WriteString("issuer_uid=$(stat -c %u \"$source\")\n")
	b.WriteString("test -d \"$source/authority\" && test ! -L \"$source/authority\" && test \"$(stat -c %u \"$source/authority\")\" -eq \"$issuer_uid\" && test \"$(stat -c %a \"$source/authority\")\" -eq 700 || exit 1\n")
	b.WriteString("test -d \"$source/deployment-crl\" && test ! -L \"$source/deployment-crl\" && test \"$(stat -c %u \"$source/deployment-crl\")\" -eq \"$issuer_uid\" || exit 1\n")
	fmt.Fprintf(&b, "test \"$(find \"$source/deployment-crl\" -mindepth 1 -maxdepth 1 | wc -l)\" -eq %d\n", len(publicFiles))
	fmt.Fprintf(&b, "test \"$(find \"$source/deployment-crl\" -mindepth 1 -maxdepth 1 -type f -name '*.crl' | wc -l)\" -eq %d\n", len(publicFiles))
	b.WriteString("for crl in \"$source/deployment-crl\"/*.crl; do\n")
	b.WriteString("  test -f \"$crl\" && test ! -L \"$crl\" && test \"$(stat -c %u \"$crl\")\" -eq \"$issuer_uid\" && test \"$(stat -c %a \"$crl\")\" -eq 644 || exit 1\n")
	b.WriteString("done\n")
	b.WriteString("check_private() {\n")
	b.WriteString("  test -f \"$1\" && test ! -L \"$1\" && test \"$(stat -c %u \"$1\")\" -eq \"$issuer_uid\" && test \"$(stat -c %a \"$1\")\" -eq 600 || exit 1\n")
	b.WriteString("}\n")
	for _, name := range []string{
		"authority/root.key", "authority/management-ca.key", "authority/console-server-ca.key",
		"authority/transport-ca.key", "device-ca.key", "lantern_dsse_interception_root_ca.key.pem",
		"authority/deployment-crl-ledger.json",
	} {
		fmt.Fprintf(&b, "check_private %s\n", shellQuote(filepath.Join(source, name)))
	}
	b.WriteString("test -f \"$bin\" && test ! -L \"$bin\" && test -x \"$bin\" && test \"$(stat -c %u \"$bin\")\" -eq \"$stage_uid\" || exit 1\n")
	b.WriteString("bin_mode=$(stat -c %a \"$bin\")\ntest \"$((0$bin_mode & 022))\" -eq 0\n")
	fmt.Fprintf(&b, "test -d %s && test ! -L %s && test \"$(stat -c %%u %s)\" -eq \"$stage_uid\" || exit 1\n",
		shellQuote(filepath.Dir(bin)), shellQuote(filepath.Dir(bin)), shellQuote(filepath.Dir(bin)))
	fmt.Fprintf(&b, "bin_parent_mode=$(stat -c %%a %s)\ntest \"$((0$bin_parent_mode & 022))\" -eq 0\n", shellQuote(filepath.Dir(bin)))
	b.WriteString("test -d \"$unit_dir\" && test ! -L \"$unit_dir\" && test \"$(stat -c %u \"$unit_dir\")\" -eq \"$stage_uid\" || exit 1\n")
	b.WriteString("unit_mode=$(stat -c %a \"$unit_dir\")\ntest \"$((0$unit_mode & 022))\" -eq 0\n")
	fmt.Fprintf(&b, "test -d %s && test ! -L %s && test \"$(stat -c %%u %s)\" -eq \"$stage_uid\" || exit 1\n",
		shellQuote(filepath.Dir(stageBase)), shellQuote(filepath.Dir(stageBase)), shellQuote(filepath.Dir(stageBase)))
	fmt.Fprintf(&b, "stage_parent_mode=$(stat -c %%a %s)\ntest \"$((0$stage_parent_mode & 022))\" -eq 0\n", shellQuote(filepath.Dir(stageBase)))
	b.WriteString("test ! -L \"$stage_base\"\ninstall -d -m 0700 \"$stage_base\"\n")
	b.WriteString("test \"$(stat -c %u \"$stage_base\")\" -eq \"$stage_uid\" && test \"$(stat -c %a \"$stage_base\")\" -eq 700 || exit 1\n")
	for _, name := range publicFiles {
		fmt.Fprintf(&b, "test -f %s && test ! -L %s && test \"$(stat -c %%u %s)\" -eq \"$issuer_uid\" || exit 1\n",
			shellQuote(filepath.Join(source, name)), shellQuote(filepath.Join(source, name)), shellQuote(filepath.Join(source, name)))
	}
	for _, name := range units {
		fmt.Fprintf(&b, "test -f %s && test ! -L %s && test \"$(stat -c %%u %s)\" -eq \"$issuer_uid\" || exit 1\n",
			shellQuote(filepath.Join(source, name)), shellQuote(filepath.Join(source, name)), shellQuote(filepath.Join(source, name)))
	}
	b.WriteString("if test -e \"$stage\" || test -L \"$stage\"; then\n")
	b.WriteString("  test -d \"$stage\" && test ! -L \"$stage\" && test \"$(stat -c %u \"$stage\")\" -eq \"$stage_uid\" && test \"$(stat -c %a \"$stage\")\" -eq 700 || exit 1\n")
	b.WriteString("else\n")
	b.WriteString("  stage_tmp=$(mktemp -d \"$stage_base/.public.XXXXXXXX\")\n")
	b.WriteString("  trap 'rm -rf -- \"$stage_tmp\"' EXIT HUP INT TERM\n")
	for _, name := range publicFiles {
		fmt.Fprintf(&b, "  install -m 0644 %s \"$stage_tmp/%s\"\n", shellQuote(filepath.Join(source, name)), name)
	}
	b.WriteString("  mv -- \"$stage_tmp\" \"$stage\"\n  stage_tmp=\n  trap - EXIT HUP INT TERM\nfi\n")
	for _, name := range publicFiles {
		fmt.Fprintf(&b, "test -f \"$stage/%s\" && test ! -L \"$stage/%s\" && test \"$(stat -c %%u \"$stage/%s\")\" -eq \"$stage_uid\" && test \"$(stat -c %%a \"$stage/%s\")\" -eq 644 && cmp -s %s \"$stage/%s\" || exit 1\n",
			name, name, name, name, shellQuote(filepath.Join(source, name)), name)
	}
	b.WriteString("chmod 0755 \"$source/deployment-crl\"\n")
	b.WriteString("test \"$(stat -c %a \"$source/deployment-crl\")\" -eq 755\n")
	fmt.Fprintf(&b, "unit_tmp=$(mktemp \"$unit_dir/.dsse-crl-unit.XXXXXXXX\")\n")
	b.WriteString("trap 'rm -f -- \"$unit_tmp\"' EXIT HUP INT TERM\n")
	fmt.Fprintf(&b, "sed \"s/^User=DSSE_ISSUER_UID$/User=$issuer_uid/\" %s > \"$unit_tmp\"\n", shellQuote(filepath.Join(source, units[0])))
	b.WriteString("chmod 0644 \"$unit_tmp\"\n")
	fmt.Fprintf(&b, "mv -f -- \"$unit_tmp\" %s\n", shellQuote(filepath.Join(unitDir, units[0])))
	b.WriteString("unit_tmp=\ntrap - EXIT HUP INT TERM\n")
	for _, name := range units[1:] {
		fmt.Fprintf(&b, "install -m 0644 %s %s\n", shellQuote(filepath.Join(source, name)), shellQuote(filepath.Join(unitDir, name)))
	}
	fmt.Fprintf(&b, "systemctl daemon-reload\nsystemctl start %s\nsystemctl enable --now %s %s\n", units[0], units[1], units[2])
	b.WriteString("echo 'Issuer renewal and local keyless publication active. Verify every public HTTP CDP with dsse-install -preflight before starting nodes.'\n")
	return b.String()
}

func systemdArg(s string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '%':
			out.WriteString("%%")
		default:
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
	return out.String()
}

// The issuer fingerprints are part of the URL contract and the unit identity.
func writeIssuedDeploymentCRLServices(dir string, root *deploymentAuthorities, origins []string) error {
	if len(origins) == 0 {
		return nil
	}
	if root == nil || root.RootCert == nil {
		return fmt.Errorf("deployment CRL root is missing")
	}
	if _, err := deploymentcrl.DistributionPoints(origins, root.RootCert, root.RootCert); err != nil {
		return err
	}
	return writeDeploymentCRLServices(dir, deploymentcrl.Fingerprint(root.RootCert), origins)
}
