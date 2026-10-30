package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/deploymentcrl"
)

// writeReplicaServiceUnits prepares a dedicated, keyless Linux publication
// host. The installer intentionally refuses a full deployment directory:
// only public CA certificates and signed CRL files belong on this machine.
// Exec commands use systemd's ":" prefix to keep environment-like text in
// operator-supplied paths literal; quotes alone do not disable ${VAR} expansion.

func writeReplicaServiceUnits(dir, outputDir, sourceOrigin, replicaOrigin string, root *x509.Certificate, issuers []*x509.Certificate) error {
	if root == nil || len(issuers) < 2 {
		return fmt.Errorf("replica units require a deployment root and issuing CAs")
	}
	if err := root.CheckSignatureFrom(root); err != nil || !root.IsCA || root.KeyUsage&x509.KeyUsageCRLSign == 0 ||
		time.Now().Before(root.NotBefore) || !time.Now().Before(root.NotAfter) {
		return fmt.Errorf("replica units require a current self-signed deployment root")
	}
	for _, path := range []string{dir, outputDir} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
			return fmt.Errorf("replica service paths must be absolute and free of control characters")
		}
	}
	if strings.HasPrefix(dir, "/home/") || strings.HasPrefix(dir, "/root/") || strings.HasPrefix(dir, "/Users/") {
		return fmt.Errorf("replica public directory must not be under a protected home")
	}
	if relative, err := filepath.Rel(dir, outputDir); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("replica service units must not be written inside the public directory")
	}
	points, err := deploymentcrl.DistributionPoints([]string{sourceOrigin, replicaOrigin}, root, root)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	rootPresent := false
	for _, issuer := range issuers {
		if issuer == nil || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCRLSign == 0 ||
			time.Now().Before(issuer.NotBefore) || !time.Now().Before(issuer.NotAfter) {
			return fmt.Errorf("invalid replica issuing CA")
		}
		id := deploymentcrl.Fingerprint(issuer)
		if seen[id] {
			return fmt.Errorf("duplicate replica issuing CA")
		}
		seen[id] = true
		if id == deploymentcrl.Fingerprint(root) {
			rootPresent = true
		} else {
			if err := issuer.CheckSignatureFrom(root); err != nil {
				return fmt.Errorf("replica issuing CA is not signed by the deployment root")
			}
			if !slices.Contains(issuer.CRLDistributionPoints, points[0]) || !slices.Contains(issuer.CRLDistributionPoints, points[1]) {
				return fmt.Errorf("both independent CRL origins must be encoded in every issuing CA")
			}
		}
	}
	if !rootPresent {
		return fmt.Errorf("replica root status is missing")
	}
	if err := requirePublicOnlyDirectory(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(outputDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("replica unit output must be a private real directory")
	}
	id := deploymentcrl.Fingerprint(root)[:12]
	base := "dsse-crl-" + id
	user := base
	replicateUnit := base + "-replicate.service"
	timerUnit := base + "-replicate.timer"
	serveUnit := base + "-serve.service"
	publicDir := filepath.Join(dir, "deployment-crl")
	bin := "/usr/local/bin/dsse-deployment-crl"
	replicate := fmt.Sprintf(`[Unit]
Description=Replicate signed DSSE deployment CRLs for %s
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=%s
Group=%s
UMask=0027
ExecStart=:%s -dir %s -mode replicate -source-origin %s
ExecStartPost=:%s -dir %s -mode replica-ready
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=%s
InaccessiblePaths=-%s
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
`, id, user, user, systemdLiteral(bin), systemdLiteral(dir), systemdLiteral(sourceOrigin),
		systemdLiteral(bin), systemdLiteral(dir), systemdLiteral(publicDir), systemdLiteral(filepath.Join(dir, "authority")))
	timer := fmt.Sprintf(`[Unit]
Description=Refresh keyless DSSE deployment CRL replica for %s

[Timer]
OnBootSec=1min
OnUnitActiveSec=10min
Persistent=true
Unit=%s

[Install]
WantedBy=timers.target
`, id, replicateUnit)
	serve := fmt.Sprintf(`[Unit]
Description=Serve signed DSSE deployment CRL replica for %s
After=network-online.target
Wants=network-online.target
ConditionPathExists=%s

[Service]
Type=simple
User=%s
Group=%s
ExecStartPre=:%s -dir %s -mode replica-ready
ExecStart=:%s -dir %s -mode serve -origins %s -listen 127.0.0.1:18081
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
InaccessiblePaths=-%s
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
`, id, systemdLiteral(filepath.Join(dir, "root.crt")), user, user,
		systemdLiteral(bin), systemdLiteral(dir), systemdLiteral(bin), systemdLiteral(dir),
		systemdLiteral(replicaOrigin), systemdLiteral(filepath.Join(dir, "authority")))
	var certChecks strings.Builder
	for _, spec := range issuerFiles {
		path := filepath.Join(dir, spec.cert)
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintf(&certChecks, "test -f %s && test ! -L %s || { echo 'Public CA certificate missing or linked' >&2; exit 1; }\n", shellLiteral(path), shellLiteral(path))
			fmt.Fprintf(&certChecks, "runuser -u %s -- test -r %s || { echo 'Replica user cannot read a public CA certificate' >&2; exit 1; }\n", user, shellLiteral(path))
		}
	}
	install := "#!/bin/sh\nset -eu\n" +
		"test \"$(id -u)\" -eq 0 || { echo 'Run replica activation as root' >&2; exit 1; }\n" +
		"test -x " + shellLiteral(bin) + " || { echo 'Reviewed dsse-deployment-crl binary missing' >&2; exit 1; }\n" +
		"test ! -e " + shellLiteral(filepath.Join(dir, "authority")) + " || { echo 'Do not place authority material on a CRL replica' >&2; exit 1; }\n" +
		"test ! -L " + shellLiteral(publicDir) + " || { echo 'Replica publication directory must not be linked' >&2; exit 1; }\n" +
		"if ! id -u " + user + " >/dev/null 2>&1; then useradd --system --no-create-home --shell /usr/sbin/nologin " + user + "; fi\n" +
		certChecks.String() +
		"install -d -m 0750 -o " + user + " -g " + user + " " + shellLiteral(publicDir) + "\n" +
		"if test -e " + shellLiteral(filepath.Join(publicDir, ".deployment-crl-replica.lock")) + " || test -L " + shellLiteral(filepath.Join(publicDir, ".deployment-crl-replica.lock")) + "; then\n" +
		"  test ! -L " + shellLiteral(filepath.Join(publicDir, ".deployment-crl-replica.lock")) + " && runuser -u " + user + " -- test -w " + shellLiteral(filepath.Join(publicDir, ".deployment-crl-replica.lock")) + " || { echo 'Replica lock is not owned by the replica user' >&2; exit 1; }\n" +
		"fi\n" +
		"install -m 0644 " + shellLiteral(filepath.Join(outputDir, replicateUnit)) + " /etc/systemd/system/" + replicateUnit + "\n" +
		"install -m 0644 " + shellLiteral(filepath.Join(outputDir, timerUnit)) + " /etc/systemd/system/" + timerUnit + "\n" +
		"install -m 0644 " + shellLiteral(filepath.Join(outputDir, serveUnit)) + " /etc/systemd/system/" + serveUnit + "\n" +
		"systemctl daemon-reload\n" +
		"systemctl start " + replicateUnit + "\n" +
		"runuser -u " + user + " -- " + shellLiteral(bin) + " -dir " + shellLiteral(dir) + " -mode replica-ready\n" +
		"systemctl enable --now " + timerUnit + " " + serveUnit + "\n" +
		"echo 'Keyless replica ready. Route the independent public HTTP origin to loopback 127.0.0.1:18081, then verify each encoded CDP online.'\n"
	for _, item := range []struct {
		name, body string
		mode       os.FileMode
	}{
		{replicateUnit, replicate, 0o644},
		{timerUnit, timer, 0o644},
		{serveUnit, serve, 0o644},
		{"install-deployment-crl-replica-services.sh", install, 0o755},
	} {
		if err := atomicUnitFile(filepath.Join(outputDir, item.name), []byte(item.body), item.mode); err != nil {
			return err
		}
	}
	return nil
}

func requirePublicOnlyDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("replica directory must be a real directory")
	}
	allowed := map[string]bool{"deployment-crl": true}
	for _, spec := range issuerFiles {
		allowed[spec.cert] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, item := range entries {
		if !allowed[item.Name()] {
			return fmt.Errorf("replica directory contains material other than public CA certificates and signed CRLs")
		}
		path := filepath.Join(dir, item.Name())
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("replica directory contains a linked or unreadable path")
		}
		if item.Name() == "deployment-crl" {
			if !info.IsDir() {
				return fmt.Errorf("replica signed-CRL path is not a directory")
			}
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("replica CA certificate is not a regular file")
		}
	}
	return nil
}

func systemdLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '%':
			b.WriteString("%%")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func shellLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func atomicUnitFile(path string, body []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".dsse-crl-replica-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
