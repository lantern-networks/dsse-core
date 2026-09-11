//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/lantern-networks/dsse-core/enroll"
	"golang.org/x/sys/windows"
)

// enroll_windows.go — `--mode enroll` (roadmap M4c). The agent generates a device keypair + CSR, enrolls with
// the Control Plane (enroll.Run: eligibility → CA-issued cert + CP-authoritative tenant/group + CA-pin check),
// and stores the material. The private key is wrapped with DPAPI at the CURRENT security context (NOT
// LOCAL_MACHINE): the DsseSteer service runs as LocalSystem, so enrollment MUST run in the same SYSTEM context
// (the installer/MDM does), and then ONLY SYSTEM can unwrap the key — a leaked file cannot be unwrapped by an
// ordinary local user (machine scope would let any local user unwrap it). The cert/CA are public. Confidentiality
// is defense-in-depth: this SYSTEM-scoped DPAPI wrap PLUS the installer's SYSTEM/Admin-only directory ACL.

var (
	crypt32                = windows.NewLazyDLL("crypt32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

// defaultEnrollDir is the well-known machine location for enrolled device material — SYSTEM/Admin-only, so the
// LocalSystem DsseSteer service reads it and only SYSTEM can DPAPI-unwrap the key. Both `--mode enroll`
// (--enroll-out default) and `--config-store` startup agree on this path so enrollment and the service line up.
func defaultEnrollDir() string {
	base := os.Getenv("ProgramData")
	if strings.TrimSpace(base) == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "DSSE", "enroll")
}

type dataBlob struct {
	cbData uint32
	pbData *byte
}

// dpapiProtect wraps data with DPAPI at the current user/context scope (dwFlags=0). Run as LocalSystem (the
// service's context) so only SYSTEM can later unwrap it.
func dpapiProtect(data []byte) ([]byte, error) {
	in := dataBlob{cbData: uint32(len(data))}
	if len(data) > 0 {
		in.pbData = &data[0]
	}
	var out dataBlob
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0,
		0, uintptr(unsafe.Pointer(&out))) // dwFlags=0: current-context (SYSTEM) scope, not LOCAL_MACHINE
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %v", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	res := make([]byte, out.cbData)
	copy(res, unsafe.Slice(out.pbData, out.cbData))
	return res, nil
}

// dpapiUnprotect reverses dpapiProtect (CryptUnprotectData, current-context scope). It succeeds only in the same
// security context that wrapped the data — the LocalSystem service, matching the SYSTEM-context enrollment wrap.
func dpapiUnprotect(data []byte) ([]byte, error) {
	in := dataBlob{cbData: uint32(len(data))}
	if len(data) > 0 {
		in.pbData = &data[0]
	}
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0,
		0, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %v", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	res := make([]byte, out.cbData)
	copy(res, unsafe.Slice(out.pbData, out.cbData))
	return res, nil
}

// enrolledMaterial is the device's transport identity read back from the enrolled dir. The key is held only
// in memory (DPAPI-unwrapped) — it is NEVER written back to disk unwrapped.
type enrolledMaterial struct {
	CAPEM   []byte // device-ca.pem — the transport CA to pin (fail-closed)
	CertPEM []byte // device.crt — the device client cert
	KeyPEM  []byte // the unwrapped device private key (in memory only)
	Meta    enrolledMeta
}

// loadEnrollment reads the enrolled material from dir, gated on the enrolled.json completion marker (a partial
// enrollment presents as not-enrolled). Returns ok=false with no error when the box is simply not enrolled yet;
// an error only for a PRESENT-but-broken enrollment (missing cert/CA, or a key that will not unwrap in this
// context). The private key is DPAPI-unwrapped in memory and never re-written to disk.
func loadEnrollment(dir string) (enrolledMaterial, bool, error) {
	metaRaw, err := os.ReadFile(filepath.Join(dir, "enrolled.json"))
	if err != nil {
		return enrolledMaterial{}, false, nil // no completion marker => not enrolled
	}
	var m enrolledMaterial
	_ = json.Unmarshal(metaRaw, &m.Meta)
	if m.CertPEM, err = os.ReadFile(filepath.Join(dir, "device.crt")); err != nil {
		return enrolledMaterial{}, false, fmt.Errorf("enroll: read device.crt: %w", err)
	}
	if m.CAPEM, err = os.ReadFile(filepath.Join(dir, "device-ca.pem")); err != nil {
		return enrolledMaterial{}, false, fmt.Errorf("enroll: read device-ca.pem: %w", err)
	}
	wrapped, err := os.ReadFile(filepath.Join(dir, "device.key.dpapi"))
	if err != nil {
		return enrolledMaterial{}, false, fmt.Errorf("enroll: read device.key.dpapi: %w", err)
	}
	if m.KeyPEM, err = dpapiUnprotect(wrapped); err != nil {
		return enrolledMaterial{}, false, fmt.Errorf("enroll: unwrap device key (must run as the enrolling SYSTEM context): %w", err)
	}
	return m, true, nil
}

// enrolledMeta is the small record persisted alongside the material for the tray/status + reload.
type enrolledMeta struct {
	DeviceID      string `json:"device_id"`
	Tenant        string `json:"tenant"`
	Group         string `json:"group"`
	PolicyVersion int    `json:"policy_version"`
	EnrolledAt    string `json:"enrolled_at"`
}

// storeEnrollment writes the enrollment result under dir: device.key.dpapi (DPAPI-wrapped private key),
// device.crt, device-ca.pem, enrolled.json. Each file is written to a .tmp then atomically renamed, and
// enrolled.json is written LAST as the completion marker — so a partial/failed write never presents as a
// complete enrollment (the reload path treats a missing enrolled.json as not-enrolled). The dir should be
// SYSTEM/Admin-only (installer ACL). NOTE: Go's Unix-style file modes are largely advisory on Windows; the
// real access control is the directory ACL + the SYSTEM-scoped DPAPI wrap.
func storeEnrollment(dir, deviceID string, res enroll.Result) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("enroll: mkdir: %w", err)
	}
	wrapped, err := dpapiProtect(res.KeyPEM)
	if err != nil {
		return fmt.Errorf("enroll: protect key: %w", err)
	}
	meta := enrolledMeta{
		DeviceID: deviceID, Tenant: res.Tenant, Group: res.Group,
		PolicyVersion: res.PolicyVersion, EnrolledAt: time.Now().UTC().Format(time.RFC3339),
	}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	// enrolled.json is written LAST (the completion marker), so ordering matters.
	writes := []struct {
		name string
		data []byte
	}{
		{"device.key.dpapi", wrapped},
		{"device.crt", res.CertPEM},
		{"device-ca.pem", res.CAPEM},
		{"enrolled.json", mb},
	}
	for _, w := range writes {
		final := filepath.Join(dir, w.name)
		tmp := final + ".tmp"
		if err := os.WriteFile(tmp, w.data, 0o600); err != nil {
			return fmt.Errorf("enroll: write %s: %w", w.name, err)
		}
		if err := os.Rename(tmp, final); err != nil { // atomic on the same volume
			_ = os.Remove(tmp)
			return fmt.Errorf("enroll: commit %s: %w", w.name, err)
		}
	}
	return nil
}

// performSelfEnrolment is Day-0 enrolment for the service path: the machine enrols ITSELF on first start from
// the per-machine enrolment config, with no one running an enrol command by hand.
//
// The issued identity is PROVEN on the wire — a real (T) handshake plus a request — BEFORE anything is
// committed. This matters more at enrolment than at renewal: a renewal that installs a bad identity still has
// the old one to fall back on, while an enrolment leaves the completion marker behind — the machine would count
// as previously enrolled on every later start and take over the network path holding a credential that does not
// work. probeIdentity (shared with renewal) reads a response, not just a handshake, because under TLS 1.3 a
// rejected client certificate only surfaces on the first read.
//
// The probe verifies the SERVER with the transport CA the device already pins (transportCAPEM) — NOT the
// enroll-returned CA. The endpoint returns the DEVICE (client) CA, which signs client certificates; the
// transport server certificate chains to a SEPARATE transport CA, so verifying the server against the device CA
// would fail on any real Edge where the two differ (they do in the reference lab). This mirrors macOS exactly:
// the probe reuses the existing transport's pinned CA and swaps only the client certificate to the candidate.
// With no transport CA to prove against, the probe is skipped rather than blocking a deployment that has no (T)
// transport — the cryptographic validation enroll.Run already did (chain to the returned CA, our key, the
// device-CA pin) is then the proof, which is what macOS falls back to as well.
//
// Order: enrol (+validate) → probe → store (enrolled.json last) → erase the spent token. A failure at any step
// leaves the machine exactly as it was: never-enrolled, standing aside, with the cause in the log.
func performSelfEnrolment(cfg enrolmentConfig, cfgPath, transportURL, enrolServerName string, transportCAPEM []byte, outDir string) error {
	// ★★★ A MACHINE ALREADY HAS A NAME, AND THIS PATH STILL DEMANDED ONE (2026-08-29, measured by installing
	// from a package + profile + token on win-dev-1, which is the only way this could be found).
	//
	// runEnroll — the hand-run `--mode enroll` — was given that default on 2026-08-25 for the operator's
	// reason: enrolling should not mean inventing an identifier and then keeping it true everywhere else the
	// organization tracks machines. SELF-enrolment, the path the product actually installs, did not get it. So
	// the installer had to write a device_id into enrolment.json, which makes the installer a second place that
	// decides what a machine is called — and when it did not, the agent refused with "enrolment config needs
	// enrol_url and device_id" and stood aside. Correctly, loudly, and for ever: nothing in the product was
	// ever going to supply that field.
	//
	// The default belongs here rather than in whatever writes the file, because there is more than one writer
	// (the Windows installer, an MDM, a person) and only one machine.
	if strings.TrimSpace(cfg.DeviceID) == "" {
		cfg.DeviceID = defaultDeviceIdentity()
		if cfg.DeviceID != "" {
			fmt.Printf("steer: the enrolment config named no device_id; enrolling as this machine's own name %q\n", cfg.DeviceID)
		}
	}
	if strings.TrimSpace(cfg.EnrolURL) == "" || strings.TrimSpace(cfg.DeviceID) == "" {
		return fmt.Errorf("enrolment config needs enrol_url, and a device_id when this machine's own name could not be read")
	}
	// The same invariant as --mode enroll and as macOS hasPinnedBootstrap: enrolment is the trust bootstrap,
	// so it must not run over an unpinned channel.
	if !cfg.hasPinnedBootstrap() {
		return fmt.Errorf("refusing to enrol over an unpinned transport — the enrolment config must carry enrol_ca_pem or device_ca_pin_sha256")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	if strings.TrimSpace(cfg.EnrolCAPEM) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.EnrolCAPEM)) {
			fmt.Println(describeBootstrapPinning(cfg.EnrolCAPEM, cfg.DeviceCAPinSHA256, enrolServerName,
				fmt.Errorf("no PEM certificate could be added to the pool")).Line())
			return fmt.Errorf("enrol_ca_pem has no usable certificate")
		}
		cfgTLS := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		// ★ THE NAME IS WHAT SELECTS THE ENROLMENT ROUTE, not what labels it. Once the deployment folds its
		// agent-facing port away, the Edge chooses an organization's certificate — and the routes that exist
		// only for that organization — from the SNI, before any certificate is exchanged. A device dialling an
		// address sends the address as its name, and if that address is an IP literal crypto/tls sends no SNI
		// at all, so it is served the deployment's shared configuration and cannot reach enrolment.
		//
		// Set ONLY when the install stated a name (installprofile.OrganizationSpec.EnrolmentServerName). Absent
		// leaves this exactly as it was, which is what every already-deployed device does — and it also means
		// this is verified against a name only when the operator has said the Edge serves that name, which is
		// the rule this deployment has now paid for twice.
		if n := strings.TrimSpace(enrolServerName); n != "" {
			cfgTLS.ServerName = n
		}
		client.Transport = &http.Transport{TLSClientConfig: cfgTLS}
		fmt.Println(describeBootstrapPinning(cfg.EnrolCAPEM, cfg.DeviceCAPinSHA256, cfgTLS.ServerName, nil).Line())
	} else if n := strings.TrimSpace(enrolServerName); n != "" {
		// No pinned enrolment CA means the system store decides, and the organization's own name will not be in
		// a publicly-trusted certificate. Presenting it here would trade a working enrolment for a failing one,
		// so the name is not sent — and the reason is said out loud rather than silently skipped.
		fmt.Printf("steer: the install states enrolment name %q, but this enrolment has no pinned CA "+
			"(enrol_ca_pem), so the name is NOT presented — a system-store verification cannot succeed against "+
			"an organization's private name\n", n)
		fmt.Println(describeBootstrapPinning("", cfg.DeviceCAPinSHA256, "", nil).Line())
	} else {
		fmt.Println(describeBootstrapPinning("", cfg.DeviceCAPinSHA256, "", nil).Line())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := enroll.RunWithMachine(ctx, cfg.EnrolURL, cfg.DeviceID, cfg.Tenant, cfg.DeviceCAPinSHA256,
		enroll.Eligibility{Mode: "token", Token: strings.TrimSpace(cfg.Token)}, machineReference(), client)
	if err != nil {
		// The Edge answers most eligibility refusals with ONE message, whatever the cause — a public endpoint
		// must not be an oracle for a tenant's issuance state. Do not try to derive a more specific cause here.
		//
		// ★ THE EXCEPTIONS ARE THE ONES WHOEVER IS AT THE MACHINE CAN ACT ON (2026-08-25): this name is already
		// enrolled by this same machine (renew), by a DIFFERENT machine (rename this one), or this machine is
		// already enrolled under another name. The Edge sends those through as written, so print what it said
		// rather than a sentence of our own — the one-time token is spent by now, and a person is standing here.
		return err
	}
	// Prove the issued identity on the (T) transport before committing — verifying the SERVER with the pinned
	// transport CA, presenting the freshly issued identity as the client. Skipped when there is no transport CA
	// to prove against, exactly as macOS skips when there is no transport contract.
	if len(transportCAPEM) > 0 && strings.TrimSpace(transportURL) != "" {
		candidate, err := tls.X509KeyPair(res.CertPEM, res.KeyPEM)
		if err != nil {
			return fmt.Errorf("the issued identity does not load back: %w", err)
		}
		probeTC, err := buildTransportConfigFromPEM(transportURL, transportCAPEM, nil, nil)
		if err != nil {
			return fmt.Errorf("build the probe transport: %w", err)
		}
		if err := probeIdentity(&probeTC, &candidate); err != nil {
			return fmt.Errorf("the issued identity could not complete a (T) request, so nothing was committed: %w", err)
		}
	} else {
		fmt.Println("steer: no transport CA to prove the issued identity against — committing on the cryptographic validation alone (chain, key, device-CA pin)")
	}
	if err := storeEnrollment(outDir, cfg.DeviceID, res); err != nil {
		return err
	}
	if err := markEnrolmentTokenSpent(cfgPath); err != nil {
		// The enrolment itself succeeded and the token is already dead on the server; a config that could not
		// be rewritten is worth a loud line, not a rollback.
		fmt.Printf("steer: enrolment succeeded but the spent token could not be erased from %s (%v)\n", cfgPath, err)
	}
	fmt.Printf("steer: self-enrolled device=%q tenant=%q group=%q\n", cfg.DeviceID, res.Tenant, res.Group)
	return nil
}

// runEnroll performs `--mode enroll`. It builds the enroll HTTP client (optionally trusting a supplied CP CA),
// runs the enrollment, and stores the result. Failure returns an error and stores nothing (stays Unenrolled).
func runEnroll(url, deviceID, tenant, mode, token, caPin, caFile, outDir string) error {
	// ★ A MACHINE ALREADY HAS A NAME (2026-08-25, the operator's point). --device-id was required, so
	// enrolling meant inventing an identifier and then keeping it true everywhere else the organization
	// tracks machines. See device_identity_default_windows.go.
	if strings.TrimSpace(deviceID) == "" {
		deviceID = defaultDeviceIdentity()
		if deviceID != "" {
			fmt.Printf("steer: --device-id was not given; enrolling as this machine's own name %q\n", deviceID)
		}
	}
	if url == "" || deviceID == "" || outDir == "" {
		return fmt.Errorf("enroll: --enroll-url and --enroll-out are required, and --device-id is required " +
			"only when this machine's own name could not be read")
	}
	// Pin-or-pinned-transport invariant (fail-open review #29): enrollment is the trust BOOTSTRAP, so it must not
	// run over an unpinned channel. With neither a CA pin (--enroll-ca-pin, cross-checked against the returned CA)
	// NOR a trusted enroll CA (--enroll-ca), the client would fall back to the system root store — a MITM of the
	// enroll endpoint could then impersonate the control plane. Require at least one; fail closed with a clear
	// error rather than silently enrolling over unpinned TLS. (Production pins the transport; lab passes --enroll-ca.)
	if strings.TrimSpace(caPin) == "" && strings.TrimSpace(caFile) == "" {
		return fmt.Errorf("enroll: refusing to enroll over an unpinned transport — provide --enroll-ca-pin (SHA-256 of the device CA) or --enroll-ca (trusted enroll CA PEM)")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	caPEM := ""
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("enroll: read --enroll-ca: %w", err)
		}
		caPEM = string(pemBytes)
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			fmt.Println(describeBootstrapPinning(caPEM, caPin, "",
				fmt.Errorf("no PEM certificate could be added to the pool")).Line())
			return fmt.Errorf("enroll: --enroll-ca has no certificates")
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	// The same sentence the self-enrolment path prints, so two machines configured differently can be compared
	// by reading one line on each.
	fmt.Println(describeBootstrapPinning(caPEM, caPin, "", nil).Line())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := enroll.RunWithMachine(ctx, url, deviceID, tenant, caPin,
		enroll.Eligibility{Mode: mode, Token: token}, machineReference(), client)
	if err != nil {
		return err
	}
	if err := storeEnrollment(outDir, deviceID, res); err != nil {
		return err
	}
	fmt.Printf("enroll: enrolled device=%q tenant=%q group=%q policy_version=%d -> %s\n",
		deviceID, res.Tenant, res.Group, res.PolicyVersion, outDir)
	return nil
}
