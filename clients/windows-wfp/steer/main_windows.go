//go:build windows

// windivert-steer — Windows transparent steering agent (W1 slice, W2 capture-layer seam). Captures one
// outbound TCP destination, terminates it locally, recovers the original destination, and steers the
// flow to the Edge via CONNECT /apps/{app} so existing Edge policy (allow/deny, east-west)
// applies to Windows traffic. See.
//
// Layering (W2): main() wires a SteeringCapture (capture.go interface; winDivertCapture in
// capture_windivert.go is today's backend) to the edge-steering layer (steer_edge.go), which depends
// ONLY on the interface. Swapping WinDivert for Wintun/WFP touches only capture_windivert.go. Pure
// packet logic stays in steer_core.go. Modes:
//   - observe:  WinDivert NETWORK-layer sniff of the target flow (no rewrite) — capture validation.
//   - redirect: capture -> terminate -> recover orig dst -> steer to edge.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/agentstatus"
	"github.com/lantern-networks/dsse-core/agenttuning"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/configstore"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/updateplatform"
	"github.com/lantern-networks/dsse-core/installprofile"
	"github.com/lantern-networks/dsse-core/regionfailover"
)

// trustAnchorPin is the L1 install-profile trust anchor baked in at build time:
// -ldflags "-X main.trustAnchorPin=<64-hex>". The service (--config-store) verifies the stored envelope against
// THIS anchor, never a value from the mutable store (review S1). Empty in dev builds → no profile verifies →
// SafeDefaults (fail-closed). --config-pin overrides for dev/lab.
var trustAnchorPin string

func main() {
	mode := flag.String("mode", "observe", "observe (sniff target flow) | redirect (steer to edge) | inbound ( server-initiated enforce) | heartbeat (W-2 device agent-liveness over (T) mTLS) | watchdog (W-5 restart the WFP driver if stopped) | bypass-observe (list tcp ports -> pid/image and which apps are bypassed) | recover (panic button: undo DNS/QUIC/WFP-redirect after an unclean exit so the network comes back)")
	targetIP := flag.String("target-ip", "", "single destination IPv4 to steer (required)")
	targetPort := flag.Int("target-port", 0, "single destination TCP port to steer (required)")
	localPort := flag.Int("local-port", 18099, "127.0.0.1 terminator port redirected flows are sent to")
	edgeURL := flag.String("edge-url", "http://127.0.0.1:18090", "edge base URL")
	applicationID := flag.String("application-id", "", "edge application id for CONNECT /apps/{id} (required for redirect)")
	connectorID := flag.String("connector-id", "conn_lab_001", "edge connector id")
	sessionID := flag.String("session-id", "", "session id forwarded to edge")
	maxFlows := flag.Int("max-flows", 5, "stop after steering this many flows (redirect mode)")
	timeout := flag.Duration("timeout", 2*time.Minute, "maximum run duration")
	omitAuthority := flag.Bool("omit-connect-authority", false, "omit x-dsse-connect-authority so the edge falls back to the request host (rarely what you want for a routed app)")
	connectAuthority := flag.String("connect-authority", "", "explicit host:port to send as x-dsse-connect-authority instead of the recovered orig dst; set this to the app route destination (e.g. dummy-ssh.local:22) for FQDN-routed apps")
	steerGeneric := flag.Bool("steer-generic", false, "W3: route to CONNECT /steer (generic policy judgment on the recovered orig dst) instead of /apps/{app}; no --application-id / --connect-authority needed")
	steerMux := flag.Bool("steer-mux", true, "carry ALL flows over a multiplexed transport (CONNECT /steer-mux) — the ONLY supported steer transport (the per-flow CONNECT /steer tunnel was removed from the Edge 2026-07-13; both this agent and the macOS NE use the mux). Collapses the Edge's per-flow FD/handshake cost to per-device (the scaling lever for many devices). Same Edge policy/interception; East-West \"authenticate\" now mediates a browser step-up over the mux too (STEPUP frame, mirrors the NE). Default true; setting =false has no Edge to fall back to. Pool sizing: --steer-mux-flows-per-conn / --steer-mux-max-conns.")
	steerMuxFlowsPerConn := flag.Int("steer-mux-flows-per-conn", 12, "adaptive mux pool: target concurrent flows per connection. Pool grows to desired=clamp(1+activeFlows/this,1,--steer-mux-max-conns) so light load uses 1 conn (Edge-friendly) and busy periods spread over several (independent TCP cwnd / no cross-flow TCP head-of-line blocking / multi-core crypto). Idle surplus conns are closed automatically.")
	steerMuxMaxConns := flag.Int("steer-mux-max-conns", 12, "adaptive mux pool: hard cap on concurrent mux connections per device. 1 == the single-connection behaviour.")
	bypassApps := flag.String("bypass-app", "automation", "comma-separated app identifiers never to steer; the agent always also bypasses itself. Forms (strongest first): thumbprint:<sha256> (exact leaf signing cert), subject:<O> (exact signer Organization — the macOS-Team-ID analog), publisher:<name> (signer display-name substring), signed:<exe> (valid signature + basename), or a bare image-PATH substring (legacy, spoofable). Signature forms are enforced on the windivert backend now and on the WFP kernel backend once verified-APP_ID push lands; on the WFP backend an unenforceable form stays steered (fail-closed).")
	bypassDests := flag.String("bypass-dest", "", "comma-separated destinations never to steer (race-free); the edge endpoint is auto-added, and DNS:53 + loopback are always excluded. Each entry is host:port, OR a bare host/IP (no port) to bypass ALL ports to that destination -- e.g. a domain controller 10.10.0.10 whose dynamic RPC uses ephemeral ports")
	steerAll := flag.Bool("steer-all", false, "capture ALL outbound TCP (minus loopback/DNS/edge/AppID exclusions) instead of a single --target; recovers each flow's original destination. Requires --steer-generic.")
	permanent := flag.Bool("permanent", false, "durable operation: run the capture under a supervisor that recreates the backend after a terminal failure (driver reload, handle death) instead of exiting. Pair with --timeout 0 to disable the self-terminate. All safety bypasses are re-applied on each restart.")
	backend := flag.String("backend", "windivert", "capture backend: windivert (reference; WFP callout driver shipped by WinDivert) | wfp (production; our own ALE connect-redirect callout driver -- requires the driver installed/loaded)")
	// (T) secure transport (): steer<->Edge tunnel over pinned mTLS instead of plaintext --edge-url.
	edgeTransportURL := flag.String("edge-transport-url", "", "(T) secure transport: Edge TLS tunnel URL e.g. https://host:18543 (empty = legacy plaintext --edge-url)")
	transportPinnedCA := flag.String("transport-pinned-ca", "", "PEM of the Edge transport CA to pin fail-closed (required with --edge-transport-url; separate from the (I) interception CA)")
	transportClientCert := flag.String("transport-client-cert", "", "device client cert PEM for mTLS device identity")
	// Where to renew from when this device's certificate has ALREADY expired — after a long shutdown, the (T)
	// transport refuses the handshake, so renewal has to go somewhere that accepts an expired certificate.
	// host:port of the Edge's recovery listener. Empty = no self-recovery; an expired device needs re-enrolment.
	enrollRenewRecoveryURL := flag.String("enroll-renew-recovery-url", "", "host:port of the Edge renewal RECOVERY listener, used only when this device's certificate has already expired (empty = no self-recovery after a long shutdown)")
	transportClientKey := flag.String("transport-client-key", "", "device client key PEM for mTLS device identity")
	dnsListen := flag.String("dns-listen", "", " DNS steering: run a local DNS proxy on this addr (e.g. 127.0.0.1:53) that forwards queries to the Edge /steer/dns-query over the (T) tunnel; point the system resolver here so DNS rides the tunnel")
	dnsReconcile := flag.Duration("dns-reconcile-interval", 15*time.Second, "--dns-listen: re-apply the DNS takeover to the current default-route interface this often, so DNS follows a network switch (Wi-Fi<->wired) instead of leaving the new link un-steered. 0 disables (one-shot takeover only).")
	answerNCSI := flag.Bool("answer-ncsi", true, "answer the Windows NCSI connectivity probes (dns.msftncsi.com + msftconnecttest connecttest.txt) LOCALLY so the OS reliably shows 'Internet' under steer-all (the probes otherwise funnel through the tunnel and time out -> a confusing 'No Internet' label). Microsoft's fixed probe values; leaks nothing.")
	dnsPublicFallback := flag.String("dns-public-fallback", "", "--fail-open DNS: OPTIONAL comma-separated public resolvers (e.g. 8.8.8.8,1.1.1.1) appended as a network-independent LAST RESORT for a Wi-Fi roam where the captured pre-steer upstream is unreachable. EMPTY by default: the fail-open path uses only the captured PRE-STEER upstream, so DNS is never silently raced to an undisclosed third party (restore-to-pre-steer). Set explicitly to opt into a public last resort.")
	ncsiSuppressProbe := flag.Bool("ncsi-suppress-probe", true, "steer-all: disable Windows' NCSI active connectivity TEST (the NoActiveProbe policy) for the steered lifetime and restore it on clean stop. Even with --answer-ncsi returning byte-correct probe values, under steer-all the active probe is genuinely intercepted by the local redirect, so NCSI's anti-hijack heuristic flags it (SuspectDnsProbeFailed) and mislabels the link 'No Internet' though traffic flows -- the active test is structurally unsatisfiable. Disabling it lets the passive detector + IPv6 aggregate drive the OS connectivity label truthfully. Snapshotted + restored like the DNS takeover (and undone by --mode recover).")
	//  inbound (server-initiated) -- only active with --mode inbound; shares nothing with outbound steering.
	inboundBackend := flag.String("inbound-backend", "firewall", " --mode inbound: firewall (standard Windows Defender Firewall rules, visible in wf.msc) | wfp (custom WFP callout driver)")
	inboundEnforce := flag.Bool("inbound-enforce", false, " --mode inbound: enforce (default-deny unmatched server-initiated inbound). False = observe-only (S3a: record + permit). wfp backend only — the firewall backend always enforces")
	inboundExportFile := flag.String("inbound-export-file", "", " --mode inbound: path to a server_initiated_export.v1 JSON (Legacy Exceptions); takes precedence over --inbound-export-url")
	inboundExportURL := flag.String("inbound-export-url", "", " --mode inbound: Edge admin export URL (.../admin/legacy-exceptions/export); rides the (T) tunnel when --edge-transport-url is set")
	inboundDeviceGroup := flag.String("device-group", "", " --mode inbound: this endpoint's device group (filters which export rules apply)")
	adminToken := flag.String("admin-token", "", " --mode inbound: bearer token for the Edge admin export endpoint")
	inboundPoll := flag.Duration("inbound-poll", 5*time.Second, " --mode inbound: export refresh + observation drain interval")
	// W-2 agent liveness -- rides the (T) mTLS tunnel for device identity. Active BOTH as the standalone
	// `--mode heartbeat` (liveness-only) and as a background loop alongside `--mode redirect` steering.
	deviceID := flag.String("device-id", "", "W-2 liveness: device identity to register/heartbeat. Empty in redirect mode falls back to the (T) client cert CN")
	deviceTenant := flag.String("device-tenant", "", "W-2 liveness: tenant the device belongs to (only needed to SELF-REGISTER a device the Edge does not know yet)")
	heartbeatInterval := flag.Duration("heartbeat-interval", 15*time.Second, "W-2 liveness: heartbeat period (keep below the Edge soft-dark threshold to stay alive)")
	watchdogInterval := flag.Duration("watchdog-interval", 3*time.Second, "W-5 --mode watchdog: driver-service poll period (restart-on-stop)")

	// Admin-managed, server-signed steer exclusions (the Windows analog of the macOS NE signed-policy
	// feature): pull the Edge's Ed25519-signed exclusion set over the (T) transport, verify against the
	// pinned key, merge additively over --bypass-app, and apply live. Empty pin = feature off.
	// ★ IT ACCEPTS ECDSA-P256 TOO, AND SAYING OTHERWISE NEARLY STOPPED A DEPLOYMENT (2026-08-12). The verifier takes either a 32-byte Ed25519 key or a 65-byte uncompressed ECDSA-P256 point, both
	// lower-case hex — agentpolicy.AcceptedPublicKeyHex is the one place that decides. The Edge's agent-policy
	// key is ECDSA when it signs through the HSM agent, which is the reference deployment, so a help string
	// naming only Ed25519 tells an operator holding the right value that it is the wrong kind.
	agentPolicyPin := flag.String("agent-policy-pin", "", "signed steer-exclusions and signed trust bundles: pinned signing public key, lower-case hex — either Ed25519 (64 hex chars) or an uncompressed ECDSA-P256 point (130 hex chars, starts 04). The Edge prints it at startup as `agent-policy signing ENABLED … public_key=…`. Empty = off")
	agentPolicyURL := flag.String("agent-policy-url", "", "signed steer-exclusions: Edge base URL (default: the (T) transport base https://<transport-host>)")
	agentPolicyRefresh := flag.Duration("agent-policy-refresh", 60*time.Second, "signed steer-exclusions: policy refresh interval")
	trustBundleURL := flag.String("trust-bundle-url", "", "anchor self-healing: base URL of the Edge's unauthenticated signed trust-bundle endpoint (default: the transport door — the agent-facing surface is ONE port). Verified against --agent-policy-pin; empty pin = self-healing off")

	// The update-manifest courier: fetch the signed update envelope over the (T) transport and drop it where
	// DsseUpdater reads it. The agent carries it because the updater deliberately holds no network identity —
	// it verifies the envelope against its OWN baked keys, so the courier never needs to be trusted.
	//
	// Default ON. It is quiet where it is not wanted: an Edge with no manifest for this device answers 404,
	// which this loop treats as the normal state and does not log, so a fleet with no updater installed and an
	// Edge without the endpoint sees one request per interval and no output. Defaulting it off would instead
	// mean the update path silently does nothing on every device that was not given an extra flag, which is the
	// failure shape this tree keeps closing.
	updateManifestCourier := flag.Bool("update-manifest-courier", true, "fetch the signed agent-update manifest over the (T) transport and write it where the updater reads it. The envelope is NOT opened here; DsseUpdater verifies it against its own keys")
	updateManifestRefresh := flag.Duration("update-manifest-refresh", 15*time.Minute, "update-manifest courier: how often to check for a published manifest")

	// Windows steer-all default posture: block QUIC so browsers fall back to the intercepted TCP path
	// immediately instead of stalling on a non-steered UDP:443 HTTP/3 attempt (no QUIC escape either way).
	blockQUIC := flag.Bool("block-quic", false, "steer-all: block outbound UDP:443 (QUIC) via a Windows Firewall rule so browsers use intercepted TCP without the h3-fallback stall (recommended default for Windows steer-all). Removed on clean exit.")

	// Fail-open posture (install-time): when the Edge/(T) tunnel is UNREACHABLE, keep the box working instead of
	// going fully dark — DNS forwards to the captured upstream resolver and TCP flows connect direct (UNMEDIATED:
	// no interception/policy) for the outage window. A reachable Edge that DENIES is still fail-closed. This is
	// the availability-over-security tradeoff for the period while the Edge/driver are still stabilizing; flip it
	// back off (default) to restore strict fail-closed once stable. Logged loudly whenever a flow goes direct.
	failOpen := flag.Bool("fail-open", false, "posture: when this deployment cannot MEDIATE for this device, forward DNS upstream + connect TCP direct (UNMEDIATED) instead of failing closed. Default false = strict fail-closed.\n"+
		"    \"Cannot mediate\" is the tunnel not being established — unreachable, refused, blocked, revoked, an expired certificate: they arrive the same way and are not told apart.\n"+
		"    A LIVE tunnel whose individual flows are denied stays enforced: mediation is working there, so policy decides.\n"+
		"    ★ If you want a blocked device to stop working, that is fail-CLOSED. This exists so a device is not cut off BECAUSE it is being steered.")
	failOpenCooldown := flag.Duration("fail-open-cooldown", 10*time.Second, "--fail-open: after 3 consecutive Edge transport failures, skip the Edge (go direct) for this long before re-probing")
	failOpenProbe := flag.Duration("fail-open-probe-interval", 5*time.Second, "--fail-open: while failed-open, actively probe the Edge ((T) mTLS dial) this often; the first success re-arms steer-all automatically")
	failOpenDisarmAfter := flag.Duration("fail-open-disarm-after", 20*time.Second, "--fail-open: if the Edge stays unreachable this long (e.g. an interface went down and the OS hasn't failed over), self-DISARM — restore DNS, stop the WFP redirect, unblock QUIC — so the box uses its NATIVE network; re-arm automatically on recovery. 0 disables disarm (per-flow fail-open only).")
	ackFailOpen := flag.Bool("acknowledge-fail-open", false, "acknowledge the stabilization-only fail-open posture. REQUIRED to enable --fail-open, which disables zero-trust enforcement on an Edge outage. Without it the agent refuses --fail-open, so production is structurally fail-closed.")

	// Captive-portal bootstrap. ALWAYS ON — there is no enable flag; the trigger discipline (disarm to the native
	// network ONLY on netchange + Edge-unreachable + captive POSITIVELY detected) makes it safe as a standard
	// behavior. These two are TUNING only (per-tenant configurable later via signed policy / Admin Console); the
	// defaults are the product defaults.
	captiveTimeout := flag.Duration("captive-timeout", 180*time.Second, "captive-portal bootstrap TUNING: T_max — the bounded window during which steering is disarmed to the native network so the OS captive sign-in can complete. On timeout with the Edge still unreachable, re-arm fail-closed (DARK). The feature itself is always on.")
	captiveProbeInterval := flag.Duration("captive-probe-interval", 3*time.Second, "captive-portal bootstrap TUNING: how often to re-probe the Edge during the window; the first success re-arms steer-all immediately.")

	// L1 signed install profile (roadmap M0/M1): instead of passing posture knobs as loose flags, the agent can
	// read them from a CP/tenant-SIGNED profile. When --config-profile is set, the profile is verified against
	// --config-pin and OVERRIDES the posture flags below; a missing/invalid/unsigned profile forces SAFE
	// fail-closed defaults (never the operator's flags). Unset = the legacy flag behaviour is unchanged
	// (backward compatible).
	configProfile := flag.String("config-profile", "", "path to a SIGNED install-profile envelope JSON (L1 seed). When set, it drives posture (fail-open/backend/bypass/dns/quic/captive) instead of the individual flags; verified against --config-pin, else SAFE fail-closed.")
	configPin := flag.String("config-pin", "", "--config-profile: pinned Ed25519 public key (hex) the install profile is verified against.")

	// Read-only agent status for the tray (roadmap M2b): opt-in loopback endpoint the dsse-tray UI reads. Exposes
	// only tenant/region/protection state (no secrets). Empty = off (running services unaffected).
	statusListen := flag.String("status-listen", "", "read-only loopback status endpoint for the tray (e.g. 127.0.0.1:18011). Serves GET /status (protection/tenant/region/posture). Empty = off.")

	// Enrollment (roadmap M4c, --mode enroll): establish device identity with the CP. Generates a keypair+CSR,
	// enrolls (CP issues the device cert + assigns tenant/group), and stores the material (key DPAPI-wrapped).
	enrollURL := flag.String("enroll-url", "", "--mode enroll: CP enrollment endpoint URL (POST)")
	enrollMode := flag.String("enroll-mode", "token", "--mode enroll: eligibility mode: mdm | token | interactive")
	enrollToken := flag.String("enroll-token", "", "--mode enroll: eligibility token (for --enroll-mode token)")
	enrollCAPin := flag.String("enroll-ca-pin", "", "--mode enroll: SHA-256 of the expected device CA (from the signed install profile). Empty requires a pinned enroll transport.")
	enrollCA := flag.String("enroll-ca", "", "--mode enroll: PEM CA to trust for the enroll endpoint's TLS (lab; production pins the transport)")
	enrollOut := flag.String("enroll-out", "", "--mode enroll: directory to write device.key.dpapi/device.crt/device-ca.pem/enrolled.json")

	// Client-side region failover (multi-region): instead of a single Edge, the agent is handed its tenant's
	// residency-filtered ALLOWED-region endpoints (signed, same Ed25519 key as --agent-policy-pin), probes them,
	// steers through the nearest healthy region, fails over to another LISTED region when the current degrades, and
	// FAILS CLOSED (denies — never bypasses, never crosses the boundary) when none are healthy. Engine + invariants
	// live in github.com/lantern-networks/dsse-core/regionfailover; this agent only does the I/O. Empty = off.
	regionFailoverOn := flag.Bool("region-failover", false, "multi-region: select+fail over across the tenant's signed allowed-region Edge endpoints (nearest-healthy, in-boundary failover, fail-closed). Requires the (T) transport + --agent-policy-pin; mutually exclusive with --fail-open.")
	regionHome := flag.String("region-home", "", "region-failover: this device's HOME region id (tiebreak/preferred anchor). Defaults to the seed/list's first region.")
	regionSeed := flag.String("region-endpoints-seed", "", "region-failover: MDM bootstrap allowed-region list 'region=URL;region=URL' used until the signed list is fetched (the --edge-transport-url is auto-added as the home seed if absent).")
	regionHealthInterval := flag.Duration("region-health-interval", 5*time.Second, "region-failover: how often to re-probe the allowed regions and re-evaluate the selection")
	regionListRefresh := flag.Duration("region-list-refresh", 5*time.Minute, "region-failover: how often to re-fetch the signed allowed-region list (residency changes take effect on refresh)")
	regionUnhealthyStrikes := flag.Int("region-unhealthy-strikes", 3, "region-failover: tolerate the current region being unhealthy for this many consecutive probe rounds before failing over (hysteresis / flap avoidance)")
	// The operator's PREFERENCE among the regions the Edge allowed. In production this comes from the SIGNED L1
	// install profile's region_priority (see below, where the profile overrides this flag) — the same one
	// install-time configuration channel as posture, backend, bypass, DNS and the transport URL. This flag is
	// the bootstrap/dev form, for a hand-configured box that has no profile.
	regionPriorityRaw := flag.String("region-priority", "", "region-failover: the operator's preference among the regions the Edge allows, 'region=N,region=N' (LOWER IS PREFERRED, 1 is highest). Outranks measured latency; RTT then decides only WITHIN one rank. A region not named here is UNSPECIFIED and ranks last; a region named here that the Edge did not serve is inert (this can never add a region). PRODUCTION SETS THIS IN THE SIGNED PROFILE (region_priority), which overrides this flag; this is the bootstrap form for a box with no profile. Empty = unset, every region ties and nearest-RTT decides as before.")

	// Agent-mediated step-up: on an "authenticate" 401 carrying X-Dsse-Stepup-Url for a steered native
	// (SMB/RDP/WinRM) flow, surface a prompt + open the Edge-issued portal in the default browser. The flow
	// stays denied (fail-closed); completing the step-up mints a device grant so the user's retry is allowed.
	stepUpPortal := flag.Bool("stepup-portal", true, "agent-mediated step-up: on a 401 + X-Dsse-Stepup-Url for a steered native (SMB/RDP/WinRM) flow, show a prompt and open the Edge-issued step-up portal in the default browser (coalesced per resource). False = deny silently (no prompt).")
	stepUpCoalesce := flag.Duration("stepup-coalesce", 30*time.Second, "agent-mediated step-up: suppress re-opening the portal for the same resource within this window (a burst of blocked flows to one resource opens the portal once)")

	// Windows service: install/run the steer-all agent as an SCM-managed service (auto-start, recovery).
	serviceInstall := flag.Bool("service-install", false, "install the steer-all agent as a Windows service (DsseSteer); bakes the remaining flags as the service args. Run elevated.")
	serviceUninstall := flag.Bool("service-uninstall", false, "stop + remove the DsseSteer Windows service. Run elevated.")
	serviceRun := flag.Bool("service-run", false, "internal: entry point used by the SCM to run the service (set automatically by --service-install). Do not run by hand.")
	configStore := flag.Bool("config-store", false, "read the signed L1 install profile from the Windows config store (HKLM\\SOFTWARE\\DSSE\\Agent) instead of --config-profile <path>. The MSI-installed service uses this; the profile is verified against the baked-in trust anchor (or --config-pin).")

	// Network panic button: --mode recover undoes everything that an unclean agent exit (force-kill / crash /
	// WFP driver fault) leaves behind — DNS pointed at the dead loopback proxy, the QUIC firewall block, and the
	// WFP redirect filters — so the box gets its network back in one elevated command instead of three manual ones.
	recoverKeepServices := flag.Bool("recover-keep-services", false, "--mode recover: restore the network but leave DsseSteer/DsseWfp installed (they re-take-over on next start). Default stops both so nothing re-applies.")

	// --version answers the INSTALLER's question: what version does the binary I have just laid down install?
	// It is deliberately not the updater's source of truth — running the on-disk binary reports the ON-DISK
	// version, which is right on every healthy box and wrong on exactly the box the distinction exists for (new
	// bytes on disk, old code in memory). The updater reads the value the LIVE process recorded; see runstate.
	//
	// The reason both come from agentVersion() is that the installer stashes rollback material under this string
	// and the updater later looks material up by the string the running agent reported. Two literals in a .wxs
	// and a .go file could drift and would produce ErrNoMaterial on every box forever, which presents exactly
	// like "nobody implemented stashing" while all the code is there and running.
	showVersion := flag.Bool("version", false, "print this binary's agent version (the string the installer keys rollback material on) and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(agentVersion())
		return
	}

	// Under the SCM (no console), redirect stdout/stderr to the log file as EARLY as possible — before the
	// fail-open production guard / banner and every other startup line — so nothing (especially the loud
	// fail-open posture banner) is lost to a non-existent console.
	if *serviceRun {
		if p := redirectServiceLogs(); p != "" {
			fmt.Printf("steer: logging to %s\n", p)
		}
	}

	// Windows service install/uninstall (meta-operations; do not start steering here).
	if *serviceInstall {
		exe, eerr := os.Executable()
		if eerr != nil {
			fmt.Fprintf(os.Stderr, "service-install: %v\n", eerr)
			os.Exit(1)
		}
		if err := installService(exe, argsWithoutFlag(os.Args[1:], "service-install")); err != nil {
			fmt.Fprintf(os.Stderr, "service-install: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("installed Windows service %q (start: sc start %s ; stop: sc stop %s ; remove: --service-uninstall)\n", serviceName, serviceName, serviceName)
		return
	}
	if *serviceUninstall {
		if err := uninstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "service-uninstall: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("uninstalled Windows service %q\n", serviceName)
		return
	}

	// Network recovery (panic button) — runs before any transport/target validation since it needs none and
	// must work on a box whose network is currently broken.
	if *mode == "recover" || *mode == "recovery" {
		if err := runRecover(*recoverKeepServices); err != nil {
			fmt.Fprintf(os.Stderr, "recover: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Enrollment (roadmap M4c): establish device identity with the CP, store the material, and exit. Needs no
	// steering, so it runs here before the transport/steer setup.
	if *mode == "enroll" {
		outDir := strings.TrimSpace(*enrollOut)
		if outDir == "" {
			outDir = defaultEnrollDir() // write where the --config-store service reads it
		}
		if err := runEnroll(*enrollURL, *deviceID, *deviceTenant, *enrollMode, *enrollToken, *enrollCAPin, *enrollCA, outDir); err != nil {
			fmt.Fprintf(os.Stderr, "enroll: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Identity captured from a verified install profile, surfaced in the tray status (M2b). Empty when no profile.
	var profTenant, profGroup string
	// The signed profile's region preference, applied further down (region failover is configured well after
	// this block). Nil when there is no profile, which is what lets the --region-priority flag stand on a
	// hand-configured box.
	var profileRegionPriority map[string]int
	// The organization's decision about virtual machines on this device. Blocked until a profile says
	// otherwise — including when there is no profile at all, which is the read-only/lab shape.
	profileVMEgress := vmEgressFromProfile("", false)
	// profilePassthrough are the deployment-authored names that bypass steering entirely (its own Console).
	var profilePassthrough []string
	var profileOrganization installprofile.OrganizationSpec
	// authoredBypass are the never-steer identifiers the signed profile carries, kept as a LIST so a comma
	// inside one of them survives (mergeIdentifiers). Empty when no profile named any.
	var authoredBypass []string
	// profileAnchorFingerprints are the authorities the CURRENT signed profile names. They are kept so the
	// startup path can say whether an ADOPTED distribution still covers the doors this profile tells the device
	// to knock on — the condition that, when it silently did not hold, left this box carrying another
	// organization's authority while reporting that it had adopted one.
	var profileAnchorFingerprints []string

	// L1 signed install profile (M1): when --config-profile is set, the SIGNED profile drives the posture knobs
	// instead of the loose flags. Placed AFTER recover (so the panic button never depends on a profile) and
	// BEFORE the fail-open guard (so the profile-derived posture is what gets validated). A verified profile is
	// authoritative; a missing/invalid/unsigned one forces SAFE fail-closed values — you opted into profile mode,
	// so we never fall back to the operator's flags for security-relevant knobs.
	if *configStore || strings.TrimSpace(*configProfile) != "" {
		// What the PACKAGE baked into the service arguments, captured before the profile overwrites the flag
		// vars. See the merge below — this is the only copy of it after that point.
		packagedBypassDests := strings.TrimSpace(*bypassDests)
		var prof installprofile.InstallProfile
		var verified bool
		var source string
		var lerr error
		pin := ""
		var profileEnvelope []byte
		if *configStore {
			// M8.3b-2: the MSI-installed service reads the profile from the config store and verifies it against
			// the BAKED anchor (never a store value — review S1). --config-pin overrides for dev/lab.
			source = "config-store"
			pin = trustAnchorPin
			if strings.TrimSpace(*configPin) != "" {
				pin = strings.TrimSpace(*configPin)
			}
			if be, berr := configstore.ProductionRegistryBackend(); berr == nil {
				if env, ok := configstore.StoredEnvelope(be); ok {
					profileEnvelope = env
				}
				var meta configstore.Meta
				prof, meta, lerr = configstore.Load(be, pin) // tamper/wrong-key/absent => resolved SafeDefaults
				verified = meta.Verified
			} else {
				prof, verified, lerr = installprofile.Load(nil, "") // no store => safe defaults
			}
		} else {
			source = "config-profile"
			pin = strings.TrimSpace(*configPin)
			raw, _ := os.ReadFile(strings.TrimSpace(*configProfile)) // read error => raw nil => Load returns safe defaults
			profileEnvelope = raw
			prof, verified, lerr = installprofile.Load(raw, pin)
		}
		if verified {
			profTenant, profGroup = prof.TenantID, prof.GroupID
			fmt.Printf("steer: install profile applied (VERIFIED) source=%s tenant=%q group=%q posture=%s backend=%s transport=%q — overriding posture flags\n",
				source, prof.TenantID, prof.GroupID, prof.Posture, prof.Backend, prof.TransportURL)
		} else {
			// ★ "ABSENT" WAS THE WRONG WORD FOR THE COMMON CASE (2026-08-13). A generic
			// package — one built without -Pin — has NO L1 anchor baked in, so a profile that is present,
			// intact and correctly signed reports as invalid with a nil error. `<nil>` is the tell: there is
			// no error because there is no key. An operator upgrading a provisioned box then sees "profile
			// absent" about a profile they can open and read, and goes looking in the wrong place.
			//
			// The device knows both halves of the comparison: the envelope says which key SIGNED it, and this
			// binary knows what it was BUILT to trust. Neither is evidence of anything — a signature is what
			// decides — but as a diagnosis for a human they are exactly the pair that names the mistake.
			signedBy := configstore.SigningKeyIDOf(profileEnvelope)
			haveEnvelope := signedBy != ""
			switch {
			// ★ THE KEY ID IS WHAT THE ENVELOPE CLAIMS, NOT WHAT WAS PROVEN (2026-08-13). configstore.Load
			// discards WHY verification failed — a corrupt signature, a wrong kind and a wrong key all arrive
			// here the same way — so saying "signed by X" would state an unverified annotation as fact, in a
			// message an operator is about to act on. It says what the envelope claims and that verification
			// failed, which is the whole of what is known.
			case lerr == nil && strings.TrimSpace(pin) == "" && haveEnvelope:
				fmt.Printf("steer: install profile PRESENT, and this build has NO trust anchor pinned to verify "+
					"it against — it was built without -Pin, so it cannot verify ANY profile. The envelope "+
					"CLAIMS to be signed by %q (unverified: nothing here checked it). Forcing SAFE fail-closed "+
					"defaults. Install a package built with -Pin <the public half of that key>.\n", signedBy)
			case lerr == nil && haveEnvelope:
				fmt.Printf("steer: install profile PRESENT and did NOT verify against the key this build pins. "+
					"The envelope CLAIMS to be signed by %q — unverified, and it would read the same for a "+
					"corrupted signature or a profile of the wrong kind. Forcing SAFE fail-closed defaults.\n", signedBy)
			default:
				fmt.Printf("steer: install profile INVALID/absent (source=%s: %v) — forcing SAFE fail-closed defaults, ignoring operator posture flags\n", source, lerr)
			}
		}
		// Apply the (verified OR safe-default) profile to the posture flag vars. The mTLS transport material
		// (pinned CA / client cert+key) still comes from enrollment (L2); the profile supplies the edge URL.
		// selfImageBypass still always applies regardless of bypass_apps.
		*failOpen = prof.FailOpenEnabled()
		*ackFailOpen = prof.FailOpenEnabled() // the signed profile IS the acknowledgment; keeps the guard consistent
		*backend = prof.Backend
		// ★★★ THE OTHER ADDRESSES THIS BOX MAY START FROM (2026-08-25, the operator's point). transport_url
		// alone is one place to begin, and a deployment whose named region is down could then enrol nothing
		// new and could not take back a box that had been off. The receiving end already existed —
		// -region-endpoints-seed, the bootstrap list used until the signed one arrives — so the profile only
		// had to carry it.
		//
		// ★ AN EXPLICIT FLAG STILL WINS. A box provisioned with its own seed keeps it; this fills the gap
		// where nobody said, which is every box that was given a profile and nothing else.
		if len(prof.TransportEndpoints) > 0 && strings.TrimSpace(*regionSeed) == "" {
			*regionSeed = strings.Join(prof.TransportEndpoints, ";")
			fmt.Printf("steer: profile carries %d starting address(es) — %s\n",
				len(prof.TransportEndpoints), *regionSeed)
		}
		// ★★★ THE AUTHORED EXCLUSIONS ARE MERGED IN, NOT ONLY bypass_apps (2026-08-30).
		//
		// The Console authors a deployment's never-steer list into deployment.steer_exclusions, and the Edge
		// fills that block per organization at issuance (authoredSteerExclusions). This line read ONLY the
		// profile's top-level bypass_apps, which is a DIFFERENT field filled from the profile-issuing request --
		// so an operator could author an exclusion in the Console, watch it land in the profile, and have this
		// device steer the application anyway. Nothing said so, because the exclusion WAS in the document the
		// device verified; it was simply read from the other field.
		//
		// That is how this box ran all of 2026-08-30 with zero protection for the session doing the measuring:
		// Sakura Foods had authored none, and had it authored some, this device would not have applied them.
		//
		// ★ MERGED, for the same reason the destinations below are merged: the two lists have different authors.
		// bypass_apps is what the profile-issuing request said; steer_exclusions is what the ORGANIZATION
		// authored. Letting either silently replace the other means one operator's screen quietly unprotects
		// what another operator's screen protected.
		// ★ KEPT AS A LIST. Flattening these into the comma-separated flag destroys any identifier that
		// contains a comma, and subject: identifiers are X.500 Organization names where a comma is ordinary
		// ("Anthropic, PBC"). See mergeIdentifiers. *bypassApps is still updated so the operator-facing
		// report line shows something, but it is NOT the source of truth any more.
		authoredBypass = mergeIdentifiers(prof.BypassApps, prof.Deployment.SteerExclusions)
		*bypassApps = strings.Join(authoredBypass, ",")
		if n := len(trimmedNonEmptyCSV(strings.Join(prof.Deployment.SteerExclusions, ","))); n > 0 {
			fmt.Printf("steer: the deployment authored %d never-steer identifier(s); this device applies the "+
				"forms it understands and STEERS the rest (an unenforceable form is not a silent exemption)\n", n)
		}
		// ★★ DESTINATIONS ARE MERGED, NOT REPLACED (2026-08-17, measured on win-dev-1 the first time a package
		// was actually built with -BypassDest).
		//
		// This was a plain assignment like the line above it, and the consequence is that `-BypassDest` — the
		// packaging option added specifically so the SSH management path would survive steer-all — was INERT on
		// every provisioned box. A verified profile carrying `bypass_dests: null` produced "", which erased what
		// the MSI had put in the service's ImagePath. The startup line then printed `bypass_dests=[127.0.0.1:18090]`
		// and nothing said a thing had been dropped. That is the exact defect this file keeps finding: an option
		// that appears to be configured, and produces nothing.
		//
		// Why MERGE rather than let the profile win, when --edge-transport-url deliberately loses to the profile:
		// those two are not the same kind of value. The transport is WHICH edge this device trusts, and letting
		// argv move it would let a local admin re-point enforcement — the profile must win. A packaged bypass
		// destination is a SITE fact about the deployment — this box's management path, and the rule that a
		// management path must never be routed through the object it manages — decided by whoever built the
		// provisioned package, which
		// on this product is the same organization that signs the profile. A tenant-wide profile cannot know it.
		//
		// The cost is stated plainly: the profile can ADD destinations but can no longer REMOVE one the package
		// baked in. Reinstalling the package is what removes it. That is acceptable only because both inputs are
		// signed by the same organization, and because the alternative measured here is worse — the site fact
		// vanishing in silence. Both sets are printed below so what is exempt is never a guess.
		merged, note := mergeBypassDests(packagedBypassDests, prof.BypassDests)
		*bypassDests = merged
		if note != "" {
			fmt.Println("steer: " + note)
		}
		*dnsListen = prof.DNSListen
		*blockQUIC = prof.BlockQUIC != nil && *prof.BlockQUIC
		// What the organization decided about virtual machines on this device. See vm_egress.go: this agent
		// does not see their traffic, so a profile that says nothing blocks them.
		profileVMEgress = vmEgressFromProfile(prof.VMEgress, prof.AckVMEgress)
		*captiveTimeout = time.Duration(prof.Captive.TimeoutSec) * time.Second
		if strings.TrimSpace(prof.TransportURL) != "" {
			*edgeTransportURL = prof.TransportURL // the profile drives the edge the service steers to
		}
		// Region preference. Taken from the profile like everything else here, but held in a variable instead of
		// written back onto the flag: the flag is the raw "region=N,..." text and this is already a map, and
		// round-tripping a parsed value back through its own text form is a way to acquire a second parser.
		// An INVALID/absent profile leaves this nil (SafeDefaults carries no preference), so the box falls back
		// to nearest-RTT — the pre-feature behaviour, which is the right safe answer for a performance hint.
		profileRegionPriority = prof.RegionPriority
		// ★ The deployment names its own hosts that must NOT be steered — its Console above all. Windows had
		// no reference to this field at all until 2026-08-31, so a steered administrator got 502 from the
		// Console of the deployment they were steering, while macOS got 200 from the same profile.
		profilePassthrough = prof.Deployment.PassthroughDomains
		// The names this organization presents, stated at install time. This is the ONLY source that exists
		// before the device has ever been told anything — the trust bundle announces them, and the bundle
		// arrives after enrolment, which was the thing that needed a name to send. An announcement still
		// outranks this; see activeServerName.
		profileOrganization = prof.Organization

		// ★★★ A DISTRIBUTION THIS DEVICE CAN PROVE IS SOMEBODY ELSE'S IS DISCARDED HERE, BEFORE ANYTHING READS
		// THE STORE (2026-08-30, the macOS session's finding after their first fix changed nothing on the
		// machine it was written for).
		//
		// The adopted set is authoritative — it REPLACES the provisioned anchors, which is what makes a
		// withdrawal possible at all — so a set carried over from another deployment silences the correct one.
		// Recording the tenant fixed that for distributions adopted from now on and for nobody currently in the
		// field: every pointer that exists today predates the field. The evidence for those was already on
		// disk, in the name the distribution tells this device to present. A name that is not the one this
		// deployment serves is not "cannot prove it is mine" — it is proof it is not.
		//
		// Done before the transport is built rather than by declining to use the files, because every reader
		// would otherwise have to remember the exception, and the reader that forgets is the one that verifies
		// the Edge.
		if discarded, note := discardForeignAdoptedAnchors(filepath.Dir(transportPinPath("")),
			prof.TenantID, prof.Organization.TransportServerName); note != "" {
			fmt.Println("steer: " + note)
			_ = discarded
		}

		// ★★★ AND THE MATERIAL THAT VERIFIES THAT NAME COMES WITH IT (2026-08-29, measured on win-dev-1).
		//
		// The profile told this device to present its organization's own name and it was handed the deployment
		// root, which does not sign the certificate served for that name. Every (T) call failed with
		// "certificate signed by unknown authority" — and then the device did something worse than fail: the
		// trust-bundle fetch that exists to recover from exactly this names no organization on its FIRST call,
		// so the Edge answered with the deployment's own, and the device ADOPTED anchors naming the
		// deployment's root as its interception authority. It printed ADOPTED. Nothing was red.
		//
		// The block is derived and written here rather than by the MSI so that a REPLACED profile moves the
		// anchors with it. --edge-transport-url deliberately cannot move the transport, which makes the profile
		// the only lever that can; anchors that stayed behind at install time would make that lever unusable.
		// (The macOS analogue runs in the pkg's postinstall — deploy/reference/build_macos_ne_pkg.sh,
		// derive_config_from_profile — because a pkg has no long-running process to do it in.)
		deploymentMaterial, dmErr := installprofile.DeriveDeployment(prof.Deployment)
		if dmErr != nil {
			// Fail LOUD and by name. A profile whose certificate fields do not parse is an authoring mistake,
			// and the device keeps whatever it was provisioned with rather than blanking it — but it must never
			// be the case that nobody said so.
			fmt.Fprintf(os.Stderr, "steer: the profile's deployment block could not be read (%v) — "+
				"keeping the material this device already holds\n", dmErr)
		} else if deploymentMaterial.Present() {
			profileAnchorFingerprints = deploymentMaterial.AnchorFingerprints
			for _, note := range applyDeploymentMaterial(deploymentMaterial, defaultEnrollDir()) {
				fmt.Println("steer: " + note)
			}
			// ★★★ THE PROFILE'S OWN KEY IS NOT TAKEN AS A PIN (2026-08-29, removed after the operator decided
			// how the key travels, and after the macOS installer was found doing the unverified version of it).
			//
			// This block used to fall back to deployment.agent_policy_signing_public_key when no pin had been
			// given. It was safer than the macOS defect — nothing reaches here unless the profile ALREADY
			// verified, because installprofile.Load returns SafeDefaults on every failure path — but it was the
			// same shape one step removed: the document naming the authority for the documents that come after
			// it. The agent-policy pin verifies signed exclusions and trust distributions, so a profile that
			// named it would be choosing who may steer this device next.
			//
			// The key now travels as its own artefact, placed by the operator, and profileapply puts it in this
			// service's arguments at install. A device with no pin therefore verifies nothing and says so,
			// which is the honest state — not one that quietly promotes whatever it was handed.
			if strings.TrimSpace(*agentPolicyPin) == "" && deploymentMaterial.AgentPolicyPin != "" {
				fmt.Printf("steer: the profile names an agent-policy signing key, and this agent was given " +
					"none. It is NOT adopted from the profile — a document does not name the authority for the " +
					"documents that follow it. Signed exclusions and trust distributions stay unverifiable " +
					"until the key is installed (PIN= at install, or --agent-policy-pin).\n")
			}
		}

		// ★ A VERIFIED PROFILE WITH A TRANSPORT IS A STEERING POLICY, AND NOTHING WAS TURNING IT INTO ONE.
		//
		// Measured on win-dev-1 2026-08-11. The MSI registers DsseSteer as `--service-run --config-store`, and
		// that is the whole argument list. `--mode` therefore kept its default, OBSERVE; `--steer-all` and
		// `--steer-generic` stayed false. So the production install path installed an agent that reads a signed
		// steering policy, applies its posture, blocks QUIC, takes over DNS — and never steers a single flow.
		// The box looks configured and enforces nothing, which is the worst of the three possible states.
		//
		// DERIVED HERE RATHER THAN ADDED TO THE PROFILE SCHEMA, and that is the decision worth arguing with.
		// A new field would need the signer, the schema, both platforms and a re-issue of every profile already
		// deployed — and every profile signed before it would still not steer, which is the bug. It is also not
		// a per-tenant knob in disguise: a profile that names a transport, a posture, bypass apps, a DNS listener
		// and a QUIC rule has already said this device is enforced through the Edge. Single-target redirect is
		// the lab shape, reached with explicit flags.
		//
		// NOT DERIVED FROM AN UNVERIFIED PROFILE: SafeDefaults carries no transport, so a box with no profile
		// (or a tampered one) is left exactly as it was — fail-closed, unconfigured, standing aside.
		//
		// AN OPERATOR'S EXPLICIT FLAG STILL WINS, and "explicit" means flag.Visit rather than a value comparison:
		// `--mode observe` on a profiled box is a deliberate diagnostic run, and it is indistinguishable from
		// the default by value alone.
		if verified && strings.TrimSpace(prof.TransportURL) != "" {
			var derived []string
			if !flagWasSet("mode") {
				*mode = "redirect"
				derived = append(derived, "--mode redirect")
			}
			if !flagWasSet("steer-generic") {
				*steerGeneric = true
				derived = append(derived, "--steer-generic")
			}
			if !flagWasSet("steer-all") {
				*steerAll = true
				derived = append(derived, "--steer-all")
			}
			switch {
			case len(derived) > 0:
				fmt.Printf("steer: the verified profile names a transport, so this device ENFORCES: %s "+
					"(derived from the profile; pass the flag explicitly to override)\n", strings.Join(derived, " "))
			default:
				fmt.Printf("steer: the verified profile names a transport; every steering flag was given "+
					"explicitly, so nothing was derived (mode=%s steer-all=%v steer-generic=%v)\n",
					*mode, *steerAll, *steerGeneric)
			}
		}
	}

	// M4<->M8 integration: the --config-store service loads the ENROLLED device identity (device.crt,
	// device-ca.pem, and the DPAPI-unwrapped key) from the well-known dir and builds its (T) transport from it —
	// so an MSI-installed box actually steers once enrollment has run, with the private key never re-written to
	// disk. Not enrolled yet => no client identity => the transport build fails fail-closed (the box must enroll
	// before it can steer). Explicit --transport-* / --config-profile flags still win for lab/manual runs.
	// ★ RESOLVED ONCE, AND EVERY CONSUMER TAKES THIS (2026-08-12, nineteenth review). transportPinPath was
	// introduced for the anchor selection and used only there, so six other places went on reading the raw
	// flag — which the MSI's service line (`--service-run --config-store`) never sets. The consequences were
	// not cosmetic: policyKeyStateDir("") loses every adopted policy key, the self-enrolment probe skips
	// proving the issued identity on the (T) transport, the refusal journal has nowhere to write, and
	// trustStateDir("") turns trust-anchor recovery OFF — so an MSI box cannot adopt the next rotation's
	// anchors and loses the Edge the moment the old CA is withdrawn. A flag nobody passes does not fail
	// loudly; each of these quietly answered "nothing configured".
	//
	// An explicit flag still wins, which is what makes a lab or hand-run box behave as it always did.
	// ★ AND THE DEFAULT IS FOR THE SERVICE CONFIGURATION ONLY (2026-08-12, twentieth review). Resolving it
	// unconditionally meant a hand-run box that omitted --transport-pinned-ca stopped erroring and quietly
	// adopted whatever CA was left in %ProgramData% from an earlier install — the opposite of "an explicit
	// flag still wins, so a lab or hand-run box is unchanged", which is what the comment claimed. --config-store
	// is the configuration the MSI service uses and the only one that reads its material from well-known
	// locations; everywhere else, an omitted pin stays the error it was.
	resolvedPinPath := strings.TrimSpace(*transportPinnedCA)
	if resolvedPinPath == "" && *configStore {
		resolvedPinPath = transportPinPath("")
	}
	var enrolledMat *enrolledMaterial
	standAside := false
	// deviceIdentityDir is where an automated renewal keeps the identity it issues, and where it looks for one
	// on the way up. It is NOT derived from --transport-client-cert any more, because the configuration this
	// product actually installs does not pass that flag at all.
	//
	// ★ THAT DERIVATION DISABLED RENEWAL ON EVERY SHIPPED DEVICE (2026-08-20, read off this box's own log).
	// Under --config-store the client certificate comes from the enrolment material and is held in memory, so
	// the flag is empty, so renewal switched itself off and said so on every start — for as long as the MSI has
	// existed. Device certificates are issued for sixty days and nothing renewed them; the whole
	// expired-certificate recovery path was unreachable code on the only configuration that ships.
	//
	// The enrolment directory is the right home for it: the renewed material sits beside the material it
	// supersedes, and the pointer left over from the hand-installed era in the parent directory — which names a
	// DIFFERENT identity — cannot be picked up by accident.
	deviceIdentityDir := ""
	if *configStore {
		deviceIdentityDir = defaultEnrollDir()
	} else if p := strings.TrimSpace(*transportClientCert); p != "" {
		deviceIdentityDir = filepath.Dir(p)
	}
	if *configStore && strings.TrimSpace(*transportClientCert) == "" && strings.TrimSpace(*transportPinnedCA) == "" {
		enrollDir := defaultEnrollDir()
		m, ok, lerr := loadEnrollment(enrollDir)
		// Durable evidence only: the completion marker counts as "was enrolled" even when its material no
		// longer loads — a device whose key was wiped must not be mistaken for a new one, or losing a
		// credential becomes losing enforcement on exactly the devices an operator cares most about.
		wasEnrolledBefore := ok || lerr != nil
		if lerr != nil {
			fmt.Printf("steer: enrolled material present but unusable (%v) — staying UNENROLLED (fail-closed, no transport)\n", lerr)
		} else if ok && !identityServesThisOrganization(m.Meta.Tenant, profTenant) {
			// Not an error and not a wipe: the credential stays on disk, it is simply not this deployment's.
			// Saying so here is what lets the gate below reach enrol_first and spend the approval that arrived
			// with the new profile, instead of proceeding with something the new Edge will refuse.
			fmt.Printf("steer: the identity on disk was issued by %q and this device is installed for %q — a "+
				"credential from another organization is refused by the Edge that did not issue it, so it is NOT "+
				"counted as enrolment here; the enrolment token that came with this profile is used instead\n",
				m.Meta.Tenant, profTenant)
		} else if ok {
			enrolledMat = &m
			reportIdentityProvenance(m.Meta.DeviceID, m.Meta.Tenant, *serviceRun)
			// Repairs a box enrolled before this existed: the installer left it demand-start and
			// nothing has asked since. Silent when it is already auto.
			raiseOwnStartTypeAfterEnrolment(*serviceRun, false)
		}
		// The enrolment gate: what to do when this machine has no identity. Decided from durable facts, and
		// the decision is logged on EVERY path — a working machine and one quietly standing aside must never
		// produce the same silence.
		enrolCfgPath := filepath.Join(enrollDir, "enrolment.json")
		enrolCfg, cfgPresent, cerr := loadEnrolmentConfig(enrolCfgPath)
		if cerr != nil {
			fmt.Printf("steer: %v\n", cerr)
		}
		decision := enrolmentGateDecide(enrolledMat != nil, cfgPresent && enrolCfg.hasUnspentToken(), wasEnrolledBefore)
		fmt.Printf("steer: enrolment_gate decision=%s identity=%v token=%v was_enrolled_before=%v\n",
			decision, enrolledMat != nil, cfgPresent && enrolCfg.hasUnspentToken(), wasEnrolledBefore)
		// ★★★ A MODE THAT DOES NOT TAKE THE NETWORK PATH DOES NOT SPEND AN APPROVAL (2026-08-30, measured by
		// spending one). --mode bypass-observe lists which processes an exclusion rule matches. It is a
		// read-only diagnostic, run precisely when somebody is checking their configuration BEFORE arming.
		//
		// It enrolled. The gate runs here, hundreds of lines before the mode is dispatched, so EVERY
		// invocation enrolled -- and enrolment is one-time and context-bound. The consequences, both observed
		// on this box within a minute of each other:
		//
		//   - the one-time token was consumed by a command that inspects nothing but the process table, and
		//     is gone for the real install;
		//   - the device key was DPAPI-wrapped at the context the DIAGNOSTIC ran in (an operator's session),
		//     so the SERVICE, running as SYSTEM, can never open it: "enrolled material present but unusable
		//     (must run as the enrolling SYSTEM context)". The machine is enrolled, the Console shows it
		//     enrolled, and it can never use the identity.
		//
		// An administrator checking their exclusions before arming is the most reasonable thing to do, and it
		// silently destroyed the install. modeTakesTheNetworkPath already draws exactly the right line and
		// was already used, forty lines further down, to decide whether standing aside matters.
		if decision == gateEnrolFirst && !modeTakesTheNetworkPath(*mode) {
			fmt.Printf("steer: --mode %s does not take the network path, so self-enrolment is NOT run here — "+
				"the one-time approval stays unspent, and the identity will be minted by the context that "+
				"actually steers (a key wrapped by a diagnostic cannot be opened by the service)\n", *mode)
			decision = gateStandAside
			if wasEnrolledBefore {
				decision = gateProceedPreviouslyEnrolled
			}
		}
		fmt.Printf("steer: enrolment_gate decision=%s identity=%v token=%v was_enrolled_before=%v\n",
			decision, enrolledMat != nil, cfgPresent && enrolCfg.hasUnspentToken(), wasEnrolledBefore)
		switch decision {
		case gateEnrolFirst:
			// Day-0: the installer left an admin-issued token; the machine enrols itself, proving the issued
			// identity on the (T) transport before anything is committed. The probe verifies the Edge SERVER
			// with the pinned transport CA (when one is configured) — never the enroll-returned device CA.
			// ★ THE PROBE READ THE PIN FILE DIRECTLY AND SWALLOWED THE ERROR (2026-08-12, twentieth review).
			// That is the one selection in this file that did not go through transportTrustAnchors, so on the
			// shape a rotated fleet reaches — pin file retired, valid adopted bundle beside it — the long-lived
			// transport correctly used the adopted anchors while the probe decided it had no CA and skipped
			// proving the identity at all. The device then PERSISTS an identity it has never demonstrated can
			// reach the Edge, which is the opposite of what the probe is for.
			var probeCAPEM []byte
			var probeErr error
			if strings.TrimSpace(*edgeTransportURL) != "" {
				pool, probeCAs, _, _, aerr := transportTrustAnchors(resolvedPinPath, profileAnchorFingerprints)
				probeErr = aerr
				if aerr == nil && pool != nil {
					probeCAPEM = encodeCertsPEM(probeCAs)
				}
			}
			// A transport is configured and there is nothing to verify it with: that is a refusal, not a
			// skipped step. Standing aside leaves the box unenrolled and unsteered, which is recoverable;
			// persisting an unproven identity is not.
			if probeErr != nil {
				fmt.Printf("steer: self-enrolment NOT attempted — a transport is configured (%s) and this "+
					"device has no anchor to verify the Edge with (%v). Proving the issued identity is the "+
					"point of enrolling here, so it is not skipped.\n", *edgeTransportURL, probeErr)
				standAside = true
			} else if err := performSelfEnrolment(enrolCfg, enrolCfgPath, *edgeTransportURL, profileOrganization.EnrolmentServerName, probeCAPEM, enrollDir); err != nil {
				// A machine that failed to enrol is still a machine nobody approved: stand aside rather than
				// take over the path with no identity — and rather than crash-looping under the SCM.
				fmt.Printf("steer: self-enrolment failed (%v) — standing aside, not taking over the network path\n", err)
				standAside = true
			} else if m, ok, lerr := loadEnrollment(enrollDir); lerr == nil && ok {
				enrolledMat = &m
				reportIdentityProvenance(m.Meta.DeviceID, m.Meta.Tenant, *serviceRun)
				// The installer could not do this: at install time there was no identity to derive it from.
				raiseOwnStartTypeAfterEnrolment(*serviceRun, true)
			}
		case gateStandAside:
			standAside = true
		case gateProceed, gateProceedPreviouslyEnrolled:
			// proceed: identity in hand. previously-enrolled: the existing fail-closed handling stands — it is
			// not this gate's to reinterpret a machine that has LOST an identity as a new one.
		}
	}

	// Standing aside: a machine that was never enrolled does not take over the network path. There is no policy
	// to bypass on a machine nobody approved, and the alternative is not "more secure" but "no network" — an
	// agent applying filters and then failing every handshake with a credential it does not have. The service
	// stays up (idle, no filters) so the SCM does not restart-loop it, and repeats the operator message so the
	// state stays visible in the log.
	if standAside && modeTakesTheNetworkPath(*mode) {
		fmt.Println("steer: " + notEnrolledOperatorMessage)
		idle := func(stop <-chan struct{}) error {
			t := time.NewTicker(time.Hour)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return nil
				case <-t.C:
					fmt.Println("steer: " + notEnrolledOperatorMessage)
				}
			}
		}
		if *serviceRun {
			if err := runAsService(idle); err != nil {
				fmt.Fprintf(os.Stderr, "service: %v\n", err)
				os.Exit(1)
			}
			return
		}
		os.Exit(3)
	}

	// --mode print-config: resolve the effective config (incl. the config-store profile overlay + enrolled
	// identity) and print it, then exit WITHOUT steering. A safe way to verify what the service would run with.
	if *mode == "print-config" {
		fmt.Printf("effective: profile_mode=%v enrolled=%v tenant=%q group=%q fail_open=%v backend=%s transport=%q dns_listen=%q block_quic=%v captive_timeout=%s bypass_apps=%q\n",
			*configStore || strings.TrimSpace(*configProfile) != "", enrolledMat != nil, profTenant, profGroup, *failOpen, *backend, *edgeTransportURL, *dnsListen, *blockQUIC, *captiveTimeout, *bypassApps)
		return
	}

	// Production guard: refuse --fail-open unless --acknowledge-fail-open is explicitly set (placed AFTER recover
	// so the panic button always works). Default (no acknowledgment) => the agent cannot run fail-open =>
	// structurally fail-closed. When fail-open IS enabled, log a loud banner so the degraded posture is never silent.
	if err := validateFailOpenPosture(*failOpen, *ackFailOpen); err != nil {
		fmt.Fprintf(os.Stderr, "steer: %v\n", err)
		os.Exit(2)
	}
	if *failOpen {
		fmt.Println(failOpenPostureBanner(*failOpenDisarmAfter))
	}

	var transport transportConfig
	var terr error
	if enrolledMat != nil {
		// In-memory build from the enrolled identity — the DPAPI-unwrapped key stays in memory, never on disk.
		//
		// ★ THE SERVER ROOTS ARE NOT enrolledMat.CAPEM, AND USING THEM BROKE EVERY ENROLLED BOX (2026-08-12,
		// measured on win-dev-1). That field is the DEVICE-ISSUING CA — the authority that signed the client
		// certificate this device presents. The Edge's transport certificate is issued by the TRANSPORT CA, a
		// different PKI by design, so the moment a machine enrolled, every (T) call failed with "certificate
		// signed by unknown authority": heartbeat, manifest, plan, steer-exclusions, DNS. On this fail-open
		// box the circuit opened and every flow went direct and unmediated with plaintext DNS behind it; a
		// fail-closed box would have had no network at all.
		//
		// The rule was already written down 70 lines above, for the self-enrolment probe: verify the Edge
		// SERVER with the pinned transport CA, never with the enroll-returned device CA. The transport that
		// runs for the rest of the process's life was the one place it was not applied.
		//
		// And the enrol response is deliberately NOT where this should come from. Transport trust arrives on a
		// channel that ROTATES — the profile's pin plus whatever the signed trust bundle has adopted — and an
		// enrolment happens once. A device whose server roots came from its enrolment could never follow a CA
		// rotation, and would look enrolled the whole time it could not talk.
		// ★ THE SAME SELECTION THE NON-ENROLLED PATH USES, rather than a second one that behaved differently
		// (2026-08-12, seventeenth review). The first version of this unioned the provisioned pin with the
		// adopted anchors, which contradicts the rule stated on setTrustAnchors: adopted REPLACES provisioned,
		// because a union can only widen what a device accepts and a CA withdrawn for being compromised would
		// stay trusted. It also carried no serial, so a device that had adopted at serial 3 reported 0 after a
		// restart and nothing re-adopted — the withdrawn CA trusted until some later serial happened along.
		// ★ AND IT HAS TO BE ABLE TO FIND THEM ON THE ONLY KIND OF BOX THAT ENROLS (2026-08-12, Windows).
		// Everything above is right and it resolved to NOTHING on an MSI-installed device: that service line is
		// `--service-run --config-store` and passes no --transport-pinned-ca, so transportTrustAnchors was handed
		// an empty path, returned "a transport CA pin is required", and the enrolled box fell straight to the
		// empty-pool branch below — correct about trust, and unable to complete a single handshake.
		//
		// The anchors were in %ProgramData%\DSSE the whole time. transportPinPath names the well-known file when
		// no flag does, and the adopted lookup follows it because it is keyed on the pin's DIRECTORY — so the
		// REPLACE semantics, the serial and the supersede logging all come along unchanged.
		pool, pinnedCAs, adoptedSerial, rootsFrom, aerr := transportTrustAnchors(resolvedPinPath, profileAnchorFingerprints)
		if aerr != nil {
			// ★ AND THE FALLBACK IS AN EMPTY ROOT SET, NOT THE DEVICE CA (2026-08-12, seventeenth review).
			// The first version substituted enrolledMat.CAPEM here on the reasoning that it would fail anyway.
			// It would fail against the Edge as deployed — and what it actually does is GRANT the
			// device-issuing CA server authority, so anything able to make that CA issue a certificate for
			// this hostname would be accepted. A different trust domain is not a degraded version of the right
			// one. An empty pool verifies nothing, which is the true statement, and the service still runs.
			pool, pinnedCAs, adoptedSerial = x509.NewCertPool(), nil, 0
			rootsFrom = "NOTHING — no transport pin and nothing adopted"
			fmt.Printf("steer: ★ NO TRANSPORT CA to verify the Edge with (%v). Every (T) handshake will fail "+
				"CLOSED: this box is about to behave as if the edge were unreachable. It will NOT fall back to "+
				"the enrolled device-issuing CA — that CA signs client certificates and must never be able to "+
				"authenticate a server.\n", aerr)
		}
		fmt.Printf("steer: (T) server verification uses %s; the enrolled identity is the CLIENT certificate\n", rootsFrom)
		transport, terr = buildTransportConfigFromAnchors(*edgeTransportURL, pool, pinnedCAs, adoptedSerial,
			deviceIdentityDir, enrolledMat.CertPEM, enrolledMat.KeyPEM)
	} else {
		transport, terr = buildTransportConfig(*edgeTransportURL, resolvedPinPath, *transportClientCert, *transportClientKey)
	}
	if terr != nil {
		fmt.Fprintf(os.Stderr, "transport config: %v\n", terr)
		os.Exit(1)
	}
	// ★ THE NAMES COME BACK BEFORE ANYTHING DIALS (2026-08-20, found from the Edge side: this device was
	// recorded refusing a certificate it had asked for under the wrong name). Restoring them late meant every
	// dial between building the transport and reaching the trust-state block below went out under the
	// PROVISIONED host name — which, once this organization is served its own certificate, is answered with the
	// deployment's shared one and refused. The first casualty was the CP steering-posture fetch, so the boot
	// kept its bootstrap flags instead of the posture the control plane had signed, and five refusals landed in
	// the journal an operator reads. Nothing here needs the trust-state block: the pointer is beside the pin.
	// What the INSTALL stated, put in place before anything dials and before the adopted names below, because
	// this is the one that has to work on a device that has never enrolled. It is a plain field rather than a
	// live pointer: the profile is applied once, and an announcement that arrives later outranks it anyway.
	transport.configuredServerName = strings.TrimSpace(profileOrganization.TransportServerName)
	if transport.configuredServerName != "" {
		fmt.Printf("steer: the install profile states this organization presents transport SNI %q (an announced "+
			"name will outrank it)\n", transport.configuredServerName)
	}
	if d := strings.TrimSpace(resolvedPinPath); d != "" {
		name, recovery := adoptedTransportServerName(filepath.Dir(d)), adoptedRecoverySNI(filepath.Dir(d))
		// A deployment that states a recovery name at install and has not yet announced one should still be
		// able to recover; the announcement wins the moment it exists.
		if strings.TrimSpace(recovery) == "" {
			recovery = strings.TrimSpace(profileOrganization.RenewalRecoveryServerName)
		}
		transport.setAnnouncedNames(name, recovery)
		if name != "" || recovery != "" {
			fmt.Printf("steer: adopted names restored — transport SNI %q, recovery SNI %q\n", name, recovery)
		}
	}
	// The certificate-recovery endpoint an adopted bundle names, shared by pointer so the renewal loop and the
	// effective report read ONE value. Declared here because both are downstream of it, and a report that
	// described a different destination from the one recovery would use would be worse than no report.
	liveRecoveryEndpoint := &atomic.Pointer[string]{}
	// Buffered depth 1: a hint that arrives while a pass is already pending is the same event.
	trustWake := make(chan struct{}, 1)

	// Attach the trust-refusal journal BEFORE the transport is copied anywhere: a failed (T) verification records
	// the served certificate and the verifier's words, and the effective-set report ships them on the next
	// connection that works — so a fleet that refused a certificate stops looking identical to one that is off.
	// Same state dir as the trust-anchor journal (the pinned-CA directory), or the enrolled dir in config-store
	// mode; empty => no journal (nil, and every call is nil-safe).
	refusalStateDir := ""
	if strings.TrimSpace(resolvedPinPath) != "" {
		refusalStateDir = filepath.Dir(resolvedPinPath)
	} else if enrolledMat != nil {
		refusalStateDir = defaultEnrollDir()
	}
	transportRefusals := newTrustRefusalJournal(refusalStateDir)
	transport.refusals = transportRefusals
	// The (I) interception side of the same idea, in the same directory so one runbook line finds both journals.
	// It is deliberately NOT wired to trustWake: a device that cannot use interception can still reach the Edge
	// perfectly well, so there is nothing for anchor recovery to fix and waking it would be noise.
	interceptionRefusals := newInterceptionRefusalJournal(refusalStateDir)
	// A device that cannot verify the Edge wakes trust-anchor recovery directly. Debounced, because a dark
	// device records a refusal on every retry and the recovery pass costs a handshake and a fetch; one look a
	// minute while dark is the urgency the scheduler comment already asks for, and it is the difference between
	// 31 minutes unprotected and one pass.
	if transportRefusals != nil {
		var lastWake atomic.Int64
		transportRefusals.onRefusal = func() {
			now := time.Now().Unix()
			prev := lastWake.Load()
			if now-prev < 60 || !lastWake.CompareAndSwap(prev, now) {
				return
			}
			select {
			case trustWake <- struct{}{}:
				log.Printf("trust_anchor_recovery woken by a trust refusal: this device cannot verify the Edge right now")
			default:
			}
		}
	}

	// Phase 3c: CP-controlled steering posture. When a signed policy is provisioned (--agent-policy-pin + the (T)
	// transport), the CP's signed posture (fail_open_mode / region_failover / cooldown) is AUTHORITATIVE over the
	// --fail-open / --region-failover / --fail-open-cooldown startup flags, which become the bootstrap fallback.
	// This is what lets an operator control posture centrally without re-registering the agent. Fail-safe: a
	// fetch/verify failure KEEPS the flag values (never widen the boundary on a bad fetch). The signed posture IS
	// the fail-open acknowledgment (mirrors the install-profile override above). Pre-Phase-4 the two remain
	// mutually exclusive — but TERMINAL fail-open (fires only on region exhaustion) COEXISTS with region-failover
	// (Phase 4). Skipped without a pin, so a flags-only deployment is unchanged (backward compatible).
	//
	// terminalFailOpen is threaded into runSteerAll (captured by the closure below): when set, the region loop's
	// exhaustion (StateFailClosed = ALL regions down) escalates to a self-disarm to the native network instead of
	// staying DARK, and re-arms automatically when a region recovers.
	var terminalFailOpen bool
	if transport.enabled && strings.TrimSpace(*agentPolicyPin) != "" {
		// ★★★ ASKED OF EVERY REGION THE PROFILE SEEDED, NOT ONLY THE HOME ONE (2026-08-30, measured with the
		// osaka doorway stopped). This document is what turns region failover ON; fetching it only from the
		// home region means a device that starts during that region's outage never learns it may fail over,
		// and stays dark until the region comes back. See posture_from_any_region.go.
		//
		// The home address is tried first and, when it answers, nothing else is dialled — the ordinary case is
		// unchanged.
		plan := posturePlan(*agentPolicyURL, transport.host, *regionSeed)
		keys := policyVerificationKeys(strings.TrimSpace(*agentPolicyPin), policyKeyStateDir(resolvedPinPath))
		posture, from, idx, perr := fetchPostureFromAnyRegion(transport, plan, keys, 8*time.Second)
		base := from.BaseURL
		if perr == nil && idx > 0 {
			fmt.Printf("steer: the steering posture came from %s%s — the address in force did not answer, and this "+
				"document is what says whether this device may move\n", base, regionLabelSuffix(from.Region))
		}
		if perr != nil {
			fmt.Printf("steer: CP steering-posture fetch failed (%v) — keeping bootstrap flags fail_open=%v region_failover=%v\n", perr, *failOpen, *regionFailoverOn)
			// And keep asking. One failed fetch used to decide this device's posture for the life of the
			// process, and said so exactly once — see keepAskingForPosture.
			keepAskingForPosture(transport, plan, strings.TrimSpace(*agentPolicyPin),
				policyKeyStateDir(resolvedPinPath),
				resolvedPosture{FailOpen: *failOpen, RegionFailover: *regionFailoverOn,
					TerminalFailOpen: terminalFailOpen, Cooldown: *failOpenCooldown},
				*failOpen, *regionFailoverOn, *failOpenCooldown, nil)
		} else {
			rp := applyCPPosture(*failOpen, *regionFailoverOn, *failOpenCooldown, posture)
			*failOpen = rp.FailOpen
			*regionFailoverOn = rp.RegionFailover
			terminalFailOpen = rp.TerminalFailOpen
			// *ackFailOpen is NOT touched: the acknowledgment is an install-time act and the CP neither grants
			// nor revokes fail-open (applyCPPosture) — it only decides region-failover, which sets the MODE.
			*failOpenCooldown = rp.Cooldown
			fmt.Printf("steer: CP steering-posture applied (region-failover/cooldown are CP-authoritative; fail-open stays the INSTALL-TIME decision) fail_open=%v region_failover=%v terminal_fail_open=%v cooldown=%s\n", *failOpen, *regionFailoverOn, terminalFailOpen, *failOpenCooldown)
			if *failOpen || terminalFailOpen {
				fmt.Println(failOpenPostureBanner(*failOpenDisarmAfter)) // keep the degraded posture loud even when CP-enabled
			}
		}
	}

	// The operator's region preference is validated UNCONDITIONALLY, before the --region-failover gate below and
	// whether or not the feature is on right now.
	//
	// ★ This ordering is the whole point, and getting it wrong was the first version. Region failover is not only
	// a startup flag: the CP's signed steering posture can turn it ON at runtime (applyCPPosture, above). If a
	// malformed REGIONPRIORITY were parsed only inside the enabled branch, a typo would install silently onto a
	// fleet, sit inert for however long, and then refuse to start every one of those agents on the day an
	// operator enabled region failover from the control plane — a mass DARK event, triggered by an unrelated
	// action, from a mistake made months earlier. Validating here moves the refusal to the install, which is the
	// one moment the person who typed it is looking.
	regionPriority, rpErr := regionfailover.ParsePriority(*regionPriorityRaw)
	if rpErr != nil {
		fmt.Fprintf(os.Stderr, "steer: --region-priority: %v\n", rpErr)
		os.Exit(2)
	}
	regionPrioritySource := "flag"
	// The SIGNED profile wins, exactly as it does for posture, backend, bypass, DNS and the transport URL.
	// Guarded on non-empty like TransportURL rather than assigned unconditionally like Posture, because unlike
	// those this setting has no meaningful default: SafeDefaults carries none, so an unconditional assignment
	// would let a profile-less box silently lose a preference given on the command line.
	if len(profileRegionPriority) > 0 {
		regionPriority, regionPrioritySource = profileRegionPriority, "signed profile"
	}
	// A signed profile is authored by a tool that refuses a bad rank, but it can also be authored by hand, and a
	// rank of 0 verifies perfectly while meaning the opposite of what it looks like. Report rather than refuse:
	// rejecting the whole profile over a preference would cost the box its transport, which is a far worse
	// outcome than a mis-ranked region. The device still runs; the operator gets told, by name, what is wrong.
	for _, issue := range regionfailover.ValidatePriority(regionPriority) {
		fmt.Fprintf(os.Stderr, "steer: WARNING region priority (%s): %v\n", regionPrioritySource, issue)
	}
	if rendered := regionfailover.RenderPriority(regionPriority); rendered != "" {
		fmt.Printf("steer: region priority %s (from the %s; lower is preferred, outranks measured latency, nearest-RTT decides within a rank)\n", rendered, regionPrioritySource)
	} else if *regionFailoverOn {
		// ★★★ SAY IT WHEN THERE IS NO PREFERENCE (2026-08-30). Until today no Console screen could author
		// region_priority and no profile-issuing route could carry it, so every fleet ran with this map empty
		// — every region tied, and measured latency decided everything. Nothing said so. The operator's stated
		// preference existed in the profile format, in both agents, and in the selector, and was never filled
		// in by anything a customer runs.
		//
		// An empty map is not a neutral default: it means "nearest wins", which is a real policy and a
		// different one from "prefer home". A device that will not say which of the two it is running leaves
		// the operator to infer it from where the device ended up — which is exactly how this went unnoticed
		// on both platforms, while both were logging the region they had selected.
		fmt.Println("steer: region priority NONE — no preference reached this device, so every allowed region " +
			"ties and measured latency decides which one is used. That is a policy, not an absence: a " +
			"deployment that means to prefer a region has to say so in its profile (region_priority).")
	}

	// Region failover preconditions: it needs the (T) transport (the signed list + per-region tunnels ride it),
	// the pinned agent-policy key (to verify the signed list), and it is mutually exclusive with --fail-open
	// (region failover IS the availability story, but a fail-CLOSED one: it never bypasses the residency boundary,
	// whereas --fail-open deliberately egresses direct on an outage — combining them would let an outage bypass).
	if *regionFailoverOn {
		if !transport.enabled {
			fmt.Fprintln(os.Stderr, "steer: --region-failover requires the (T) transport (--edge-transport-url)")
			os.Exit(2)
		}
		if strings.TrimSpace(*agentPolicyPin) == "" {
			fmt.Fprintln(os.Stderr, "steer: --region-failover requires --agent-policy-pin (the signed allowed-region list is verified against it)")
			os.Exit(2)
		}
		if *failOpen {
			fmt.Fprintln(os.Stderr, "steer: --region-failover and --fail-open are mutually exclusive (region failover is fail-CLOSED; it never bypasses the boundary)")
			os.Exit(2)
		}
	}

	// bypass-observe needs no target: it lists the TCP table (port->pid->image) and which apps would be
	// bypassed by --bypass-app (read-only; confirms Automation is identifiable before steer-all).
	if *mode == "bypass-observe" {
		if err := runBypassObserve(effectiveBypassApps(*bypassApps, authoredBypass)); err != nil {
			fmt.Fprintf(os.Stderr, "bypass-observe: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// --mode selftest: read-only deployment validator (driver + (T) mTLS + signed exclusions + AppID).
	if *mode == "selftest" {
		os.Exit(runSelfTest(transport, *agentPolicyPin, *agentPolicyURL, policyKeyStateDir(resolvedPinPath)))
	}

	// W-5 driver-recovery watchdog: restart the WFP driver if it is stopped (admin-tamper resistance, loud).
	if *mode == "watchdog" {
		err := runWatchdog(watchdogConfig{interval: *watchdogInterval, timeout: *timeout})
		if err != nil {
			fmt.Fprintf(os.Stderr, "watchdog: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// W-3 test affordance: delete ONE of the driver's WFP filters to simulate an admin "partial tamper"
	// (driver stays loaded but a filter is removed). The next heartbeat then reports enforcement UNHEALTHY
	// (wfp-filters-incomplete). Reverse with `sc stop/start DsseWfp` (DriverEntry re-adds all six).
	if *mode == "wfp-tamper" {
		name, err := deleteFirstDsseFilter()
		if err != nil {
			fmt.Fprintf(os.Stderr, "wfp-tamper: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("wfp-tamper: deleted WFP filter %q (driver still loaded). Restore: sc stop/start DsseWfp\n", name)
		return
	}

	// W-2 agent liveness mode: register + periodically heartbeat over the (T) mTLS tunnel. Killing this process
	// stops the heartbeats, so the Edge's agent-dark sweep sees the device go dark and auto-revokes its trust.
	if *mode == "heartbeat" {
		err := runHeartbeat(heartbeatConfig{
			deviceID:  *deviceID,
			tenantID:  *deviceTenant,
			interval:  *heartbeatInterval,
			timeout:   *timeout,
			transport: transport,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "heartbeat: %v\n", err)
			os.Exit(1)
		}
		return
	}

	//  inbound (server-initiated) mode: enforce the Incoming-Connections policy. Default backend programs the
	// standard Windows Defender Firewall (visible in wf.msc; can both open and close — a private WFP sublayer
	// PERMIT cannot open what the standard firewall blocks). The wfp backend (custom callout driver, kernel
	// inbound policy + observation ring) stays selectable for comparison during bring-up. Wholly separate from
	// outbound steering; does not capture or redirect any flow.
	if *mode == "inbound" {
		runBackend := runInbound // wfp
		switch strings.ToLower(strings.TrimSpace(*inboundBackend)) {
		case "firewall":
			runBackend = runInboundNetsh
		case "wfp":
		default:
			fmt.Fprintf(os.Stderr, "--inbound-backend must be firewall or wfp (got %q)\n", *inboundBackend)
			os.Exit(1)
		}
		err := runBackend(inboundRuntimeConfig{
			enforce:     *inboundEnforce,
			exportFile:  *inboundExportFile,
			exportURL:   *inboundExportURL,
			adminToken:  *adminToken,
			deviceGroup: *inboundDeviceGroup,
			poll:        *inboundPoll,
			timeout:     *timeout,
			transport:   transport,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "inbound: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var targetIP4 [4]byte
	if !*steerAll {
		tip, err := netip.ParseAddr(strings.TrimSpace(*targetIP))
		if err != nil || !tip.Is4() {
			fmt.Fprintln(os.Stderr, "--target-ip must be a valid IPv4 address (or use --steer-all)")
			os.Exit(1)
		}
		if *targetPort < 1 || *targetPort > 65535 {
			fmt.Fprintln(os.Stderr, "--target-port must be 1..65535")
			os.Exit(1)
		}
		targetIP4 = tip.As4()
	}
	if *localPort < 1 || *localPort > 65535 {
		fmt.Fprintln(os.Stderr, "--local-port must be 1..65535")
		os.Exit(1)
	}

	// ★ THE TWO-MINUTE LIFE OF THIS AGENT (2026-08-14, win-dev-1, and the reason a box lost its network).
	//
	// `--timeout` defaults to 2 minutes and is described as "maximum run duration" — a foreground/test
	// facility, exactly like `--max-flows 5`. The max-flows cap was ALREADY recognised as unfit for continuous
	// operation and zeroed for steer-all a few hundred lines below, with a comment saying why. The same
	// reasoning was never applied here, and the MSI's service arguments do not override it:
	//
	//	"...\dsse-steer.exe" --service-run --config-store --agent-policy-pin <hex>
	//
	// So newWFPCapture armed `time.AfterFunc(2m, c.Close)`, the capture closed ITSELF two minutes after every
	// start, acceptLoop returned without recording an error (a Close is not a failure), the flows channel
	// closed, and the supervisor read "no error, no stop request" as an intentional shutdown and returned nil.
	// The service then exited with code 0 — so the SCM's restart never fired either — leaving the resolver
	// pointed at the loopback proxy of a process that no longer existed. Measured lifetimes: 2m13s, 2m20s.
	//
	// Zeroed here rather than by changing the installed arguments, because every box the MSI has already
	// touched carries those arguments and cannot be reached to correct them — the update lane needs the agent
	// alive to do it.
	if *serviceRun || *steerAll {
		if *timeout > 0 {
			fmt.Printf("steer: ignoring --timeout %s — continuous operation has no maximum run duration, and a "+
				"capture that closes itself is indistinguishable from a shutdown somebody asked for\n", *timeout)
		}
		*timeout = 0
	}

	// ★★ AND THE SERVICE WAS RUNNING THE VERIFICATION PATTERN, NOT THE PRODUCTION ONE (2026-08-14, win-dev-1).
	//
	// The supervised path — the only one that recreates a dead backend, and the only one that carries a WATCHER
	// FOR THE SCM STOP — runs solely under --permanent. The MSI's service arguments are:
	//
	//	"...\dsse-steer.exe" --service-run --config-store --agent-policy-pin <hex>
	//
	// so the installed agent took the other branch, the one whose own comment calls it "One-shot (contained
	// burst) -- the established safe pattern for verification". --permanent's help text names the pairing this
	// needs — "Pair with --timeout 0 to disable the self-terminate" — and the service passed NEITHER flag.
	//
	// That single omission produced both faults seen on this box:
	//
	//   - the agent died after two minutes, because in one-shot mode the --timeout self-close was the only
	//     thing that ever ended the run, and it ended it for good;
	//   - and once the timeout was removed, `sc stop` hung for minutes with the service reporting StopPending
	//     while STILL STEERING — measured, with the redirect listener open and new flows forwarded 90 seconds
	//     after the request — because one-shot mode has nothing watching the stop channel.
	//
	// A Windows service IS durable operation; there is no meaning to a service that runs a contained burst. So
	// --service-run implies it, in the binary rather than in the arguments, for the same reason as the timeout:
	// every box the MSI has already touched carries the old arguments and cannot be corrected remotely by a
	// lane that needs the agent alive.
	if *serviceRun && !*permanent {
		fmt.Println("steer: --service-run implies --permanent — a service is durable operation, and the " +
			"unsupervised path neither restarts a dead backend nor listens for the SCM's stop")
		*permanent = true
	}

	capCfg := captureConfig{
		targetIP:    targetIP4,
		targetPort:  uint16(*targetPort),
		localPort:   uint16(*localPort),
		timeout:     *timeout,
		bypassApps:  effectiveBypassApps(*bypassApps, authoredBypass),
		bypassDests: parseAddrPorts(splitCSV(*bypassDests)),
		steerAll:    *steerAll,
		selfImage:   selfImageBypass(), // always bypass the agent's own process (fail-open direct dials must not loop)
		// What the kernel driver should do with the redirect policy if this process dies without disarming.
		// It follows the SAME resolved posture as everything else fail-open: *failOpen is the install profile's
		// decision when one is verified (see the profile-derived posture block above) and the flag otherwise,
		// and it is already gated on --acknowledge-fail-open. Reusing it, rather than adding a knob, is the
		// point: there must be exactly one answer on this box to "may this endpoint reach the network without
		// enforcement", and a second switch would eventually disagree with the first.
		disarmOnAgentExit: *failOpen,
	}
	// Auto-add the edge endpoint as a never-steer destination so the agent's own connection to the edge
	// can never be steered into a loop (race-free; complements the AppID self-exclusion).
	if ep, ok := edgeEndpoint(*edgeURL); ok {
		capCfg.bypassDests = append(capCfg.bypassDests, ep)
	}
	// With the (T) transport on, the tunnel connects to the transport host -- never steer it (loop guard).
	//
	// ★ RESOLVE A HOSTNAME TRANSPORT, DO NOT SKIP IT (2026-08-17, found on win-dev-1 the day it moved onto a
	// MagicDNS Edge name). This was ParseAddrPort alone, which only accepts an IP literal — so the moment the
	// profile named the Edge by hostname, the destination loop guard silently disappeared and the agent's own
	// tunnel was protected by the AppID self-exclusion alone. That exclusion is the one this rule exists to
	// COMPLEMENT: it classifies by looking the process up at connect time, which is exactly the part the
	// comment above calls race-free by contrast. Losing it by configuration, with nothing said, is the shape
	// of defect this file keeps finding. resolveAddrPort is what edgeEndpoint already uses one block up.
	//
	// Best-effort, and honestly so: refreshEdgePins re-resolves the name every 60s and the driver's rule set
	// is fixed at arm time, so if the A record moves, this entry names the OLD address until the next restart.
	// The AppID exclusion still covers the agent, and an IP-literal Edge is unaffected.
	// ★★ AND THE ANSWER IS LIVE, BECAUSE ONE FAILED LOOKUP USED TO COST THE GUARD FOREVER (2026-08-18).
	// The previous version resolved once, here, and wrote the result into a slice the running backend could
	// never be told about again. Measured on this box: a UDP timeout during an install was enough -- the
	// capture armed with bypass_dests=[127.0.0.1:18090], refreshEdgePins repaired the DIAL pins two minutes
	// later, and the kernel rule set stayed wrong until the process was restarted. The Edge is now a
	// replaceable slot in a liveDests set (bypass_dest_live.go) that the refresher fills and the wfp backend
	// re-pushes, so a late resolution -- or an A record that moves -- corrects the guard instead of being
	// noticed by nobody.
	capCfg.dests = newLiveDests(capCfg.bypassDests)
	if transport.enabled {
		if ap, e := netip.ParseAddrPort(transport.host); e == nil {
			capCfg.dests.setEdge(ap)
		} else if ap, ok := resolveAddrPort(transport.host); ok {
			capCfg.dests.setEdge(ap)
		} else {
			fmt.Fprintf(os.Stderr, "steer: WARNING the (T) transport host %q could not be resolved to a "+
				"destination bypass yet; the tunnel is protected only by the AppID self-exclusion until the "+
				"Edge pin refresher succeeds (it retries every 60s and fills this in)\n", transport.host)
		}
	}
	// NOTE: do NOT bypass the Windows NCSI connectivity-probe hosts (msftconnecttest/msftncsi). It was tried and
	// REMOVED: their IPs are CDN and change on every resolution, so an IP-pinned bypass is inconsistent and
	// actually makes NCSI report "No Internet" on the ACTIVE link. Letting the probes ride the steer path (the
	// Edge forwards them) yields the correct "Internet" status. A standby link showing "LocalNetwork" is cosmetic
	// and does NOT block failover — the agent's tunnel to the LAN Edge re-establishes on the surviving link
	// regardless (verified: wired->Wi-Fi failover re-armed in ~2s).

	// The live effective bypass-app set: starts at the --bypass-app baseline; the signed steer-exclusion sync
	// (started below in redirect mode) merges the verified server set on top and the backend applies it live.
	// Must be attached BEFORE the capture factory runs so a supervisor-recreated backend seeds from it too.
	live := newLiveExclusions(capCfg.bypassApps)
	capCfg.exclusions = live

	// ★★★ THE DEPLOYMENT'S OWN NAMES GO STRAIGHT OUT (2026-08-31). deployment.passthrough_domains carries the
	// hosts a steered device must reach untouched — the Console it is administered from, above all. This agent
	// had no reference to that field until today: a steered administrator got 502 from their own Console while
	// macOS, reading the same profile, got 200.
	//
	// Attached HERE, beside the exclusions and before the capture factory runs, so a supervisor-recreated
	// backend seeds from the resolved set rather than from an empty one. It reports its counts whether or not
	// it matched anything — an implementation that speaks only on a hit cannot be told apart from one that was
	// never given anything.
	passthroughStop := make(chan struct{})
	defer close(passthroughStop)
	// ★ The box's OWN resolvers, read here because this runs BEFORE the DNS takeover — a Console on a private
	// zone is only resolvable by them, and the public fallback would never find it. The same list is what the
	// out-of-band resolver falls back from; it never queries the loopback proxy, which is the cycle these
	// addresses exist to keep open in the first place.
	keepPassthroughResolved(passthroughStop, capCfg.dests, profilePassthrough, currentEgressResolvers, 5*time.Minute)

	switch *mode {
	case "observe":
		if err := runObserveWinDivert(capCfg); err != nil {
			fmt.Fprintf(os.Stderr, "observe: %v\n", err)
			os.Exit(1)
		}
	case "redirect":
		if *steerAll && !*steerGeneric {
			fmt.Fprintln(os.Stderr, "--steer-all requires --steer-generic (steer-all routes every destination to /steer)")
			os.Exit(1)
		}
		if !*steerGeneric && strings.TrimSpace(*applicationID) == "" {
			fmt.Fprintln(os.Stderr, "--application-id is required for redirect mode (or use --steer-generic)")
			os.Exit(1)
		}
		// runSteerAll runs the redirect/steer-all data path until stop is closed (service) or forever
		// (foreground, stop=nil). All teardown (QUIC block, DNS proxy) is deferred so an SCM clean stop
		// releases it. Returns an error instead of os.Exit so the service path can report it.
		runSteerAll := func(stop <-chan struct{}) error {
			// steer-all is a continuous whole-device capture: a max-flows cap (meant for the single-target W1
			// test) would stop steering after a handful of connections, so disable it (0 = unlimited).
			flowCap := *maxFlows
			if *steerAll {
				flowCap = 0
			}
			// --fail-open shared state. health is the per-flow circuit breaker (DNS + TCP both consult it).
			// mgr/dnsProxyInst are set in the DNS block below; the recovery monitor (started AFTER that block so
			// it can reach them) probes the Edge and, on a SUSTAINED outage, escalates from per-flow fail-open to
			// a full self-DISARM (restore DNS, stop the WFP redirect, unblock QUIC) so the box uses its native
			// network — then re-arms when the Edge returns. `disarmed` gates the DNS reconcile loop.
			var health *edgeHealth
			var mgr *resolverManager
			var dnsProxyInst *dnsProxy
			var disarmed atomic.Bool
			// captiveActive reflects whether the captive bootstrap window is currently open, so the tray status
			// (M2b) shows CaptiveOnboarding rather than a plain fail-open Disarmed.
			var captiveActive atomic.Bool
			// captiveTrigger nudges the captive-portal bootstrap controller to re-evaluate posture (fired at
			// startup and on every network change). Buffered/coalesced so a roam's event burst evaluates once.
			captiveTrigger := make(chan struct{}, 1)

			// Region failover: install the shared LIVE endpoint pointer on `transport` BEFORE it is copied into the
			// edge steerer / DNS proxy / list-fetch client, so a region swap (one atomic Store) repoints them all.
			// Seed it from the bootstrap endpoint (--edge-transport-url) until the loop makes its first selection.
			// This OWNS the dial target, so the single-host pinning path below is skipped under region failover.
			if *regionFailoverOn {
				transport.active = &atomic.Pointer[activeEndpoint]{}
				transport.active.Store(bootstrapActiveEndpoint(transport))
			}

			// Edge endpoint pinning: if the (T) Edge is a HOSTNAME, resolve it OUT OF BAND and dial by IP so the
			// tunnel never depends on the loopback DNS proxy resolving the Edge name (chicken-and-egg). Done BEFORE
			// the DNS proxy/takeover start (the proxy itself dials the Edge). TLS still verifies the hostname, so
			// the CA pin is unchanged. An IP-literal Edge needs none of this. This is what lets production use a
			// hostname Edge (DNS-based HA) without being forced to an IP for the Windows WFP path.
			if !*regionFailoverOn && transportHostIsName(transport) {
				transport.pins = &atomic.Pointer[[]string]{}
				if addrs, perr := resolveEdgeEndpoints(transport, true, nil); perr == nil {
					transport.pins.Store(&addrs)
					fmt.Printf("steer: Edge %s pinned -> %v (dial by IP, verify by name; no DNS-on-tunnel dependency)\n", transport.serverName, addrs)
				} else {
					fmt.Fprintf(os.Stderr, "steer: WARNING could not pre-resolve Edge %s: %v (the refresh loop will retry)\n", transport.serverName, perr)
				}
				refreshStop := make(chan struct{})
				defer close(refreshStop)
				go refreshEdgePins(refreshStop, transport, func() []string {
					if mgr != nil {
						return mgr.upstreams()
					}
					return nil
				}, 60*time.Second, func(first string) {
					// Fill (or correct) the destination loop guard from whatever the refresher just resolved.
					// setEdge is a no-op when the address has not moved, so the ordinary sixty-second success
					// is silent; the line below is printed only when the rule set actually changes.
					ap, ok := resolveAddrPort(first)
					if !ok || capCfg.dests == nil {
						return
					}
					had := capCfg.dests.hasEdge()
					if !capCfg.dests.setEdge(ap) {
						return
					}
					if had {
						fmt.Printf("steer: Edge destination bypass MOVED to %v (the loop guard follows the pin)\n", ap)
					} else {
						fmt.Printf("steer: Edge destination bypass FILLED IN at %v — it was missing since arm time, and the tunnel had been relying on the AppID self-exclusion alone\n", ap)
					}
				})
			}

			if *failOpen {
				// Threshold 2 (not 3) so a network switch that makes the Edge unreachable trips fail-open
				// within a couple of flows instead of lingering on the dead control plane.
				health = newEdgeHealth(2, *failOpenCooldown)
				fmt.Printf("steer: FAIL-OPEN posture enabled — Edge outage: DNS forwards upstream + TCP goes direct; a SUSTAINED outage (>%s, e.g. an interface dropped and the OS hasn't failed over) self-disarms to the native network and re-arms on recovery.\n", *failOpenDisarmAfter)
			}
			edgeCfg := edgeConfig{
				edgeURL:          strings.TrimRight(*edgeURL, "/"),
				applicationID:    *applicationID,
				connectorID:      *connectorID,
				sessionID:        *sessionID,
				connectAuthority: strings.TrimSpace(*connectAuthority),
				omitAuthority:    *omitAuthority,
				maxFlows:         flowCap,
				genericSteer:     *steerGeneric,
				muxSteer:         *steerMux,
				muxFlowsPerConn:  *steerMuxFlowsPerConn,
				muxMaxConns:      *steerMuxMaxConns,
				transport:        transport,
				failOpen:         *failOpen,
				health:           health,
				answerNCSI:       *answerNCSI,
			}
			// Verify what interception is actually serving this device, so an Edge signing under material this
			// device cannot verify is reported instead of leaving a healthy heartbeat as the only signal.
			// Observation only — it never touches a flow; see the posture note in interception_observation.go.
			// The probe itself is wired once the mux exists, because it needs the same door the traffic uses.
			if interceptionRefusals != nil {
				edgeCfg.interception = newInterceptionWatch(interceptionRefusals,
					func(f string, a ...any) { fmt.Printf("steer: "+f+"\n", a...) })
			}
			// Under fail-open, bound the Edge dial short so a flow falls through to the direct path quickly on
			// an outage (e.g. right after a network switch) instead of hanging on the ~10s default.
			if *failOpen {
				edgeCfg.dialTimeout = 4 * time.Second
			}
			// Agent-mediated step-up: wire the coordinator that opens the Edge-issued step-up portal on an
			// "authenticate" 401. Disabled (--stepup-portal=false) leaves stepUp nil -> Trigger is a no-op and
			// the flow is simply denied. The (T) transport must be on for the step-up loop to bind a grant to
			// this device (the browser flow rides the same tunnel), but the prompt itself is harmless without it.
			if *stepUpPortal {
				edgeCfg.stepUp = newStepUpCoordinator(*stepUpCoalesce, defaultStepUpLauncher, log.Printf)
				fmt.Printf("steer: agent-mediated step-up enabled (coalesce=%s)\n", *stepUpCoalesce)
			}
			// Warn-stage (S3) passive notice: on a steer-mux WARN frame, show a "this connection is monitored"
			// tray balloon (coalesced per service|destination). The flow is already allowed — nothing is held.
			edgeCfg.warn = newWarnNotifier(defaultWarnLauncher, log.Printf)
			fmt.Println("steer: East-West Warn-stage notice enabled (passive toast on WARN frame)")
			// Steer-exclusion reverse telemetry + (optional) admin-managed signed exclusions. The effective-set
			// REPORT — admin observability of what this device actually bypasses, including the local --bypass-app
			// baseline the server never issued — must run even with NO signed policy: a box carrying only a local
			// --bypass-app is exactly the unmanaged-bypass case an admin most needs to see. So the loop is gated on
			// the (T) transport (the report needs the mTLS device identity), NOT on --agent-policy-pin. A pin
			// ADDITIONALLY enables the signed fetch+verify+merge+apply (live.set -> appBypass.setAppSubs / wfp re-push).
			agentPin := strings.TrimSpace(*agentPolicyPin)
			if agentPin != "" && !transport.enabled {
				return fmt.Errorf("--agent-policy-pin requires the (T) transport (--edge-transport-url)")
			}
			// Shared between the signed-policy sync (which verifies and PUBLISHES the operator's stale-before
			// declaration) and the renewal scheduler (which READS it). One verified fetch feeds both, so the
			// signature check lives in exactly one place. Nil value = no declaration = ordinary schedule.
			renewCutoff := newRenewalDeclaration()
			if transport.enabled {
				base := strings.TrimSpace(*agentPolicyURL)
				if base == "" {
					base = "https://" + transport.host
				}
				exSync := &exclusionSync{
					client:        transportHTTPClient(transport),
					baseURL:       strings.TrimRight(base, "/"),
					pinHex:        agentPin,
					localBaseline: effectiveBypassApps(*bypassApps, authoredBypass),
					interval:      *agentPolicyRefresh,
					apply:         live.set,
					logf:          log.Printf,
					// Device-state (Phase 1): report the live posture/region alongside the effective exclusions so
					// the CP/console device page can see this device without a separate telemetry channel. A report
					// only lands when the Edge is reachable, so at report time edgeReachable is effectively true —
					// hence deriveProtection(..., true) is the correct runtime protection state to publish here.
					// Report which transport CAs this device trusts, so the CA-rotation readiness view can
					// show whether it is safe to cut over yet.
					pinnedCAFingerprints: transport.pinnedCAFingerprints,
					// The serial of the adopted trust bundle in force, read from the SAME transport as the
					// fingerprints above so the withdrawal gate never sees a serial and a fingerprint set from
					// different realities.
					adoptedTrustSerial: transport.currentTrustSerial,
					// The Edge answers this report with the serial it is distributing; acting on it is what turns a
					// six-hour adoption timer into a next-report one. The comparison uses the SAME accessor the
					// report does, so the value compared and the value reported cannot disagree.
					adoptedTrustSerialNow: transport.currentTrustSerial,
					trustSerialHint: func(offered int64) {
						select {
						case trustWake <- struct{}{}:
							log.Printf("trust_anchor_recovery hint: the Edge is distributing serial %d, this device holds %d — looking now",
								offered, transport.currentTrustSerial())
						default: // a look is already pending; coalesce
						}
					},
					// What this agent would actually put in a ClientHello — the answer the two SNI switches are
					// gated on, which the serial cannot give (an older agent adopts the bundle and ignores the
					// field). Read live, from the same transport that does the dialling.
					sentServerNames: func() (string, string) {
						return transport.activeServerName(), transport.currentRecoverySNI()
					},
					// WHERE a recovering device would actually go, resolved by the SAME function recovery uses.
					//
					// ★ REPORTING THE NAME WAS NOT ENOUGH, AND A PORT WAS CLOSED ON IT (2026-08-20). Sending a
					// recovery SNI says only that this agent can put it in a ClientHello; it says nothing about
					// where the request goes. This agent reported the name while still dialling the dedicated
					// endpoint, so the deployment retired that endpoint on evidence that did not mean what it
					// was read to mean. Behaviour, not capability.
					renewalRecoveryTarget: func() string {
						dial, _, ok := recoveryDial(&transport, currentRecoveryEndpoint(*enrollRenewRecoveryURL, liveRecoveryEndpoint))
						if !ok {
							return ""
						}
						// Contract shared with the macOS agent: "host:port" alone, or "host:port|sni" when a recovery
						// name is in force. BOTH halves are needed to express the accident the gate exists to catch —
						// a device that holds the name and still dials the retired port — and reporting only the
						// address made this device read as "does NOT hold" while it was in fact correct (2026-08-20).
						target := dial.dialTarget()
						if sni := strings.TrimSpace(dial.sendSNI); sni != "" {
							target += "|" + sni
						}
						return target
					},
					// Accept signatures from the provisioned pin PLUS any key published in an adopted trust
					// bundle, so the signing key can be rotated without every device freezing on its last
					// applied policy. Read at each refresh, so a set adopted at runtime takes effect at once.
					policyKeys: func() []string {
						return policyVerificationKeys(agentPin, policyKeyStateDir(resolvedPinPath))
					},
					// The report is the connection a refused device finally makes: carry what it refused, and
					// (inside reportEffective) clear it only after the Edge accepts.
					refusals: transportRefusals,
					// The same channel for the (I) side: which PROCESSES on this device cannot use what
					// interception hands them. Until this existed the fleet could not tell a device that is
					// steering happily from one whose user has no working HTTPS at all.
					interceptionRefusals: interceptionRefusals,
					// Report which of the interception roots the deployment names are actually in this machine's
					// trust store, so the interception-root switch (which would otherwise break every HTTPS site
					// on a device that lacks the new root) has the readiness signal it needs. Wanted list from the
					// adopted bundle; presence from the Windows Root stores.
					interceptionRoots: func() []string {
						if refusalStateDir == "" {
							return nil
						}
						return interceptionRootsPresent(advertisedInterceptionRoots(refusalStateDir))
					},
					// The certificate this device would fall back to if the renewed identity became unusable.
					// Reported so the Edge's retire gate will not retire a CA that still issues this device's
					// safety net — the case that took the fleet down for seven minutes on 2026-08-02.
					fallbackClientCert: func() string {
						// The day-0 credential differs by configuration: a flag names it on the file path, and on an
						// enrolled device it IS the enrolment certificate. Reporting nothing there left the retire
						// gate with no constraint for every device this product installs.
						bootstrap := strings.TrimSpace(*transportClientCert)
						if bootstrap == "" && *configStore {
							bootstrap = filepath.Join(defaultEnrollDir(), "device.crt")
						}
						return fallbackClientCertPEM(deviceIdentityDir, bootstrap)
					},
					// Publish the operator's stale-before declaration from the verified policy so the renewal
					// scheduler reads it without a second fetch or a second signature check.
					publishRenewCutoff: renewCutoff.publish,
					state: func() deviceStateExtra {
						region := strings.TrimSpace(transport.serverName)
						if *regionFailoverOn && transport.active != nil {
							if ae := transport.active.Load(); ae != nil && strings.TrimSpace(ae.serverName) != "" {
								region = strings.TrimSpace(ae.serverName)
							}
						}
						return deviceStateExtra{
							Posture:               string(deriveProtection(disarmed.Load(), captiveActive.Load(), true)),
							FailOpenConfigured:    *failOpen,
							RegionFailoverEnabled: *regionFailoverOn,
							ActiveRegion:          region,
							// server-initiated inbound rule count: wired in a follow-up (this path does not run the
							// inbound runtime); 0 until then.
							ServerInitiatedRuleCount: 0,
						}
					},
				}
				go exSync.run(context.Background())
				if agentPin != "" {
					fmt.Printf("steer: signed steer-exclusion sync enabled (url=%s refresh=%s)\n", exSync.baseURL, exSync.interval)
				} else {
					fmt.Printf("steer: steer-exclusion effective-set reporting enabled (url=%s refresh=%s; no signed policy)\n", exSync.baseURL, exSync.interval)
				}

				// The update-manifest courier. The updater service holds no network identity by design — it
				// verifies a signed envelope against keys baked into its own binary — so the agent, which already
				// has this transport and is already the device the Edge identifies, fetches the envelope and drops
				// it beside the other DSSE state.
				//
				// Deliberately NOT gated on agentPin: the agent does not verify this document, the updater does,
				// with a DIFFERENT key. Requiring the steer-policy pin here would make a deployment that has not
				// adopted signed exclusions unable to update, for a signature this loop never checks.
				if *updateManifestCourier {
					// Two couriers, one type. The manifest says WHAT this device may install and is verified
					// against the update key; the plan says WHEN and whether the fleet is halted, and is
					// verified against the agent-policy key. Different powers, different keys, and neither key
					// is touched here — the agent carries both documents unopened.
					for _, c := range []*signedDocCourier{
						newManifestCourier(&signedDocCourier{
							client:   transportHTTPClient(transport),
							baseURL:  strings.TrimRight(base, "/"),
							interval: *updateManifestRefresh,
							write: func(b []byte) error {
								return courierWriteAtomic(filepath.Join(courierDataDir(), "update-manifest.json"), b)
							},
							logf: log.Printf,
						}),
						newPlanCourier(&signedDocCourier{
							client:   transportHTTPClient(transport),
							baseURL:  strings.TrimRight(base, "/"),
							interval: *updateManifestRefresh,
							write: func(b []byte) error {
								return courierWriteAtomic(filepath.Join(courierDataDir(), "update-plan.json"), b)
							},
							logf: log.Printf,
						}),
					} {
						go c.run(context.Background())
						fmt.Printf("steer: %s courier enabled (url=%s%s refresh=%s)\n", c.name, c.baseURL, c.path, c.interval)
					}

					// ★ AND THE PACKAGE ITSELF, since 2026-08-13. The artifact route now requires the same
					// verified transport identity the two documents do, so the updater — which holds no network
					// identity by design — can no longer fetch it. This process can: it is already the device the
					// Edge identifies, and the bytes land under the exact name updateplatform.StagedPath returns,
					// where the updater already looks. Stage() returns immediately when the digest matches, so
					// nothing over there changed.
					//
					// A THIRD COURIER RATHER THAN A THIRD signedDocCourier: that type reads a bounded body into
					// memory and checks it is a JSON envelope, and this is tens of megabytes with nothing to
					// parse. See the comment on artifactCourier.
					artifacts := &artifactCourier{
						client:     transportHTTPClient(transport),
						baseURL:    strings.TrimRight(base, "/"),
						platform:   manifestPlatform,
						arch:       manifestArch(),
						interval:   *updateManifestRefresh,
						stagedPath: updateplatform.StagedPath,
						logf:       log.Printf,
					}
					go artifacts.run(context.Background())
					fmt.Printf("steer: update-artifact courier enabled (url=%s%s refresh=%s)\n",
						artifacts.baseURL, updateArtifactPath, artifacts.interval)
				}
			}
			// ★★★ VIRTUAL MACHINES ON THIS DEVICE. Armed HERE, with the rest of what steering turns on, because
			// it is part of the same promise: this agent says it carries all outbound traffic, and a guest
			// behind the virtual switch is the part it does not see. See vm_egress.go for the measurement.
			//
			// Said before it is attempted and after: the ONE state an operator must never be left in is a box
			// that looks compliant while guest traffic leaves unseen, so a failure to enforce is loud and the
			// decision itself is printed either way.
			fmt.Println("steer: " + profileVMEgress.Line())
			if err := applyVMEgress(profileVMEgress); err != nil {
				fmt.Fprintf(os.Stderr, "★ WARNING: %v — this box is NOT keeping the decision its profile carries, "+
					"and traffic from virtual machines on it is neither steered nor recorded. Nothing else here "+
					"will say so.\n", err)
			}
			// QUIC block (Windows steer-all default posture): force browsers onto the intercepted TCP path.
			if *blockQUIC {
				if err := addQUICBlock(); err != nil {
					fmt.Fprintf(os.Stderr, "block-quic: %v\n", err)
				} else {
					fmt.Println("steer: QUIC blocked (UDP:443 outbound) -> browsers fall back to intercepted TCP immediately")
					defer removeQUICBlock()
				}
			}
			// NCSI active-probe suppression: under steer-all the OS connectivity active test is genuinely
			// intercepted by the local redirect, so NCSI's anti-hijack heuristic mislabels the link "No Internet"
			// despite working traffic and byte-correct local probe answers (the active test is unsatisfiable).
			// Disable it for the steered lifetime and restore on clean stop, like the DNS takeover below.
			if *ncsiSuppressProbe {
				suppressNCSIActiveProbe()
				defer restoreNCSIActiveProbe()
			}

			//  DNS steering: local DNS proxy -> Edge /steer/dns-query over the (T) tunnel. Mirrors the macOS
			// DsseDNSTunnelProxy. We start the proxy FIRST, then repoint the system resolver at it (the Windows
			// analog of the macOS agent setup), so DNS rides the tunnel with no plaintext leak on the LAN.
			if strings.TrimSpace(*dnsListen) != "" {
				listen := strings.TrimSpace(*dnsListen)
				stopDNS, bound, dp, derr := startDNSProxy(listen, transport, strings.TrimRight(*edgeURL, "/"), *failOpen, health)
				if derr != nil {
					return fmt.Errorf("dns proxy: %w", derr)
				}
				dnsProxyInst = dp
				dnsProxyInst.setAnswerNCSI(*answerNCSI)
				// Optional operator opt-in only (empty by default = no undisclosed third-party egress; review #26).
				if fb := splitCSV(*dnsPublicFallback); len(fb) > 0 {
					dnsProxyInst.setPublicFallback(fb)
				}
				defer stopDNS()
				// Repoint the system resolver at the proxy and restore it on clean stop. Done only after the
				// proxy is listening (and only for the families it bound), so DNS never points at a dead loopback.
				mgr = newResolverManager(bound)
				upstream, rerr := mgr.start()
				if rerr != nil {
					fmt.Fprintf(os.Stderr, "dns_resolver: %v (DNS left on the system resolver — it would leak)\n", rerr)
				} else {
					defer mgr.restore()
					// fail-open: teach the proxy the real upstream resolver(s) to forward to during an Edge outage.
					if *failOpen {
						dnsProxyInst.setFallback(upstream)
						fmt.Printf("steer: fail-open DNS fallback resolver(s): %v\n", upstream)
					}
					// Follow the default route across network switches (Wi-Fi<->wired): periodically re-take-over
					// whatever is now the egress interface so its DNS rides the tunnel too (no un-steered bypass).
					if *dnsReconcile > 0 {
						reconcileStop := make(chan struct{})
						defer close(reconcileStop)
						go func() {
							t := time.NewTicker(*dnsReconcile)
							defer t.Stop()
							for {
								select {
								case <-reconcileStop:
									return
								case <-t.C:
									if disarmed.Load() {
										continue // steering is torn down (sustained Edge outage) — don't re-take-over DNS
									}
									if changed, err := mgr.reconcile(); err != nil {
										fmt.Fprintf(os.Stderr, "dns_resolver: reconcile: %v\n", err)
									} else if changed && *failOpen {
										dnsProxyInst.setFallback(mgr.upstreams())
									}
								}
							}
						}()
						fmt.Printf("steer: DNS default-route reconcile every %s (follows Wi-Fi<->wired switches)\n", *dnsReconcile)
					}
					// React to a network change the MOMENT Windows reports it (Wi-Fi roam / Wi-Fi<->wired / new DHCP
					// lease) — re-converge DNS onto the now-active interface immediately, rather than waiting up to
					// one reconcile poll. This is what makes a switch settle fast/cleanly. The poll above remains as
					// a backstop. While disarmed (sustained outage), the recovery monitor owns re-arm, so we skip.
					netChangeStop := make(chan struct{})
					defer close(netChangeStop)
					go watchNetworkChanges(netChangeStop, func() {
						// Nudge the captive-portal bootstrap controller first (non-blocking): a new network is
						// exactly when a captive portal may need escaping. This fires regardless of disarmed state.
						select {
						case captiveTrigger <- struct{}{}:
						default:
						}
						if disarmed.Load() {
							return
						}
						fmt.Println("net_change: network change — re-converging DNS onto the active interface")
						if changed, err := mgr.reconcile(); err != nil {
							fmt.Fprintf(os.Stderr, "net_change: reconcile: %v\n", err)
						} else if changed && *failOpen {
							dnsProxyInst.setFallback(mgr.upstreams())
						}
					})
					fmt.Println("steer: watching network-change events (immediate DNS reconcile on roam/switch)")
				}
			}

			// Disarm / re-arm primitives + their two consumers (the fail-open recovery monitor and the
			// captive-portal bootstrap controller). Both consumers tear steering down to the NATIVE network and
			// re-apply it; only their TRIGGERS differ — fail-open on a sustained mid-session outage, captive on
			// netchange + Edge-unreachable + captive-positive. Defined here (mgr/dnsProxyInst exist) and shared.
			// Skipped when neither is active.
			useWFP := *backend == "wfp"
			// onDisarm/onRearm are HOISTED here (not scoped inside the block below) so the region-failover loop
			// further down can also drive them: under TERMINAL fail-open the region loop escalates to a self-disarm
			// on region exhaustion and re-arms on recovery, reusing the exact same disarm/re-arm as fail-open.
			var onDisarm, onRearm func()
			if *failOpen || (useWFP && mgr != nil) {
				edgeURLForProbe := strings.TrimRight(*edgeURL, "/")
				onDisarm = func() {
					fmt.Println("steer_disarm: REMOVING steering (stop WFP redirect, reset DNS to automatic, unblock QUIC) so the box uses its NATIVE network. Will re-arm on recovery.")
					if useWFP {
						// Verified, not best-effort. This runs when the box is ALREADY in trouble (a sustained
						// Edge outage, or a captive portal), so it is the worst possible moment to believe a
						// disarm that did not happen: the operator would read "steer_disarm: REMOVING steering"
						// and conclude the box is on its native network while it is refusing every connection.
						if v := removePolicyVerified(); !v.Verified {
							fmt.Printf("disarm: WARNING the WFP redirect is NOT confirmed cleared: %s\n", v.Reason)
						}
					}
					if mgr != nil {
						// Reset to AUTOMATIC (DHCP), not the captured static servers: disarm may be due to a Wi-Fi
						// roam to a different network where the old servers are unreachable. Automatic = the new
						// network's DHCP resolver, which is what actually recovers the box.
						mgr.restoreToAutomatic()
					}
					if *blockQUIC {
						removeQUICBlock()
					}
					disarmed.Store(true)
				}
				onRearm = func() {
					fmt.Println("steer_rearm: re-applying steering (WFP redirect, DNS takeover, QUIC block).")
					if useWFP {
						if err := pushPolicy(capCfg); err != nil {
							fmt.Printf("rearm: pushPolicy: %v\n", err)
						}
					}
					if mgr != nil {
						if _, err := mgr.converge(); err != nil {
							fmt.Printf("rearm: converge: %v\n", err)
						}
						// Refresh the fail-open upstream from the (possibly NEW) network's DNS that converge just
						// re-captured, so a subsequent outage forwards to a reachable resolver, not the old one.
						if dnsProxyInst != nil {
							dnsProxyInst.setFallback(mgr.upstreams())
						}
					}
					if *blockQUIC {
						addQUICBlock()
					}
					disarmed.Store(false)
				}

				// Fail-open recovery + self-disarm monitor. While the Edge is reachable it does nothing; once
				// per-flow fail-open trips the circuit it probes the Edge and a SUSTAINED outage escalates to a
				// full disarm, then recovery re-arms.
				if *failOpen {
					monitorStop := make(chan struct{})
					defer close(monitorStop)
					go runEdgeHealthMonitor(monitorStop, health, func() bool { return probeEdge(transport, edgeURLForProbe) }, *failOpenProbe, *failOpenDisarmAfter, &disarmed, onDisarm, onRearm)
					fmt.Printf("steer: fail-open recovery monitor probing the Edge every %s (self-disarm after %s of outage; auto re-arm on recovery)\n", *failOpenProbe, *failOpenDisarmAfter)
				}

				// Captive-portal bootstrap controller. Runs when NOT --fail-open: it disarms ONLY on netchange +
				// Edge-unreachable + captive-POSITIVE, so during normal operation (Edge reachable) it never acts.
				// Gated OFF under --fail-open because the fail-open recovery monitor already disarms to the native
				// network on an Edge outage (providing the same connectivity captive needs) and they share
				// onDisarm/onRearm + `disarmed`: running both would let the captive T_max rearm re-apply fail-closed
				// steering while fail-open still wants the native network (a transient DARK regression). One owner of
				// disarm/rearm at a time. (Co-existence with coordinated ownership is a future enhancement.) Under
				// TERMINAL fail-open the region-failover loop is that single owner (it disarms on region exhaustion
				// and re-arms on recovery), so captive is gated OFF there too.
				if useWFP && mgr != nil && !*failOpen && !terminalFailOpen {
					capStop := make(chan struct{})
					defer close(capStop)
					// Live captive timing (seconds), settable by the signed tuning policy (M5) without a restart.
					// FLOOR the seed at 1s: the flags are time.Duration and a sub-second value would truncate to 0
					// seconds, and timeout()/probeInterval()==0 makes newTimer(0) fire immediately — a probe storm
					// (0 probe interval) or an instant window flap (0 T_max). The tuning policy is already clamped in
					// ApplyCaptive; this floors the flag/profile SEED, the only other write source.
					floorSec := func(d time.Duration) int64 {
						if s := int64(d.Seconds()); s >= 1 {
							return s
						}
						return 1
					}
					var captiveTimeoutSec, captiveProbeSec atomic.Int64
					captiveTimeoutSec.Store(floorSec(*captiveTimeout))
					captiveProbeSec.Store(floorSec(*captiveProbeInterval))
					capDeps := captiveDeps{
						probeEdge: func() bool { return probeEdge(transport, edgeURLForProbe) },
						detectCaptive: func() captiveVerdict {
							return detectCaptive(defaultCaptiveProbeHostsWindows, newCaptiveProbe(mgr.upstreams))
						},
						disarm: onDisarm,
						rearm:  onRearm,
						osCaptiveDetect: func(on bool) {
							// Only meaningful when we suppress the OS active probe under steer-all. Entering the
							// window RESTORES it so Windows runs captive detection + shows the native sign-in; on
							// re-arm we re-suppress it.
							if !*ncsiSuppressProbe {
								return
							}
							if on {
								restoreNCSIActiveProbe()
							} else {
								suppressNCSIActiveProbe()
							}
						},
						setActive:     func(b bool) { captiveActive.Store(b) },
						timeout:       func() time.Duration { return time.Duration(captiveTimeoutSec.Load()) * time.Second },
						probeInterval: func() time.Duration { return time.Duration(captiveProbeSec.Load()) * time.Second },
						now:           time.Now,
						newTimer:      realTimer,
						logf:          func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
					}
					// Kick an initial evaluation (a boot straight onto a captive network).
					select {
					case captiveTrigger <- struct{}{}:
					default:
					}
					go runCaptiveController(capStop, captiveTrigger, capDeps)
					fmt.Printf("steer: captive-portal bootstrap ON (timeout=%s probe=%s; disarms only on netchange+Edge-unreachable+captive-positive)\n", *captiveTimeout, *captiveProbeInterval)

					// L3 live tuning (M5): pull the signed tuning policy over (T) and apply captive timing centrally
					// without a restart. Gated on the signed-policy pin + transport (same trust as steer-exclusions);
					// a bad/absent bundle keeps the current settings.
					if strings.TrimSpace(*agentPolicyPin) != "" && transport.enabled {
						base := strings.TrimSpace(*agentPolicyURL)
						if base == "" {
							base = "https://" + transport.host
						}
						tuner := agenttuning.Syncer{
							URL:    strings.TrimRight(base, "/") + "/steer/agent-tuning",
							PinHex: strings.TrimSpace(*agentPolicyPin),
							// Same accepted-key set as every other signed-policy path here, read fresh per fetch so
							// an adoption that happens while this Syncer is running is picked up.
							Keys: func() []string {
								return policyVerificationKeys(strings.TrimSpace(*agentPolicyPin), policyKeyStateDir(resolvedPinPath))
							},
							Client:   transportHTTPClient(transport),
							Interval: *agentPolicyRefresh,
							Apply: func(p agenttuning.TuningPolicy) {
								cur := agenttuning.CaptiveSettings{TimeoutSec: int(captiveTimeoutSec.Load()), ProbeIntervalSec: int(captiveProbeSec.Load())}
								eff := p.ApplyCaptive(cur)
								captiveTimeoutSec.Store(int64(eff.TimeoutSec))
								captiveProbeSec.Store(int64(eff.ProbeIntervalSec))
								fmt.Printf("steer_captive_tuning_applied timeout=%ds probe=%ds source=tenant\n", eff.TimeoutSec, eff.ProbeIntervalSec)
							},
							Logf: log.Printf,
						}
						tunerStop := make(chan struct{})
						defer close(tunerStop)
						tctx, tcancel := context.WithCancel(context.Background())
						go func() { <-tunerStop; tcancel() }()
						go tuner.Run(tctx)
						fmt.Printf("steer: agent tuning sync enabled (url=%s refresh=%s)\n", tuner.URL, *agentPolicyRefresh)
					}
				}
			}

			// Read-only status endpoint for the tray (M2b). Opt-in via --status-listen; running services that do
			// not set it are unaffected. Serves protection/tenant/region/posture (no secrets). A background poller
			// derives the protection state from the live disarmed/captive flags + an Edge reachability probe.
			if strings.TrimSpace(*statusListen) != "" {
				posture := "fail-closed"
				if *failOpen {
					posture = "fail-open"
				}
				region := strings.TrimSpace(transport.serverName)
				if region == "" {
					region = strings.TrimRight(*edgeURL, "/")
				}
				holder := agentstatus.NewHolder(agentstatus.Status{Protection: agentstatus.Stopped})
				holder.Set(func(s *agentstatus.Status) {
					s.Tenant, s.Group, s.Posture, s.Region = profTenant, profGroup, posture, region
				})
				if ln, lerr := net.Listen("tcp", strings.TrimSpace(*statusListen)); lerr != nil {
					fmt.Fprintf(os.Stderr, "status-listen: %v\n", lerr)
				} else {
					statusStop := make(chan struct{})
					defer close(statusStop)
					go serveStatus(statusStop, ln, holder, log.Printf)
					edgeURLForStatus := strings.TrimRight(*edgeURL, "/")
					go func() {
						// Fast fields (disarmed/captive) refresh every 3s, but the Edge REACHABILITY probe is a full
						// (T) mTLS dial+CONNECT — probing it every 3s would add a constant tunnel handshake load per
						// device just to paint the tray. Probe at most every 15s and reuse the cached result.
						t := time.NewTicker(3 * time.Second)
						defer t.Stop()
						var lastProbe time.Time
						edgeOK := false
						for {
							select {
							case <-statusStop:
								return
							case <-t.C:
								if time.Since(lastProbe) >= 15*time.Second {
									edgeOK = probeEdge(transport, edgeURLForStatus)
									lastProbe = time.Now()
								}
								p := deriveProtection(disarmed.Load(), captiveActive.Load(), edgeOK)
								holder.Set(func(s *agentstatus.Status) {
									s.Protection, s.EdgeReachable, s.UpdatedUnix = p, edgeOK, time.Now().Unix()
								})
							}
						}
					}()
					fmt.Printf("steer: status endpoint on http://%s/status (read-only, tray)\n", strings.TrimSpace(*statusListen))
				}
			}

			// Region failover loop: probe the tenant's signed allowed-region endpoints, steer through the nearest
			// healthy one, fail over in-boundary, fail closed when none are healthy. Started here (after the DNS
			// block) so it can prefer the box's real upstreams for out-of-band probe/resolve. It swaps the live
			// endpoint via transport.active, which every consumer (per-flow CONNECT, DNS proxy, list client) follows.
			if *regionFailoverOn {
				// Seed: the MDM bootstrap list, anchored on the (T) bootstrap endpoint as the home region.
				seedList, serr := parseRegionSeed(*regionSeed)
				if serr != nil {
					return fmt.Errorf("region-failover seed: %w", serr)
				}
				// regionPriority was parsed and validated at startup (above), unconditionally — see the comment
				// there for why it must not be parsed inside this branch.
				home := strings.ToLower(strings.TrimSpace(*regionHome))
				if home == "" {
					if len(seedList) > 0 {
						home = seedList[0].Region
					} else {
						home = "home"
					}
				}
				hasHome := false
				for _, e := range seedList {
					if e.Region == home {
						hasHome = true
						break
					}
				}
				if !hasHome {
					seedList = append([]regionfailover.RegionEndpoint{{Region: home, Endpoint: *edgeTransportURL}}, seedList...)
				}
				rfUpstreams := func() []string {
					if mgr != nil {
						return mgr.upstreams()
					}
					return nil
				}
				rfBase := strings.TrimSpace(*agentPolicyURL)
				if rfBase == "" {
					rfBase = "https://" + transport.host
				}
				rfActions := &windowsRegionActions{
					active: transport.active, upstreams: rfUpstreams, logf: log.Printf,
					// The capture's Edge destination bypass follows the region. Without this the loop guard
					// keeps naming the region the device just left, and the new region's tunnel runs on the
					// AppID self-exclusion alone (2026-08-30).
					onEndpoint: func(addrs []string) {
						if capCfg.dests == nil || len(addrs) == 0 {
							return
						}
						ap, ok := resolveAddrPort(addrs[0])
						if !ok || !capCfg.dests.setEdge(ap) {
							return
						}
						fmt.Printf("steer: Edge destination bypass follows the region -> %v\n", ap)
					},
				}
				rf := newRegionFailover(
					seedList, home,
					newWindowsRegionProbe(transport, 2*time.Second, rfUpstreams),
					regionFailoverActions{
						switchTo: rfActions.switchTo,
						// Phase 4: on region EXHAUSTION (StateFailClosed = ALL in-boundary regions down — a single
						// region blip never reaches here, the engine fails over instead), TERMINAL fail-open escalates
						// to a self-disarm to the native network instead of staying DARK. Fires once on the transition
						// (act() is edge-triggered). Without terminal posture, unchanged fail-CLOSED behavior.
						failClosed: func(reason string) {
							if terminalFailOpen && onDisarm != nil && !disarmed.Load() {
								fmt.Printf("region_failover: ALL in-boundary regions exhausted — escalating to TERMINAL fail-open (UNMEDIATED native egress): %s\n", reason)
								onDisarm()
								return
							}
							log.Printf("region_failover: egress DENIED (fail-closed): %s", reason)
						},
						surfaceDenied: func(reason string) { log.Printf("region_failover: device admission DENIED: %s", reason) },
						// Phase 4: recovering to a healthy region re-arms from terminal fail-open back to in-boundary
						// steering (edge-triggered on the fail-closed -> connected transition). This is the auto-recovery
						// path — only an explicit STOP is terminal.
						connectedOK: func(ep regionfailover.RegionEndpoint) {
							if onRearm != nil && disarmed.Load() {
								fmt.Println("region_failover: a region recovered — re-arming from terminal fail-open back to in-boundary steering")
								onRearm()
							}
						},
					},
					regionFailoverOptions{
						client:  transportHTTPClient(transport),
						baseURL: strings.TrimRight(rfBase, "/"),
						pinHex:  strings.TrimSpace(*agentPolicyPin),
						policyKeys: func() []string {
							return policyVerificationKeys(strings.TrimSpace(*agentPolicyPin), policyKeyStateDir(resolvedPinPath))
						},
						regionPriority: regionPriority,
						// Publish the fleet-wide name onto the SAME transport every dial reads, so a refreshed
						// list takes effect on the next handshake rather than at the next restart.
						publishFleetServerName: transport.setFleetServerName,
						listRefresh:            *regionListRefresh,
						healthTick:             *regionHealthInterval,
						unhealthyStrike:        *regionUnhealthyStrikes,
						logf:                   log.Printf,
					},
				)
				rfCtx, rfCancel := context.WithCancel(context.Background())
				defer rfCancel()
				if stop != nil {
					go func() { <-stop; rfCancel() }()
				}
				go rf.run(rfCtx, nil, nil)
				// ★★★ AND THEN SAY WHICH REGION IT IS ACTUALLY ON (2026-08-30).
				//
				// The banner below names home= from the profile. nearest-healthy decides where this device
				// GOES, and the two are routinely different: this box armed straight onto the non-home region,
				// the peer dropped the home region, nothing happened, and three minutes of uninterrupted
				// traffic read as a flawless zero-loss failover. It was a device sitting in the region that
				// stayed up. A banner that names the intention and not the outcome invites exactly that
				// reading, so the selection is reported as soon as it exists.
				go reportSelectedRegion(rfCtx, transport, home)
				fmt.Printf("steer: region-failover enabled — home=%q, %d seed region(s); nearest-healthy + in-boundary failover + fail-closed (probe every %s, list refresh every %s)\n", home, len(seedList), *regionHealthInterval, *regionListRefresh)
			}

			// W-2 liveness, alongside steering. `--mode heartbeat` is an exclusive mode that returns long
			// before this point, so a redirect-mode agent used to send no beats at all: the Edge saw an
			// actively-enforcing device as dark and revoked its trust. Never fatal to steering.
			startBackgroundHeartbeat(heartbeatConfig{
				deviceID: *deviceID, // empty => falls back to the (T) client cert CN
				tenantID: *deviceTenant,
				// The VERIFIED profile's tenant, for the runstate record only — never for self-registration.
				// An MSI box carries no --device-tenant (the service line is two flags), so the plan-addressing
				// check would have had a device identity and an empty tenant on every device the product
				// installs, which weakens it to device-only exactly where it is meant to work. Registration is
				// deliberately NOT changed: its refusal to self-register into an unset tenant is a separate,
				// conservative rule about writing to the Edge, and widening it is not this change's business.
				profileTenantID: profTenant,
				interval:        *heartbeatInterval,
				transport:       transport,
			}, stop)

			// Anchor self-healing + automated device-certificate renewal, also alongside steering and for the
			// same reason: an exclusive mode would not run in the configuration the service actually uses.
			// Never fatal to steering — both log and retry, and the existing material stays in use.
			//
			// liveRecoveryEndpoint connects the two: a signed trust bundle may name the certificate-recovery
			// endpoint (possibly port-only), and the renewal loop must see it without a restart — the device
			// that needs it is exactly the one that was off too long to have been told any other way. Seeded
			// from a previously adopted bundle so the value survives a restart too.
			trustStateDir := ""
			if strings.TrimSpace(resolvedPinPath) != "" {
				trustStateDir = filepath.Dir(resolvedPinPath)
				if ep := adoptedRecoveryEndpoint(trustStateDir); ep != "" {
					liveRecoveryEndpoint.Store(&ep)
				}
				// The announced names are NOT restored here. They are restored beside the transport, before
				// anything dials — see the comment there. Doing it in this block was the defect: every dial
				// in between went out under the provisioned name.
			}
			startTrustAnchorRecovery(&transport, trustRecoveryConfig{
				stateDir: trustStateDir,
				pinHex:   strings.TrimSpace(*agentPolicyPin),
				// Which organization this device belongs to, from the signed profile. Without it a serial from
				// somebody else's distribution gates this one's, and a correctly-signed document belonging to
				// another organization is adopted without comment — both measured on this box.
				tenantID:     strings.TrimSpace(profTenant),
				bundleURL:    *trustBundleURL,
				wake:         trustWake,
				liveRecovery: liveRecoveryEndpoint,
			})
			startCertificateRenewal(&transport, deviceIdentityDir, *enrollRenewRecoveryURL, liveRecoveryEndpoint, &renewCutoff.cutoff, renewCutoff.wake)

			// Who can rewrite this agent? Every guarantee it makes is void if somebody else can replace it, and
			// that precondition was previously only ever checked by a person reading ACLs.
			reportSelfIntegrity(log.Printf)

			// Which optional companions actually made it onto this machine. The branded step-up window was
			// implemented, wired, and installed nowhere — and because its absence only degrades a feature at
			// the moment it is used, it went unnoticed. Report it at startup instead.
			reportCompanions()

			// Wire the capture backend to the edge-steering layer via the SteeringCapture interface; the
			// factory lets the supervisor recreate the backend after a failure (durable operation).
			newCapture := func() (SteeringCapture, error) {
				switch *backend {
				case "wfp":
					return newWFPCapture(capCfg)
				case "windivert", "":
					return newWinDivertCapture(capCfg)
				default:
					return nil, fmt.Errorf("unknown --backend %q (want windivert|wfp)", *backend)
				}
			}
			steer := func(c SteeringCapture) { edgeSteerer{cfg: edgeCfg}.run(c) }
			if *permanent {
				fmt.Println("steer: permanent mode (supervised; restarts backend on failure)")
				return superviseCapture(newCapture, steer, superviseConfig{permanent: true, backoff: defaultSupervisorBackoff, stop: stop})
			}
			// One-shot (contained burst) -- the established safe pattern for verification.
			capture, err := newCapture()
			if err != nil {
				return err
			}
			defer capture.Close()
			steer(capture)
			return nil
		}

		if *serviceRun {
			// Launched by the SCM: run under service control (clean stop closes the capture + teardown).
			// (Log redirection already happened at the top of main, before the fail-open guard/banner.)
			if err := runAsService(runSteerAll); err != nil {
				fmt.Fprintf(os.Stderr, "service: %v\n", err)
				os.Exit(1)
			}
			return
		}
		if err := runSteerAll(nil); err != nil {
			fmt.Fprintf(os.Stderr, "redirect: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown --mode %q\n", *mode)
		os.Exit(1)
	}
}

// argsWithoutFlag drops a boolean flag (any of -name / --name / --name=...) from an arg slice, used to bake
// the remaining steer flags into the installed service's command line.
func argsWithoutFlag(args []string, name string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		t := strings.TrimLeft(a, "-")
		if t == name || strings.HasPrefix(t, name+"=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

func splitCSV(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// resolveAddrPort turns a "host:port" (host may be an IPv4 literal or a name) into an IPv4 AddrPort.
func resolveAddrPort(hostPort string) (netip.AddrPort, bool) {
	trimmed := strings.TrimSpace(hostPort)
	host, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		// No port given: treat the whole token as an IP/host and bypass ALL ports to it
		// (port 0 = wildcard). This is how a "whole-host" exception (e.g. a domain controller,
		// whose dynamic RPC uses ephemeral ports) is expressed; the driver/windivert side match
		// port 0 against any connection port.
		return resolveHostWildcard(trimmed)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port < 1 || port > 65535 {
		return netip.AddrPort{}, false
	}
	if a, err := netip.ParseAddr(host); err == nil && a.Is4() {
		return netip.AddrPortFrom(a, uint16(port)), true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte{v4[0], v4[1], v4[2], v4[3]}), uint16(port)), true
		}
	}
	return netip.AddrPort{}, false
}

// resolveHostWildcard resolves a bare IP/host (no port) to an IPv4 AddrPort with port 0, meaning "bypass
// every port to this destination". Used for whole-host exceptions like a domain controller.
func resolveHostWildcard(host string) (netip.AddrPort, bool) {
	if a, err := netip.ParseAddr(host); err == nil && a.Is4() {
		return netip.AddrPortFrom(a, 0), true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte{v4[0], v4[1], v4[2], v4[3]}), 0), true
		}
	}
	return netip.AddrPort{}, false
}

func parseAddrPorts(hostPorts []string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, hp := range hostPorts {
		if ap, ok := resolveAddrPort(hp); ok {
			out = append(out, ap)
		}
	}
	return out
}

// edgeEndpoint extracts the edge's host:port from the edge URL and resolves it to an IPv4 AddrPort.
func edgeEndpoint(edgeURL string) (netip.AddrPort, bool) {
	hostPort, err := edgeHostPort(strings.TrimRight(edgeURL, "/"))
	if err != nil {
		return netip.AddrPort{}, false
	}
	return resolveAddrPort(hostPort)
}
