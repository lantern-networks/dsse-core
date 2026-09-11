package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/neflowcopy"
	"github.com/lantern-networks/dsse-core/tunnel"
)

const (
	connectorIDHeader     = "x-connector-id"
	connectorSecretHeader = "x-connector-secret"
)

const (
	runtimeCopyRoundTripPath                = "/network-extension/runtime-copy/round-trip"
	runtimeCopyRoundTripRequestSchema       = "network_extension_runtime_copy_round_trip_request.v1"
	runtimeCopyRoundTripResponseSchema      = "network_extension_runtime_copy_round_trip_response.v1"
	runtimeCopyRoundTripErrorResponseSchema = "network_extension_runtime_copy_round_trip_error.v1"
	runtimeCopyRoundTripMaxRequestBodyBytes = 1 << 20
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18090", "connector private app listen address")
	privateBaseURLOverride := flag.String("private-base-url", "", "optional connector private base URL registered with Edge; defaults to http://<listen>")
	edgeURL := flag.String("edge-url", "https://127.0.0.1:443", "edge base URL (HTTPS; mTLS pinned via --edge-transport-ca outside --dev-mode)")
	edgeEndpoints := flag.String("edge-endpoints", "",
		"the deployment's Edge doors, in the order this connector should try them: \"region-a=https://agents.example;"+
			"region-b=https://agents-b.example\" (bare URLs are accepted too). A connector reaches the FLEET, not one "+
			"Edge: when the door in use stops answering it moves to the next, and returns to the first once a "+
			"connection holds. Empty = use --edge-url alone, which is the previous behaviour exactly.")
	connectorID := flag.String("connector-id", "conn_lab_001", "connector id")
	connectorSecret := flag.String("connector-secret", "local-connector-secret", "shared secret for local connector registration and heartbeat")
	connectorBootstrapSecret := flag.String("connector-bootstrap-secret", "", "optional bootstrap secret for connector registration; defaults to connector-secret")
	tenantID := flag.String("tenant-id", "tenant_lab_001", "tenant id")
	connectorGroupID := flag.String("connector-group-id", "cgrp_lab_001", "connector group id")
	edgeRegionID := flag.String("edge-region-id", "local", "edge region id")
	edgeClusterID := flag.String("edge-cluster-id", "local-edge-001", "edge cluster id")
	policyBundleID := flag.String("policy-bundle-id", "pb_lab_20260522_001", "policy bundle id")
	policyBundleVersion := flag.String("policy-bundle-version", "2026.05.22.001", "policy bundle version")
	enableTunnel := flag.Bool("enable-tunnel", true, "connect outbound websocket tunnel to local edge")
	skipEdgeRegistration := flag.Bool("skip-edge-registration", false, "skip Edge registration and heartbeat for local endpoint availability checks; requires --enable-tunnel=false")
	protectedAppMapPath := flag.String("protected-app-map", "", "protected app map JSON path used as the connector-side TCP route allowlist")
	identitySyncFile := flag.String("identity-sync-file", "", "optional Human Identity import JSON file to sync through Edge runtime identity-source endpoints")
	identitySyncSource := flag.String("identity-sync-source", "", "optional Human Identity source name to select from due source policies")
	identitySyncStateFile := flag.String("identity-sync-state-file", "", "optional local JSON file where the last connector identity sync result is written")
	identitySyncInterval := flag.Duration("identity-sync-interval", 5*time.Minute, "Human Identity sync interval; set to 0 or negative for one-shot sync")
	edgeTransportCA := flag.String("edge-transport-ca", "", "PEM path of the Edge transport trust anchors for Connector↔Edge TLS — every certificate in the file is a trusted anchor, so a rotation overlays old+new instead of swapping (required outside --dev-mode)")
	connectorClientCert := flag.String("connector-client-cert", "", "PEM path of the Connector Identity certificate for mTLS to the Edge")
	connectorClientKey := flag.String("connector-client-key", "", "PEM path of the Connector Identity private key for mTLS to the Edge")
	devMode := flag.Bool("dev-mode", false, "relax mandatory mTLS for local bring-up (plaintext/anon TLS allowed)")
	// ★★★ A CONNECTOR ANNOUNCES WHAT IT WAS TOLD TO FRONT, AND A NEW DEPLOYMENT IS TOLD NOTHING (2026-09-04,
	// found by building a deployment from the published tree and looking at what its first connector claimed).
	//
	// This list used to be a hard-coded five: app_dummy_https, app_internal_web, app_dummy_ssh,
	// app_dummy_postgres, app_dummy_rdp. Every connector in every deployment registered them, so the first
	// thing an administrator saw on a brand-new site was five private applications that do not exist, in a
	// screen whose whole purpose is to say what is reachable. There is no way to tell, from that screen, that
	// they are furniture.
	//
	// Empty is the honest default: this connector fronts what an administrator publishes to it. That path is
	// the connector GROUP — the Console stamps a published catalogue entry with the group, and the Edge
	// resolves a live connector in that group (connectorForApplication's group fallback). Enumerating ids here
	// is the older, connector-authored way, kept for a site that wants it.
	applicationIDs := flag.String("applications", "", "comma-separated application ids this connector fronts. Empty (the default) announces none: applications reach this connector by being published to its connector group, which is the administrator's act, not this process's claim")
	// ★ THE SAMPLE INTRANET, BEHIND ITS OWN SWITCH AND NOT BEHIND -dev-mode. The five endpoints below are what
	// the smoke tests read. Hanging them off -dev-mode would have meant a lab that wants to see a private
	// application has to relax mandatory mTLS to get one — the reference deployment deleted -dev-mode for
	// exactly that reason — so this says what it does and nothing else.
	sampleApplications := flag.Bool("sample-applications", false, "serve five sample private applications on this connector's listener and announce them. For labs and smoke tests; a deployment fronts real applications published to its connector group")
	enrollmentToken := flag.String("token", "", "one-time enrollment token from the Admin Console 'Add connector' (first run only). It carries the Edge URL, tenant, and Site, so no other coordinates are needed; requires --state-dir.")
	// ★ SO THE RENEWAL CAN BE MEASURED. A connector's certificate is issued for 60 days, so the renewal path
	// would otherwise first run on a live deployment forty days after anybody could have watched it. This makes
	// "renew now, then exit" a thing an operator — or a check — can ask for.
	renewNow := flag.Bool("renew-identity-now", false,
		"renew this connector's identity certificate immediately and exit, instead of running. Requires --state-dir "+
			"and an already-enrolled connector; used to verify the renewal path without waiting for expiry")
	stateDir := flag.String("state-dir", "", "directory where the connector persists its identity after enrolling from --token; every later start reconnects from it with NO token and NO coordinate flags")
	flag.Parse()

	// edgeServerName is the organization's own door name, resolved from the token or the saved state below.
	// It is not a flag: an operator running the connector by hand against their own PKI passes --edge-url and
	// their own anchors, and the name is then the dialled host, as it has always been.
	var edgeServerName string

	// Bootstrap resolution: a first run consumes --token and persists identity+coordinates to --state-dir; every
	// later run loads that state and reconnects with no token (which is single-use and already invalid by then).
	// With no --state-dir this is a no-op and the explicit flags above are used unchanged.
	if firstRun, err := resolveConnectorEnrollment(*stateDir, *enrollmentToken, connectorEnrollmentFlags{
		EdgeURL: edgeURL, TenantID: tenantID, Site: connectorGroupID, ConnectorID: connectorID,
		ConnectorSecret: connectorSecret, BootstrapSecret: connectorBootstrapSecret,
		Region: edgeRegionID, Cluster: edgeClusterID, EdgeTransportCA: edgeTransportCA,
		EdgeEndpoints: edgeEndpoints, EdgeServerName: &edgeServerName,
	}); err != nil {
		log.Fatalf("connector enrollment: %v", err)
	} else if strings.TrimSpace(*stateDir) != "" {
		if firstRun {
			log.Printf("connector enrolled from token into site %q as %s (state saved to %s)", *connectorGroupID, *connectorID, *stateDir)
		} else if st, ok, _ := loadConnectorState(filepath.Join(*stateDir, "connector-state.json")); ok {
			log.Printf("connector reconnecting from saved state %s as %s (site %q)", *stateDir, st.ConnectorID, st.Site)
		} else {
			// ★ SAYING "reconnecting from saved state" WHEN THERE IS NONE sent me looking for a connector that
			// had never enrolled (2026-08-23). The state-dir was empty and the line named the connector id from
			// the FLAGS, which read as proof the directory held it.
			log.Printf("connector state dir %s holds no enrollment; starting from the flags given", *stateDir)
		}
	}

	// ★ AND THE CERTIFICATE THE EDGE REQUIRES. Enrolment used to stop at the state file, so the printed command
	// brought a connector up to the point of refusing to start for want of an identity — see identity.go.
	if issued, ierr := func() (bool, error) {
		st, ok, lerr := loadConnectorState(filepath.Join(strings.TrimSpace(*stateDir), "connector-state.json"))
		if strings.TrimSpace(*stateDir) == "" || lerr != nil || !ok {
			return false, nil // no state-dir, or nothing enrolled: the explicit flags are the whole story
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		return ensureConnectorIdentity(ctx, *stateDir, st, *connectorBootstrapSecret, connectorClientCert, connectorClientKey)
	}(); ierr != nil {
		// ★ AND A FAILED FIRST RUN LEAVES NOTHING BEHIND (2026-08-23). Enrollment writes the state file BEFORE
		// the certificate is obtained, so a first run that could not obtain one left a state dir holding an
		// identity with no certificate and no way to get one: the next start has no --token to present, and
		// this connector could never come up again in that directory. The operator's obvious move — run the
		// same command again — is now the right one, because the bootstrap secret was not consumed by the
		// attempt and there is no half-enrolled state to trip over.
		if strings.TrimSpace(*enrollmentToken) != "" && strings.TrimSpace(*stateDir) != "" {
			if rerr := os.Remove(filepath.Join(strings.TrimSpace(*stateDir), "connector-state.json")); rerr == nil {
				log.Printf("connector identity: rolled back this first-run enrollment, so running the same " +
					"command again starts clean")
			}
		}
		log.Fatalf("connector identity: %v", ierr)
	} else if issued {
		log.Printf("connector identity issued by this organization's device CA and stored in %s", *stateDir)
	}

	// build the Connector↔Edge encrypted-transport TLS config (pin Edge CA + present mTLS identity).
	edgeTLSConfig, err := buildConnectorTLSConfig(connectorTransportConfig{
		EdgeCAFile:     *edgeTransportCA,
		ClientCertFile: *connectorClientCert,
		ClientKeyFile:  *connectorClientKey,
		DevMode:        *devMode,
		ServerName:     edgeServerName,
	})
	if err != nil {
		log.Fatalf("connector transport TLS: %v", err)
	}
	if edgeTLSConfig != nil && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(*edgeURL)), "https://") {
		log.Fatalf("connector transport TLS is configured but --edge-url %q is not https", *edgeURL)
	}
	// ★★★ THE DOORS THIS CONNECTOR MAY USE, in order. See region_failover.go: a connector had exactly one and
	// retried it for ever, so one region being away took everything behind that connector with it.
	doors := parseConnectorEndpoints(*edgeEndpoints)
	if doors.count() == 0 {
		doors = parseConnectorEndpoints(*edgeURL)
	}
	if doors.count() > 1 {
		log.Printf("connector: %d Edge door(s) configured; starting at %s%s", doors.count(), doors.current(),
			regionSuffix(doors.currentRegion()))
	}
	edgeHTTPClient := newConnectorEdgeHTTPClient(edgeTLSConfig)
	if *renewNow {
		st, ok, lerr := loadConnectorState(filepath.Join(strings.TrimSpace(*stateDir), "connector-state.json"))
		if !ok || lerr != nil || edgeTLSConfig == nil {
			log.Fatalf("--renew-identity-now needs an enrolled --state-dir and a pinned transport")
		}
		if err := renewConnectorIdentityIfDue(context.Background(), *stateDir, st, edgeTLSConfig,
			true, log.Printf); err != nil {
			log.Fatalf("connector identity renewal: %v", err)
		}
		log.Printf("connector identity renewal completed")
		return
	}

	// ★ AND KEEP THAT IDENTITY ALIVE. The certificate has the same 60-day TTL a laptop's does, so a connector
	// that never renews takes its whole Site dark on day 60 — and every connector installed the same week goes
	// dark within the same hour. See identity.go.
	if st, ok, lerr := loadConnectorState(filepath.Join(strings.TrimSpace(*stateDir), "connector-state.json")); ok &&
		lerr == nil && strings.TrimSpace(*stateDir) != "" && edgeTLSConfig != nil {
		go renewConnectorIdentityLoop(context.Background(), *stateDir, st, edgeTLSConfig, log.Printf)
	}
	if edgeTLSConfig != nil {
		log.Printf("connector↔edge transport: TLS pinned (mTLS=%t)", len(edgeTLSConfig.Certificates) > 0)
	} else {
		log.Printf("connector↔edge transport: PLAINTEXT (dev mode; mTLS not enforced)")
	}

	privateBaseURL := strings.TrimSpace(*privateBaseURLOverride)
	if privateBaseURL == "" {
		privateBaseURL = "http://" + *listen
	}
	tcpRoutes, err := loadConnectorTCPRoutesFromProtectedAppMap(*protectedAppMapPath)
	if err != nil {
		log.Fatalf("load connector tcp routes: %v", err)
	}
	// The connector declares NO routes to the Edge (owner decision 2026-07-18): it is not an authority on what
	// it may reach. Its SSRF guard is populated ONLY by the Edge's effective-routes push (CP-configured); until
	// the first push the guard is empty, which is fail-closed (an empty reachable set denies every dial).
	log.Printf("connector tcp routes loaded: %d", len(tcpRoutes))

	identitySyncConfigured := strings.TrimSpace(*identitySyncFile) != ""
	identitySyncMonitor := &connectorIdentitySyncMonitor{}
	if err := validateConnectorStartupMode(connectorStartupMode{
		SkipEdgeRegistration: *skipEdgeRegistration,
		EnableTunnel:         *enableTunnel,
		IdentitySync:         identitySyncConfigured,
	}); err != nil {
		log.Fatalf("connector startup mode: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":        "ok",
			"connector_id":  *connectorID,
			"identity_sync": identitySyncMonitor.Snapshot(identitySyncConfigured),
		})
	})
	mux.HandleFunc("GET /identity-sync/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, identitySyncMonitor.Snapshot(identitySyncConfigured))
	})
	// ★ THE SAMPLE APPLICATIONS SERVE THE LAB, AND ONLY THE LAB (2026-09-04). They answer on this connector's
	// own listener and describe applications that do not exist. In a deployment they are five endpoints
	// pretending to be an intranet; the smoke tests that read them run with -dev-mode, so that is where they
	// live now.
	if *sampleApplications {
		mux.HandleFunc("GET /private-app/dummy", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{
				"application_id": "app_dummy_https",
				"connector_id":   *connectorID,
				"status":         "reachable_via_connector",
			})
		})
		mux.HandleFunc("GET /private-app/internal-web", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{
				"application_id": "app_internal_web",
				"connector_id":   *connectorID,
				"service_family": "https",
				"status":         "internal_web_reachable_via_connector",
			})
		})
		mux.HandleFunc("GET /private-app/dummy-ssh", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{
				"application_id": "app_dummy_ssh",
				"banner":         "SSH-2.0-dsse",
				"connector_id":   *connectorID,
				"service_family": "ssh",
				"status":         "ssh_banner_reachable",
			})
		})
		mux.HandleFunc("GET /private-app/dummy-postgres", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{
				"application_id": "app_dummy_postgres",
				"connector_id":   *connectorID,
				"service_family": "database",
				"status":         "database_probe_reachable",
			})
		})
		mux.HandleFunc("GET /private-app/dummy-rdp", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{
				"application_id": "app_dummy_rdp",
				"connector_id":   *connectorID,
				"service_family": "rdp",
				"status":         "rdp_probe_reachable",
			})
		})
	}
	mux.HandleFunc(runtimeCopyRoundTripPath, runtimeCopyRoundTripHandler(runtimeCopyRoundTripHandlerConfig{
		TenantID: *tenantID,
		Routes:   tcpRoutes,
		Dialer:   connectorTCPNetDialer{},
	}))
	go func() {
		log.Printf("connector private app listening on %s", *listen)
		if err := http.ListenAndServe(*listen, mux); err != nil {
			log.Fatalf("listen connector: %v", err)
		}
	}()

	if *skipEdgeRegistration {
		log.Printf("connector Edge registration skipped for local endpoint availability check")
	} else {
		registration := model.ConnectorRegistration{
			ID:               *connectorID,
			TenantID:         *tenantID,
			ConnectorGroupID: *connectorGroupID,
			// ★ NO NAME IS BETTER THAN THE SAME NAME (2026-08-25, seen on a site holding several). This
			// registered every connector in every deployment as "Lab Connector", so a site's route-governance
			// panels — which label by name — were indistinguishable from each other, and an operator binding a
			// network could not tell which connector they were binding it to. Naming a connector is the
			// operator's act (the Console's Rename); until they do, the id is what identifies it, and the
			// screens fall back to it.
			Name:           connectorDefaultName(),
			EdgeRegionID:   *edgeRegionID,
			EdgeClusterID:  *edgeClusterID,
			ApplicationIDs: announcedApplicationIDs(*applicationIDs, *sampleApplications),
			PrivateBaseURL: privateBaseURL,
			Status:         "registered",
			Metadata: map[string]any{
				"runtime_secret_hash": connectorRuntimeSecretHash(*connectorSecret),
			},
		}
		bootstrapSecret := strings.TrimSpace(*connectorBootstrapSecret)
		if bootstrapSecret == "" {
			bootstrapSecret = *connectorSecret
		}
		// ★★ IT USED TO DIE HERE, AND THAT IS WHY PRIVATE ACCESS VANISHED FOR A WEEK (2026-08-13, found from the
		// lab: the connector had not been seen since 2026-08-06).
		//
		// Registration and the first heartbeat were log.Fatalf. Both talk to the EDGE, so ANY edge restart — a
		// rebuild, a config change, a crash — killed the connector, and the container's restart raced the edge
		// coming back and lost again: thirteen attempts in thirty seconds, then nothing, for days. The container
		// reported "Up" throughout and the admin API went on listing the connector as registered, because the
		// record is durable and the PROCESS is what was gone. Nothing anywhere said "your private applications
		// are unreachable".
		//
		// A connector that cannot register is not a security problem — it serves nothing until the Edge accepts
		// it, and the Edge is the party that decides. It is an availability problem, and exiting converts a
		// transient one into a permanent one. So it retries, for ever, with a bounded backoff, and says so.
		registerWithRetry := func() {
			delay := time.Second
			for attempt := 1; ; attempt++ {
				err := postJSON(edgeHTTPClient, doors.current()+"/connectors/register", registration, bootstrapSecret)
				if err == nil {
					if attempt > 1 {
						log.Printf("connector registered after %d attempts", attempt)
					}
					return
				}
				log.Printf("register connector (attempt %d, retrying in %s): %v", attempt, delay, err)
				// ★★★ AND IT MOVES DOOR, BECAUSE NOTHING ELSE IS RUNNING YET (2026-09-02, measured: 24
				// consecutive attempts against one region's door while two others answered, and the connector
				// never reached the tunnel loop or the home watch — both of which start AFTER this returns).
				//
				// A connector is not a device. A device is rebooted, its user signs in again, and every one of
				// those is a fresh chance to reach a different door. A connector is a server process that runs
				// for months and nobody restarts, so a door it cannot reach at start-up is one it will still
				// be dialling next week — with the estate behind it unreachable the whole time.
				//
				// Third attempt, not the first: one failure is an Edge restarting, and moving on that would
				// walk the door list every time a region bounced.
				if attempt%3 == 0 && doorIsUnreachable(err) {
					doors.advance(err)
				}
				time.Sleep(delay)
				if delay < 30*time.Second {
					delay *= 2
				}
			}
		}
		registerWithRetry()
		// The first heartbeat is best-effort for the same reason the ticker below is: the loop sends another in
		// ten seconds, and killing the process over one of them is what this whole block exists to stop.
		if err := sendHeartbeat(edgeHTTPClient, doors.current(), *connectorID, *connectorSecret, *tenantID, *policyBundleID, *policyBundleVersion, identitySyncConfigured, identitySyncMonitor); err != nil {
			log.Printf("send connector heartbeat (the ticker will retry): %v", err)
		}

		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			// ★ CONSECUTIVE FAILURES MEAN RE-REGISTER, NOT JUST COMPLAIN (2026-08-13). A heartbeat names a
			// connector the Edge is supposed to already know. An Edge that restarted without this connector in
			// its store answers every heartbeat the same way for ever, and the connector goes on sending them
			// into a fleet that does not list it — reachable-looking from here, absent over there. Re-registering
			// is idempotent and is what a human would do.
			//
			// Three, not one: a single failure is an Edge that is restarting, and re-registering on every blip
			// would replace a heartbeat storm with a registration storm.
			consecutive := 0
			for range ticker.C {
				if err := sendHeartbeat(edgeHTTPClient, doors.current(), *connectorID, *connectorSecret, *tenantID, *policyBundleID, *policyBundleVersion, identitySyncConfigured, identitySyncMonitor); err != nil {
					consecutive++
					log.Printf("send connector heartbeat (%d in a row): %v", consecutive, err)
					if consecutive >= 3 {
						log.Printf("★ re-registering: %d heartbeats in a row were refused, so this edge may no "+
							"longer know this connector — until it does, every private application behind it is "+
							"unreachable and nothing else says so", consecutive)
						// ★★★ AND THE DOOR IS TOLD, BECAUSE THIS IS THE FIRST THING THAT KNOWS (2026-09-02,
						// measured during a region blackhole). The heartbeat concluded the door was gone at
						// +92s and said so in those words — and then nothing acted on it. The door was only
						// changed at +141s, when the TUNNEL's own TCP read finally timed out, which is the
						// kernel's clock and not ours: on a network that drops silently for longer, the wait
						// is longer, and on one that resets immediately it never happens at all.
						//
						// Three consecutive refusals of an authenticated call is the same evidence the tunnel
						// eventually produces, 49 seconds earlier. A connector that has already told its log
						// that everything behind it is unreachable should not then wait for a second opinion.
						//
						// It only counts when the failure is REACHING the door. A door that answers and
						// refuses is a different fault — the connector is unknown there, which re-registering
						// is exactly the fix for — and moving to another region would hide it.
						if doorIsUnreachable(err) {
							doors.advance(err)
						}
						registerWithRetry()
						consecutive = 0
					}
					continue
				}
				consecutive = 0
			}
		}()

		if *enableTunnel {
			go spreadConnectorOverTheFleet(context.Background(), doors, *connectorID, *connectorSecret, privateBaseURL, tcpRoutes, connectorTCPNetDialer{}, edgeTLSConfig)
			// ★ AND THE DEPLOYMENT'S OWN ANSWER ABOUT ITS DOORS, RE-READ. See profile_poll.go: what the token
			// carried was true on the day it was issued and not afterwards.
			pollConnectorProfile(context.Background(), doors, *stateDir, *connectorID, *connectorSecret, edgeTLSConfig)
		}
		if identitySyncConfigured {
			go identitySyncLoop(context.Background(), edgeHTTPClient, doors.current(), *connectorID, *connectorSecret, *identitySyncSource, *identitySyncFile, *identitySyncStateFile, *identitySyncInterval, identitySyncMonitor)
		}
		log.Printf("connector registered to %s%s", doors.current(), regionSuffix(doors.currentRegion()))
	}
	select {}
}

type connectorStartupMode struct {
	SkipEdgeRegistration bool
	EnableTunnel         bool
	IdentitySync         bool
}

func validateConnectorStartupMode(mode connectorStartupMode) error {
	if !mode.SkipEdgeRegistration {
		return nil
	}
	if mode.EnableTunnel {
		return fmt.Errorf("skip-edge-registration requires --enable-tunnel=false")
	}
	if mode.IdentitySync {
		return fmt.Errorf("skip-edge-registration cannot be combined with identity sync")
	}
	return nil
}

func sendHeartbeat(client *http.Client, edgeURL, connectorID, connectorSecret, tenantID, policyBundleID, policyBundleVersion string, identitySyncConfigured bool, identitySyncMonitor *connectorIdentitySyncMonitor) error {
	heartbeat := model.ConnectorHeartbeat{
		ID:                  connectorID,
		TenantID:            tenantID,
		Status:              "healthy",
		PolicyBundleID:      policyBundleID,
		PolicyBundleVersion: policyBundleVersion,
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"identity_sync": identitySyncMonitor.Snapshot(identitySyncConfigured),
		},
	}
	return postJSON(client, fmt.Sprintf("%s/connectors/%s/heartbeat", edgeURL, connectorID), heartbeat, connectorSecret)
}

func connectorRuntimeSecretHash(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return fmt.Sprintf("sha256:%x", sum)
}

func postJSON(client *http.Client, url string, value any, connectorSecret string) error {
	if client == nil {
		client = http.DefaultClient
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	if connectorSecret != "" {
		req.Header.Set(connectorSecretHeader, connectorSecret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}
	return nil
}

// connectorFailbackAfter is how long a tunnel must hold before this connector counts the door as good and
// returns to the operator's first choice on the next reconnect.
//
// ★ LONG ENOUGH THAT A DOOR WHICH ACCEPTS AND IMMEDIATELY DROPS DOES NOT COUNT. A shorter window would make a
// half-broken first region capture the connector on every cycle: connect, fail, fail back, connect, fail —
// which is worse than staying in the second region, because the flow of traffic never settles.
const connectorFailbackAfter = 60 * time.Second

// connectTunnelLoop keeps ONE attachment alive. primary marks the worker that owns door selection: a
// connector lives in one region at a time, so region failover is decided once, by the first worker, and the
// others follow it when their own tunnels reconnect. A probe worker that cannot connect must never be able to
// drive the whole connector into another region.
func connectTunnelLoop(ctx context.Context, doors *connectorEndpoints, attachments *connectorFleetAttachments, primary bool, connectorID, connectorSecret, privateBaseURL string, tcpRoutes []connectorTCPRoute, tcpDialer connectorTCPConnectionDialer, tlsConfig *tls.Config) {
	duplicates := 0
	for {
		door := doors.current()
		region := doors.currentRegion()
		if primary {
			// ★ THE PRIMARY DECIDES WHERE THIS CONNECTOR LIVES. Anything still attached through a region it has
			// moved away from is let go, so the deployment gets one answer to "where is this connector" instead
			// of two nodes in two regions each telling the authority something different.
			if letGo := attachments.belongsTo(region); len(letGo) > 0 {
				log.Printf("connector is now in %s and is letting go of %v, which it reached through another region — "+
					"holding tunnels in two regions makes the deployment's answer to where this connector is flap", region, letGo)
			}
		}
		started := time.Now()
		node, displaced, err := connectTunnelOnce(ctx, door, region, connectorID, connectorSecret, privateBaseURL, tcpRoutes, tcpDialer, tlsConfig, attachments)
		held := time.Since(started)
		if displaced {
			// ★★★ THIS CONNECTOR'S OWN PROBE ENDED THIS TUNNEL, SO THE DOOR IS NOT ON TRIAL (2026-08-26,
			// measured: the primary's tunnel was replaced two seconds after it formed by a sibling worker that
			// had snapshotted the held set before the claim landed. It "did not hold", so the connector failed
			// over — and then out of the next region too, cycling the whole door list in two seconds, on
			// evidence it had manufactured itself).
			log.Printf("connector tunnel on Edge node %s was replaced by this connector's own reconnect — "+
				"reconnecting, and NOT counting it against %s%s", node, door, regionSuffix(region))
			select {
			case <-ctx.Done():
				return
			case <-time.After(connectorFleetDuplicateBackoff):
			}
			continue
		}
		switch {
		case errors.Is(err, errConnectorNodeAlreadyHeld):
			// Not a failure: the door handed back a node this connector already covers. Say nothing, wait, and
			// dial again — that is how the remaining nodes are found.
			duplicates++
			if !primary && attachments.searchIsDone(duplicates) {
				attachments.dropWorker()
				log.Printf("connector search finished: on %s", attachments.coverage())
				return
			}
			// ★ BACK OFF WHILE STILL SHORT. With a known denominator this worker keeps looking until the fleet
			// is covered, which can take a while when a node is down or has not yet been told about this
			// connector — so the retry slows instead of hammering the door every two seconds for ever.
			wait := connectorFleetDuplicateBackoff * time.Duration(min(duplicates, 15))
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			continue
		case err != nil:
			log.Printf("connector tunnel ended: %v", err)
		}
		duplicates = 0
		if node != "" {
			log.Printf("connector no longer holds a tunnel on Edge node %s; now on %s", node, attachments.coverage())
		}
		if primary && doors.current() != door {
			// ★★★ THE DOOR ALREADY MOVED, AND THIS TUNNEL BELONGS TO THE OLD ONE (2026-09-02, measured within
			// a minute of adding the heartbeat-driven decision). The heartbeat concluded the region was gone
			// and advanced to the next door; the long-held tunnel to the DEAD door then ended and was judged
			// against wherever the list now points — it had held for hours, the connector was no longer at its
			// preferred door, so it was sent "home" to the region that had just been declared gone. One second
			// after failing over, in the same log:
			//
			//	connector region failover: … — trying https://agents.tokyo-east…
			//	connector: returning to https://agents.osaka…, the first door configured
			//
			// A verdict on a tunnel is a verdict about the door that tunnel was ON. When the door has changed
			// since it was dialled, the decision has already been taken by whoever changed it.
			log.Printf("connector: the tunnel to %s%s ended after the door had already changed — leaving that "+
				"decision alone", door, regionSuffix(region))
		} else if primary {
			// A tunnel that HELD is evidence about the door, whichever way it ended: the region answered, carried
			// traffic, and something ordinary closed it. That is the case to fail back from — but only when
			// there is somewhere to fail back FROM.
			//
			// ★★★ A CONNECTOR COULD NOT FAIL OVER OUT OF ITS PREFERRED REGION AT ALL (2026-09-02, measured:
			// three minutes into a blackhole of its region, with two live doors in its own list, it was still
			// dialling the dead one). resetToPreferred() sets the index to 0 and does nothing when it is
			// already 0 — so on the door the operator listed first, which is where every connector sits in
			// steady state, a tunnel that held for more than a minute and then died took this branch and the
			// failure was CONSUMED. advance() was never reached. In steady state a tunnel always holds longer
			// than a minute, so this was every region failure of the door that matters most.
			//
			// Its own installer prints "a connector that loses one door moves to the next, so the estate behind
			// it survives losing a region", and --verify reports "each door answers this connector: 3 of 3".
			// Both were true about the doors and neither was about this.
			//
			// The two cases are about WHERE the connector is, not only how long it held:
			//   away from home + it held  -> go home
			//   at home, or it did not hold -> move on
			if held >= connectorFailbackAfter && !doors.atPreferred() {
				doors.resetToPreferred()
			} else {
				doors.advance(err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// errConnectorNodeAlreadyHeld means the door led to a node this connector is already attached to. It is the
// signal to dial again, not an error to report.
var errConnectorNodeAlreadyHeld = errors.New("this connector already holds a tunnel on that Edge node")

// connectTunnelOnce holds one tunnel until it ends, returning the Edge node it was attached to (empty against
// an Edge too old to name itself).
func connectTunnelOnce(ctx context.Context, edgeURL, region, connectorID, connectorSecret, privateBaseURL string, tcpRoutes []connectorTCPRoute, tcpDialer connectorTCPConnectionDialer, tlsConfig *tls.Config, attachments *connectorFleetAttachments) (string, bool, error) {
	var owner int64
	wsURL, err := connectorTunnelURL(edgeURL, connectorID)
	if err != nil {
		return "", false, err
	}
	headers := http.Header{}
	headers.Set(connectorSecretHeader, connectorSecret)
	// ★ DECLARE BEFORE DIALLING. An Edge registers a tunnel the moment the upgrade completes, replacing and
	// closing whatever this connector had on that node — so a probe that decides AFTER the handshake kills the
	// tunnel it was probing. Saying what is already held lets the node refuse without registering anything.
	if attachments != nil {
		if held := attachments.nodes(); len(held) > 0 {
			headers.Set(tunnel.ConnectorHoldsHeader, strings.Join(held, ","))
		}
	}
	conn, err := tunnel.DialTLS(ctx, wsURL, headers, tlsConfig)
	if err != nil {
		// A node this connector already holds refuses with 409 and names itself. That is the walk working, not
		// a failure: drop it, and dial the door again for a node nobody has yet.
		var rejected *tunnel.UpgradeRejectedError
		if errors.As(err, &rejected) && rejected.StatusCode == http.StatusConflict {
			return strings.TrimSpace(rejected.Header.Get(tunnel.EdgeNodeHeader)), false, errConnectorNodeAlreadyHeld
		}
		return "", false, err
	}
	defer conn.Close()
	node := ""
	if conn.ResponseHeader != nil {
		node = strings.TrimSpace(conn.ResponseHeader.Get(tunnel.EdgeNodeHeader))
		// The denominator, when the deployment knows it: how many Edge nodes this region has. Without it this
		// connector can say how many nodes it is on, but not whether that is all of them.
		if attachments != nil {
			if size, err := strconv.Atoi(strings.TrimSpace(conn.ResponseHeader.Get(tunnel.EdgeFleetNodesHeader))); err == nil {
				attachments.noteFleetSize(size)
			}
			// Whether the rest of this region relays to whichever node holds this connector. Only the node
			// knows; without it the coverage line warns about a hole this deployment has closed.
			attachments.noteSiblingsRelay(strings.EqualFold(strings.TrimSpace(conn.ResponseHeader.Get(tunnel.EdgeSiblingsRelayHeader)), "true"))
		}
	}
	// This attachment can be let go from outside — when the connector moves region and this tunnel belongs to
	// the one it left, or when it is going back to the door the operator put first.
	//
	// ★★★ LETTING GO HAS TO CLOSE THE SOCKET, NOT JUST CANCEL THE CONTEXT (2026-08-26, measured on a live
	// return home). The worker sits in a blocking read on the websocket; a context has no way to interrupt
	// that, so cancelling alone left the tunnel held and the connector was still listing the nodes of the
	// region it had just left two minutes later. It came home eventually — when the far side or the OS
	// noticed — which is a cutover whose duration nothing in this deployment decides.
	attachCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	letGo := func() {
		cancel()
		_ = conn.Close()
	}
	ctx = attachCtx
	if attachments != nil {
		// A node can still be claimed here in a race with a sibling worker: the declaration is a snapshot taken
		// before the dial. Losing that race costs one connection, which the Edge has already registered — so
		// this is the one case that does displace, and it is why the declaration above matters: it removes
		// every avoidable instance of it.
		id, ok := attachments.claim(node, region, letGo)
		if !ok {
			// ★★★ AND THE SOCKET IS CLOSED, OR THIS CONNECTOR CARRIES NOTHING UNTIL IT IS RESTARTED
			// (2026-09-02, measured after a failover/failback cycle on a real deployment).
			//
			// The Edge registers a tunnel the moment the upgrade completes, and registering REPLACES whatever
			// this connector had on that node — closing it. So by the time this claim is attempted, the
			// connector's only serving session is the one we are about to walk away from. Returning without
			// closing it left:
			//
			//   the Edge:      "a session to this member exists but nothing answered behind it" (open timed out)
			//   the connector: "still 1 of the 2 Edge node(s) ... and the others relay to it"  — a STALE claim
			//   the estate:    every flow timed out, plaintext and TLS alike, for twelve minutes
			//
			// Both sides reported themselves healthy and nothing joined the two. Restarting the connector was
			// the only thing that cleared it, and nothing in either log said so.
			//
			// `defer cancel()` below is not enough, and the comment fifteen lines above says why: a worker
			// sits in a blocking read and a context cannot interrupt that. The socket has to be closed.
			_ = conn.Close()
			return node, false, errConnectorNodeAlreadyHeld
		}
		owner = id
		defer func() { attachments.release(node, id) }()
	}
	if node != "" {
		log.Printf("connector tunnel connected to %s on Edge node %s; now on %s", wsURL, node, attachments.coverage())
	} else {
		log.Printf("connector tunnel connected to %s (this Edge does not name its node, so this connector cannot tell whether the rest of the fleet can reach it)", wsURL)
	}
	tcpDispatcher := newConnectorTunnelTCPDispatcher(tcpRoutes, tcpDialer, time.Now)
	// No seed: the dispatcher starts with an empty (deny-all) reachable set and is populated by the Edge's
	// effective-routes push (pollEffectiveRoutes). Fail-closed until then.
	expiryCtx, cancelExpiry := context.WithCancel(ctx)
	defer cancelExpiry()
	tcpDispatcher.StartExpiryLoop(expiryCtx, time.Second)
	// Poll the Edge for this connector's EFFECTIVE reachable routes (self-declared UNION admin-authored) and
	// merge them into the SSRF allowlist, so a flow the Edge routes here for an admin-authored destination is
	// accepted. Tied to the tunnel's lifetime. See docs/connector_network_route_advertisement_design.md.
	go pollEffectiveRoutes(expiryCtx, edgeURL, connectorID, connectorSecret, tlsConfig, tcpDispatcher)
	runErr := handleConnectorTunnelConn(ctx, conn, privateBaseURL, tcpDispatcher)
	// If this node is now held by a SIBLING worker of this connector, the Edge replaced our session with
	// theirs — one session per connector — and the end of this tunnel says nothing about the region.
	return node, attachments != nil && attachments.stillHeldByAnother(node, owner), runErr
}

// pollEffectiveRoutes fetches GET /connectors/{id}/effective-routes and applies it to the dispatcher's SSRF
// allowlist. Best-effort: a failed poll leaves the last-known routes in place (the self-declared set always
// works even if the Edge is unreachable).
func pollEffectiveRoutes(ctx context.Context, edgeURL, connectorID, connectorSecret string, tlsConfig *tls.Config, dispatcher *connectorTunnelTCPDispatcher) {
	client := newConnectorEdgeHTTPClient(tlsConfig)
	url := fmt.Sprintf("%s/connectors/%s/effective-routes", strings.TrimRight(edgeURL, "/"), connectorID)
	lastSig := ""
	fetch := func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return
		}
		if connectorSecret != "" {
			req.Header.Set(connectorSecretHeader, connectorSecret)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("connector effective-routes fetch error: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("connector effective-routes fetch status=%d", resp.StatusCode)
			return
		}
		var eff model.ConnectorReachableRoutes
		if err := json.NewDecoder(resp.Body).Decode(&eff); err != nil {
			log.Printf("connector effective-routes decode error: %v", err)
			return
		}
		if len(eff.CIDRs) > 0 || len(eff.FQDNDomains) > 0 {
			dispatcher.SetReachableRoutes(eff)
			if sig := fmt.Sprintf("%v|%v|%s", eff.CIDRs, eff.FQDNDomains, eff.Namespace); sig != lastSig {
				lastSig = sig
				log.Printf("connector effective-routes applied: cidrs=%v fqdns=%d ns=%q", eff.CIDRs, len(eff.FQDNDomains), eff.Namespace)
			}
		}
	}
	fetch()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fetch()
		}
	}
}

type connectorTunnelJSONConn interface {
	ReadJSON(value any) error
	WriteJSON(value any) error
}

type connectorTunnelResponseWriter struct {
	mu   sync.Mutex
	conn connectorTunnelJSONConn
}

func (writer *connectorTunnelResponseWriter) WriteFrames(frames []tunnel.Frame) error {
	if writer == nil || writer.conn == nil {
		return fmt.Errorf("connector tunnel response writer is required")
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	for _, frame := range frames {
		if err := writer.conn.WriteJSON(frame); err != nil {
			return err
		}
	}
	return nil
}

func handleConnectorTunnelConn(ctx context.Context, conn connectorTunnelJSONConn, privateBaseURL string, tcpDispatcher *connectorTunnelTCPDispatcher) error {
	responseWriter := &connectorTunnelResponseWriter{conn: conn}
	if tcpDispatcher != nil {
		tcpDispatcher.SetResponseWriter(responseWriter.WriteFrames)
	}
	for {
		var frame tunnel.Frame
		if err := conn.ReadJSON(&frame); err != nil {
			return err
		}
		responses, err := handleConnectorTunnelFrame(ctx, privateBaseURL, tcpDispatcher, frame)
		if err != nil {
			return err
		}
		if err := responseWriter.WriteFrames(responses); err != nil {
			return err
		}
		if tcpDispatcher != nil && connectorTCPOpenAccepted(frame, responses) {
			tcpDispatcher.StartReadPumpForRequest(frame.RequestID)
		}
	}
}

func connectorTCPOpenAccepted(frame tunnel.Frame, responses []tunnel.Frame) bool {
	if frame.Type != tunnel.FrameTCPOpen || len(responses) != 1 {
		return false
	}
	response := responses[0]
	return response.Type == tunnel.FrameTCPOpenResult &&
		response.RequestID == frame.RequestID &&
		response.Error == ""
}

type connectorTCPNetDialer struct{}

func (connectorTCPNetDialer) OpenTCPConnection(ctx context.Context, route connectorTCPRoute) (io.ReadWriteCloser, error) {
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(route.Host, strconv.Itoa(route.Port)))
}

func handleTunnelHTTPRequest(privateBaseURL string, frame tunnel.Frame) tunnel.Frame {
	method := frame.Method
	if method == "" {
		method = http.MethodGet
	}
	path := frame.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequest(method, privateBaseURL+path, nil)
	if err != nil {
		return tunnel.Frame{Type: tunnel.FrameHTTPResponse, RequestID: frame.RequestID, TunnelID: frame.TunnelID, StatusCode: http.StatusBadGateway, Error: err.Error()}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tunnel.Frame{Type: tunnel.FrameHTTPResponse, RequestID: frame.RequestID, TunnelID: frame.TunnelID, StatusCode: http.StatusBadGateway, Error: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tunnel.Frame{Type: tunnel.FrameHTTPResponse, RequestID: frame.RequestID, TunnelID: frame.TunnelID, StatusCode: http.StatusBadGateway, Error: err.Error()}
	}
	return tunnel.Frame{
		Type:          tunnel.FrameHTTPResponse,
		RequestID:     frame.RequestID,
		TunnelID:      frame.TunnelID,
		ApplicationID: frame.ApplicationID,
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("content-type"),
		Body:          string(body),
	}
}

func connectorTunnelURL(edgeURL, connectorID string) (string, error) {
	parsed, err := url.Parse(edgeURL)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported edge url scheme %q", parsed.Scheme)
	}
	parsed.Path = fmt.Sprintf("/connectors/%s/tunnel", connectorID)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write json response: %v", err)
	}
}

type runtimeCopyRoundTripRequest struct {
	SchemaVersion         string `json:"schema_version"`
	TenantID              string `json:"tenant_id"`
	RequestID             string `json:"request_id"`
	ApplicationID         string `json:"application_id"`
	UpstreamPayloadBase64 string `json:"upstream_payload_b64"`
}

type runtimeCopyRoundTripResponse struct {
	SchemaVersion                          string                         `json:"schema_version"`
	Status                                 string                         `json:"status"`
	Category                               string                         `json:"category"`
	RequestID                              string                         `json:"request_id,omitempty"`
	DownstreamPayloadBase64                string                         `json:"downstream_payload_b64,omitempty"`
	Audit                                  runtimeCopyRoundTripAuditEvent `json:"audit"`
	AuditMetadataOnlyGate                  string                         `json:"audit_metadata_only_gate"`
	SecretLeakGate                         string                         `json:"secret_leak_gate"`
	RuntimeOverclaimGate                   string                         `json:"runtime_overclaim_gate"`
	FlowCopyOverclaimGate                  string                         `json:"flow_copy_overclaim_gate"`
	RuntimeInstalledClaimed                bool                           `json:"runtime_installed_claimed"`
	FlowTunneledClaimed                    bool                           `json:"flow_tunneled_claimed"`
	FlowDeniedClaimed                      bool                           `json:"flow_denied_claimed"`
	RealTLSInterceptionClaimed             bool                           `json:"real_tls_interception_claimed"`
	CertificateIssuanceClaimed             bool                           `json:"certificate_issuance_claimed"`
	ProductionPrivateAppEnforcementClaimed bool                           `json:"production_private_app_enforcement_claimed"`
}

type runtimeCopyRoundTripAuditEvent struct {
	SchemaVersion                          string `json:"schema_version"`
	Status                                 string `json:"status"`
	Category                               string `json:"category"`
	TenantID                               string `json:"tenant_id,omitempty"`
	RequestID                              string `json:"request_id,omitempty"`
	ApplicationID                          string `json:"application_id,omitempty"`
	MetadataOnly                           bool   `json:"metadata_only"`
	RawPayloadIncluded                     bool   `json:"raw_payload_included"`
	RawNEFlowIncluded                      bool   `json:"raw_ne_flow_included"`
	RawDestinationIPIncluded               bool   `json:"raw_destination_ip_included"`
	HostUserMaterialIncluded               bool   `json:"host_user_material_included"`
	CredentialsIncluded                    bool   `json:"credentials_included"`
	TokenIncluded                          bool   `json:"token_included"`
	CookieIncluded                         bool   `json:"cookie_included"`
	SessionIDIncluded                      bool   `json:"session_id_included"`
	ClientSecretIncluded                   bool   `json:"client_secret_included"`
	TLSMaterialIncluded                    bool   `json:"tls_material_included"`
	CertificateMaterialIncluded            bool   `json:"certificate_material_included"`
	DeviceIdentifierIncluded               bool   `json:"device_identifier_included"`
	AppleIdentifierIncluded                bool   `json:"apple_identifier_included"`
	RuntimeInstalledClaimed                bool   `json:"runtime_installed_claimed"`
	FlowTunneledClaimed                    bool   `json:"flow_tunneled_claimed"`
	FlowDeniedClaimed                      bool   `json:"flow_denied_claimed"`
	RealTLSInterceptionClaimed             bool   `json:"real_tls_interception_claimed"`
	CertificateIssuanceClaimed             bool   `json:"certificate_issuance_claimed"`
	ProductionPrivateAppEnforcementClaimed bool   `json:"production_private_app_enforcement_claimed"`
}

type runtimeCopyRoundTripHandlerConfig struct {
	TenantID string
	Routes   []connectorTCPRoute
	Dialer   connectorTCPConnectionDialer
	Timeout  time.Duration
	Now      func() time.Time
}

type runtimeCopyRoundTripFailure struct {
	status   int
	category string
}

func (failure runtimeCopyRoundTripFailure) Error() string {
	return failure.category
}

func runtimeCopyRoundTripHandler(config runtimeCopyRoundTripHandlerConfig) http.HandlerFunc {
	tenantID := strings.TrimSpace(config.TenantID)
	routes := append([]connectorTCPRoute(nil), config.Routes...)
	dialer := config.Dialer
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = time.Duration(neflowcopy.DefaultLimits().ConnectTimeoutMillis) * time.Millisecond
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRuntimeCopyRoundTripError(w, http.StatusMethodNotAllowed, "method_not_allowed", runtimeCopyRoundTripRequest{}, tenantID)
			return
		}
		if r.ContentLength > runtimeCopyRoundTripMaxRequestBodyBytes {
			writeRuntimeCopyRoundTripError(w, http.StatusRequestEntityTooLarge, "request_body_too_large", runtimeCopyRoundTripRequest{}, tenantID)
			return
		}

		var req runtimeCopyRoundTripRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, runtimeCopyRoundTripMaxRequestBodyBytes))
		if err := decoder.Decode(&req); err != nil {
			status := http.StatusBadRequest
			category := "invalid_request_json"
			if strings.Contains(err.Error(), "request body too large") {
				status = http.StatusRequestEntityTooLarge
				category = "request_body_too_large"
			}
			writeRuntimeCopyRoundTripError(w, status, category, req, tenantID)
			return
		}
		if req.SchemaVersion != runtimeCopyRoundTripRequestSchema {
			writeRuntimeCopyRoundTripError(w, http.StatusBadRequest, "invalid_schema_version", req, tenantID)
			return
		}
		if strings.TrimSpace(req.TenantID) == "" {
			writeRuntimeCopyRoundTripError(w, http.StatusBadRequest, "invalid_tenant_id", req, tenantID)
			return
		}
		if strings.TrimSpace(req.TenantID) != tenantID {
			writeRuntimeCopyRoundTripError(w, http.StatusBadGateway, "tenant_scope_mismatch", req, tenantID)
			return
		}
		req.TenantID = tenantID
		req.RequestID = strings.TrimSpace(req.RequestID)
		req.ApplicationID = strings.TrimSpace(req.ApplicationID)
		if req.RequestID == "" {
			writeRuntimeCopyRoundTripError(w, http.StatusBadRequest, "invalid_request_id", req, tenantID)
			return
		}
		upstream, err := base64.StdEncoding.DecodeString(req.UpstreamPayloadBase64)
		if err != nil {
			writeRuntimeCopyRoundTripError(w, http.StatusBadRequest, "invalid_base64_payload", req, tenantID)
			return
		}
		if len(upstream) == 0 {
			writeRuntimeCopyRoundTripError(w, http.StatusBadRequest, "empty_upstream_payload", req, tenantID)
			return
		}
		route, ok := connectorTCPRouteForApplicationID(req.ApplicationID, routes)
		if !ok {
			writeRuntimeCopyRoundTripError(w, http.StatusBadGateway, "unknown_application_default_deny", req, tenantID)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		downstream, err := runRuntimeCopyRoundTrip(ctx, req, upstream, route, dialer, now)
		if err != nil {
			var failure runtimeCopyRoundTripFailure
			if errors.As(err, &failure) {
				writeRuntimeCopyRoundTripError(w, failure.status, failure.category, req, tenantID)
				return
			}
			writeRuntimeCopyRoundTripError(w, http.StatusBadGateway, "round_trip_failed", req, tenantID)
			return
		}

		writeJSON(w, http.StatusOK, runtimeCopyRoundTripResponse{
			SchemaVersion:           runtimeCopyRoundTripResponseSchema,
			Status:                  "ok",
			Category:                "round_trip_completed",
			RequestID:               req.RequestID,
			DownstreamPayloadBase64: base64.StdEncoding.EncodeToString(downstream),
			Audit:                   runtimeCopyRoundTripAudit("ok", "round_trip_completed", req, tenantID),
			AuditMetadataOnlyGate:   "ok",
			SecretLeakGate:          "ok",
			RuntimeOverclaimGate:    "ok",
			FlowCopyOverclaimGate:   "ok",
		})
	}
}

func connectorTCPRouteForApplicationID(applicationID string, routes []connectorTCPRoute) (connectorTCPRoute, bool) {
	applicationID = strings.TrimSpace(applicationID)
	if applicationID == "" {
		return connectorTCPRoute{}, false
	}
	for _, route := range routes {
		if route.ApplicationID == applicationID {
			return route, true
		}
	}
	return connectorTCPRoute{}, false
}

func runRuntimeCopyRoundTrip(ctx context.Context, req runtimeCopyRoundTripRequest, upstream []byte, route connectorTCPRoute, dialer connectorTCPConnectionDialer, now func() time.Time) ([]byte, error) {
	if dialer == nil {
		return nil, runtimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed"}
	}
	conn, err := dialer.OpenTCPConnection(ctx, route)
	if err != nil {
		if ctx.Err() != nil {
			return nil, runtimeCopyRoundTripFailure{status: http.StatusGatewayTimeout, category: "round_trip_timeout"}
		}
		return nil, runtimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed"}
	}
	if connectorTCPConnectionMissing(conn) {
		return nil, runtimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed"}
	}
	if deadline, ok := ctx.Deadline(); ok {
		if deadlineConn, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
			_ = deadlineConn.SetDeadline(deadline)
		}
	}

	type copyResult struct {
		downstream []byte
		err        error
	}
	resultCh := make(chan copyResult, 1)
	go func() {
		downstream, err := copyRuntimeCopyRoundTrip(ctx, req, upstream, route, conn, now)
		resultCh <- copyResult{downstream: downstream, err: err}
	}()

	select {
	case result := <-resultCh:
		if result.err != nil {
			if isRuntimeCopyTimeout(ctx, result.err) {
				return nil, runtimeCopyRoundTripFailure{status: http.StatusGatewayTimeout, category: "round_trip_timeout"}
			}
			var failure runtimeCopyRoundTripFailure
			if errors.As(result.err, &failure) {
				return nil, failure
			}
			return nil, runtimeCopyRoundTripFailure{status: http.StatusBadGateway, category: "round_trip_failed"}
		}
		return result.downstream, nil
	case <-ctx.Done():
		_ = conn.Close()
		<-resultCh
		return nil, runtimeCopyRoundTripFailure{status: http.StatusGatewayTimeout, category: "round_trip_timeout"}
	}
}

func copyRuntimeCopyRoundTrip(ctx context.Context, req runtimeCopyRoundTripRequest, upstream []byte, route connectorTCPRoute, conn io.ReadWriteCloser, now func() time.Time) ([]byte, error) {
	defer conn.Close()
	contract := neflowcopy.NewContract(now)
	defer func() {
		if contract.Count() > 0 {
			_, _ = contract.Close(req.RequestID, tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError)
		}
	}()

	if _, err := contract.Open(neflowcopy.OpenMetadata{
		TenantID:      req.TenantID,
		RequestID:     req.RequestID,
		ApplicationID: req.ApplicationID,
		Host:          route.Host,
		Port:          route.Port,
		Limits:        neflowcopy.DefaultLimits(),
	}); err != nil {
		return nil, err
	}
	upFrame, closed, err := contract.CopyUpstream(req.RequestID, bytes.NewReader(upstream), len(upstream))
	if err != nil {
		return nil, err
	}
	if closed {
		return nil, fmt.Errorf("runtime-copy upstream closed before payload copy")
	}
	if _, err := tunnel.WriteTCPDataFrame(conn, upFrame); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	downFrame, _, err := tunnel.ReadTCPDataFrame(conn, req.RequestID, tunnel.TCPDirectionDown, tunnel.DefaultTCPDataFrameChunkBytes)
	if err != nil {
		return nil, err
	}
	var downstream bytes.Buffer
	written, closeMaterial, closed, err := contract.CopyDownstream(downFrame, &downstream)
	if err != nil {
		return nil, err
	}
	if closed || closeMaterial.Type != "" || written == 0 {
		return nil, fmt.Errorf("runtime-copy downstream copy failed")
	}
	if _, _, err := contract.CloseWithMetadataAudit(req.RequestID, tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF); err != nil {
		return nil, err
	}
	return downstream.Bytes(), nil
}

func isRuntimeCopyTimeout(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func writeRuntimeCopyRoundTripError(w http.ResponseWriter, status int, category string, req runtimeCopyRoundTripRequest, runtimeTenantID string) {
	writeJSON(w, status, runtimeCopyRoundTripResponse{
		SchemaVersion:         runtimeCopyRoundTripErrorResponseSchema,
		Status:                "error",
		Category:              category,
		RequestID:             strings.TrimSpace(req.RequestID),
		Audit:                 runtimeCopyRoundTripAudit("error", category, req, runtimeTenantID),
		AuditMetadataOnlyGate: "ok",
		SecretLeakGate:        "ok",
		RuntimeOverclaimGate:  "ok",
		FlowCopyOverclaimGate: "ok",
	})
}

func runtimeCopyRoundTripAudit(status, category string, req runtimeCopyRoundTripRequest, runtimeTenantID string) runtimeCopyRoundTripAuditEvent {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(runtimeTenantID)
	}
	return runtimeCopyRoundTripAuditEvent{
		SchemaVersion: "connector_runtime_copy_round_trip_audit.v1",
		Status:        status,
		Category:      category,
		TenantID:      tenantID,
		RequestID:     strings.TrimSpace(req.RequestID),
		ApplicationID: strings.TrimSpace(req.ApplicationID),
		MetadataOnly:  true,
	}
}

// connectorDefaultName is what a connector calls itself before an operator names it.
//
// The machine it runs on, which is the one thing about it an operator recognises without looking anything up.
// Empty when the host cannot be read — the screens then show the connector id, which is always true.
func connectorDefaultName() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(host)
}

// sampleApplicationIDs are the five the -sample-applications listener serves. They exist in the lab and
// nowhere else; a deployment that announced them showed an administrator five private applications that do
// not exist, on the screen whose job is to say what is reachable.
var sampleApplicationIDs = []string{"app_dummy_https", "app_internal_web", "app_dummy_ssh", "app_dummy_postgres", "app_dummy_rdp"}

// announcedApplicationIDs is what this connector claims to front. Empty, blank and a list of only separators
// all mean "announce nothing" — a connector that claims no application is correct and is the default; what it
// fronts is then decided by what an administrator publishes to its connector group. An explicit -applications
// list wins over -sample-applications, so a lab can serve the samples and still announce only real ids.
func announcedApplicationIDs(list string, samples bool) []string {
	ids := []string{}
	for _, part := range strings.Split(list, ",") {
		if id := strings.TrimSpace(part); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 && samples {
		return append([]string{}, sampleApplicationIDs...)
	}
	return ids
}
