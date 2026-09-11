//go:build windows

// inbound_runtime_windows.go —  S3 runtime: maintains the kernel inbound (server-initiated) policy and
// drains the inbound observation ring. Self-contained and additive: it shares NOTHING with the outbound
// connect-redirect path (separate IOCTLs, separate driver policy blob), so enabling it cannot perturb
// steering. The Edge is the policy authority; this loop fetches the S2 export (server_initiated_export.v1)
// from a file or the admin API, filters it to this device's group, resolves source_server -> IP, and pushes
// the result as the kernel inbound policy. In enforce mode the kernel default-denies unmatched inbound; in
// observe mode it records-and-permits. See.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type inboundRuntimeConfig struct {
	enforce     bool          // false = S3a observe, true = S3b enforce (default-deny)
	exportFile  string        // path to a server_initiated_export.v1 JSON (lab; takes precedence over URL)
	exportURL   string        // GET .../admin/legacy-exceptions/export
	adminToken  string        // bearer for the admin export endpoint
	deviceGroup string        // this endpoint's group (filters which export rules apply)
	poll        time.Duration // refresh interval (re-fetch export + re-push; propagates expiry)
	timeout     time.Duration // 0 = run until interrupted
	transport   transportConfig
}

// loadInboundExport reads the S2 export from the configured file or URL. A missing/empty source yields a nil
// export (=> observe records everything / enforce default-denies everything), which is a valid baseline.
func loadInboundExport(cfg inboundRuntimeConfig) (*serverInitiatedExport, error) {
	var raw []byte
	var err error
	switch {
	case strings.TrimSpace(cfg.exportFile) != "":
		raw, err = os.ReadFile(cfg.exportFile)
		if err != nil {
			return nil, fmt.Errorf("read export file: %w", err)
		}
	case strings.TrimSpace(cfg.exportURL) != "":
		raw, err = httpGetExport(cfg)
		if err != nil {
			return nil, err
		}
	default:
		return nil, nil // no source configured: empty policy baseline
	}
	var exp serverInitiatedExport
	if err := json.Unmarshal(raw, &exp); err != nil {
		return nil, fmt.Errorf("parse export: %w", err)
	}
	if exp.SchemaVersion != "" && exp.SchemaVersion != "server_initiated_export.v1" {
		return nil, fmt.Errorf("unexpected export schema_version %q", exp.SchemaVersion)
	}
	return &exp, nil
}

// httpGetExport fetches the export over the (T) tunnel when transport is enabled, else plain HTTP.
func httpGetExport(cfg inboundRuntimeConfig) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	if cfg.transport.enabled {
		tc := cfg.transport
		client.Transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tc.dial(10 * time.Second)
			},
		}
	}
	req, err := http.NewRequest(http.MethodGet, cfg.exportURL, nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.adminToken) != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.adminToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch export: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The Edge explains its refusals; printing the number alone made an operator guess which of several
		// situations 403 was. See edge_refusal_text.go.
		return nil, fmt.Errorf("the Edge refused the legacy-exceptions export: %s", edgeRefusal(resp))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// pushFromExport loads the export, builds the kernel inbound policy for this device group, and pushes it.
func pushFromExport(cfg inboundRuntimeConfig) (int, error) {
	exp, err := loadInboundExport(cfg)
	if err != nil {
		return 0, err
	}
	pol, berrs := buildWFPInboundPolicy(exp, cfg.deviceGroup, net.LookupIP, cfg.enforce)
	for _, e := range berrs {
		fmt.Fprintf(os.Stderr, "inbound: rule build warning: %v\n", e)
	}
	if err := pushInboundPolicy(&pol); err != nil {
		return 0, fmt.Errorf("push inbound policy (driver loaded? admin?): %w", err)
	}
	return int(pol.NumRules), nil
}

// runInbound maintains the inbound policy and drains observations until timeout/interrupt. Boundary logging
// is non-secret by default (counts + family/port/action); raw source IPs are printed only as a lab aid here
// because verifying block/allow needs them — they are NOT persisted/committed (feedback_secret_handling).
func runInbound(cfg inboundRuntimeConfig) error {
	mode := "observe (S3a)"
	if cfg.enforce {
		mode = "enforce (S3b, default-deny)"
	}
	n, err := pushFromExport(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("inbound: %s active; %d allow rule(s) pushed (group=%q)\n", mode, n, cfg.deviceGroup)
	defer func() {
		_ = removeInboundPolicy()
		fmt.Println("inbound: policy cleared")
	}()

	poll := cfg.poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	deadline := time.Time{}
	if cfg.timeout > 0 {
		deadline = time.Now().Add(cfg.timeout)
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		<-ticker.C
		// refresh policy (propagates Legacy Exception expiry / new rules), then drain observations.
		if rn, rerr := pushFromExport(cfg); rerr != nil {
			fmt.Fprintf(os.Stderr, "inbound: refresh failed: %v\n", rerr)
		} else if rn != n {
			fmt.Printf("inbound: rule count changed %d -> %d\n", n, rn)
			n = rn
		}
		obs, derr := drainInboundObservations()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "inbound: drain failed: %v\n", derr)
		}
		for _, o := range obs {
			act := "PERMIT"
			if o.Action == 1 {
				act = "BLOCK"
			}
			var src net.IP
			if o.Family == afInet {
				src = net.IP(o.RemoteAddr[:4])
			} else {
				src = net.IP(o.RemoteAddr[:16])
			}
			fmt.Printf("inbound %s src=%s sport=%d lport=%d proto=%d pid=%d\n",
				act, src, o.RemotePort, o.LocalPort, o.Protocol, o.ProcessId)
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil
		}
	}
}
