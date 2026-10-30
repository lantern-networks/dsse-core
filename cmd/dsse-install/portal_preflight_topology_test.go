package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortalImagePreflightPreservesTopologyCertificateScope(t *testing.T) {
	all := []string{"portal.region-a.example.test", "portal.region-b.example.test", "portal.region-c.example.test"}
	for _, tc := range []struct {
		name, profile string
		names         []string
		wantOK        bool
	}{
		{"regional-own-name", "three-regions-multi-edge", all[1:2], true},
		{"regional-foreign-name", "three-regions-multi-edge", all[:1], false},
		{"shared-all-names", "one-region-three-nodes", all, true},
		{"shared-missing-names", "one-region-three-nodes", all[1:2], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, key, root := installerPortalPair(t, tc.names, false)
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(root) {
				t.Fatal("fixture CA")
			}
			env := map[string]string{
				"DSSE_TOPOLOGY_PROFILE":      tc.profile,
				"DSSE_NODE_PORTAL_NAME":      all[1],
				"DSSE_STEPUP_PORTAL_ORIGINS": "https://" + strings.Join(all, ",https://"),
				"DSSE_OPERATOR_TOKEN":        "must-not-enter-staged-environment",
			}
			called := false
			command := func(_ context.Context, args ...string) ([]byte, error) {
				called = true
				var staged string
				for i, arg := range args {
					if arg == "--mount" && i+1 < len(args) {
						mount := args[i+1]
						if strings.HasSuffix(mount, ",dst=/check,readonly") {
							staged = strings.TrimSuffix(strings.TrimPrefix(mount, "type=bind,src="), ",dst=/check,readonly")
						}
					}
				}
				if !filepath.IsAbs(staged) {
					t.Fatal("image certificate checker did not receive its staged environment")
				}
				imageEnv := readDeploymentEnv(staged)
				if imageEnv["DSSE_OPERATOR_TOKEN"] != "" {
					t.Fatal("private deployment setting leaked into the image preflight")
				}
				return json.Marshal(map[string]bool{"ok": validatePortalPair(cert, key, imageEnv, pool) == nil})
			}
			err := verifyPortalInsideImage(context.Background(), t.TempDir(), "fixture-image", env, command)
			if !called || (err == nil) != tc.wantOK {
				t.Fatalf("image preflight certificate scope: called=%v err=%v wantOK=%v", called, err, tc.wantOK)
			}
		})
	}
}
