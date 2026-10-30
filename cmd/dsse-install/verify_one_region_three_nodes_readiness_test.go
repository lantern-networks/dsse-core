package main

import "testing"

func TestOneRegionThreeNodesCannotBeReportedReadyWithUnfinishedTrustAndStepUp(t *testing.T) {
	checks := verifyOneRegionThreeNodesReadiness(t.TempDir(), map[string]string{
		"DSSE_ETCD_CLIENT_CERT_AUTH": "false",
	})
	if len(checks) != 3 {
		t.Fatalf("want three explicit release gates, got %+v", checks)
	}
	for _, check := range checks {
		if check.ok || check.note == "" {
			t.Fatalf("unfinished profile path passed or lacks an explanation: %+v", check)
		}
	}
}

func TestTransportSettingsAloneCannotPassDeploymentVerification(t *testing.T) {
	checks := verifyOneRegionThreeNodesReadiness(t.TempDir(), map[string]string{
		"DSSE_ETCD_CLIENT_CERT_AUTH": "true", "DSSE_ETCD_CLIENT_CERT": "/run/dsse-postgres-tls/store-client.pem", "DSSE_ETCD_CLIENT_KEY": "/run/dsse-postgres-tls/store-client-key.pem", "DSSE_ETCD_CLIENT_SCHEME": "https",
	})
	for _, check := range checks {
		if check.ok {
			t.Fatalf("settings alone passed: %+v", check)
		}
	}
}
