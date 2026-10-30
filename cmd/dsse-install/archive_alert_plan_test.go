package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchivePlanGeneratesSignedOutboxPublisher(t *testing.T) {
	p := oneRegionMultiEdgePlan()
	p.Archive = &PlanArchive{Endpoint: "objects.example.test:443", Bucket: "audit", AuthMode: "static", WebhookURL: "https://alerts.example.test/dsse"}
	work := t.TempDir()
	planPath := filepath.Join(work, "plan.json")
	plan, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, plan, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, "deployment")
	installFromPlan(t, planPath, dir)
	for name, required := range map[string][]string{
		"docker-compose.yml":               {"dsse-archive-alert-publisher:", "start-archive-alert-publisher.sh", "DSSE_ARCHIVE_WEBHOOK_SIGNING_SECRET:"},
		"start-control-plane.sh":           {"DOMAIN_EVENT_OUTBOX=\"\""},
		"start-archive-alert-publisher.sh": {"-worker-tenant-id=deployment", "-domain-event-publisher-delivery=webhook", "export DSSE_DOMAIN_EVENT_PUBLISHER_WEBHOOK_SIGNING_SECRET="},
		"deployment.env":                   {"DSSE_ARCHIVE_WEBHOOK_URL='https://alerts.example.test/dsse'", "DSSE_ARCHIVE_WEBHOOK_SIGNING_SECRET='"},
	} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range required {
			if !strings.Contains(string(body), fragment) {
				t.Fatalf("%s omitted %s", name, fragment)
			}
		}
	}
	if strings.Contains(string(plan), "SIGNING_SECRET") {
		t.Fatal("private webhook secret entered the public plan")
	}
	launcher, err := os.ReadFile(filepath.Join(dir, "start-archive-alert-publisher.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(launcher), "-domain-event-publisher-webhook-signing-secret=") {
		t.Fatal("webhook signing secret must not be passed in process arguments")
	}
	control, err := os.ReadFile(filepath.Join(dir, "start-control-plane.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(control), `DOMAIN_EVENT_OUTBOX="-domain-event-outbox=postgres"`) {
		t.Fatal("archive alerts must not enable customer domain events without a delivery worker")
	}
}
