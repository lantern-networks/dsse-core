package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Exercise the installer's own launcher with the actual product binary,
// PostgreSQL outbox, and a TLS-verified webhook. A rendered Compose fragment
// alone cannot prove that archive alerts leave the generated deployment.
func TestGeneratedArchiveAlertPublisherDeliversOverHTTPS(t *testing.T) {
	adminDSN := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if adminDSN == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	if runtime.GOOS == "darwin" {
		// macOS uses Keychain trust for Go's default TLS client and does not
		// honor a subprocess-only SSL_CERT_FILE for this ephemeral test CA.
		// The Linux CI job runs this exact generated deployment over HTTPS.
		t.Skip("ephemeral webhook CA is exercised by the Linux CI runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	admin, err := sql.Open("postgres", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	dbName := fmt.Sprintf("dsse_alert_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+dbName); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = admin.ExecContext(cleanup, `DROP DATABASE IF EXISTS `+dbName+` WITH (FORCE)`)
		_ = admin.Close()
	})
	dbURL, err := url.Parse(adminDSN)
	if err != nil || dbURL.Scheme != "postgres" {
		t.Fatal("POSTGRES_QUEUE_E2E_DSN must be a postgres URL")
	}
	dbURL.Path = "/" + dbName
	db, err := sql.Open("postgres", dbURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, name := range []string{"006_domain_event_outbox.sql", "054_cold_archive_health_events.sql"} {
		migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	payload := []byte(`{"reason":"put_failed"}`)
	digest := sha256.Sum256(payload)
	const eventID = "cold_archive_generated_install_alert"
	if _, err := db.ExecContext(ctx, `INSERT INTO domain_event_outbox
		(tenant_id,outbox_id,schema_version,event_plane,stream,event_type,status,occurred_at,received_at,payload_checksum,payload)
		VALUES ('deployment',$1,'2026-10-20.1','domain','cold_archive_health_events','cold_archive_degraded','pending',now(),now(),$2,$3)`, eventID, "sha256:"+hex.EncodeToString(digest[:]), string(payload)); err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	webhook := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var event struct {
			ID string `json:"id"`
		}
		if r.Method != http.MethodPost || r.Header.Get("x-domain-event-signature") == "" || json.NewDecoder(r.Body).Decode(&event) != nil {
			http.Error(w, "invalid signed event", http.StatusBadRequest)
			return
		}
		select {
		case received <- event.ID:
		default:
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhook.Close()
	work := t.TempDir()
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: webhook.Certificate().Raw})
	rootFile := filepath.Join(work, "webhook-ca.pem")
	if err := os.WriteFile(rootFile, root, 0600); err != nil {
		t.Fatal(err)
	}
	p := oneRegionMultiEdgePlan()
	p.Archive = &PlanArchive{Endpoint: "objects.example.test:443", Bucket: "audit", AuthMode: "static", WebhookURL: webhook.URL}
	plan, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	planFile := filepath.Join(work, "plan.json")
	if err := os.WriteFile(planFile, plan, 0600); err != nil {
		t.Fatal(err)
	}
	deployment := filepath.Join(work, "deployment")
	installFromPlan(t, planFile, deployment)
	secret := readDeploymentEnv(deployment)["DSSE_ARCHIVE_WEBHOOK_SIGNING_SECRET"]
	if len(secret) < 32 {
		t.Fatal("installer did not generate a private signing secret")
	}
	binary := os.Getenv("DSSE_TEST_EDGE_BINARY")
	if binary == "" {
		binary = filepath.Join(work, "dsse-edge")
		build := exec.CommandContext(ctx, "go", "build", "-o", binary, "../dsse-edge")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build product binary: %v: %s", err, output)
		}
	}
	runCtx, stop := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, "/bin/sh", filepath.Join(deployment, "start-archive-alert-publisher.sh"))
	cmd.Env = append(os.Environ(), "DSSE_EDGE_BINARY="+binary, "DSSE_POSTGRES_DSN="+dbURL.String(),
		"DSSE_NODE_NAME=archive-test-cp", "DSSE_ARCHIVE_WEBHOOK_URL="+webhook.URL,
		"DSSE_ARCHIVE_WEBHOOK_SIGNING_SECRET="+secret, "SSL_CERT_FILE="+rootFile)
	if err := cmd.Start(); err != nil {
		stop()
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case id := <-received:
		if id != eventID {
			t.Fatalf("webhook received unexpected event %q", id)
		}
	case err := <-waited:
		stop()
		t.Fatalf("generated publisher stopped before delivery: %v", err)
	case <-ctx.Done():
		stop()
		t.Fatal("generated publisher did not deliver an archive alert")
	}
	var status string
	for attempt := 0; attempt < 30; attempt++ {
		if err := db.QueryRowContext(ctx, `SELECT status FROM domain_event_outbox WHERE tenant_id='deployment' AND outbox_id=$1`, eventID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "published" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not stop")
	}
	if strings.TrimSpace(status) != "published" {
		t.Fatalf("archive alert remained %q", status)
	}
}
