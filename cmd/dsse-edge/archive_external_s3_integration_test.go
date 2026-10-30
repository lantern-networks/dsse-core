package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

// TestExternalS3RetentionPostgresE2E is opt-in because it writes a real object
// to an operator-provisioned bucket. Use only an isolated, disposable bucket;
// the object may be retained by Object Lock until the test retention expires.
func TestExternalS3RetentionPostgresE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	bucket := os.Getenv("DSSE_ARCHIVE_E2E_BUCKET")
	if dsn == "" || bucket == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN and DSSE_ARCHIVE_E2E_BUCKET are required")
	}
	// Some S3-compatible stores do not require a region. AWS S3 callers should
	// supply the bucket's actual region explicitly.
	region := os.Getenv("DSSE_ARCHIVE_E2E_REGION")
	endpoint := os.Getenv("DSSE_ARCHIVE_E2E_ENDPOINT")
	if endpoint == "" {
		t.Fatal("DSSE_ARCHIVE_E2E_ENDPOINT is required")
	}
	authMode := os.Getenv("DSSE_ARCHIVE_E2E_AUTH_MODE")
	if authMode == "" {
		authMode = "iam"
	}
	if authMode != "iam" && authMode != "static" {
		t.Fatal("DSSE_ARCHIVE_E2E_AUTH_MODE must be iam or static")
	}
	accessKey := os.Getenv("DSSE_ARCHIVE_E2E_ACCESS_KEY")
	secretKey := os.Getenv("DSSE_ARCHIVE_E2E_SECRET_KEY")
	if authMode == "static" && (accessKey == "" || secretKey == "") {
		t.Fatal("static archive E2E requires both dedicated access and secret keys")
	}
	if authMode == "iam" && (accessKey != "" || secretKey != "") {
		t.Fatal("IAM archive E2E must not contain static archive keys")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg := archive.Config{Endpoint: endpoint, Bucket: bucket, Region: region, UseSSL: true, AuthMode: authMode, AccessKey: accessKey, SecretKey: secretKey}
	if err := archive.CheckBucket(ctx, cfg); err != nil {
		t.Fatalf("external S3 bucket preflight: %v", err)
	}
	arc, err := archive.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("archive_s3_e2e_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	scoped := dsn + " search_path=" + schema
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		scoped = u.String()
	}
	db, err := sql.Open("postgres", scoped)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	all, err := migrationstore.LoadDir("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selectPostgresComponentMigrations(all, "archive fixture", "003")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrationstore.Apply(ctx, db, selected); err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("s3-e2e-%d", time.Now().UnixNano())
	content := []byte(`{"event":"external-s3-e2e"}`)
	if !json.Valid(content) {
		t.Fatal("invalid fixture")
	}
	_, err = db.ExecContext(ctx, `INSERT INTO hot_events(tenant_id,stream,event_id,occurred_at,received_at,payload)
		VALUES($1,'audit','old',now()-interval '10 days',now()-interval '10 days',$2)`, tenant, content)
	if err != nil {
		t.Fatal(err)
	}
	count := func() int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM hot_events WHERE tenant_id=$1", tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	cutoff, now := time.Now().Add(-24*time.Hour), time.Now()
	chain := newAuditChainStore(&holdOutcomePersister{})
	offlineCfg := cfg
	offlineCfg.Endpoint = "127.0.0.1:1"
	offline, err := archive.New(offlineCfg)
	if err != nil {
		t.Fatal(err)
	}
	offlineCtx, offlineCancel := context.WithTimeout(context.Background(), 3*time.Second)
	archiveThenPruneStream(offlineCtx, db, retentionConfig{archive: offline, auditChain: chain}, tenant, "audit", cutoff, now)
	offlineCancel()
	if count() != 1 {
		t.Fatal("unreachable S3 removed a hot row")
	}
	failed := &archiveWriteProbe{fakeArchive: fakeArchive{objs: map[string][]byte{}}, fail: true}
	archiveThenPruneStream(ctx, db, retentionConfig{archive: failed, auditChain: chain}, tenant, "audit", cutoff, now)
	if failed.puts != 1 || count() != 1 {
		t.Fatal("failed archive write removed a hot row")
	}
	archiveThenPruneStream(ctx, db, retentionConfig{archive: arc, auditChain: chain, auditColdRetain: time.Minute}, tenant, "audit", cutoff, now)
	if count() != 0 {
		t.Fatal("successful S3 write did not retire the hot row")
	}
	objects, err := arc.List(ctx, "hot_events/"+tenant+"/audit/", 0)
	if err != nil || len(objects) != 1 {
		t.Fatalf("archive list: count=%d err=%v", len(objects), err)
	}
	r, err := arc.Get(ctx, objects[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	gz, err := gzip.NewReader(r)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(payload), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatal("retrieved archive does not contain exactly one audit header and event")
	}
	var stored map[string]string
	if err := json.Unmarshal(lines[1], &stored); err != nil || stored["event"] != "external-s3-e2e" {
		t.Fatal("retrieved archive does not contain the retired row")
	}
	verified, err := verifyAuditChain(ctx, arc, tenant)
	if err != nil || !verified.OK {
		t.Fatalf("archive chain verification failed: %+v %v", verified, err)
	}
	otherTenant := tenant + "-peer"
	_, err = db.ExecContext(ctx, `INSERT INTO hot_events(tenant_id,stream,event_id,occurred_at,received_at,payload)
		VALUES($1,'audit','peer-old',now()-interval '10 days',now()-interval '10 days',$2)`, otherTenant, []byte(`{"event":"other-tenant"}`))
	if err != nil {
		t.Fatal(err)
	}
	archiveThenPruneStream(ctx, db, retentionConfig{archive: arc, auditChain: chain, auditColdRetain: time.Minute}, otherTenant, "audit", cutoff, now)
	var otherHotRows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM hot_events WHERE tenant_id=$1", otherTenant).Scan(&otherHotRows); err != nil || otherHotRows != 0 {
		t.Fatalf("other tenant hot row was not archived: count=%d err=%v", otherHotRows, err)
	}
	otherObjects, err := arc.List(ctx, "hot_events/"+otherTenant+"/audit/", 0)
	if err != nil || len(otherObjects) != 1 || otherObjects[0].Key == objects[0].Key {
		t.Fatalf("other tenant archive was not separate: count=%d err=%v", len(otherObjects), err)
	}
	otherReader, err := arc.Get(ctx, otherObjects[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	otherGzip, err := gzip.NewReader(otherReader)
	if err != nil {
		otherReader.Close()
		t.Fatal(err)
	}
	otherPayload, err := io.ReadAll(otherGzip)
	otherGzip.Close()
	otherReader.Close()
	if err != nil || !bytes.Contains(otherPayload, []byte(`"event":"other-tenant"`)) || bytes.Contains(otherPayload, content) {
		t.Fatalf("other tenant archive content crossed scope: %v", err)
	}
	firstObjects, err := arc.List(ctx, "hot_events/"+tenant+"/audit/", 0)
	if err != nil || len(firstObjects) != 1 || firstObjects[0].Key != objects[0].Key {
		t.Fatalf("first tenant archive listing changed after peer write: count=%d err=%v", len(firstObjects), err)
	}
	otherVerified, err := verifyAuditChain(ctx, arc, otherTenant)
	if err != nil || !otherVerified.OK {
		t.Fatalf("other tenant archive chain verification failed: %+v %v", otherVerified, err)
	}
	t.Log("external S3 preflight, hot-row retention and retry, and separate two-tenant archive readback and chains verified")
}
