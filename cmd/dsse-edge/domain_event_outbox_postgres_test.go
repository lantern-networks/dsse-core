package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/objectstore"
	schemavalidator "github.com/lantern-networks/dsse-core/schema"
)

func TestSetupEdgeDomainEventOutboxModes(t *testing.T) {
	writer, closeFn, err := setupEdgeDomainEventOutbox(context.Background(), edgeDomainEventOutboxConfig{Mode: "disabled"})
	if err != nil {
		t.Fatalf("setupEdgeDomainEventOutbox disabled returned error: %v", err)
	}
	if writer != nil {
		t.Fatalf("disabled writer = %#v, want nil", writer)
	}
	if closeFn == nil {
		t.Fatalf("disabled close function is nil")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("disabled close returned error: %v", err)
	}

	if _, _, err := setupEdgeDomainEventOutbox(context.Background(), edgeDomainEventOutboxConfig{Mode: "postgres"}); err == nil || !strings.Contains(err.Error(), "domain-event-outbox-postgres-dsn") {
		t.Fatalf("postgres without DSN error = %v, want DSN error", err)
	}
	if _, _, err := setupEdgeDomainEventOutbox(context.Background(), edgeDomainEventOutboxConfig{Mode: "bogus"}); err == nil || !strings.Contains(err.Error(), "unsupported domain event outbox mode") {
		t.Fatalf("unsupported mode error = %v", err)
	}
}

func TestJSONLDomainEventOutboxDeliveryWritesPlaneLog(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	event := mustDomainEventOutboxEnvelope(t)
	if err := (jsonlDomainEventOutboxDelivery{Writer: writer}).DeliverDomainEvent(context.Background(), event); err != nil {
		t.Fatalf("DeliverDomainEvent returned error: %v", err)
	}
	rows, err := writer.ReadJSONL("domain_events.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != event.ID || rows[0]["event_plane"] != "domain" {
		t.Fatalf("rows = %#v", rows)
	}
}

func TestJSONLDomainEventOutboxDeliveryWritesAllPlaneLogs(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	for _, tc := range []struct {
		plane    string
		filename string
	}{
		{plane: "domain", filename: "domain_events.log.jsonl"},
		{plane: "access", filename: "access_events.log.jsonl"},
		{plane: "evidence", filename: "evidence_events.log.jsonl"},
	} {
		event := mustDomainEventOutboxEnvelope(t)
		event.ID = "domain_outbox_" + tc.plane + "_delivery_001"
		event.EventPlane = tc.plane
		if err := (jsonlDomainEventOutboxDelivery{Writer: writer}).DeliverDomainEvent(context.Background(), event); err != nil {
			t.Fatalf("DeliverDomainEvent(%s) returned error: %v", tc.plane, err)
		}
		rows, err := writer.ReadJSONL(tc.filename)
		if err != nil {
			t.Fatalf("ReadJSONL(%s) returned error: %v", tc.filename, err)
		}
		if len(rows) != 1 || rows[0]["id"] != event.ID || rows[0]["event_plane"] != tc.plane {
			t.Fatalf("%s rows = %#v", tc.filename, rows)
		}
	}
}

func TestObjectStoreDomainEventOutboxDeliveryWritesGzipObject(t *testing.T) {
	store, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	event := mustDomainEventOutboxEnvelope(t)
	event.EventPlane = "evidence"
	if err := (objectStoreDomainEventOutboxDelivery{ObjectStore: store}).DeliverDomainEvent(context.Background(), event); err != nil {
		t.Fatalf("DeliverDomainEvent returned error: %v", err)
	}
	data, err := store.ReadGeneratedFile(domainEventOutboxObjectFilename(event))
	if err != nil {
		t.Fatalf("ReadGeneratedFile returned error: %v", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer reader.Close()
	var got map[string]any
	if err := json.NewDecoder(reader).Decode(&got); err != nil {
		t.Fatalf("decode gzip object row: %v", err)
	}
	if got["id"] != event.ID || got["event_plane"] != "evidence" || got["tenant_id"] != event.TenantID {
		t.Fatalf("object row = %#v", got)
	}
	manifestData, err := store.ReadGeneratedFile(domainEventOutboxManifestFilename(domainEventOutboxObjectFilename(event)))
	if err != nil {
		t.Fatalf("ReadGeneratedFile manifest returned error: %v", err)
	}
	manifestReader, err := gzip.NewReader(bytes.NewReader(manifestData))
	if err != nil {
		t.Fatalf("NewReader manifest returned error: %v", err)
	}
	defer manifestReader.Close()
	var manifest map[string]any
	if err := json.NewDecoder(manifestReader).Decode(&manifest); err != nil {
		t.Fatalf("decode gzip manifest row: %v", err)
	}
	if manifest["outbox_id"] != event.ID || manifest["object_ref"] != domainEventOutboxObjectFilename(event) || manifest["payload_checksum"] != event.PayloadChecksum {
		t.Fatalf("manifest = %#v", manifest)
	}
	if manifest["format"] != "ndjson" || manifest["compression"] != "gzip" || manifest["row_count"] != float64(1) {
		t.Fatalf("manifest format fields = %#v", manifest)
	}
	if checksum, _ := manifest["object_checksum"].(string); !strings.HasPrefix(checksum, "sha256:") {
		t.Fatalf("manifest object checksum = %#v", manifest["object_checksum"])
	}
	verification, err := verifyDomainEventOutboxObjectManifest(store, domainEventOutboxManifestFilename(domainEventOutboxObjectFilename(event)))
	if err != nil {
		t.Fatalf("verifyDomainEventOutboxObjectManifest returned error: %v", err)
	}
	if verification.ObjectRef != domainEventOutboxObjectFilename(event) || verification.PayloadChecksum != event.PayloadChecksum || verification.RowCount != 1 {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestDomainEventOutboxObjectFilenameUsesEventPlanePrefix(t *testing.T) {
	event := mustDomainEventOutboxEnvelope(t)
	event.EventPlane = "access"
	filename := domainEventOutboxObjectFilename(event)
	if !strings.HasPrefix(filename, "domain-events/tenant_lab_001/access/") || !strings.HasSuffix(filename, ".ndjson.gz") {
		t.Fatalf("filename = %q, want tenant access-plane object prefix", filename)
	}
}

func TestVerifyDomainEventOutboxObjectManifestRejectsChecksumMismatch(t *testing.T) {
	store, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	event := mustDomainEventOutboxEnvelope(t)
	if err := (objectStoreDomainEventOutboxDelivery{ObjectStore: store}).DeliverDomainEvent(context.Background(), event); err != nil {
		t.Fatalf("DeliverDomainEvent returned error: %v", err)
	}
	manifestRef := domainEventOutboxManifestFilename(domainEventOutboxObjectFilename(event))
	manifest := map[string]any{
		"schema_version":   event.SchemaVersion,
		"tenant_id":        event.TenantID,
		"event_plane":      event.EventPlane,
		"stream":           event.Stream,
		"event_type":       event.EventType,
		"outbox_id":        event.ID,
		"object_ref":       domainEventOutboxObjectFilename(event),
		"object_checksum":  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"payload_checksum": event.PayloadChecksum,
		"format":           "ndjson",
		"compression":      "gzip",
		"row_count":        1,
		"occurred_at":      event.OccurredAt.Format(time.RFC3339),
		"received_at":      event.ReceivedAt.Format(time.RFC3339),
		"created_at":       time.Date(2026, 5, 24, 7, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
	if _, err := store.WriteGzipJSONL(manifestRef, []map[string]any{manifest}); err != nil {
		t.Fatalf("WriteGzipJSONL manifest returned error: %v", err)
	}
	err = func() error {
		_, err := verifyDomainEventOutboxObjectManifest(store, manifestRef)
		return err
	}()
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("verifyDomainEventOutboxObjectManifest error = %v, want checksum mismatch", err)
	}
}

func TestVerifyDomainEventOutboxObjectManifestRejectsMismatchedObjectRef(t *testing.T) {
	store, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	event := mustDomainEventOutboxEnvelope(t)
	value, err := domainEventOutboxEnvelopeMap(event)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeMap returned error: %v", err)
	}
	objectRef := "exports/tenant_lab_001/domain_event_object.ndjson.gz"
	objectChecksum, err := store.WriteGzipJSONL(objectRef, []map[string]any{value})
	if err != nil {
		t.Fatalf("WriteGzipJSONL object returned error: %v", err)
	}
	manifestRef := "domain-events/tenant_lab_001/domain/2026/05/24/forged.manifest.ndjson.gz"
	manifest := map[string]any{
		"schema_version":   event.SchemaVersion,
		"tenant_id":        event.TenantID,
		"event_plane":      event.EventPlane,
		"stream":           event.Stream,
		"event_type":       event.EventType,
		"outbox_id":        event.ID,
		"object_ref":       objectRef,
		"object_checksum":  objectChecksum,
		"payload_checksum": event.PayloadChecksum,
		"format":           "ndjson",
		"compression":      "gzip",
		"row_count":        1,
		"occurred_at":      event.OccurredAt.Format(time.RFC3339),
		"received_at":      event.ReceivedAt.Format(time.RFC3339),
		"created_at":       time.Date(2026, 5, 24, 7, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
	if _, err := store.WriteGzipJSONL(manifestRef, []map[string]any{manifest}); err != nil {
		t.Fatalf("WriteGzipJSONL manifest returned error: %v", err)
	}

	_, err = verifyDomainEventOutboxObjectManifest(store, manifestRef)
	if err == nil || !strings.Contains(err.Error(), "object_ref must point to a domain event object") {
		t.Fatalf("verifyDomainEventOutboxObjectManifest error = %v, want object_ref rejection", err)
	}
}

func TestDomainEventOutboxObjectFilenameSanitizesPathSegments(t *testing.T) {
	event := mustDomainEventOutboxEnvelope(t)
	event.TenantID = ".."
	event.EventPlane = "evidence/../../x"
	event.ID = "domain_outbox:../evil"
	filename := domainEventOutboxObjectFilename(event)
	if strings.Contains(filename, "..") || strings.Contains(filename, ":") || strings.Contains(filename, "\\") {
		t.Fatalf("filename = %q, want sanitized path segments", filename)
	}
	if !strings.HasPrefix(filename, "domain-events/__/evidence_______x/") {
		t.Fatalf("filename = %q, want sanitized tenant and plane", filename)
	}
}

func TestDomainEventOutboxObjectManifestDocumentMatchesSchema(t *testing.T) {
	event := mustDomainEventOutboxEnvelope(t)
	manifest, err := domainEventOutboxObjectManifestMap(event, domainEventOutboxObjectFilename(event), "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", time.Date(2026, 5, 24, 7, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("domainEventOutboxObjectManifestMap returned error: %v", err)
	}
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schemas", "domain_event_object_manifest.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	documentData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := schemavalidator.ValidateRequired(schemaData, documentData); err != nil {
		t.Fatalf("manifest does not match domain event object manifest schema: %v", err)
	}
}

func TestDomainEventOutboxDeliveryFromConfig(t *testing.T) {
	if _, err := domainEventOutboxDeliveryFromConfig(postgresDomainEventOutboxPublisherConfig{DeliveryMode: "jsonl"}); err == nil || !strings.Contains(err.Error(), "writer is required") {
		t.Fatalf("jsonl without writer error = %v, want writer error", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	delivery, err := domainEventOutboxDeliveryFromConfig(postgresDomainEventOutboxPublisherConfig{DeliveryMode: "", Writer: writer})
	if err != nil {
		t.Fatalf("default delivery returned error: %v", err)
	}
	if _, ok := delivery.(jsonlDomainEventOutboxDelivery); !ok {
		t.Fatalf("delivery = %T, want jsonlDomainEventOutboxDelivery", delivery)
	}
	objectDelivery, err := domainEventOutboxDeliveryFromConfig(postgresDomainEventOutboxPublisherConfig{DeliveryMode: "objectstore", ObjectStore: storeForTest(t)})
	if err != nil {
		t.Fatalf("objectstore delivery returned error: %v", err)
	}
	if _, ok := objectDelivery.(objectStoreDomainEventOutboxDelivery); !ok {
		t.Fatalf("delivery = %T, want objectStoreDomainEventOutboxDelivery", objectDelivery)
	}
	webhook, err := domainEventOutboxDeliveryFromConfig(postgresDomainEventOutboxPublisherConfig{DeliveryMode: "webhook", WebhookURL: "https://domain-events.example.test/events"})
	if err != nil {
		t.Fatalf("webhook delivery returned error: %v", err)
	}
	if _, ok := webhook.(httpDomainEventOutboxDelivery); !ok {
		t.Fatalf("delivery = %T, want httpDomainEventOutboxDelivery", webhook)
	}
	if _, err := domainEventOutboxDeliveryFromConfig(postgresDomainEventOutboxPublisherConfig{DeliveryMode: "bad", Writer: writer}); err == nil || !strings.Contains(err.Error(), "unknown domain event outbox delivery mode") {
		t.Fatalf("unknown delivery mode error = %v", err)
	}
}

func storeForTest(t *testing.T) *objectstore.LocalStore {
	t.Helper()
	store, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	return store
}

func TestHTTPDomainEventOutboxDeliveryPostsSignedJSON(t *testing.T) {
	event := mustDomainEventOutboxEnvelope(t)
	var gotAuth string
	var gotSignature string
	var gotSignatureKeyID string
	var gotTimestamp string
	var gotNonce string
	var gotEvent domainEventOutboxEnvelope
	var gotPayload []byte
	client := &http.Client{Transport: auditOutboxRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("authorization")
		gotSignature = r.Header.Get("x-domain-event-signature")
		gotSignatureKeyID = r.Header.Get("x-domain-event-signature-key-id")
		gotTimestamp = r.Header.Get("x-domain-event-timestamp")
		gotNonce = r.Header.Get("x-domain-event-nonce")
		if r.Header.Get("content-type") != "application/json" {
			t.Fatalf("content-type = %q, want application/json", r.Header.Get("content-type"))
		}
		var err error
		gotPayload, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read webhook body: %v", err)
		}
		if err := json.Unmarshal(gotPayload, &gotEvent); err != nil {
			t.Fatalf("decode webhook body: %v", err)
		}
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	delivery := httpDomainEventOutboxDelivery{
		Endpoint:      "https://domain-events.example.test/events",
		BearerToken:   "secret-token",
		SigningSecret: "signing-secret",
		SigningKeyID:  "kid-domain-001",
		Timeout:       time.Second,
		Client:        client,
		Now: func() time.Time {
			return time.Date(2026, 5, 24, 6, 30, 0, 0, time.UTC)
		},
		Nonce: func() (string, error) {
			return "nonce-domain-001", nil
		},
	}
	if err := delivery.DeliverDomainEvent(context.Background(), event); err != nil {
		t.Fatalf("DeliverDomainEvent returned error: %v", err)
	}
	if gotAuth != "Bearer secret-token" || gotSignatureKeyID != "kid-domain-001" || gotTimestamp != "2026-05-24T06:30:00Z" || gotNonce != "nonce-domain-001" {
		t.Fatalf("headers auth=%q key=%q timestamp=%q nonce=%q", gotAuth, gotSignatureKeyID, gotTimestamp, gotNonce)
	}
	if want := domainEventWebhookSignature("signing-secret", gotTimestamp, gotNonce, gotPayload); gotSignature != want {
		t.Fatalf("x-domain-event-signature = %q, want %q", gotSignature, want)
	}
	if gotEvent.ID != event.ID || gotEvent.EventPlane != event.EventPlane || gotEvent.Stream != event.Stream {
		t.Fatalf("got event = %#v", gotEvent)
	}
	if err := verifyDomainEventWebhookSignature("signing-secret", gotTimestamp, gotNonce, gotSignature, gotPayload, time.Date(2026, 5, 24, 6, 31, 0, 0, time.UTC), 5*time.Minute); err != nil {
		t.Fatalf("verifyDomainEventWebhookSignature returned error: %v", err)
	}
}

func TestHTTPDomainEventOutboxDeliveryRejectsNon2xx(t *testing.T) {
	client := &http.Client{Transport: auditOutboxRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	err := (httpDomainEventOutboxDelivery{
		Endpoint: "https://domain-events.example.test/events",
		Timeout:  time.Second,
		Client:   client,
	}).DeliverDomainEvent(context.Background(), mustDomainEventOutboxEnvelope(t))
	if err == nil || !strings.Contains(err.Error(), "status 429") {
		t.Fatalf("DeliverDomainEvent error = %v, want status 429", err)
	}
	if got, want := domainEventOutboxDeliveryFailureReason(err), "domain_event_delivery_http_4xx"; got != want {
		t.Fatalf("delivery failure reason = %q, want %q", got, want)
	}
}

func TestDomainEventOutboxDeliveryFailureReason(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "typed", err: domainEventOutboxDeliveryFailure{Code: "domain_event_delivery_jsonl_failed", Err: io.ErrClosedPipe}, want: "domain_event_delivery_jsonl_failed"},
		{name: "fallback", err: io.ErrUnexpectedEOF, want: "domain_event_delivery_failed"},
		{name: "blank typed", err: domainEventOutboxDeliveryFailure{Err: io.ErrClosedPipe}, want: "domain_event_delivery_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domainEventOutboxDeliveryFailureReason(tc.err); got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDomainEventOutboxEnvelopeFromDomainEvents(t *testing.T) {
	now := time.Date(2026, 5, 24, 5, 30, 0, 0, time.UTC)
	approval := "hae_lab_001"
	toolEnvelope, err := domainEventOutboxEnvelopeFromToolCallEvent(model.ToolCallEvent{
		ID:                   "tce_lab_001",
		TenantID:             "tenant_lab_001",
		ActorNHIID:           "nhi_soc_agent_001",
		ToolID:               "tool_ticket_create_001",
		ActionType:           "ticket.create",
		HumanApprovalEventID: &approval,
		ResultSummaryScope:   "metadata_only",
		Timestamp:            "2026-05-24T05:29:00Z",
		Metadata:             map[string]any{"masked": true},
	}, now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromToolCallEvent returned error: %v", err)
	}
	if toolEnvelope.EventPlane != "domain" || toolEnvelope.Stream != "tool_call_events" || toolEnvelope.EventType != "tool_call_event_recorded" || toolEnvelope.Status != "pending" {
		t.Fatalf("tool envelope = %#v", toolEnvelope)
	}
	if toolEnvelope.Payload["tool_id"] != "tool_ticket_create_001" || toolEnvelope.Metadata["dedup_key"] != "tenant_lab_001:tool_call_events:tce_lab_001" {
		t.Fatalf("tool envelope payload/metadata = %#v / %#v", toolEnvelope.Payload, toolEnvelope.Metadata)
	}
	if toolEnvelope.OccurredAt.Format(time.RFC3339) != "2026-05-24T05:29:00Z" || !toolEnvelope.ReceivedAt.Equal(now) {
		t.Fatalf("tool envelope times = %s / %s", toolEnvelope.OccurredAt, toolEnvelope.ReceivedAt)
	}

	humanEnvelope, err := domainEventOutboxEnvelopeFromHumanApprovalEvent(model.HumanApprovalEvent{
		ID:             "hae_lab_001",
		TenantID:       "tenant_lab_001",
		ApprovalSource: "slack",
		ApprovalResult: "approved",
		CreatedAt:      "2026-05-24T05:28:00Z",
		Metadata:       map[string]any{},
	}, now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromHumanApprovalEvent returned error: %v", err)
	}
	if humanEnvelope.Stream != "human_approval_events" || humanEnvelope.EventType != "human_approval_event_recorded" {
		t.Fatalf("human envelope = %#v", humanEnvelope)
	}

	inspectionEnvelope, err := domainEventOutboxEnvelopeFromInspectionEvent(model.InspectionEvent{
		ID:              "ie_lab_001",
		TenantID:        "tenant_lab_001",
		PayloadStored:   true,
		PayloadRef:      stringPtr("evidence://tenant_lab_001/ie_lab_001"),
		RetentionPolicy: stringPtr("standard_30d"),
		Timestamp:       "2026-05-24T05:27:00Z",
		Metadata:        map[string]any{},
	}, now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromInspectionEvent returned error: %v", err)
	}
	if inspectionEnvelope.Stream != "inspection_events" || inspectionEnvelope.EventType != "inspection_event_recorded" || inspectionEnvelope.Payload["payload_stored"] != true {
		t.Fatalf("inspection envelope = %#v", inspectionEnvelope)
	}

	authEnvelope, err := domainEventOutboxEnvelopeFromAuthenticationEvent(model.AuthenticationEvent{
		ID:        "auth_lab_001",
		TenantID:  "tenant_lab_001",
		UserID:    "user_lab_001",
		SessionID: "sess_lab_001",
		IDPID:     "idp_keycloak_lab",
		Method:    "oidc_authorization_code",
		MFAState:  "fresh",
		AuthTime:  "2026-05-24T05:26:00Z",
		Result:    "success",
		Timestamp: "2026-05-24T05:26:00Z",
		Metadata:  map[string]any{},
	}, now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromAuthenticationEvent returned error: %v", err)
	}
	if authEnvelope.Stream != "authentication_events" || authEnvelope.EventType != "authentication_event_recorded" || authEnvelope.Payload["session_id"] != "sess_lab_001" {
		t.Fatalf("auth envelope = %#v", authEnvelope)
	}

	grantEnvelope, err := domainEventOutboxEnvelopeFromDelegatedAccessGrant(model.DelegatedAccessGrant{
		ID:            "dag_lab_001",
		TenantID:      "tenant_lab_001",
		SubjectUserID: "user_lab_001",
		ActorNHIID:    "nhi_soc_agent_001",
		ExpiresAt:     "2026-05-24T06:00:00Z",
		CreatedAt:     stringPtr("2026-05-24T05:25:00Z"),
		Status:        "active",
		Metadata:      map[string]any{},
	}, "delegated_access_grant_recorded", "2026-05-24T05:25:00Z", now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromDelegatedAccessGrant returned error: %v", err)
	}
	if grantEnvelope.Stream != "delegated_access_grants" || grantEnvelope.EventType != "delegated_access_grant_recorded" || grantEnvelope.Payload["actor_nhi_id"] != "nhi_soc_agent_001" {
		t.Fatalf("grant envelope = %#v", grantEnvelope)
	}

	breakGlassEnvelope, err := domainEventOutboxEnvelopeFromBreakGlassAccessRequest(breakGlassAccessRequest{
		ID:         "bg_req_001",
		TenantID:   "tenant_lab_001",
		UserID:     "user_lab_001",
		Reason:     "Emergency admin access",
		Status:     "approved",
		ApprovedAt: "2026-05-24T05:24:00Z",
	}, "break_glass_approved", "2026-05-24T05:24:00Z", now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromBreakGlassAccessRequest returned error: %v", err)
	}
	if breakGlassEnvelope.Stream != "break_glass_events" || breakGlassEnvelope.EventType != "break_glass_approved" || breakGlassEnvelope.Payload["status"] != "approved" {
		t.Fatalf("break-glass envelope = %#v", breakGlassEnvelope)
	}

	deviceEnvelope, err := domainEventOutboxEnvelopeFromDevice(model.Device{
		ID:                  "dev_lab_001",
		TenantID:            "tenant_lab_001",
		UserID:              "user_lab_001",
		Hostname:            "lab-mac",
		OS:                  "macos",
		AgentVersion:        "0.1.0",
		DeviceTrustLevel:    "managed",
		PolicyBundleID:      "pb_lab_20260522_001",
		PolicyBundleVersion: "2026.05.22.001",
		Status:              "registered",
		RegisteredAt:        "2026-05-24T05:23:00Z",
		LastSeenAt:          "2026-05-24T05:23:00Z",
		Metadata:            map[string]any{},
	}, "device_registered", "2026-05-24T05:23:00Z", now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromDevice returned error: %v", err)
	}
	if deviceEnvelope.Stream != "device_events" || deviceEnvelope.EventType != "device_registered" || deviceEnvelope.Payload["hostname"] != "lab-mac" {
		t.Fatalf("device envelope = %#v", deviceEnvelope)
	}

	agentEnvelope, err := domainEventOutboxEnvelopeFromAgentUpdateEvent(model.AgentUpdateEvent{
		ID:                  "agent_update_lab_001",
		TenantID:            "tenant_lab_001",
		DeviceID:            "dev_lab_001",
		UserID:              "user_lab_001",
		CurrentAgentVersion: "0.1.0",
		TargetAgentVersion:  "0.1.1",
		ReleaseChannel:      "lab",
		UpdateStatus:        "installed",
		UpdateSource:        "control_plane",
		Timestamp:           "2026-05-24T05:22:00Z",
		Metadata:            map[string]any{},
	}, now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromAgentUpdateEvent returned error: %v", err)
	}
	if agentEnvelope.Stream != "agent_update_events" || agentEnvelope.EventType != "agent_update_event_recorded" || agentEnvelope.Payload["device_id"] != "dev_lab_001" {
		t.Fatalf("agent update envelope = %#v", agentEnvelope)
	}
}

func TestDomainEventOutboxEnvelopeFromAccessEvents(t *testing.T) {
	now := time.Date(2026, 5, 24, 6, 30, 0, 0, time.UTC)
	accessEnvelope, err := domainEventOutboxEnvelopeFromAccessLog(model.AccessLog{
		ID:               "alog_lab_001",
		TenantID:         "tenant_lab_001",
		AccessDecisionID: "dec_lab_001",
		ApplicationID:    stringPtr("app_dummy_https"),
		Decision:         "allow",
		ReasonCodes:      []string{"policy_matched"},
		Timestamp:        "2026-05-24T06:29:00Z",
		Metadata:         map[string]any{"service_family": "https"},
	}, now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromAccessLog returned error: %v", err)
	}
	if accessEnvelope.EventPlane != "access" || accessEnvelope.Stream != "access_logs" || accessEnvelope.EventType != "access_log_recorded" {
		t.Fatalf("access envelope = %#v", accessEnvelope)
	}
	if accessEnvelope.Payload["access_decision_id"] != "dec_lab_001" || accessEnvelope.Metadata["dedup_key"] != "tenant_lab_001:access_logs:alog_lab_001" {
		t.Fatalf("access envelope payload/metadata = %#v / %#v", accessEnvelope.Payload, accessEnvelope.Metadata)
	}

	traceEnvelope, err := domainEventOutboxEnvelopeFromDecisionTrace(model.DecisionTrace{
		ID:               "trace_lab_001",
		AccessDecisionID: "dec_lab_001",
		PolicyID:         "pol_lab_allow_001",
		PolicyBundleID:   "pb_lab_20260522_001",
		CacheStatus:      "miss",
		ReasonCodes:      []string{"policy_matched"},
		Timestamp:        "2026-05-24T06:29:00Z",
		Metadata:         map[string]any{},
	}, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromDecisionTrace returned error: %v", err)
	}
	if traceEnvelope.EventPlane != "access" || traceEnvelope.Stream != "decision_traces" || traceEnvelope.EventType != "decision_trace_recorded" {
		t.Fatalf("trace envelope = %#v", traceEnvelope)
	}
	if traceEnvelope.Payload["policy_id"] != "pol_lab_allow_001" || traceEnvelope.Metadata["source_event_id"] != "trace_lab_001" {
		t.Fatalf("trace envelope payload/metadata = %#v / %#v", traceEnvelope.Payload, traceEnvelope.Metadata)
	}

	connectorEnvelope, err := domainEventOutboxEnvelopeFromConnectorLog(map[string]any{
		"id":                 "connlog_lab_001",
		"tenant_id":          "tenant_lab_001",
		"event_type":         "connector_route_allowed",
		"connector_id":       "conn_lab_001",
		"connector_group_id": "cgrp_lab_001",
		"timestamp":          "2026-05-24T06:29:30Z",
		"metadata":           map[string]any{},
	}, now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromConnectorLog returned error: %v", err)
	}
	if connectorEnvelope.EventPlane != "access" || connectorEnvelope.Stream != "connector_logs" || connectorEnvelope.EventType != "connector_log_recorded" {
		t.Fatalf("connector envelope = %#v", connectorEnvelope)
	}
	if connectorEnvelope.Payload["connector_id"] != "conn_lab_001" || connectorEnvelope.Metadata["dedup_key"] != "tenant_lab_001:connector_logs:connlog_lab_001" {
		t.Fatalf("connector envelope payload/metadata = %#v / %#v", connectorEnvelope.Payload, connectorEnvelope.Metadata)
	}
}

func TestDomainEventOutboxRuntimeBuildersCoverAllowedStreams(t *testing.T) {
	now := time.Date(2026, 5, 24, 7, 0, 0, 0, time.UTC)
	envelopes := []domainEventOutboxEnvelope{}
	add := func(envelope domainEventOutboxEnvelope, err error) {
		envelopes = append(envelopes, mustDomainEventOutboxEnvelopeFromBuilder(t, envelope, err))
	}
	add(domainEventOutboxEnvelopeFromAuthenticationEvent(model.AuthenticationEvent{ID: "auth_cov_001", TenantID: "tenant_lab_001", UserID: "user_lab_001", SessionID: "sess_cov_001", IDPID: "idp_lab", Method: "oidc_authorization_code", MFAState: "fresh", AuthTime: now.Format(time.RFC3339), Result: "success", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{}}, now))
	add(domainEventOutboxEnvelopeFromBreakGlassAccessRequest(breakGlassAccessRequest{ID: "bg_cov_001", TenantID: "tenant_lab_001", UserID: "user_lab_001", Reason: "coverage", Status: "requested", CreatedAt: now.Format(time.RFC3339)}, "break_glass_requested", now.Format(time.RFC3339), now))
	add(domainEventOutboxEnvelopeFromDevice(model.Device{ID: "dev_cov_001", TenantID: "tenant_lab_001", UserID: "user_lab_001", Hostname: "lab", OS: "macos", AgentVersion: "0.1.0", DeviceTrustLevel: "managed", PolicyBundleID: "pb_lab_001", PolicyBundleVersion: "2026.05.24.001", Status: "registered", RegisteredAt: now.Format(time.RFC3339), LastSeenAt: now.Format(time.RFC3339), Metadata: map[string]any{}}, "device_registered", now.Format(time.RFC3339), now))
	add(domainEventOutboxEnvelopeFromAgentUpdateEvent(model.AgentUpdateEvent{ID: "aue_cov_001", TenantID: "tenant_lab_001", DeviceID: "dev_cov_001", UserID: "user_lab_001", CurrentAgentVersion: "0.1.0", TargetAgentVersion: "0.1.1", ReleaseChannel: "lab", UpdateStatus: "installed", UpdateSource: "control_plane", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{}}, now))
	add(domainEventOutboxEnvelopeFromHumanApprovalEvent(model.HumanApprovalEvent{ID: "hae_cov_001", TenantID: "tenant_lab_001", ApprovalSource: "admin_console", ApprovalResult: "approved", CreatedAt: now.Format(time.RFC3339), Metadata: map[string]any{}}, now))
	add(domainEventOutboxEnvelopeFromDelegatedAccessGrant(model.DelegatedAccessGrant{ID: "dag_cov_001", TenantID: "tenant_lab_001", SubjectUserID: "user_lab_001", ActorNHIID: "nhi_lab_001", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), CreatedAt: stringPtr(now.Format(time.RFC3339)), Status: "active", Metadata: map[string]any{}}, "delegated_access_grant_recorded", now.Format(time.RFC3339), now))
	add(domainEventOutboxEnvelopeFromToolCallEvent(model.ToolCallEvent{ID: "tce_cov_001", TenantID: "tenant_lab_001", ActorNHIID: "nhi_lab_001", ToolID: "tool_lab_001", ActionType: "ticket.create", ResultSummaryScope: "metadata_only", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{}}, now))
	add(domainEventOutboxEnvelopeFromInspectionEvent(model.InspectionEvent{ID: "ie_cov_001", TenantID: "tenant_lab_001", PayloadStored: false, Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{}}, now))
	add(domainEventOutboxEnvelopeFromAccessLog(model.AccessLog{ID: "alog_cov_001", TenantID: "tenant_lab_001", AccessDecisionID: "dec_cov_001", Decision: "allow", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{}}, now))
	add(domainEventOutboxEnvelopeFromDecisionTrace(model.DecisionTrace{ID: "trace_cov_001", AccessDecisionID: "dec_cov_001", PolicyID: "pol_lab_001", PolicyBundleID: "pb_lab_001", CacheStatus: "miss", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{}}, "tenant_lab_001", now))
	add(domainEventOutboxEnvelopeFromConnectorLog(map[string]any{"id": "connlog_cov_001", "tenant_id": "tenant_lab_001", "event_type": "connector_registered", "connector_id": "conn_lab_001", "timestamp": now.Format(time.RFC3339), "metadata": map[string]any{}}, now))
	got := map[string]bool{}
	for _, envelope := range envelopes {
		got[envelope.Stream] = true
	}
	for _, stream := range domainEventOutboxAllowedStreamList {
		if !got[stream] {
			t.Fatalf("missing runtime builder coverage for stream %q; got %#v", stream, got)
		}
	}
	if len(got) != len(domainEventOutboxAllowedStreamList) {
		t.Fatalf("runtime builder streams = %#v, want %d streams", got, len(domainEventOutboxAllowedStreamList))
	}
}

func mustDomainEventOutboxEnvelopeFromBuilder(t *testing.T, envelope domainEventOutboxEnvelope, err error) domainEventOutboxEnvelope {
	t.Helper()
	if err != nil {
		t.Fatalf("domain event builder returned error: %v", err)
	}
	return envelope
}

func mustDomainEventOutboxEnvelope(t *testing.T) domainEventOutboxEnvelope {
	t.Helper()
	event, err := domainEventOutboxEnvelopeFromToolCallEvent(model.ToolCallEvent{
		ID:                 "tce_delivery_001",
		TenantID:           "tenant_lab_001",
		ActorNHIID:         "nhi_soc_agent_001",
		ToolID:             "tool_ticket_create_001",
		ActionType:         "ticket.create",
		ResultSummaryScope: "metadata_only",
		Timestamp:          "2026-05-24T05:29:00Z",
		Metadata:           map[string]any{},
	}, time.Date(2026, 5, 24, 5, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromToolCallEvent returned error: %v", err)
	}
	return event
}

func TestMonitoredDomainEventOutboxRecordsSuccessAndFailure(t *testing.T) {
	now := time.Date(2026, 5, 24, 8, 45, 0, 0, time.UTC)
	event := mustDomainEventOutboxEnvelope(t)
	monitor := newDomainEventOutboxMirrorMonitor()
	outbox := &recordingDomainEventOutbox{}
	appendDomainEventOutbox(context.Background(), monitoredDomainEventOutbox{Writer: outbox, Monitor: monitor}, event, now)
	health := monitor.Health(now)
	if health.Status != "ok" || health.Stats["mirrored"] != 1 || health.LastOutboxID != event.ID || health.LastStream != event.Stream {
		t.Fatalf("success health = %#v", health)
	}

	failingMonitor := newDomainEventOutboxMirrorMonitor()
	failingOutbox := &recordingDomainEventOutbox{err: fmt.Errorf("postgres unavailable")}
	appendDomainEventOutbox(context.Background(), monitoredDomainEventOutbox{Writer: failingOutbox, Monitor: failingMonitor}, event, now.Add(time.Minute))
	health = failingMonitor.Health(now.Add(time.Minute))
	if health.Status != "degraded" || health.Stats["insert_failures"] != 1 || !strings.Contains(health.LastError, "postgres unavailable") {
		t.Fatalf("failure health = %#v", health)
	}
}

func TestDomainEventOutboxEnvelopeFromModelRejectsInvalidTimestamp(t *testing.T) {
	_, err := domainEventOutboxEnvelopeFromToolCallEvent(model.ToolCallEvent{
		ID:                 "tce_bad_time_001",
		TenantID:           "tenant_lab_001",
		ActorNHIID:         "nhi_soc_agent_001",
		ToolID:             "tool_ticket_create_001",
		ActionType:         "ticket.create",
		ResultSummaryScope: "metadata_only",
		Timestamp:          "bad timestamp",
		Metadata:           map[string]any{},
	}, time.Date(2026, 5, 24, 5, 30, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "occurred_at") {
		t.Fatalf("error = %v, want occurred_at parse error", err)
	}
}

func TestDomainEventOutboxEnvelopeFromModelRejectsUnknownStream(t *testing.T) {
	_, err := domainEventOutboxEnvelopeFromModel("unknown_events", "unknown_event_recorded", "unknown_001", "tenant_lab_001", "2026-05-24T05:29:00Z", map[string]any{
		"id":        "unknown_001",
		"tenant_id": "tenant_lab_001",
	}, time.Date(2026, 5, 24, 5, 30, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "stream is invalid") {
		t.Fatalf("error = %v, want stream invalid", err)
	}
}

func TestBuildPostgresDomainEventOutboxInsertStatementSerializesPayloadAndMetadata(t *testing.T) {
	now := time.Date(2026, 5, 24, 4, 0, 0, 0, time.UTC)
	payload := map[string]any{
		"id":           "tce_lab_001",
		"tenant_id":    "tenant_lab_001",
		"actor_nhi_id": "nhi_soc_agent_001",
		"tool_id":      "tool_ticket_create_001",
	}
	_, checksum, err := domainEventOutboxPayloadAndChecksum(payload)
	if err != nil {
		t.Fatalf("domainEventOutboxPayloadAndChecksum returned error: %v", err)
	}
	statement, err := buildPostgresDomainEventOutboxInsertStatement(domainEventOutboxEnvelope{
		ID:              "domain_outbox_tool_call_lab_001",
		TenantID:        "tenant_lab_001",
		SchemaVersion:   "2026-05-24.1",
		EventPlane:      "domain",
		Stream:          "tool_call_events",
		EventType:       "tool_call_event_recorded",
		Status:          "pending",
		OccurredAt:      now.Add(-time.Second),
		ReceivedAt:      now,
		Payload:         payload,
		PayloadChecksum: checksum,
		PublishAttempt:  0,
		Metadata:        map[string]any{"dedup_key": "tenant_lab_001:tool_call_events:tce_lab_001"},
	}, now)
	if err != nil {
		t.Fatalf("buildPostgresDomainEventOutboxInsertStatement returned error: %v", err)
	}
	for _, want := range []string{
		"INSERT INTO domain_event_outbox",
		"tenant_id, outbox_id, schema_version, event_plane, stream, event_type, status",
		"$12::jsonb",
		"$13::jsonb",
		"ON CONFLICT (tenant_id, outbox_id) DO NOTHING",
	} {
		if !strings.Contains(statement.SQL, want) {
			t.Fatalf("statement SQL missing %q: %s", want, statement.SQL)
		}
	}
	if got, want := len(statement.Args), 14; got != want {
		t.Fatalf("arg count = %d, want %d", got, want)
	}
	if statement.Args[0] != "tenant_lab_001" || statement.Args[1] != "domain_outbox_tool_call_lab_001" || statement.Args[2] != "2026-05-24.1" || statement.Args[3] != "domain" {
		t.Fatalf("statement args = %#v", statement.Args)
	}
	if statement.Args[10] != checksum {
		t.Fatalf("payload checksum arg = %#v, want %s", statement.Args[10], checksum)
	}
	var gotPayload map[string]any
	if err := json.Unmarshal([]byte(statement.Args[11].(string)), &gotPayload); err != nil {
		t.Fatalf("unmarshal payload arg: %v", err)
	}
	if gotPayload["tool_id"] != "tool_ticket_create_001" {
		t.Fatalf("payload arg = %#v", gotPayload)
	}
	var gotMetadata map[string]any
	if err := json.Unmarshal([]byte(statement.Args[12].(string)), &gotMetadata); err != nil {
		t.Fatalf("unmarshal metadata arg: %v", err)
	}
	if gotMetadata["dedup_key"] != "tenant_lab_001:tool_call_events:tce_lab_001" {
		t.Fatalf("metadata arg = %#v", gotMetadata)
	}
}

func TestBuildPostgresDomainEventOutboxInsertStatementRejectsInvalidEnvelope(t *testing.T) {
	now := time.Date(2026, 5, 24, 4, 0, 0, 0, time.UTC)
	payload := map[string]any{"id": "event_001"}
	_, checksum, err := domainEventOutboxPayloadAndChecksum(payload)
	if err != nil {
		t.Fatalf("domainEventOutboxPayloadAndChecksum returned error: %v", err)
	}
	valid := domainEventOutboxEnvelope{
		ID:              "domain_outbox_001",
		TenantID:        "tenant_lab_001",
		SchemaVersion:   "2026-05-24.1",
		EventPlane:      "domain",
		Stream:          "tool_call_events",
		EventType:       "tool_call_event_recorded",
		Status:          "pending",
		OccurredAt:      now.Add(-time.Second),
		ReceivedAt:      now,
		Payload:         payload,
		PayloadChecksum: checksum,
	}
	cases := map[string]domainEventOutboxEnvelope{
		"missing tenant":    withDomainEventOutboxTenant(valid, ""),
		"invalid plane":     withDomainEventOutboxPlane(valid, "admin"),
		"invalid status":    withDomainEventOutboxStatus(valid, "queued"),
		"checksum mismatch": withDomainEventOutboxChecksum(valid, "sha256:0000000000000000000000000000000000000000000000000000000000000000"),
		"negative attempt":  withDomainEventOutboxAttempt(valid, -1),
	}
	for name, event := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := buildPostgresDomainEventOutboxInsertStatement(event, now); err == nil {
				t.Fatalf("buildPostgresDomainEventOutboxInsertStatement accepted %s", name)
			}
		})
	}
}

func TestBuildPostgresDomainEventOutboxPublisherStatements(t *testing.T) {
	now := time.Date(2026, 5, 24, 4, 15, 0, 0, time.UTC)
	lockedUntil := now.Add(time.Minute)
	claim, err := buildPostgresDomainEventOutboxClaimStatement("tenant_lab_001", "domain", "publisher_tokyo_001", 25, 5, now, lockedUntil)
	if err != nil {
		t.Fatalf("buildPostgresDomainEventOutboxClaimStatement returned error: %v", err)
	}
	for _, want := range []string{
		"FROM domain_event_outbox",
		"tenant_id = $1 AND event_plane = $2",
		"status = 'pending'",
		"status = 'publishing' AND locked_until < $5::timestamptz",
		"publish_attempt < $6",
		"FOR UPDATE SKIP LOCKED LIMIT $3",
		"status = 'publishing'",
		"RETURNING outbox.tenant_id, outbox.outbox_id, outbox.schema_version, outbox.event_plane, outbox.stream, outbox.event_type, outbox.publish_attempt, outbox.occurred_at, outbox.received_at, outbox.payload_checksum, outbox.payload, outbox.metadata",
	} {
		if !strings.Contains(claim.SQL, want) {
			t.Fatalf("claim SQL missing %q: %s", want, claim.SQL)
		}
	}
	if got, want := len(claim.Args), 7; got != want {
		t.Fatalf("claim arg count = %d, want %d", got, want)
	}
	if claim.Args[0] != "tenant_lab_001" || claim.Args[1] != "domain" || claim.Args[3] != "publisher_tokyo_001" {
		t.Fatalf("claim args = %#v", claim.Args)
	}

	must := func(statement postgresExportTaskQueueStatement, err error) postgresExportTaskQueueStatement {
		t.Helper()
		if err != nil {
			t.Fatalf("statement builder returned error: %v", err)
		}
		return statement
	}
	cases := map[string]struct {
		statement postgresExportTaskQueueStatement
		wants     []string
	}{
		"published": {
			statement: must(buildPostgresDomainEventOutboxMarkPublishedStatement("tenant_lab_001", "domain_outbox_001", "publisher_tokyo_001", now)),
			wants:     []string{"status = 'published'", "published_at = $4::timestamptz", "locked_by = NULL", "status = 'publishing'"},
		},
		"release": {
			statement: must(buildPostgresDomainEventOutboxReleaseStatement("tenant_lab_001", "domain_outbox_001", "publisher_tokyo_001", "webhook_503", now.Add(30*time.Second), now)),
			wants:     []string{"status = 'pending'", "next_attempt_at = $5::timestamptz", "last_error = $4", "status = 'publishing'"},
		},
		"dead": {
			statement: must(buildPostgresDomainEventOutboxMarkDeadStatement("tenant_lab_001", "domain_outbox_001", "publisher_tokyo_001", "max_attempts_exceeded", now)),
			wants:     []string{"status = 'dead'", "dead_at = $5::timestamptz", "last_error = $4", "status = 'publishing'"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for _, want := range append([]string{"UPDATE domain_event_outbox", "tenant_id = $1", "outbox_id = $2", "locked_by = $3"}, tc.wants...) {
				if !strings.Contains(tc.statement.SQL, want) {
					t.Fatalf("%s SQL missing %q: %s", name, want, tc.statement.SQL)
				}
			}
			if tc.statement.Args[0] != "tenant_lab_001" || tc.statement.Args[1] != "domain_outbox_001" || tc.statement.Args[2] != "publisher_tokyo_001" {
				t.Fatalf("%s args = %#v", name, tc.statement.Args)
			}
		})
	}
}

func TestBuildPostgresDomainEventOutboxDeadQueryStatements(t *testing.T) {
	list, err := buildPostgresDomainEventOutboxListDeadStatement("tenant_lab_001", "domain", 2000)
	if err != nil {
		t.Fatalf("buildPostgresDomainEventOutboxListDeadStatement returned error: %v", err)
	}
	for _, want := range []string{
		"FROM domain_event_outbox",
		"tenant_id = $1 AND event_plane = $2 AND status = 'dead'",
		"ORDER BY COALESCE(dead_at, updated_at) DESC",
		"LIMIT $3",
	} {
		if !strings.Contains(list.SQL, want) {
			t.Fatalf("list dead SQL missing %q: %s", want, list.SQL)
		}
	}
	if list.Args[0] != "tenant_lab_001" || list.Args[1] != "domain" || list.Args[2] != 1000 {
		t.Fatalf("list args = %#v", list.Args)
	}

	stats, err := buildPostgresDomainEventOutboxStatsStatement("tenant_lab_001", "domain")
	if err != nil {
		t.Fatalf("buildPostgresDomainEventOutboxStatsStatement returned error: %v", err)
	}
	for _, want := range []string{
		"SELECT status, count(*)",
		"CASE WHEN status = 'dead' THEN COALESCE(dead_at, updated_at) ELSE occurred_at END",
		"WHERE tenant_id = $1 AND event_plane = $2",
		"GROUP BY status",
	} {
		if !strings.Contains(stats.SQL, want) {
			t.Fatalf("stats SQL missing %q: %s", want, stats.SQL)
		}
	}
	if stats.Args[0] != "tenant_lab_001" || stats.Args[1] != "domain" {
		t.Fatalf("stats args = %#v", stats.Args)
	}

	replay, err := buildPostgresDomainEventOutboxReplayDeadStatement("tenant_lab_001", "domain", "domain_outbox_001", time.Date(2026, 5, 24, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("buildPostgresDomainEventOutboxReplayDeadStatement returned error: %v", err)
	}
	for _, want := range []string{"WITH picked AS", "previous_last_error", "status = 'pending'", "publish_attempt = 0", "last_error = NULL", "dead_at = NULL", "WHERE tenant_id = $1 AND event_plane = $2 AND outbox_id = $3 AND status = 'dead'"} {
		if !strings.Contains(replay.SQL, want) {
			t.Fatalf("replay dead SQL missing %q: %s", want, replay.SQL)
		}
	}
	if replay.Args[0] != "tenant_lab_001" || replay.Args[1] != "domain" || replay.Args[2] != "domain_outbox_001" {
		t.Fatalf("replay args = %#v", replay.Args)
	}

	if _, err := buildPostgresDomainEventOutboxListDeadStatement("", "domain", 100); err == nil {
		t.Fatalf("list dead accepted blank tenant")
	}
	if _, err := buildPostgresDomainEventOutboxStatsStatement("tenant_lab_001", "admin"); err == nil {
		t.Fatalf("stats accepted invalid event plane")
	}
	if _, err := buildPostgresDomainEventOutboxReplayDeadStatement("tenant_lab_001", "admin", "domain_outbox_001", time.Now()); err == nil {
		t.Fatalf("replay dead accepted invalid event plane")
	}
}

func TestBuildPostgresDomainEventOutboxPublisherStatementsRejectInvalidInputs(t *testing.T) {
	now := time.Date(2026, 5, 24, 4, 15, 0, 0, time.UTC)
	if _, err := buildPostgresDomainEventOutboxClaimStatement("", "domain", "publisher_tokyo_001", 25, 5, now, now.Add(time.Minute)); err == nil {
		t.Fatalf("claim accepted empty tenant")
	}
	if _, err := buildPostgresDomainEventOutboxClaimStatement("tenant_lab_001", "admin", "publisher_tokyo_001", 25, 5, now, now.Add(time.Minute)); err == nil {
		t.Fatalf("claim accepted admin event_plane")
	}
	if _, err := buildPostgresDomainEventOutboxClaimStatement("tenant_lab_001", "domain", "publisher_tokyo_001", 0, 5, now, now.Add(time.Minute)); err == nil {
		t.Fatalf("claim accepted zero limit")
	}
	if _, err := buildPostgresDomainEventOutboxMarkPublishedStatement("tenant_lab_001", "", "publisher_tokyo_001", now); err == nil {
		t.Fatalf("mark published accepted empty outbox id")
	}
	if _, err := buildPostgresDomainEventOutboxReleaseStatement("tenant_lab_001", "domain_outbox_001", "publisher_tokyo_001", "", time.Time{}, now); err == nil {
		t.Fatalf("release accepted zero next attempt")
	}
	if _, err := buildPostgresDomainEventOutboxMarkDeadStatement("tenant_lab_001", "domain_outbox_001", "publisher_tokyo_001", "", time.Time{}); err == nil {
		t.Fatalf("mark dead accepted zero now")
	}
}

func TestHydratePostgresDomainEventOutboxClaimedRowVerifiesChecksum(t *testing.T) {
	now := time.Date(2026, 5, 24, 4, 30, 0, 0, time.UTC)
	payload := map[string]any{"id": "tce_lab_001", "tool_id": "tool_ticket_create_001"}
	payloadBytes, checksum, err := domainEventOutboxPayloadAndChecksum(payload)
	if err != nil {
		t.Fatalf("domainEventOutboxPayloadAndChecksum returned error: %v", err)
	}
	metadataBytes, err := json.Marshal(map[string]any{"dedup_key": "tenant_lab_001:tool_call_events:tce_lab_001"})
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	envelope, err := hydratePostgresDomainEventOutboxClaimedRow(postgresDomainEventOutboxClaimedRow{
		TenantID:        "tenant_lab_001",
		OutboxID:        "domain_outbox_tool_call_lab_001",
		SchemaVersion:   "2026-05-24.1",
		EventPlane:      "domain",
		Stream:          "tool_call_events",
		EventType:       "tool_call_event_recorded",
		PublishAttempt:  1,
		OccurredAt:      now.Add(-time.Second),
		ReceivedAt:      now,
		PayloadChecksum: checksum,
		Payload:         payloadBytes,
		Metadata:        metadataBytes,
	})
	if err != nil {
		t.Fatalf("hydratePostgresDomainEventOutboxClaimedRow returned error: %v", err)
	}
	if envelope.ID != "domain_outbox_tool_call_lab_001" || envelope.Status != "publishing" || envelope.PublishAttempt != 1 {
		t.Fatalf("envelope = %#v", envelope)
	}
	if envelope.Payload["tool_id"] != "tool_ticket_create_001" || envelope.Metadata["dedup_key"] != "tenant_lab_001:tool_call_events:tce_lab_001" {
		t.Fatalf("envelope payload/metadata = %#v / %#v", envelope.Payload, envelope.Metadata)
	}
}

func TestHydratePostgresDomainEventOutboxClaimedRowRejectsChecksumMismatch(t *testing.T) {
	now := time.Date(2026, 5, 24, 4, 30, 0, 0, time.UTC)
	payloadBytes, _, err := domainEventOutboxPayloadAndChecksum(map[string]any{"id": "tce_lab_001"})
	if err != nil {
		t.Fatalf("domainEventOutboxPayloadAndChecksum returned error: %v", err)
	}
	_, err = hydratePostgresDomainEventOutboxClaimedRow(postgresDomainEventOutboxClaimedRow{
		TenantID:        "tenant_lab_001",
		OutboxID:        "domain_outbox_tool_call_lab_001",
		SchemaVersion:   "2026-05-24.1",
		EventPlane:      "domain",
		Stream:          "tool_call_events",
		EventType:       "tool_call_event_recorded",
		PublishAttempt:  1,
		OccurredAt:      now.Add(-time.Second),
		ReceivedAt:      now,
		PayloadChecksum: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Payload:         payloadBytes,
	})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("hydrate error = %v, want checksum mismatch", err)
	}
}

func withDomainEventOutboxTenant(event domainEventOutboxEnvelope, tenantID string) domainEventOutboxEnvelope {
	event.TenantID = tenantID
	return event
}

func withDomainEventOutboxPlane(event domainEventOutboxEnvelope, plane string) domainEventOutboxEnvelope {
	event.EventPlane = plane
	return event
}

func withDomainEventOutboxStatus(event domainEventOutboxEnvelope, status string) domainEventOutboxEnvelope {
	event.Status = status
	return event
}

func withDomainEventOutboxChecksum(event domainEventOutboxEnvelope, checksum string) domainEventOutboxEnvelope {
	event.PayloadChecksum = checksum
	return event
}

func withDomainEventOutboxAttempt(event domainEventOutboxEnvelope, attempt int) domainEventOutboxEnvelope {
	event.PublishAttempt = attempt
	return event
}

func TestPostgresDomainEventOutboxMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "006_domain_event_outbox.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresDomainEventOutboxSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("migration drift:\nwant: %s\n got: %s", want, got)
	}
}

func TestPostgresDomainEventOutboxStreamCheckMigrationMatchesSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "007_domain_event_outbox_stream_check.sql"))
	if err != nil {
		t.Fatalf("read stream check migration: %v", err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresDomainEventOutboxStreamCheckMigrationSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("stream check migration drift:\nwant: %s\n got: %s", want, got)
	}
}

func TestPostgresDomainEventOutboxSchemaSQLMatchesEnvelopeContract(t *testing.T) {
	joined := strings.Join(postgresDomainEventOutboxSchemaSQL(), "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS domain_event_outbox",
		"PRIMARY KEY (tenant_id, outbox_id)",
		"schema_version text NOT NULL",
		"event_plane text NOT NULL CHECK (event_plane IN ('domain', 'access', 'evidence'))",
		"stream text NOT NULL CONSTRAINT domain_event_outbox_stream_check CHECK (" + domainEventOutboxStreamCheckExpression() + ")",
		"status text NOT NULL CHECK (status IN ('pending', 'publishing', 'published', 'dead'))",
		"payload_checksum text NOT NULL CHECK (payload_checksum ~ '^sha256:[a-f0-9]{64}$')",
		"metadata jsonb NOT NULL DEFAULT '{}'::jsonb",
		"domain_event_outbox_pending_idx",
		"tenant_id, event_plane, status, next_attempt_at, occurred_at, outbox_id",
		"domain_event_outbox_stream_idx",
		"domain_event_outbox_event_idx",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("schema SQL missing %q: %s", want, joined)
		}
	}
}

func TestDomainEventOutboxStreamAllowlistMatchesSchema(t *testing.T) {
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schemas", "domain_event_outbox.schema.json"))
	if err != nil {
		t.Fatalf("read domain event outbox schema: %v", err)
	}
	var schema struct {
		Properties map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		t.Fatalf("decode domain event outbox schema: %v", err)
	}
	streams := schema.Properties["stream"].Enum
	if len(streams) == 0 {
		t.Fatalf("schema stream enum is empty")
	}
	seen := make(map[string]bool, len(streams))
	for _, stream := range streams {
		seen[stream] = true
		if !domainEventOutboxStreamAllowed(stream) {
			t.Fatalf("schema stream %q is not accepted by Go allowlist", stream)
		}
	}
	for stream := range domainEventOutboxAllowedStreams {
		if !seen[stream] {
			t.Fatalf("Go stream %q is missing from schema enum", stream)
		}
	}
}
