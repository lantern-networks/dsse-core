package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

type postgresDomainEventOutboxPublisher struct {
	Store        postgresDomainEventOutboxStore
	TenantID     string
	EventPlane   string
	PublisherID  string
	Writer       *logs.Writer
	Delivery     domainEventOutboxDelivery
	BatchSize    int
	LockDuration time.Duration
	RetryDelay   time.Duration
	MaxAttempts  int
}

type domainEventOutboxDelivery interface {
	DeliverDomainEvent(ctx context.Context, event domainEventOutboxEnvelope) error
}

type domainEventOutboxDeliveryFailure struct {
	Code string
	Err  error
}

func (failure domainEventOutboxDeliveryFailure) Error() string {
	code := strings.TrimSpace(failure.Code)
	if code == "" {
		code = "domain_event_delivery_failed"
	}
	if failure.Err == nil {
		return code
	}
	return code + ": " + failure.Err.Error()
}

func (failure domainEventOutboxDeliveryFailure) Unwrap() error {
	return failure.Err
}

func domainEventOutboxDeliveryFailureReason(err error) string {
	var failure domainEventOutboxDeliveryFailure
	if errors.As(err, &failure) && strings.TrimSpace(failure.Code) != "" {
		return strings.TrimSpace(failure.Code)
	}
	return "domain_event_delivery_failed"
}

type jsonlDomainEventOutboxDelivery struct {
	Writer *logs.Writer
}

func (delivery jsonlDomainEventOutboxDelivery) DeliverDomainEvent(_ context.Context, event domainEventOutboxEnvelope) error {
	if delivery.Writer == nil {
		return fmt.Errorf("domain event outbox writer is not configured")
	}
	filename := domainEventOutboxDeliveryFilename(event.EventPlane)
	if err := delivery.Writer.Append(filename, event); err != nil {
		return domainEventOutboxDeliveryFailure{Code: "domain_event_delivery_jsonl_failed", Err: err}
	}
	return nil
}

type objectStoreDomainEventOutboxDelivery struct {
	ObjectStore adminExportObjectStore
}

type domainEventOutboxObjectManifest struct {
	SchemaVersion   string    `json:"schema_version"`
	TenantID        string    `json:"tenant_id"`
	EventPlane      string    `json:"event_plane"`
	Stream          string    `json:"stream"`
	EventType       string    `json:"event_type"`
	OutboxID        string    `json:"outbox_id"`
	ObjectRef       string    `json:"object_ref"`
	ObjectChecksum  string    `json:"object_checksum"`
	PayloadChecksum string    `json:"payload_checksum"`
	Format          string    `json:"format"`
	Compression     string    `json:"compression"`
	RowCount        int       `json:"row_count"`
	OccurredAt      time.Time `json:"occurred_at"`
	ReceivedAt      time.Time `json:"received_at"`
	CreatedAt       time.Time `json:"created_at"`
}

type domainEventOutboxObjectVerification struct {
	ManifestRef     string `json:"manifest_ref"`
	ObjectRef       string `json:"object_ref"`
	ObjectChecksum  string `json:"object_checksum"`
	PayloadChecksum string `json:"payload_checksum"`
	RowCount        int    `json:"row_count"`
}

type domainEventOutboxObjectVerificationErrorKind string

const (
	domainEventOutboxObjectVerificationNotFound domainEventOutboxObjectVerificationErrorKind = "not_found"
	domainEventOutboxObjectVerificationFailed   domainEventOutboxObjectVerificationErrorKind = "verification_failed"
	domainEventOutboxObjectVerificationInternal domainEventOutboxObjectVerificationErrorKind = "internal"
)

type domainEventOutboxObjectVerificationError struct {
	Kind domainEventOutboxObjectVerificationErrorKind
	Err  error
}

func (err domainEventOutboxObjectVerificationError) Error() string {
	if err.Err == nil {
		return string(err.Kind)
	}
	switch err.Kind {
	case domainEventOutboxObjectVerificationNotFound:
		return "domain event object manifest not found: " + err.Err.Error()
	case domainEventOutboxObjectVerificationFailed:
		return "domain event object manifest verification failed: " + err.Err.Error()
	default:
		return "domain event object manifest verification internal error: " + err.Err.Error()
	}
}

func (err domainEventOutboxObjectVerificationError) Unwrap() error {
	return err.Err
}

func (delivery objectStoreDomainEventOutboxDelivery) DeliverDomainEvent(_ context.Context, event domainEventOutboxEnvelope) error {
	if delivery.ObjectStore == nil {
		return fmt.Errorf("domain event object store is not configured")
	}
	value, err := domainEventOutboxEnvelopeMap(event)
	if err != nil {
		return domainEventOutboxDeliveryFailure{Code: "domain_event_delivery_object_encode_failed", Err: err}
	}
	objectFilename := domainEventOutboxObjectFilename(event)
	objectChecksum, err := delivery.ObjectStore.WriteGzipJSONL(objectFilename, []map[string]any{value})
	if err != nil {
		return domainEventOutboxDeliveryFailure{Code: "domain_event_delivery_object_write_failed", Err: err}
	}
	manifest, err := domainEventOutboxObjectManifestMap(event, objectFilename, objectChecksum, time.Now().UTC())
	if err != nil {
		return domainEventOutboxDeliveryFailure{Code: "domain_event_delivery_manifest_encode_failed", Err: err}
	}
	if _, err := delivery.ObjectStore.WriteGzipJSONL(domainEventOutboxManifestFilename(objectFilename), []map[string]any{manifest}); err != nil {
		return domainEventOutboxDeliveryFailure{Code: "domain_event_delivery_manifest_write_failed", Err: err}
	}
	return nil
}

func verifyDomainEventOutboxObjectManifest(objectStore adminExportObjectStore, manifestRef string) (domainEventOutboxObjectVerification, error) {
	if objectStore == nil {
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationInternalError(fmt.Errorf("domain event object store is not configured"))
	}
	manifestData, err := objectStore.ReadGeneratedFile(manifestRef)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationNotFoundError(fmt.Errorf("read domain event object manifest: %w", err))
		}
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationInternalError(fmt.Errorf("read domain event object manifest: %w", err))
	}
	manifestRows, err := decodeDomainEventOutboxGzipJSONL(manifestData)
	if err != nil {
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(fmt.Errorf("decode domain event object manifest: %w", err))
	}
	if len(manifestRows) != 1 {
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(fmt.Errorf("domain event object manifest row count = %d, want 1", len(manifestRows)))
	}
	manifest := manifestRows[0]
	objectRef, _ := manifest["object_ref"].(string)
	objectRef, err = domainEventOutboxObjectRefFromManifest(manifestRef, objectRef)
	if err != nil {
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(err)
	}
	wantObjectChecksum, _ := manifest["object_checksum"].(string)
	if strings.TrimSpace(wantObjectChecksum) == "" {
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(fmt.Errorf("domain event object manifest object_checksum is required"))
	}
	wantPayloadChecksum, _ := manifest["payload_checksum"].(string)
	if strings.TrimSpace(wantPayloadChecksum) == "" {
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(fmt.Errorf("domain event object manifest payload_checksum is required"))
	}
	wantRows, err := intFromManifestValue(manifest["row_count"])
	if err != nil {
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(err)
	}
	objectData, err := objectStore.ReadGeneratedFile(objectRef)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(fmt.Errorf("read domain event object: %w", err))
		}
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationInternalError(fmt.Errorf("read domain event object: %w", err))
	}
	gotObjectChecksum := sha256Checksum(objectData)
	if gotObjectChecksum != wantObjectChecksum {
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(fmt.Errorf("domain event object checksum mismatch: got %s want %s", gotObjectChecksum, wantObjectChecksum))
	}
	objectRows, err := decodeDomainEventOutboxGzipJSONL(objectData)
	if err != nil {
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(fmt.Errorf("decode domain event object: %w", err))
	}
	if len(objectRows) != wantRows {
		return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(fmt.Errorf("domain event object row count = %d, want %d", len(objectRows), wantRows))
	}
	for _, row := range objectRows {
		if gotPayloadChecksum, _ := row["payload_checksum"].(string); gotPayloadChecksum != wantPayloadChecksum {
			return domainEventOutboxObjectVerification{}, domainEventOutboxObjectVerificationFailedError(fmt.Errorf("domain event object payload checksum mismatch: got %s want %s", gotPayloadChecksum, wantPayloadChecksum))
		}
	}
	return domainEventOutboxObjectVerification{
		ManifestRef:     manifestRef,
		ObjectRef:       objectRef,
		ObjectChecksum:  gotObjectChecksum,
		PayloadChecksum: wantPayloadChecksum,
		RowCount:        len(objectRows),
	}, nil
}

func domainEventOutboxObjectVerificationNotFoundError(err error) error {
	return domainEventOutboxObjectVerificationError{Kind: domainEventOutboxObjectVerificationNotFound, Err: err}
}

func domainEventOutboxObjectVerificationFailedError(err error) error {
	return domainEventOutboxObjectVerificationError{Kind: domainEventOutboxObjectVerificationFailed, Err: err}
}

func domainEventOutboxObjectVerificationInternalError(err error) error {
	return domainEventOutboxObjectVerificationError{Kind: domainEventOutboxObjectVerificationInternal, Err: err}
}

func domainEventOutboxObjectVerificationHTTPError(err error) (int, error) {
	var verificationErr domainEventOutboxObjectVerificationError
	if errors.As(err, &verificationErr) {
		switch verificationErr.Kind {
		case domainEventOutboxObjectVerificationNotFound:
			return http.StatusNotFound, fmt.Errorf("domain event object manifest not found")
		case domainEventOutboxObjectVerificationFailed:
			return http.StatusUnprocessableEntity, fmt.Errorf("domain event object manifest verification failed")
		}
	}
	return http.StatusInternalServerError, fmt.Errorf("domain event object manifest verification internal error")
}

func decodeDomainEventOutboxGzipJSONL(data []byte) ([]map[string]any, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	rows := make([]map[string]any, 0)
	for {
		var row map[string]any
		if err := decoder.Decode(&row); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func domainEventOutboxObjectRefFromManifest(manifestRef, objectRef string) (string, error) {
	objectRef = strings.TrimSpace(objectRef)
	if objectRef == "" {
		return "", fmt.Errorf("domain event object manifest object_ref is required")
	}
	if !strings.HasPrefix(objectRef, "domain-events/") || !strings.HasSuffix(objectRef, ".ndjson.gz") || strings.HasSuffix(objectRef, ".manifest.ndjson.gz") {
		return "", fmt.Errorf("domain event object manifest object_ref must point to a domain event object")
	}
	// path/*, not filepath/*: an object-store ref is a slash-separated key rather than a host filesystem path.
	// See the same check in main.go — filepath.Clean rewrites separators on Windows so no valid ref is ever
	// "already clean", and filepath.IsAbs there does not consider "/x" absolute.
	if path.IsAbs(objectRef) || strings.Contains(objectRef, "\\") {
		return "", fmt.Errorf("domain event object manifest object_ref must be a relative object path")
	}
	clean := path.Clean(objectRef)
	if clean != objectRef || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("domain event object manifest object_ref must be a clean relative object path")
	}
	if expectedManifestRef := domainEventOutboxManifestFilename(objectRef); expectedManifestRef != manifestRef {
		return "", fmt.Errorf("domain event object manifest object_ref does not match manifest_ref")
	}
	return objectRef, nil
}

func intFromManifestValue(value any) (int, error) {
	switch v := value.(type) {
	case int:
		if v < 1 {
			return 0, fmt.Errorf("domain event object manifest row_count must be positive")
		}
		return v, nil
	case float64:
		if v < 1 || v != float64(int(v)) {
			return 0, fmt.Errorf("domain event object manifest row_count must be a positive integer")
		}
		return int(v), nil
	default:
		return 0, fmt.Errorf("domain event object manifest row_count is required")
	}
}

func sha256Checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func domainEventOutboxEnvelopeMap(event domainEventOutboxEnvelope) (map[string]any, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshal domain event object payload: %w", err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("decode domain event object payload: %w", err)
	}
	return value, nil
}

func domainEventOutboxObjectManifestMap(event domainEventOutboxEnvelope, objectRef, objectChecksum string, now time.Time) (map[string]any, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	manifest := domainEventOutboxObjectManifest{
		SchemaVersion:   event.SchemaVersion,
		TenantID:        event.TenantID,
		EventPlane:      event.EventPlane,
		Stream:          event.Stream,
		EventType:       event.EventType,
		OutboxID:        event.ID,
		ObjectRef:       objectRef,
		ObjectChecksum:  objectChecksum,
		PayloadChecksum: event.PayloadChecksum,
		Format:          "ndjson",
		Compression:     "gzip",
		RowCount:        1,
		OccurredAt:      event.OccurredAt,
		ReceivedAt:      event.ReceivedAt,
		CreatedAt:       now.UTC(),
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal domain event object manifest: %w", err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("decode domain event object manifest: %w", err)
	}
	return value, nil
}

func domainEventOutboxObjectFilename(event domainEventOutboxEnvelope) string {
	occurredAt := event.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = event.ReceivedAt
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	return fmt.Sprintf(
		"domain-events/%s/%s/%04d/%02d/%02d/%s.ndjson.gz",
		safeDomainEventOutboxObjectSegment(event.TenantID),
		safeDomainEventOutboxObjectSegment(event.EventPlane),
		occurredAt.UTC().Year(),
		occurredAt.UTC().Month(),
		occurredAt.UTC().Day(),
		safeDomainEventOutboxObjectSegment(event.ID),
	)
}

func domainEventOutboxManifestFilename(objectFilename string) string {
	if strings.HasSuffix(objectFilename, ".ndjson.gz") {
		return strings.TrimSuffix(objectFilename, ".ndjson.gz") + ".manifest.ndjson.gz"
	}
	return strings.TrimSuffix(objectFilename, ".gz") + ".manifest.ndjson.gz"
}

func safeDomainEventOutboxObjectSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "unknown"
	}
	return builder.String()
}

type httpDomainEventOutboxDelivery struct {
	Endpoint      string
	BearerToken   string
	SigningSecret string
	SigningKeyID  string
	Timeout       time.Duration
	Client        *http.Client
	Now           func() time.Time
	Nonce         func() (string, error)
}

func (delivery httpDomainEventOutboxDelivery) DeliverDomainEvent(ctx context.Context, event domainEventOutboxEnvelope) error {
	endpoint := strings.TrimSpace(delivery.Endpoint)
	if endpoint == "" {
		return fmt.Errorf("domain event webhook endpoint is required")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal domain event webhook payload: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if delivery.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, delivery.Timeout)
		defer cancel()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build domain event webhook request: %w", err)
	}
	request.Header.Set("content-type", "application/json")
	if token := strings.TrimSpace(delivery.BearerToken); token != "" {
		request.Header.Set("authorization", "Bearer "+token)
	}
	if secret := strings.TrimSpace(delivery.SigningSecret); secret != "" {
		timestamp := delivery.now().UTC().Format(time.RFC3339Nano)
		nonce, err := delivery.nonce()
		if err != nil {
			return fmt.Errorf("domain event webhook nonce: %w", err)
		}
		request.Header.Set("x-domain-event-timestamp", timestamp)
		request.Header.Set("x-domain-event-nonce", nonce)
		if keyID := strings.TrimSpace(delivery.SigningKeyID); keyID != "" {
			request.Header.Set("x-domain-event-signature-key-id", keyID)
		}
		request.Header.Set("x-domain-event-signature", domainEventWebhookSignature(secret, timestamp, nonce, payload))
	}
	client := delivery.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return domainEventOutboxDeliveryFailure{Code: "domain_event_delivery_transport_failed", Err: fmt.Errorf("domain event webhook delivery: %w", err)}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return domainEventOutboxDeliveryFailure{Code: domainEventOutboxHTTPStatusFailureCode(response.StatusCode), Err: fmt.Errorf("domain event webhook delivery status %d", response.StatusCode)}
	}
	return nil
}

func domainEventOutboxHTTPStatusFailureCode(statusCode int) string {
	switch {
	case statusCode >= 500:
		return "domain_event_delivery_http_5xx"
	case statusCode >= 400:
		return "domain_event_delivery_http_4xx"
	case statusCode >= 300:
		return "domain_event_delivery_http_3xx"
	default:
		return "domain_event_delivery_http_status"
	}
}

func (delivery httpDomainEventOutboxDelivery) now() time.Time {
	if delivery.Now != nil {
		return delivery.Now()
	}
	return time.Now().UTC()
}

func (delivery httpDomainEventOutboxDelivery) nonce() (string, error) {
	if delivery.Nonce != nil {
		return delivery.Nonce()
	}
	return adminAuditWebhookNonce()
}

func domainEventWebhookSignature(secret, timestamp, nonce string, payload []byte) string {
	return adminAuditWebhookSignature(secret, timestamp, nonce, payload)
}

func verifyDomainEventWebhookSignature(secret, timestamp, nonce, signature string, payload []byte, now time.Time, maxSkew time.Duration) error {
	return verifyAdminAuditWebhookSignature(secret, timestamp, nonce, signature, payload, now, maxSkew)
}

func domainEventOutboxDeliveryFilename(eventPlane string) string {
	switch strings.TrimSpace(eventPlane) {
	case "access":
		return "access_events.log.jsonl"
	case "evidence":
		return "evidence_events.log.jsonl"
	default:
		return "domain_events.log.jsonl"
	}
}

func (publisher postgresDomainEventOutboxPublisher) PublishOnce(ctx context.Context, now time.Time) (int, error) {
	delivery := publisher.delivery()
	if delivery == nil {
		return 0, fmt.Errorf("domain event outbox delivery is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	events, err := publisher.claim(ctx, now)
	if err != nil {
		return 0, err
	}
	published := 0
	for _, event := range events {
		if err := delivery.DeliverDomainEvent(ctx, event); err != nil {
			if releaseErr := publisher.release(ctx, event, domainEventOutboxDeliveryFailureReason(err), now); releaseErr != nil {
				return published, fmt.Errorf("domain event outbox delivery failed: %w; release failed: %v", err, releaseErr)
			}
			return published, err
		}
		if err := publisher.Store.MarkPublished(ctx, event.TenantID, event.ID, publisher.PublisherID, now); err != nil {
			return published, err
		}
		published++
	}
	return published, nil
}

func (publisher postgresDomainEventOutboxPublisher) claim(ctx context.Context, now time.Time) ([]domainEventOutboxEnvelope, error) {
	limit := publisher.BatchSize
	if limit <= 0 {
		limit = 100
	}
	lockDuration := publisher.LockDuration
	if lockDuration <= 0 {
		lockDuration = time.Minute
	}
	return publisher.Store.Claim(ctx, publisher.TenantID, publisher.eventPlane(), publisher.PublisherID, limit, publisher.maxAttempts(), now, lockDuration)
}

func (publisher postgresDomainEventOutboxPublisher) release(ctx context.Context, event domainEventOutboxEnvelope, reason string, now time.Time) error {
	if event.PublishAttempt >= publisher.maxAttempts() {
		return publisher.Store.MarkDead(ctx, event.TenantID, event.ID, publisher.PublisherID, reason, now)
	}
	retryDelay := publisher.RetryDelay
	if retryDelay <= 0 {
		retryDelay = 30 * time.Second
	}
	return publisher.Store.Release(ctx, event.TenantID, event.ID, publisher.PublisherID, reason, now.Add(retryDelay), now)
}

func (publisher postgresDomainEventOutboxPublisher) maxAttempts() int {
	if publisher.MaxAttempts > 0 {
		return publisher.MaxAttempts
	}
	return 5
}

func (publisher postgresDomainEventOutboxPublisher) eventPlane() string {
	plane := strings.TrimSpace(publisher.EventPlane)
	if plane == "" {
		return "domain"
	}
	return plane
}

func (publisher postgresDomainEventOutboxPublisher) delivery() domainEventOutboxDelivery {
	if publisher.Delivery != nil {
		return publisher.Delivery
	}
	if publisher.Writer == nil {
		return nil
	}
	return jsonlDomainEventOutboxDelivery{Writer: publisher.Writer}
}
