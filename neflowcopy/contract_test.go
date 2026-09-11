package neflowcopy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

func TestContractSimulatesTakeoverFlowWithRegistryAndCleanup(t *testing.T) {
	now := time.Date(2026, 6, 1, 10, 40, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })

	openFrame, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_001",
		ApplicationID: "app_dummy_https",
		Host:          "DUMMY-PRIVATE-APP.LOCAL",
		Port:          443,
	})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if openFrame.Type != tunnel.FrameTCPOpen || openFrame.Host != "dummy-private-app.local" {
		t.Fatalf("openFrame = %+v, want normalized tcp_open", openFrame)
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want 1", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_001"); !ok || tenantID != "tenant_lab_001" {
		t.Fatalf("TenantID = %q/%v, want tenant_lab_001/true", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_001"); !ok || applicationID != "app_dummy_https" {
		t.Fatalf("ApplicationID = %q/%v, want app_dummy_https/true", applicationID, ok)
	}

	now = now.Add(time.Second)
	upFrame, closed, err := contract.CopyUpstream("req_tcp_ne_001", strings.NewReader("client hello"), 64)
	if err != nil {
		t.Fatalf("CopyUpstream returned error: %v", err)
	}
	if closed || upFrame.Type != tunnel.FrameTCPData || upFrame.Direction != tunnel.TCPDirectionUp {
		t.Fatalf("upFrame=%+v closed=%v, want up tcp_data", upFrame, closed)
	}
	upPayload, err := tunnel.TCPDataFramePayload(upFrame)
	if err != nil {
		t.Fatalf("TCPDataFramePayload returned error: %v", err)
	}
	if string(upPayload) != "client hello" {
		t.Fatalf("up payload = %q, want client hello", string(upPayload))
	}

	now = now.Add(time.Second)
	downFrame, err := tunnel.NewTCPDataFrame("req_tcp_ne_001", tunnel.TCPDirectionDown, []byte("server hello"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	var localWriter bytes.Buffer
	written, closeFrame, closed, err := contract.CopyDownstream(downFrame, &localWriter)
	if err != nil {
		t.Fatalf("CopyDownstream returned error: %v", err)
	}
	if closed || closeFrame.Type != "" {
		t.Fatalf("CopyDownstream closed=%v closeFrame=%+v, want no close", closed, closeFrame)
	}
	if written != len("server hello") || localWriter.String() != "server hello" {
		t.Fatalf("written=%d localWriter=%q, want downstream payload", written, localWriter.String())
	}

	now = now.Add(time.Second)
	closeFrame, err = contract.Close("req_tcp_ne_001", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.BytesUp != int64(len("client hello")) || closeFrame.BytesDown != int64(len("server hello")) {
		t.Fatalf("closeFrame = %+v, want metrics for simulated copy", closeFrame)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d, want cleanup", got)
	}
	if _, ok := contract.TenantID("req_tcp_ne_001"); ok {
		t.Fatal("tenant metadata remained after close")
	}
}

func TestContractCloseMetadataAuditDerivesOpenRecordScope(t *testing.T) {
	now := time.Date(2026, 6, 1, 15, 45, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_002",
		RequestID:     "req_tcp_ne_record_audit",
		ApplicationID: "app_dummy_ssh",
		Host:          "private-app.example.internal",
		Port:          22,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if _, _, err := contract.CopyUpstream("req_tcp_ne_record_audit", strings.NewReader("ssh client bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream returned error: %v", err)
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_record_audit", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit returned error: %v", err)
	}
	if closeFrame.ApplicationID != "" {
		t.Fatalf("closeFrame.ApplicationID = %q, want close audit scope derived from open record only", closeFrame.ApplicationID)
	}
	if event.TenantID != "tenant_lab_002" || event.ApplicationID != "app_dummy_ssh" {
		t.Fatalf("event scope = tenant:%q app:%q, want tenant/app from open record", event.TenantID, event.ApplicationID)
	}
	if event.EventType != AuditEventFlowCopyClosed || event.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("event = %+v, want closed EOF audit event", event)
	}
	if event.BytesUp != int64(len("ssh client bytes")) || event.BytesDown != 0 || event.DurationMillis != 1000 {
		t.Fatalf("event metrics = up:%d down:%d duration:%d, want open-record close metrics", event.BytesUp, event.BytesDown, event.DurationMillis)
	}
	if _, ok := contract.OpenRecord("req_tcp_ne_record_audit"); ok {
		t.Fatal("open record remained after CloseWithMetadataAudit")
	}
}

func TestContractRequiresTenantScopeBeforeOpen(t *testing.T) {
	contract := NewContract(nil)
	_, err := contract.Open(OpenMetadata{
		RequestID:     "req_tcp_ne_missing_tenant",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	})
	if err == nil {
		t.Fatal("Open returned nil error without tenant scope")
	}
	if !strings.Contains(err.Error(), "tenant_id is required") {
		t.Fatalf("error = %q, want tenant_id is required", err.Error())
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d, want no open connection", got)
	}
}

func TestContractCopyUpstreamEOFClosesAndCleansTenantMetadata(t *testing.T) {
	now := time.Date(2026, 6, 1, 11, 10, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_upstream_eof",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	upFrame, closed, err := contract.CopyUpstream("req_tcp_ne_upstream_eof", strings.NewReader("client bytes"), 64)
	if err != nil {
		t.Fatalf("CopyUpstream returned error before EOF: %v", err)
	}
	if closed || upFrame.Type != tunnel.FrameTCPData || upFrame.Direction != tunnel.TCPDirectionUp {
		t.Fatalf("upFrame=%+v closed=%v, want upstream tcp_data before EOF", upFrame, closed)
	}

	now = now.Add(time.Second)
	closeFrame, closed, err := contract.CopyUpstream("req_tcp_ne_upstream_eof", strings.NewReader(""), 64)
	if err != nil {
		t.Fatalf("CopyUpstream returned error on EOF: %v", err)
	}
	if !closed || closeFrame.Type != tunnel.FrameTCPClose || closeFrame.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("closeFrame=%+v closed=%v, want EOF tcp_close", closeFrame, closed)
	}
	if closeFrame.BytesUp != int64(len("client bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("closeFrame metrics = up:%d down:%d, want upstream bytes only", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d, want cleanup", got)
	}
	if _, ok := contract.TenantID("req_tcp_ne_upstream_eof"); ok {
		t.Fatal("tenant metadata remained after upstream EOF close")
	}
}

func TestContractCopyDownstreamRejectsWrongDirectionWithoutWriteOrCleanup(t *testing.T) {
	now := time.Date(2026, 6, 1, 11, 25, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_wrong_direction",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	upFrame, err := tunnel.NewTCPDataFrame("req_tcp_ne_wrong_direction", tunnel.TCPDirectionUp, []byte("client bytes"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	var localWriter bytes.Buffer
	written, closeFrame, closed, err := contract.CopyDownstream(upFrame, &localWriter)
	if err == nil {
		t.Fatal("CopyDownstream returned nil error for upstream frame")
	}
	if !strings.Contains(err.Error(), "downstream flow copy requires down direction") {
		t.Fatalf("error = %q, want wrong direction guard", err.Error())
	}
	if written != 0 || closed || closeFrame.Type != "" || localWriter.Len() != 0 {
		t.Fatalf("written=%d closed=%v closeFrame=%+v localWriterLen=%d, want no write or close", written, closed, closeFrame, localWriter.Len())
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want connection to remain open after rejected wrong direction", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_wrong_direction"); !ok || tenantID != "tenant_lab_001" {
		t.Fatalf("TenantID = %q/%v, want tenant metadata retained", tenantID, ok)
	}
}

func TestContractOpenRejectsMissingOrWhitespaceMetadata(t *testing.T) {
	tests := []struct {
		name        string
		metadata    OpenMetadata
		errContains string
	}{
		{
			name: "missing_request_id",
			metadata: OpenMetadata{
				TenantID:      "tenant_lab_001",
				ApplicationID: "app_dummy_https",
				Host:          "dummy-private-app.local",
				Port:          443,
			},
			errContains: "request_id is required",
		},
		{
			name: "whitespace_request_id",
			metadata: OpenMetadata{
				TenantID:      "tenant_lab_001",
				RequestID:     "req tcp ne",
				ApplicationID: "app_dummy_https",
				Host:          "dummy-private-app.local",
				Port:          443,
			},
			errContains: "request_id must be non-secret metadata without whitespace",
		},
		{
			name: "missing_application_id",
			metadata: OpenMetadata{
				TenantID:  "tenant_lab_001",
				RequestID: "req_tcp_ne_missing_application",
				Host:      "dummy-private-app.local",
				Port:      443,
			},
			errContains: "application_id is required",
		},
		{
			name: "whitespace_application_id",
			metadata: OpenMetadata{
				TenantID:      "tenant_lab_001",
				RequestID:     "req_tcp_ne_bad_application",
				ApplicationID: "app dummy https",
				Host:          "dummy-private-app.local",
				Port:          443,
			},
			errContains: "application_id must be non-secret metadata without whitespace",
		},
		{
			name: "whitespace_tenant_id",
			metadata: OpenMetadata{
				TenantID:      "tenant lab 001",
				RequestID:     "req_tcp_ne_bad_tenant",
				ApplicationID: "app_dummy_https",
				Host:          "dummy-private-app.local",
				Port:          443,
			},
			errContains: "tenant_id must be non-secret metadata without whitespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := NewContract(nil)
			_, err := contract.Open(tt.metadata)
			if err == nil {
				t.Fatal("Open returned nil error for invalid metadata")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.errContains)
			}
			if got := contract.Count(); got != 0 {
				t.Fatalf("Count = %d, want no open connection", got)
			}
		})
	}
}

func TestContractRejectsDuplicateAndConcurrentRegistryOpen(t *testing.T) {
	now := time.Date(2026, 6, 1, 11, 40, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	limits := DefaultLimits()
	limits.ConcurrentConnectionCap = 1

	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_registry_001",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		Limits:        limits,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	_, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_shadow",
		RequestID:     "req_tcp_ne_registry_001",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		Limits:        limits,
	})
	if err == nil {
		t.Fatal("Open returned nil error for duplicate request_id")
	}
	if !strings.Contains(err.Error(), "already open") {
		t.Fatalf("duplicate Open error = %q, want already open", err.Error())
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d after duplicate rejection, want original connection only", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_registry_001"); !ok || tenantID != "tenant_lab_001" {
		t.Fatalf("TenantID = %q/%v, want original tenant retained", tenantID, ok)
	}

	_, err = contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_002",
		RequestID:     "req_tcp_ne_registry_002",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		Limits:        limits,
	})
	if err == nil {
		t.Fatal("Open returned nil error after concurrent cap was reached")
	}
	if !strings.Contains(err.Error(), "concurrent connection cap") {
		t.Fatalf("concurrent Open error = %q, want concurrent connection cap", err.Error())
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d after concurrent cap rejection, want original connection only", got)
	}
	if _, ok := contract.TenantID("req_tcp_ne_registry_002"); ok {
		t.Fatal("tenant metadata recorded for rejected concurrent-cap open")
	}
}

func TestContractCloseCleansOnlyClosedTenantScope(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 35, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })

	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_tenant_001",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open first tenant returned error: %v", err)
	}
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_002",
		RequestID:     "req_tcp_ne_tenant_002",
		ApplicationID: "app_dummy_ssh",
		Host:          "dummy-private-app.local",
		Port:          22,
	}); err != nil {
		t.Fatalf("Open second tenant returned error: %v", err)
	}

	now = now.Add(time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_tenant_001", strings.NewReader("tenant one bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream first tenant returned error: %v", err)
	}
	if _, _, err := contract.CopyUpstream("req_tcp_ne_tenant_002", strings.NewReader("tenant two bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream second tenant returned error: %v", err)
	}

	now = now.Add(time.Second)
	closeFrame, err := contract.Close("req_tcp_ne_tenant_001", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("Close first tenant returned error: %v", err)
	}
	if closeFrame.RequestID != "req_tcp_ne_tenant_001" || closeFrame.BytesUp != int64(len("tenant one bytes")) {
		t.Fatalf("closeFrame = %+v, want first tenant metrics only", closeFrame)
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want second tenant connection to remain open", got)
	}
	if _, ok := contract.TenantID("req_tcp_ne_tenant_001"); ok {
		t.Fatal("tenant metadata remained after closing first tenant request")
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_tenant_002"); !ok || tenantID != "tenant_lab_002" {
		t.Fatalf("TenantID = %q/%v, want second tenant metadata retained", tenantID, ok)
	}

	now = now.Add(time.Second)
	secondClose, err := contract.Close("req_tcp_ne_tenant_002", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("Close second tenant returned error: %v", err)
	}
	if secondClose.RequestID != "req_tcp_ne_tenant_002" || secondClose.BytesUp != int64(len("tenant two bytes")) {
		t.Fatalf("secondClose = %+v, want second tenant metrics only", secondClose)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d, want cleanup after both tenant scopes close", got)
	}
}

func TestContractClosesBeforeDownstreamWriteWhenByteCapExceeded(t *testing.T) {
	now := time.Date(2026, 6, 1, 10, 45, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	limits := DefaultLimits()
	limits.ByteCap = 4
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_byte_cap",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		Limits:        limits,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	downFrame, err := tunnel.NewTCPDataFrame("req_tcp_ne_byte_cap", tunnel.TCPDirectionDown, []byte("12345"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	var localWriter bytes.Buffer
	written, closeFrame, closed, err := contract.CopyDownstream(downFrame, &localWriter)
	if err != nil {
		t.Fatalf("CopyDownstream returned error: %v", err)
	}
	if !closed || closeFrame.CloseReason != tunnel.TCPCloseReasonByteCapExceeded {
		t.Fatalf("closed=%v closeFrame=%+v, want byte_cap_exceeded close", closed, closeFrame)
	}
	if written != 0 || localWriter.Len() != 0 {
		t.Fatalf("written=%d localWriterLen=%d, want fail-closed before local write", written, localWriter.Len())
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d, want cleanup", got)
	}
	if _, ok := contract.TenantID("req_tcp_ne_byte_cap"); ok {
		t.Fatal("tenant metadata remained after byte cap close")
	}
}

func TestContractCopyUpstreamByteCapClosesAndCleansTenantMetadata(t *testing.T) {
	now := time.Date(2026, 6, 1, 11, 58, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	limits := DefaultLimits()
	limits.ByteCap = 4
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_upstream_byte_cap",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		Limits:        limits,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	closeFrame, closed, err := contract.CopyUpstream("req_tcp_ne_upstream_byte_cap", strings.NewReader("12345"), 64)
	if err != nil {
		t.Fatalf("CopyUpstream returned error: %v", err)
	}
	if !closed || closeFrame.Type != tunnel.FrameTCPClose || closeFrame.CloseReason != tunnel.TCPCloseReasonByteCapExceeded {
		t.Fatalf("closeFrame=%+v closed=%v, want upstream byte cap close", closeFrame, closed)
	}
	if closeFrame.BytesUp != int64(len("12345")) || closeFrame.BytesDown != 0 {
		t.Fatalf("closeFrame metrics = up:%d down:%d, want upstream bytes only", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d, want cleanup after upstream byte cap", got)
	}
	if _, ok := contract.TenantID("req_tcp_ne_upstream_byte_cap"); ok {
		t.Fatal("tenant metadata remained after upstream byte cap close")
	}
}

func TestContractCloseExpiredCleansTenantMetadata(t *testing.T) {
	now := time.Date(2026, 6, 1, 10, 50, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	limits := DefaultLimits()
	limits.IdleTimeoutMillis = 100
	limits.MaxConnectionLifetimeMillis = 1_000
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_expire",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		Limits:        limits,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(101 * time.Millisecond)
	closed := contract.CloseExpired()
	if len(closed) != 1 {
		t.Fatalf("CloseExpired returned %d frames, want 1", len(closed))
	}
	if closed[0].CloseReason != tunnel.TCPCloseReasonIdleTimeoutExceeded {
		t.Fatalf("close reason = %s, want idle timeout", closed[0].CloseReason)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d, want cleanup", got)
	}
	if _, ok := contract.TenantID("req_tcp_ne_expire"); ok {
		t.Fatal("tenant metadata remained after CloseExpired")
	}
}

func TestContractCloseExpiredCleansLifetimeTenantMetadata(t *testing.T) {
	now := time.Date(2026, 6, 1, 11, 45, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	limits := DefaultLimits()
	limits.IdleTimeoutMillis = 100
	limits.MaxConnectionLifetimeMillis = 100
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_lifetime",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		Limits:        limits,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(50 * time.Millisecond)
	upFrame, closed, err := contract.CopyUpstream("req_tcp_ne_lifetime", strings.NewReader("abc"), 64)
	if err != nil {
		t.Fatalf("CopyUpstream returned error: %v", err)
	}
	if closed || upFrame.Type != tunnel.FrameTCPData {
		t.Fatalf("upFrame=%+v closed=%v, want active upstream data before lifetime expiry", upFrame, closed)
	}

	now = now.Add(50 * time.Millisecond)
	closedFrames := contract.CloseExpired()
	if len(closedFrames) != 1 {
		t.Fatalf("CloseExpired returned %d frames, want 1", len(closedFrames))
	}
	if closedFrames[0].CloseReason != tunnel.TCPCloseReasonLifetimeExceeded {
		t.Fatalf("close reason = %s, want lifetime exceeded", closedFrames[0].CloseReason)
	}
	if closedFrames[0].BytesUp != int64(len("abc")) || closedFrames[0].BytesDown != 0 {
		t.Fatalf("closeFrame metrics = up:%d down:%d, want upstream bytes only", closedFrames[0].BytesUp, closedFrames[0].BytesDown)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d, want cleanup after lifetime expiry", got)
	}
	if _, ok := contract.TenantID("req_tcp_ne_lifetime"); ok {
		t.Fatal("tenant metadata remained after lifetime CloseExpired")
	}
}

func TestContractCloseExpiredKeepsActiveOpenRecordForLaterCloseAudit(t *testing.T) {
	now := time.Date(2026, 6, 1, 18, 20, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	limits := DefaultLimits()
	limits.IdleTimeoutMillis = int((30 * time.Second) / time.Millisecond)
	limits.MaxConnectionLifetimeMillis = int((5 * time.Minute) / time.Millisecond)

	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_expired",
		RequestID:     "req_tcp_ne_expired_cleanup",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		Limits:        limits,
	}); err != nil {
		t.Fatalf("Open expired request returned error: %v", err)
	}
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_active",
		RequestID:     "req_tcp_ne_active_after_expire",
		ApplicationID: "app_dummy_ssh",
		Host:          "dummy-private-app.local",
		Port:          22,
		Limits:        limits,
	}); err != nil {
		t.Fatalf("Open active request returned error: %v", err)
	}

	now = now.Add(10 * time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_expired_cleanup", strings.NewReader("expired bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream expired request returned error: %v", err)
	}
	now = now.Add(39 * time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_active_after_expire", strings.NewReader("active bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream active request returned error: %v", err)
	}

	now = now.Add(time.Second)
	closed := contract.CloseExpired()
	if len(closed) != 1 {
		t.Fatalf("CloseExpired returned %d frames, want only expired request", len(closed))
	}
	if closed[0].RequestID != "req_tcp_ne_expired_cleanup" || closed[0].CloseReason != tunnel.TCPCloseReasonIdleTimeoutExceeded {
		t.Fatalf("closed[0] = %+v, want expired idle timeout close", closed[0])
	}
	if closed[0].BytesUp != int64(len("expired bytes")) || closed[0].BytesDown != 0 {
		t.Fatalf("expired close metrics = up:%d down:%d, want expired request metrics only", closed[0].BytesUp, closed[0].BytesDown)
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d after CloseExpired, want active request retained", got)
	}
	if _, ok := contract.TenantID("req_tcp_ne_expired_cleanup"); ok {
		t.Fatal("expired tenant metadata remained after CloseExpired")
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_active_after_expire"); !ok || tenantID != "tenant_lab_active" {
		t.Fatalf("TenantID = %q/%v, want active tenant metadata retained", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_active_after_expire"); !ok || applicationID != "app_dummy_ssh" {
		t.Fatalf("ApplicationID = %q/%v, want active application metadata retained", applicationID, ok)
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_active_after_expire", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit active request returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len("active bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("active close metrics = up:%d down:%d, want active metrics preserved", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if event.TenantID != "tenant_lab_active" || event.ApplicationID != "app_dummy_ssh" {
		t.Fatalf("active close audit scope = tenant:%q app:%q, want retained active open record", event.TenantID, event.ApplicationID)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d after active close, want cleanup", got)
	}
}

func TestContractCloseWithMetadataAuditRejectsUnknownReasonWithoutCleanup(t *testing.T) {
	now := time.Date(2026, 6, 1, 18, 35, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_audit_guard",
		RequestID:     "req_tcp_ne_close_audit_guard",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_close_audit_guard", strings.NewReader("guard bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream returned error: %v", err)
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_close_audit_guard", tunnel.TCPDirectionLocal, "surprise")
	if err == nil {
		t.Fatal("CloseWithMetadataAudit returned nil error for unknown close reason")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("error = %q, want unknown close reason rejection", err.Error())
	}
	if closeFrame.Type != "" || event.EventType != "" {
		t.Fatalf("closeFrame=%+v event=%+v, want no close audit material on invalid reason", closeFrame, event)
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want open connection retained after rejected close audit", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_close_audit_guard"); !ok || tenantID != "tenant_lab_audit_guard" {
		t.Fatalf("TenantID = %q/%v, want metadata retained after rejected close audit", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_close_audit_guard"); !ok || applicationID != "app_dummy_https" {
		t.Fatalf("ApplicationID = %q/%v, want application metadata retained after rejected close audit", applicationID, ok)
	}

	now = now.Add(time.Second)
	closeFrame, event, err = contract.CloseWithMetadataAudit("req_tcp_ne_close_audit_guard", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit valid retry returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len("guard bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("valid retry metrics = up:%d down:%d, want preserved byte metrics", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if event.EventType != AuditEventFlowCopyClosed || event.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("event = %+v, want metadata-only EOF close audit", event)
	}
	if event.TenantID != "tenant_lab_audit_guard" || event.ApplicationID != "app_dummy_https" {
		t.Fatalf("event scope = tenant:%q app:%q, want retained open record", event.TenantID, event.ApplicationID)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d after valid retry close, want cleanup", got)
	}
}

func TestContractCopyUpstreamNilReaderRejectsWithoutCleanup(t *testing.T) {
	now := time.Date(2026, 6, 1, 18, 50, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_upstream_guard",
		RequestID:     "req_tcp_ne_upstream_nil_reader",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_upstream_nil_reader", strings.NewReader("preserved bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream returned error before nil reader guard: %v", err)
	}

	now = now.Add(time.Second)
	frame, closed, err := contract.CopyUpstream("req_tcp_ne_upstream_nil_reader", nil, 64)
	if err == nil {
		t.Fatal("CopyUpstream returned nil error for nil reader")
	}
	if !strings.Contains(err.Error(), "tcp reader is required") {
		t.Fatalf("error = %q, want nil reader rejection", err.Error())
	}
	if closed || frame.Type != "" {
		t.Fatalf("frame=%+v closed=%v, want nil reader rejected before close material", frame, closed)
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want open connection retained after nil reader rejection", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_upstream_nil_reader"); !ok || tenantID != "tenant_lab_upstream_guard" {
		t.Fatalf("TenantID = %q/%v, want metadata retained after nil reader rejection", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_upstream_nil_reader"); !ok || applicationID != "app_dummy_https" {
		t.Fatalf("ApplicationID = %q/%v, want application metadata retained after nil reader rejection", applicationID, ok)
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_upstream_nil_reader", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit after nil reader rejection returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len("preserved bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("close metrics = up:%d down:%d, want preserved upstream bytes only", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if event.EventType != AuditEventFlowCopyClosed || event.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("event = %+v, want metadata-only EOF close audit", event)
	}
	if event.TenantID != "tenant_lab_upstream_guard" || event.ApplicationID != "app_dummy_https" {
		t.Fatalf("event scope = tenant:%q app:%q, want retained open record", event.TenantID, event.ApplicationID)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d after valid close, want cleanup", got)
	}
}

func TestContractCopyDownstreamNilWriterRejectsWithoutRegistryMutation(t *testing.T) {
	now := time.Date(2026, 6, 1, 19, 9, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_downstream_guard",
		RequestID:     "req_tcp_ne_downstream_nil_writer",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_downstream_nil_writer", strings.NewReader("preserved upstream bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream returned error before nil writer guard: %v", err)
	}

	downFrame, err := tunnel.NewTCPDataFrame("req_tcp_ne_downstream_nil_writer", tunnel.TCPDirectionDown, []byte("unwritten downstream bytes"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	now = now.Add(time.Second)
	written, closeFrame, closed, err := contract.CopyDownstream(downFrame, nil)
	if err == nil {
		t.Fatal("CopyDownstream returned nil error for nil writer")
	}
	if !strings.Contains(err.Error(), "tcp writer is required") {
		t.Fatalf("error = %q, want nil writer rejection", err.Error())
	}
	if written != 0 || closed || closeFrame.Type != "" {
		t.Fatalf("written=%d closeFrame=%+v closed=%v, want nil writer rejected before close material", written, closeFrame, closed)
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want open connection retained after nil writer rejection", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_downstream_nil_writer"); !ok || tenantID != "tenant_lab_downstream_guard" {
		t.Fatalf("TenantID = %q/%v, want metadata retained after nil writer rejection", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_downstream_nil_writer"); !ok || applicationID != "app_dummy_https" {
		t.Fatalf("ApplicationID = %q/%v, want application metadata retained after nil writer rejection", applicationID, ok)
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_downstream_nil_writer", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit after nil writer rejection returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len("preserved upstream bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("close metrics = up:%d down:%d, want nil writer rejected before downstream bytes", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if event.EventType != AuditEventFlowCopyClosed || event.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("event = %+v, want metadata-only EOF close audit", event)
	}
	if event.TenantID != "tenant_lab_downstream_guard" || event.ApplicationID != "app_dummy_https" {
		t.Fatalf("event scope = tenant:%q app:%q, want retained open record", event.TenantID, event.ApplicationID)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d after valid close, want cleanup", got)
	}
}

func TestContractCopyDownstreamUnknownRequestRejectsBeforeWriteOrMutation(t *testing.T) {
	now := time.Date(2026, 6, 1, 19, 27, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_downstream_unknown_guard",
		RequestID:     "req_tcp_ne_downstream_known",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_downstream_known", strings.NewReader("preserved known bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream returned error before unknown downstream guard: %v", err)
	}

	downFrame, err := tunnel.NewTCPDataFrame("req_tcp_ne_downstream_unknown", tunnel.TCPDirectionDown, []byte("unwritten unknown bytes"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	var localWriter bytes.Buffer
	now = now.Add(time.Second)
	written, closeFrame, closed, err := contract.CopyDownstream(downFrame, &localWriter)
	if err == nil {
		t.Fatal("CopyDownstream returned nil error for unknown request")
	}
	if !strings.Contains(err.Error(), "not open") {
		t.Fatalf("error = %q, want unknown request rejection", err.Error())
	}
	if written != 0 || closed || closeFrame.Type != "" || localWriter.Len() != 0 {
		t.Fatalf("written=%d closeFrame=%+v closed=%v localWriterLen=%d, want unknown request rejected before write or close material", written, closeFrame, closed, localWriter.Len())
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want known connection retained after unknown downstream rejection", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_downstream_known"); !ok || tenantID != "tenant_lab_downstream_unknown_guard" {
		t.Fatalf("TenantID = %q/%v, want known metadata retained after unknown downstream rejection", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_downstream_known"); !ok || applicationID != "app_dummy_https" {
		t.Fatalf("ApplicationID = %q/%v, want known application metadata retained after unknown downstream rejection", applicationID, ok)
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_downstream_known", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit after unknown downstream rejection returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len("preserved known bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("close metrics = up:%d down:%d, want unknown downstream payload not counted", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if event.EventType != AuditEventFlowCopyClosed || event.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("event = %+v, want metadata-only EOF close audit", event)
	}
	if event.TenantID != "tenant_lab_downstream_unknown_guard" || event.ApplicationID != "app_dummy_https" {
		t.Fatalf("event scope = tenant:%q app:%q, want retained known open record", event.TenantID, event.ApplicationID)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d after valid close, want cleanup", got)
	}
}

func TestContractCopyUpstreamUnknownRequestRejectsWithoutRegistryMutation(t *testing.T) {
	now := time.Date(2026, 6, 1, 19, 43, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_upstream_unknown_guard",
		RequestID:     "req_tcp_ne_upstream_known",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_upstream_known", strings.NewReader("preserved upstream bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream returned error before unknown upstream guard: %v", err)
	}

	now = now.Add(time.Second)
	frame, closed, err := contract.CopyUpstream("req_tcp_ne_upstream_unknown", strings.NewReader("unrecorded unknown bytes"), 64)
	if err == nil {
		t.Fatal("CopyUpstream returned nil error for unknown request")
	}
	if !strings.Contains(err.Error(), "not open") {
		t.Fatalf("error = %q, want unknown request rejection", err.Error())
	}
	if closed || frame.Type != "" {
		t.Fatalf("frame=%+v closed=%v, want unknown upstream rejected before close material", frame, closed)
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want known connection retained after unknown upstream rejection", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_upstream_known"); !ok || tenantID != "tenant_lab_upstream_unknown_guard" {
		t.Fatalf("TenantID = %q/%v, want known metadata retained after unknown upstream rejection", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_upstream_known"); !ok || applicationID != "app_dummy_https" {
		t.Fatalf("ApplicationID = %q/%v, want known application metadata retained after unknown upstream rejection", applicationID, ok)
	}
	if _, ok := contract.OpenRecord("req_tcp_ne_upstream_unknown"); ok {
		t.Fatal("open record was created for rejected unknown upstream request")
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_upstream_known", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit after unknown upstream rejection returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len("preserved upstream bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("close metrics = up:%d down:%d, want unknown upstream payload not counted", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if event.EventType != AuditEventFlowCopyClosed || event.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("event = %+v, want metadata-only EOF close audit", event)
	}
	if event.TenantID != "tenant_lab_upstream_unknown_guard" || event.ApplicationID != "app_dummy_https" {
		t.Fatalf("event scope = tenant:%q app:%q, want retained known open record", event.TenantID, event.ApplicationID)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d after valid close, want cleanup", got)
	}
}

func TestContractCopyUpstreamZeroChunkSizeRejectsWithoutRegistryMutation(t *testing.T) {
	now := time.Date(2026, 6, 1, 20, 5, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_upstream_chunk_guard",
		RequestID:     "req_tcp_ne_upstream_zero_chunk",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_upstream_zero_chunk", strings.NewReader("preserved upstream bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream returned error before zero chunk guard: %v", err)
	}

	now = now.Add(time.Second)
	frame, closed, err := contract.CopyUpstream("req_tcp_ne_upstream_zero_chunk", strings.NewReader("rejected zero chunk bytes"), 0)
	if err == nil {
		t.Fatal("CopyUpstream returned nil error for zero chunk size")
	}
	if !strings.Contains(err.Error(), "tcp chunk size") {
		t.Fatalf("error = %q, want zero chunk size rejection", err.Error())
	}
	if closed || frame.Type != "" {
		t.Fatalf("frame=%+v closed=%v, want zero chunk rejected before close material", frame, closed)
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want open connection retained after zero chunk rejection", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_upstream_zero_chunk"); !ok || tenantID != "tenant_lab_upstream_chunk_guard" {
		t.Fatalf("TenantID = %q/%v, want metadata retained after zero chunk rejection", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_upstream_zero_chunk"); !ok || applicationID != "app_dummy_https" {
		t.Fatalf("ApplicationID = %q/%v, want application metadata retained after zero chunk rejection", applicationID, ok)
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_upstream_zero_chunk", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit after zero chunk rejection returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len("preserved upstream bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("close metrics = up:%d down:%d, want zero chunk payload not counted", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if event.EventType != AuditEventFlowCopyClosed || event.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("event = %+v, want metadata-only EOF close audit", event)
	}
	if event.TenantID != "tenant_lab_upstream_chunk_guard" || event.ApplicationID != "app_dummy_https" {
		t.Fatalf("event scope = tenant:%q app:%q, want retained open record", event.TenantID, event.ApplicationID)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d after valid close, want cleanup", got)
	}
}

func TestContractCopyUpstreamOversizedChunkSizeRejectsWithoutRegistryMutation(t *testing.T) {
	now := time.Date(2026, 6, 1, 20, 15, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_upstream_oversized_chunk_guard",
		RequestID:     "req_tcp_ne_upstream_oversized_chunk",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_upstream_oversized_chunk", strings.NewReader("preserved upstream bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream returned error before oversized chunk guard: %v", err)
	}

	now = now.Add(time.Second)
	frame, closed, err := contract.CopyUpstream("req_tcp_ne_upstream_oversized_chunk", strings.NewReader("rejected oversized chunk bytes"), tunnel.MaxTCPDataFramePayloadBytes+1)
	if err == nil {
		t.Fatal("CopyUpstream returned nil error for oversized chunk size")
	}
	if !strings.Contains(err.Error(), "tcp chunk size") {
		t.Fatalf("error = %q, want oversized chunk size rejection", err.Error())
	}
	if closed || frame.Type != "" {
		t.Fatalf("frame=%+v closed=%v, want oversized chunk rejected before close material", frame, closed)
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want open connection retained after oversized chunk rejection", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_upstream_oversized_chunk"); !ok || tenantID != "tenant_lab_upstream_oversized_chunk_guard" {
		t.Fatalf("TenantID = %q/%v, want metadata retained after oversized chunk rejection", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_upstream_oversized_chunk"); !ok || applicationID != "app_dummy_https" {
		t.Fatalf("ApplicationID = %q/%v, want application metadata retained after oversized chunk rejection", applicationID, ok)
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_upstream_oversized_chunk", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit after oversized chunk rejection returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len("preserved upstream bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("close metrics = up:%d down:%d, want oversized chunk payload not counted", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if event.EventType != AuditEventFlowCopyClosed || event.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("event = %+v, want metadata-only EOF close audit", event)
	}
	if event.TenantID != "tenant_lab_upstream_oversized_chunk_guard" || event.ApplicationID != "app_dummy_https" {
		t.Fatalf("event scope = tenant:%q app:%q, want retained open record", event.TenantID, event.ApplicationID)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d after valid close, want cleanup", got)
	}
}

func TestContractCopyDownstreamMalformedPayloadRejectsWithoutRegistryMutation(t *testing.T) {
	now := time.Date(2026, 6, 1, 20, 32, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_downstream_malformed_guard",
		RequestID:     "req_tcp_ne_downstream_malformed",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_downstream_malformed", strings.NewReader("preserved upstream bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream returned error before malformed downstream guard: %v", err)
	}

	downFrame := tunnel.Frame{
		Type:      tunnel.FrameTCPData,
		RequestID: "req_tcp_ne_downstream_malformed",
		Direction: tunnel.TCPDirectionDown,
		Data:      "not-base64!",
	}
	var localWriter bytes.Buffer
	now = now.Add(time.Second)
	written, closeFrame, closed, err := contract.CopyDownstream(downFrame, &localWriter)
	if err == nil {
		t.Fatal("CopyDownstream returned nil error for malformed downstream payload")
	}
	if !strings.Contains(err.Error(), "tcp_data payload must be base64") {
		t.Fatalf("error = %q, want malformed payload rejection", err.Error())
	}
	if written != 0 || closed || closeFrame.Type != "" || localWriter.Len() != 0 {
		t.Fatalf("written=%d closeFrame=%+v closed=%v localWriterLen=%d, want malformed downstream rejected before write or close material", written, closeFrame, closed, localWriter.Len())
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want open connection retained after malformed downstream rejection", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_downstream_malformed"); !ok || tenantID != "tenant_lab_downstream_malformed_guard" {
		t.Fatalf("TenantID = %q/%v, want metadata retained after malformed downstream rejection", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_downstream_malformed"); !ok || applicationID != "app_dummy_https" {
		t.Fatalf("ApplicationID = %q/%v, want application metadata retained after malformed downstream rejection", applicationID, ok)
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_downstream_malformed", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit after malformed downstream rejection returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len("preserved upstream bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("close metrics = up:%d down:%d, want malformed downstream payload not counted", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if event.EventType != AuditEventFlowCopyClosed || event.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("event = %+v, want metadata-only EOF close audit", event)
	}
	if event.TenantID != "tenant_lab_downstream_malformed_guard" || event.ApplicationID != "app_dummy_https" {
		t.Fatalf("event scope = tenant:%q app:%q, want retained open record", event.TenantID, event.ApplicationID)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d after valid close, want cleanup", got)
	}
}

func TestContractCopyDownstreamOversizedPayloadRejectsWithoutRegistryMutation(t *testing.T) {
	now := time.Date(2026, 6, 1, 20, 52, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_downstream_oversized_guard",
		RequestID:     "req_tcp_ne_downstream_oversized_payload",
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	if _, _, err := contract.CopyUpstream("req_tcp_ne_downstream_oversized_payload", strings.NewReader("preserved upstream bytes"), 64); err != nil {
		t.Fatalf("CopyUpstream returned error before oversized downstream guard: %v", err)
	}

	oversizedPayload := strings.Repeat("x", tunnel.MaxTCPDataFramePayloadBytes+1)
	downFrame := tunnel.Frame{
		Type:      tunnel.FrameTCPData,
		RequestID: "req_tcp_ne_downstream_oversized_payload",
		Direction: tunnel.TCPDirectionDown,
		Data:      base64.StdEncoding.EncodeToString([]byte(oversizedPayload)),
	}
	var localWriter bytes.Buffer
	now = now.Add(time.Second)
	written, closeFrame, closed, err := contract.CopyDownstream(downFrame, &localWriter)
	if err == nil {
		t.Fatal("CopyDownstream returned nil error for oversized downstream payload")
	}
	if !strings.Contains(err.Error(), "tcp_data payload length") {
		t.Fatalf("error = %q, want oversized payload rejection", err.Error())
	}
	if written != 0 || closed || closeFrame.Type != "" || localWriter.Len() != 0 {
		t.Fatalf("written=%d closeFrame=%+v closed=%v localWriterLen=%d, want oversized downstream rejected before write or close material", written, closeFrame, closed, localWriter.Len())
	}
	if got := contract.Count(); got != 1 {
		t.Fatalf("Count = %d, want open connection retained after oversized downstream rejection", got)
	}
	if tenantID, ok := contract.TenantID("req_tcp_ne_downstream_oversized_payload"); !ok || tenantID != "tenant_lab_downstream_oversized_guard" {
		t.Fatalf("TenantID = %q/%v, want metadata retained after oversized downstream rejection", tenantID, ok)
	}
	if applicationID, ok := contract.ApplicationID("req_tcp_ne_downstream_oversized_payload"); !ok || applicationID != "app_dummy_https" {
		t.Fatalf("ApplicationID = %q/%v, want application metadata retained after oversized downstream rejection", applicationID, ok)
	}

	now = now.Add(time.Second)
	closeFrame, event, err := contract.CloseWithMetadataAudit("req_tcp_ne_downstream_oversized_payload", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
	if err != nil {
		t.Fatalf("CloseWithMetadataAudit after oversized downstream rejection returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len("preserved upstream bytes")) || closeFrame.BytesDown != 0 {
		t.Fatalf("close metrics = up:%d down:%d, want oversized downstream payload not counted", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if event.EventType != AuditEventFlowCopyClosed || event.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("event = %+v, want metadata-only EOF close audit", event)
	}
	if event.TenantID != "tenant_lab_downstream_oversized_guard" || event.ApplicationID != "app_dummy_https" {
		t.Fatalf("event scope = tenant:%q app:%q, want retained open record", event.TenantID, event.ApplicationID)
	}
	if got := contract.Count(); got != 0 {
		t.Fatalf("Count = %d after valid close, want cleanup", got)
	}
}

func TestMetadataAuditEventFromOpenIsMetadataOnly(t *testing.T) {
	contract := NewContract(nil)
	openFrame, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_audit_open",
		ApplicationID: "app_dummy_https",
		Host:          "private-app.example.internal",
		Port:          443,
	})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	event, err := MetadataAuditEventFromOpen("tenant_lab_001", openFrame)
	if err != nil {
		t.Fatalf("MetadataAuditEventFromOpen returned error: %v", err)
	}
	if event.SchemaVersion != MetadataAuditContractVersion || event.EventType != AuditEventFlowCopyStarted {
		t.Fatalf("event = %+v, want metadata audit started event", event)
	}
	if !event.MetadataOnly {
		t.Fatal("MetadataOnly = false, want true")
	}
	if event.NetworkExtensionRuntimeUsed || event.NetworkExtensionFlowReadStarted ||
		event.NetworkExtensionFlowWriteStarted || event.EdgeTunnelOpenStarted ||
		event.TCPPayloadCopyStarted || event.RawPayloadIncluded ||
		event.RawNEFlowIncluded || event.RawDestinationIPIncluded ||
		event.CredentialsIncluded || event.SessionIDIncluded {
		t.Fatalf("event overclaimed runtime or raw material fields: %+v", event)
	}

	encoded := mustMarshalAuditEvent(t, event)
	for _, forbidden := range []string{"private-app.example.internal", `"host":`, `"port":`, `"data":`, `"source_ip":`, `"destination":`, `"session_id":`} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("metadata audit event JSON contains forbidden raw/routing field %q: %s", forbidden, encoded)
		}
	}
}

func TestMetadataAuditEventFromCloseMapsReasonAndMetricsOnly(t *testing.T) {
	now := time.Date(2026, 6, 1, 15, 5, 0, 0, time.UTC)
	contract := NewContract(func() time.Time { return now })
	limits := DefaultLimits()
	limits.ByteCap = 4
	if _, err := contract.Open(OpenMetadata{
		TenantID:      "tenant_lab_001",
		RequestID:     "req_tcp_ne_audit_close",
		ApplicationID: "app_dummy_https",
		Host:          "private-app.example.internal",
		Port:          443,
		Limits:        limits,
	}); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	now = now.Add(time.Second)
	closeFrame, closed, err := contract.CopyUpstream("req_tcp_ne_audit_close", strings.NewReader("12345"), 64)
	if err != nil {
		t.Fatalf("CopyUpstream returned error: %v", err)
	}
	if !closed {
		t.Fatal("CopyUpstream did not close on byte cap")
	}

	event, err := MetadataAuditEventFromClose("tenant_lab_001", "app_dummy_https", closeFrame)
	if err != nil {
		t.Fatalf("MetadataAuditEventFromClose returned error: %v", err)
	}
	if event.EventType != AuditEventFlowCopyByteCapExceeded || event.CloseReason != tunnel.TCPCloseReasonByteCapExceeded {
		t.Fatalf("event = %+v, want byte cap close audit event", event)
	}
	if event.BytesUp != int64(len("12345")) || event.BytesDown != 0 || event.DurationMillis != 1000 {
		t.Fatalf("event metrics = up:%d down:%d duration:%d, want copied byte counters only", event.BytesUp, event.BytesDown, event.DurationMillis)
	}

	encoded := mustMarshalAuditEvent(t, event)
	for _, forbidden := range []string{"12345", `"data":`, `"source_ip":`, `"destination_ip":`, `"session_id":`, `"credentials":`} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("metadata close audit event JSON contains forbidden raw field %q: %s", forbidden, encoded)
		}
	}
}

func TestMetadataAuditEventCloseReasonMapping(t *testing.T) {
	tests := []struct {
		name       string
		reason     string
		wantEvent  string
		wantReason string
	}{
		{
			name:       "idle_timeout",
			reason:     tunnel.TCPCloseReasonIdleTimeoutExceeded,
			wantEvent:  AuditEventFlowCopyIdleTimeout,
			wantReason: tunnel.TCPCloseReasonIdleTimeoutExceeded,
		},
		{
			name:       "ordinary_close",
			reason:     tunnel.TCPCloseReasonEOF,
			wantEvent:  AuditEventFlowCopyClosed,
			wantReason: tunnel.TCPCloseReasonEOF,
		},
		{
			name:       "lifetime_exceeded_folds_to_closed",
			reason:     tunnel.TCPCloseReasonLifetimeExceeded,
			wantEvent:  AuditEventFlowCopyClosed,
			wantReason: tunnel.TCPCloseReasonLifetimeExceeded,
		},
		{
			name:       "concurrent_cap_exceeded_folds_to_closed",
			reason:     tunnel.TCPCloseReasonConcurrentCapExceeded,
			wantEvent:  AuditEventFlowCopyClosed,
			wantReason: tunnel.TCPCloseReasonConcurrentCapExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := MetadataAuditEventFromClose("tenant_lab_001", "app_dummy_https", tunnel.Frame{
				Type:           tunnel.FrameTCPClose,
				RequestID:      "req_tcp_ne_audit_reason",
				Direction:      tunnel.TCPDirectionLocal,
				CloseReason:    tt.reason,
				BytesUp:        10,
				BytesDown:      5,
				DurationMillis: 1500,
			})
			if err != nil {
				t.Fatalf("MetadataAuditEventFromClose returned error: %v", err)
			}
			if event.EventType != tt.wantEvent || event.CloseReason != tt.wantReason {
				t.Fatalf("event=%+v, want event %s reason %s", event, tt.wantEvent, tt.wantReason)
			}
		})
	}
}

func TestMetadataAuditBackpressureAndTenantMismatchEventsAreMetadataOnly(t *testing.T) {
	tests := []struct {
		name  string
		input MetadataAuditInput
	}{
		{
			name: "backpressure_overflow_closed",
			input: MetadataAuditInput{
				EventType:      AuditEventFlowCopyBackpressureOverflowClosed,
				TenantID:       "tenant_lab_001",
				RequestID:      "req_tcp_ne_backpressure",
				ApplicationID:  "app_dummy_https",
				Direction:      tunnel.TCPDirectionLocal,
				CloseReason:    "backpressure_overflow",
				BytesUp:        12,
				BytesDown:      7,
				DurationMillis: 2500,
			},
		},
		{
			name: "tenant_scope_mismatch",
			input: MetadataAuditInput{
				EventType:     AuditEventFlowCopyTenantScopeMismatch,
				TenantID:      "tenant_lab_001",
				RequestID:     "req_tcp_ne_tenant_mismatch",
				ApplicationID: "app_dummy_ssh",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := NewMetadataAuditEvent(tt.input)
			if err != nil {
				t.Fatalf("NewMetadataAuditEvent returned error: %v", err)
			}
			if event.EventType != tt.input.EventType ||
				event.TenantID != tt.input.TenantID ||
				event.RequestID != tt.input.RequestID ||
				event.ApplicationID != tt.input.ApplicationID {
				t.Fatalf("event identity = %+v, want input metadata", event)
			}
			if event.Direction != tt.input.Direction || event.CloseReason != tt.input.CloseReason {
				t.Fatalf("event close metadata = direction:%q reason:%q, want direction:%q reason:%q", event.Direction, event.CloseReason, tt.input.Direction, tt.input.CloseReason)
			}
			if event.BytesUp != tt.input.BytesUp ||
				event.BytesDown != tt.input.BytesDown ||
				event.DurationMillis != tt.input.DurationMillis {
				t.Fatalf("event metrics = up:%d down:%d duration:%d, want input aggregate metrics", event.BytesUp, event.BytesDown, event.DurationMillis)
			}
			if !event.MetadataOnly {
				t.Fatal("MetadataOnly = false, want true")
			}
			if event.NetworkExtensionRuntimeUsed || event.NetworkExtensionFlowReadStarted ||
				event.NetworkExtensionFlowWriteStarted || event.EdgeTunnelOpenStarted ||
				event.TCPPayloadCopyStarted || event.RawPayloadIncluded ||
				event.RawNEFlowIncluded || event.RawDestinationIPIncluded ||
				event.CredentialsIncluded || event.SessionIDIncluded {
				t.Fatalf("event overclaimed runtime or raw material fields: %+v", event)
			}

			encoded := mustMarshalAuditEvent(t, event)
			for _, forbidden := range []string{"private-app.example.internal", `"host":`, `"port":`, `"data":`, `"source_ip":`, `"destination_ip":`, `"payload":`, `"raw_ne_flow":`, `"raw_logs":`, `"raw_command_output":`, `"session_id":`, `"credentials":`} {
				if strings.Contains(encoded, forbidden) {
					t.Fatalf("metadata audit event JSON contains forbidden raw/routing field %q: %s", forbidden, encoded)
				}
			}
		})
	}
}

func TestMetadataAuditContractRejectsUnknownEventAndBadMetadata(t *testing.T) {
	tests := []struct {
		name        string
		input       MetadataAuditInput
		errContains string
	}{
		{
			name: "unknown_event",
			input: MetadataAuditInput{
				EventType:     "flow_copy_payload_sampled",
				TenantID:      "tenant_lab_001",
				RequestID:     "req_tcp_ne_audit_bad",
				ApplicationID: "app_dummy_https",
			},
			errContains: "event_type",
		},
		{
			name: "whitespace_tenant",
			input: MetadataAuditInput{
				EventType:     AuditEventFlowCopyClosed,
				TenantID:      "tenant lab 001",
				RequestID:     "req_tcp_ne_audit_bad",
				ApplicationID: "app_dummy_https",
			},
			errContains: "tenant_id must be non-secret metadata without whitespace",
		},
		{
			name: "negative_metrics",
			input: MetadataAuditInput{
				EventType:     AuditEventFlowCopyClosed,
				TenantID:      "tenant_lab_001",
				RequestID:     "req_tcp_ne_audit_bad",
				ApplicationID: "app_dummy_https",
				BytesUp:       -1,
			},
			errContains: "metrics cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMetadataAuditEvent(tt.input)
			if err == nil {
				t.Fatal("NewMetadataAuditEvent returned nil error")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestRequiredMetadataAuditEventsAreStableAndCurrent(t *testing.T) {
	events := RequiredMetadataAuditEvents()
	want := []string{
		AuditEventFlowCopyStarted,
		AuditEventFlowCopyByteCapExceeded,
		AuditEventFlowCopyIdleTimeout,
		AuditEventFlowCopyBackpressureOverflowClosed,
		AuditEventFlowCopyTenantScopeMismatch,
		AuditEventFlowCopyClosed,
	}
	if len(events) != len(want) {
		t.Fatalf("RequiredMetadataAuditEvents length = %d, want %d: %#v", len(events), len(want), events)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("RequiredMetadataAuditEvents[%d] = %q, want %q", i, events[i], want[i])
		}
	}
	events[0] = "mutated"
	if RequiredMetadataAuditEvents()[0] != AuditEventFlowCopyStarted {
		t.Fatal("RequiredMetadataAuditEvents returned mutable backing slice")
	}
}

func mustMarshalAuditEvent(t *testing.T, event MetadataAuditEvent) string {
	t.Helper()
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	return string(encoded)
}
