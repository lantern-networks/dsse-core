package neflowcopy

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

type Limits struct {
	ConnectTimeoutMillis        int
	MaxConnectionLifetimeMillis int
	IdleTimeoutMillis           int
	ByteCap                     int64
	ConcurrentConnectionCap     int
}

type OpenMetadata struct {
	TenantID      string
	RequestID     string
	ApplicationID string
	Host          string
	Port          int
	Limits        Limits
}

type OpenRecord struct {
	TenantID      string
	ApplicationID string
}

type Contract struct {
	mu          sync.Mutex
	registry    *tunnel.TCPConnectionRegistry
	openRecords map[string]OpenRecord
	now         func() time.Time
}

func DefaultLimits() Limits {
	return Limits{
		ConnectTimeoutMillis:        int((5 * time.Second) / time.Millisecond),
		MaxConnectionLifetimeMillis: int((5 * time.Minute) / time.Millisecond),
		IdleTimeoutMillis:           int((30 * time.Second) / time.Millisecond),
		ByteCap:                     64 << 20,
		ConcurrentConnectionCap:     32,
	}
}

func NewContract(now func() time.Time) *Contract {
	if now == nil {
		now = time.Now
	}
	return &Contract{
		registry:    tunnel.NewTCPConnectionRegistry(),
		openRecords: map[string]OpenRecord{},
		now:         now,
	}
}

func (c *Contract) Open(metadata OpenMetadata) (tunnel.Frame, error) {
	if c == nil || c.registry == nil {
		return tunnel.Frame{}, fmt.Errorf("flow copy contract registry is required")
	}
	tenantID, err := requiredMetadataID("tenant_id", metadata.TenantID)
	if err != nil {
		return tunnel.Frame{}, err
	}
	requestID, err := requiredMetadataID("request_id", metadata.RequestID)
	if err != nil {
		return tunnel.Frame{}, err
	}
	applicationID, err := requiredMetadataID("application_id", metadata.ApplicationID)
	if err != nil {
		return tunnel.Frame{}, err
	}
	frame := tunnel.Frame{
		Type:                        tunnel.FrameTCPOpen,
		RequestID:                   requestID,
		ApplicationID:               applicationID,
		Host:                        strings.ToLower(strings.TrimSpace(metadata.Host)),
		Port:                        metadata.Port,
		ConnectTimeoutMillis:        limitOrDefault(metadata.Limits.ConnectTimeoutMillis, DefaultLimits().ConnectTimeoutMillis),
		MaxConnectionLifetimeMillis: limitOrDefault(metadata.Limits.MaxConnectionLifetimeMillis, DefaultLimits().MaxConnectionLifetimeMillis),
		IdleTimeoutMillis:           limitOrDefault(metadata.Limits.IdleTimeoutMillis, DefaultLimits().IdleTimeoutMillis),
		ByteCap:                     byteLimitOrDefault(metadata.Limits.ByteCap, DefaultLimits().ByteCap),
		ConcurrentConnectionCap:     limitOrDefault(metadata.Limits.ConcurrentConnectionCap, DefaultLimits().ConcurrentConnectionCap),
	}
	if err := c.registry.Open(frame, c.now()); err != nil {
		return tunnel.Frame{}, err
	}
	c.mu.Lock()
	c.openRecords[requestID] = OpenRecord{
		TenantID:      tenantID,
		ApplicationID: applicationID,
	}
	c.mu.Unlock()
	return frame, nil
}

func (c *Contract) CopyUpstream(requestID string, reader io.Reader, maxChunkBytes int) (tunnel.Frame, bool, error) {
	if c == nil || c.registry == nil {
		return tunnel.Frame{}, false, fmt.Errorf("flow copy contract registry is required")
	}
	frame, _, err := tunnel.ReadTCPDataFrame(reader, requestID, tunnel.TCPDirectionUp, maxChunkBytes)
	if err == io.EOF {
		closeFrame, closeErr := c.Close(requestID, tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF)
		return closeFrame, true, closeErr
	}
	if err != nil {
		return tunnel.Frame{}, false, err
	}
	return c.recordData(frame)
}

func (c *Contract) CopyDownstream(frame tunnel.Frame, writer io.Writer) (int, tunnel.Frame, bool, error) {
	if c == nil || c.registry == nil {
		return 0, tunnel.Frame{}, false, fmt.Errorf("flow copy contract registry is required")
	}
	if frame.Direction != tunnel.TCPDirectionDown {
		return 0, tunnel.Frame{}, false, fmt.Errorf("downstream flow copy requires down direction")
	}
	if writer == nil {
		return 0, tunnel.Frame{}, false, fmt.Errorf("tcp writer is required")
	}
	closeFrame, closed, err := c.recordData(frame)
	if err != nil {
		return 0, tunnel.Frame{}, false, err
	}
	if closed {
		return 0, closeFrame, true, nil
	}
	written, err := tunnel.WriteTCPDataFrame(writer, frame)
	return written, tunnel.Frame{}, false, err
}

func (c *Contract) Close(requestID, direction, reason string) (tunnel.Frame, error) {
	if c == nil || c.registry == nil {
		return tunnel.Frame{}, fmt.Errorf("flow copy contract registry is required")
	}
	closeFrame, err := c.registry.Close(requestID, direction, reason, c.now())
	if err != nil {
		return tunnel.Frame{}, err
	}
	c.deleteOpenRecord(requestID)
	return closeFrame, nil
}

func (c *Contract) CloseWithMetadataAudit(requestID, direction, reason string) (tunnel.Frame, MetadataAuditEvent, error) {
	if c == nil || c.registry == nil {
		return tunnel.Frame{}, MetadataAuditEvent{}, fmt.Errorf("flow copy contract registry is required")
	}
	record, ok := c.OpenRecord(requestID)
	if !ok {
		return tunnel.Frame{}, MetadataAuditEvent{}, fmt.Errorf("flow copy open record for %s is required before close audit event", requestID)
	}
	closeFrame, err := c.registry.Close(requestID, direction, reason, c.now())
	if err != nil {
		return tunnel.Frame{}, MetadataAuditEvent{}, err
	}
	defer c.deleteOpenRecord(requestID)
	event, err := metadataAuditEventFromOpenRecord(record, closeFrame)
	if err != nil {
		return closeFrame, MetadataAuditEvent{}, err
	}
	return closeFrame, event, nil
}

func (c *Contract) CloseExpired() []tunnel.Frame {
	if c == nil || c.registry == nil {
		return nil
	}
	frames := c.registry.CloseExpired(c.now())
	for _, frame := range frames {
		c.deleteOpenRecord(frame.RequestID)
	}
	return frames
}

func (c *Contract) Count() int {
	if c == nil || c.registry == nil {
		return 0
	}
	return c.registry.Count()
}

func (c *Contract) TenantID(requestID string) (string, bool) {
	record, ok := c.OpenRecord(requestID)
	return record.TenantID, ok
}

func (c *Contract) ApplicationID(requestID string) (string, bool) {
	record, ok := c.OpenRecord(requestID)
	return record.ApplicationID, ok
}

func (c *Contract) OpenRecord(requestID string) (OpenRecord, bool) {
	if c == nil {
		return OpenRecord{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	record, ok := c.openRecords[requestID]
	return record, ok
}

func (c *Contract) recordData(frame tunnel.Frame) (tunnel.Frame, bool, error) {
	closeFrame, closed, err := c.registry.RecordData(frame, c.now())
	if err != nil {
		return tunnel.Frame{}, false, err
	}
	if closed {
		c.deleteOpenRecord(frame.RequestID)
		return closeFrame, true, nil
	}
	return frame, false, nil
}

func (c *Contract) deleteOpenRecord(requestID string) {
	c.mu.Lock()
	delete(c.openRecords, requestID)
	c.mu.Unlock()
}

func metadataAuditEventFromOpenRecord(record OpenRecord, frame tunnel.Frame) (MetadataAuditEvent, error) {
	return MetadataAuditEventFromClose(record.TenantID, record.ApplicationID, frame)
}

func requiredMetadataID(name, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("%s is required before flow copy open", name)
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		return "", fmt.Errorf("%s must be non-secret metadata without whitespace", name)
	}
	return trimmed, nil
}

func limitOrDefault(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func byteLimitOrDefault(value int64, fallback int64) int64 {
	if value <= 0 {
		return fallback
	}
	return value
}
