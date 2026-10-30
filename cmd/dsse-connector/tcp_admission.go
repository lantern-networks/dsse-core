package main

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// One instance is shared by every attachment and the local round-trip path.
// The optional operator budget belongs to the Connector process, not an Edge,
// application, or reconnecting tunnel. Zero imposes no connection-count limit.
type connectorTCPAdmission struct {
	base   connectorTCPConnectionDialer
	mu     sync.Mutex
	limit  int
	active int // Includes in-progress dials, so concurrent opens cannot overbook.
}

func parseConnectorTCPConnectionLimit(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	limit, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || limit < 0 {
		return 0, fmt.Errorf("DSSE_CONNECTOR_MAX_TCP_CONNECTIONS must be a non-negative integer (0 = no connection-count limit)")
	}
	return limit, nil
}

func (d *connectorTCPAdmission) OpenTCPConnection(ctx context.Context, route connectorTCPRoute) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	if d.limit > 0 && d.active >= d.limit {
		active, limit := d.active, d.limit
		d.mu.Unlock()
		return nil, fmt.Errorf("operator-configured Connector TCP connection limit reached: %d/%d", active, limit)
	}
	d.active++
	d.mu.Unlock()
	conn, err := d.base.OpenTCPConnection(ctx, route)
	if err != nil || connectorTCPConnectionMissing(conn) {
		if !connectorTCPConnectionMissing(conn) {
			_ = conn.Close()
		}
		d.release()
		if err == nil {
			err = fmt.Errorf("tcp connection is required")
		}
		return nil, err
	}
	return &connectorAdmittedTCPConnection{ReadWriteCloser: conn, release: d.release}, nil
}

func (d *connectorTCPAdmission) release() {
	d.mu.Lock()
	d.active--
	d.mu.Unlock()
}

func (d *connectorTCPAdmission) snapshot() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return map[string]int{"active": d.active, "max_connections": d.limit}
}

type connectorAdmittedTCPConnection struct {
	io.ReadWriteCloser
	release func()
	once    sync.Once
	err     error
}

func (c *connectorAdmittedTCPConnection) Close() error {
	c.once.Do(func() {
		c.err = c.ReadWriteCloser.Close()
		c.release()
	})
	return c.err
}

func (c *connectorAdmittedTCPConnection) SetDeadline(deadline time.Time) error {
	if conn, ok := c.ReadWriteCloser.(interface{ SetDeadline(time.Time) error }); ok {
		return conn.SetDeadline(deadline)
	}
	return nil
}
