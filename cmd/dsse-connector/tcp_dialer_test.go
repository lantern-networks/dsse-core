package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/neflowcopy"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func TestValidateConnectorTCPDialRequestAllowsConfiguredRoute(t *testing.T) {
	frame := validConnectorTCPOpenFrame()
	routes := []connectorTCPRoute{{
		ApplicationID: "app_dummy_https",
		Host:          "DUMMY-PRIVATE-APP.LOCAL",
		Port:          443,
	}}
	if err := validateConnectorTCPDialRequest(frame, routes); err != nil {
		t.Fatalf("validateConnectorTCPDialRequest returned error: %v", err)
	}
}

func TestValidateConnectorTCPDialRequestDeniesMismatchedRoute(t *testing.T) {
	tests := []struct {
		name   string
		routes []connectorTCPRoute
	}{
		{
			name: "empty routes",
		},
		{
			name: "application mismatch",
			routes: []connectorTCPRoute{{
				ApplicationID: "app_other",
				Host:          "dummy-private-app.local",
				Port:          443,
			}},
		},
		{
			name: "host mismatch",
			routes: []connectorTCPRoute{{
				ApplicationID: "app_dummy_https",
				Host:          "other-private-app.local",
				Port:          443,
			}},
		},
		{
			name: "port mismatch",
			routes: []connectorTCPRoute{{
				ApplicationID: "app_dummy_https",
				Host:          "dummy-private-app.local",
				Port:          8443,
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConnectorTCPDialRequest(validConnectorTCPOpenFrame(), test.routes)
			if err == nil {
				t.Fatal("validateConnectorTCPDialRequest returned nil error")
			}
			if !strings.Contains(err.Error(), "tcp dial denied") {
				t.Fatalf("error = %q, want tcp dial denied", err.Error())
			}
		})
	}
}

func TestValidateConnectorTCPDialRequestRejectsInvalidOpenFrame(t *testing.T) {
	frame := validConnectorTCPOpenFrame()
	frame.ByteCap = 0
	err := validateConnectorTCPDialRequest(frame, []connectorTCPRoute{{
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}})
	if err == nil {
		t.Fatal("validateConnectorTCPDialRequest returned nil error")
	}
	if !strings.Contains(err.Error(), "byte_cap") {
		t.Fatalf("error = %q, want byte_cap", err.Error())
	}
}

func TestLoadConnectorTCPRoutesFromProtectedAppMapBuildsDenyClosedRoutes(t *testing.T) {
	path := writeConnectorProtectedAppMap(t, `{
		"tenant_id": "tenant_lab_001",
		"version": "2026.05.26.001",
		"applications": [
			{"application_id":"app_dummy_https","fqdn":"DUMMY-PRIVATE-APP.LOCAL","service_family":"https","destination_port":443,"steering_mode":"explicit_proxy"},
			{"application_id":"app_dummy_ssh","fqdn":"dummy-ssh.local","service_family":"ssh","destination_port":22,"steering_mode":"network_extension"}
		]
	}`)
	routes, err := loadConnectorTCPRoutesFromProtectedAppMap(path)
	if err != nil {
		t.Fatalf("loadConnectorTCPRoutesFromProtectedAppMap returned error: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("routes = %+v, want 2 routes", routes)
	}
	if routes[0].ApplicationID != "app_dummy_https" || routes[0].Host != "dummy-private-app.local" || routes[0].Port != 443 {
		t.Fatalf("routes[0] = %+v, want normalized https route", routes[0])
	}
	if routes[1].ApplicationID != "app_dummy_ssh" || routes[1].Host != "dummy-ssh.local" || routes[1].Port != 22 {
		t.Fatalf("routes[1] = %+v, want ssh route", routes[1])
	}
	if err := validateConnectorTCPDialRequest(validConnectorTCPOpenFrame(), routes); err != nil {
		t.Fatalf("validateConnectorTCPDialRequest with loaded routes returned error: %v", err)
	}
}

func TestConnectorMajorProtocolRoutesFromProtectedAppMapDenyBeforeDialAndCleanupRegistry(t *testing.T) {
	routes, err := loadConnectorTCPRoutesFromProtectedAppMap(filepath.Join("testdata", "protected_app_map.json"))
	if err != nil {
		t.Fatalf("loadConnectorTCPRoutesFromProtectedAppMap returned error: %v", err)
	}
	now := time.Date(2026, 6, 9, 0, 30, 0, 0, time.UTC)
	tests := []struct {
		applicationID string
		host          string
		port          int
	}{
		{applicationID: "app_dummy_ssh", host: "dummy-ssh.local", port: 22},
		{applicationID: "app_dummy_rdp", host: "dummy-rdp.local", port: 3389},
		{applicationID: "app_dummy_postgres", host: "dummy-postgres.local", port: 5432},
	}

	for _, test := range tests {
		t.Run(test.applicationID+"_allowed", func(t *testing.T) {
			frame := validConnectorTCPOpenFrame()
			frame.RequestID = "req_tcp_" + strings.TrimPrefix(test.applicationID, "app_dummy_") + "_m1454"
			frame.ApplicationID = test.applicationID
			frame.Host = strings.ToUpper(test.host)
			frame.Port = test.port
			conn := newRecordingTCPConnection("")
			dialer := &recordingTCPConnectionDialer{conn: conn}
			registry := tunnel.NewTCPConnectionRegistry()

			response, handler := handleTunnelTCPOpenConnection(context.Background(), frame, routes, dialer, registry, now)
			if response.Type != tunnel.FrameTCPOpenResult || response.RequestID != frame.RequestID || response.Error != "" {
				t.Fatalf("response = %+v, want successful major protocol tcp_open_result", response)
			}
			if handler == nil {
				t.Fatal("handler is nil for allowed major protocol route")
			}
			if len(dialer.routes) != 1 || dialer.routes[0].ApplicationID != test.applicationID || dialer.routes[0].Host != test.host || dialer.routes[0].Port != test.port {
				t.Fatalf("dialer routes = %+v, want exact allowlist route %s:%d", dialer.routes, test.host, test.port)
			}
			if got := registry.Count(); got != 1 {
				t.Fatalf("registry Count = %d, want one open major protocol connection", got)
			}
			if conn.closed {
				t.Fatal("connection was closed before explicit cleanup")
			}
			if _, err := handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, now.Add(time.Second)); err != nil {
				t.Fatalf("handler.Close returned error: %v", err)
			}
			if got := registry.Count(); got != 0 {
				t.Fatalf("registry Count after explicit cleanup = %d, want 0", got)
			}
			if !conn.closed {
				t.Fatal("connection was not closed after explicit cleanup")
			}
		})

		t.Run(test.applicationID+"_wrong_port_denied_before_dial", func(t *testing.T) {
			frame := validConnectorTCPOpenFrame()
			frame.RequestID = "req_tcp_" + strings.TrimPrefix(test.applicationID, "app_dummy_") + "_wrong_port_m1454"
			frame.ApplicationID = test.applicationID
			frame.Host = test.host
			frame.Port = test.port + 1
			conn := newRecordingTCPConnection("")
			dialer := &recordingTCPConnectionDialer{conn: conn}
			registry := tunnel.NewTCPConnectionRegistry()

			response, handler := handleTunnelTCPOpenConnection(context.Background(), frame, routes, dialer, registry, now)
			if handler != nil {
				t.Fatalf("handler = %v, want nil for denied major protocol route", handler)
			}
			if response.Type != tunnel.FrameTCPOpenResult || !strings.Contains(response.Error, "tcp dial denied") {
				t.Fatalf("response = %+v, want tcp dial denied", response)
			}
			if len(dialer.routes) != 0 {
				t.Fatalf("dialer routes = %+v, want denied route rejected before dial", dialer.routes)
			}
			if got := registry.Count(); got != 0 {
				t.Fatalf("registry Count = %d, want deny before registry mutation", got)
			}
			if conn.closed {
				t.Fatal("connection was closed even though denied route was never dialed")
			}
		})
	}
}

func TestConnectorRouteMatcherIsScopedByDispatcherInstanceNotFrameTenant(t *testing.T) {
	labRoutes, err := loadConnectorTCPRoutesFromProtectedAppMap(writeConnectorProtectedAppMap(t, `{
		"tenant_id": "tenant_lab_001",
		"applications": [
			{"application_id":"app_shared_https","fqdn":"lab-private-app.local","destination_port":443}
		]
	}`))
	if err != nil {
		t.Fatalf("load lab routes returned error: %v", err)
	}
	otherRoutes, err := loadConnectorTCPRoutesFromProtectedAppMap(writeConnectorProtectedAppMap(t, `{
		"tenant_id": "tenant_other_001",
		"applications": [
			{"application_id":"app_shared_https","fqdn":"other-private-app.local","destination_port":443}
		]
	}`))
	if err != nil {
		t.Fatalf("load other routes returned error: %v", err)
	}

	labFrame := validConnectorTCPOpenFrame()
	labFrame.RequestID = "req_tcp_lab_instance"
	labFrame.TunnelID = "tenant_other_001"
	labFrame.ApplicationID = "app_shared_https"
	labFrame.Host = "lab-private-app.local"
	labFrame.Port = 443

	if err := validateConnectorTCPDialRequest(labFrame, labRoutes); err != nil {
		t.Fatalf("lab instance route matcher returned error: %v", err)
	}
	if err := validateConnectorTCPDialRequest(labFrame, otherRoutes); err == nil {
		t.Fatal("other instance route matcher accepted lab route")
	} else if !strings.Contains(err.Error(), "tcp dial denied") {
		t.Fatalf("other instance error = %q, want tcp dial denied", err.Error())
	}

	otherFrame := labFrame
	otherFrame.RequestID = "req_tcp_other_instance"
	otherFrame.TunnelID = "tenant_lab_001"
	otherFrame.Host = "other-private-app.local"

	if err := validateConnectorTCPDialRequest(otherFrame, otherRoutes); err != nil {
		t.Fatalf("other instance route matcher returned error: %v", err)
	}
	if err := validateConnectorTCPDialRequest(otherFrame, labRoutes); err == nil {
		t.Fatal("lab instance route matcher accepted other route")
	} else if !strings.Contains(err.Error(), "tcp dial denied") {
		t.Fatalf("lab instance error = %q, want tcp dial denied", err.Error())
	}
}

func TestLoadConnectorTCPRoutesFromProtectedAppMapEmptyPathDenyClosed(t *testing.T) {
	routes, err := loadConnectorTCPRoutesFromProtectedAppMap("")
	if err != nil {
		t.Fatalf("loadConnectorTCPRoutesFromProtectedAppMap returned error: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("routes = %+v, want empty deny-closed route list", routes)
	}
	if err := validateConnectorTCPDialRequest(validConnectorTCPOpenFrame(), routes); err == nil {
		t.Fatal("validateConnectorTCPDialRequest returned nil error for empty route list")
	}
}

func TestLoadConnectorTCPRoutesFromProtectedAppMapRejectsMalformedRoutes(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "missing application id",
			body:    `{"applications":[{"fqdn":"dummy-private-app.local","destination_port":443}]}`,
			wantErr: "application_id",
		},
		{
			name:    "missing fqdn",
			body:    `{"applications":[{"application_id":"app_dummy_https","destination_port":443}]}`,
			wantErr: "fqdn",
		},
		{
			name:    "fqdn includes port",
			body:    `{"applications":[{"application_id":"app_dummy_https","fqdn":"dummy-private-app.local:443","destination_port":443}]}`,
			wantErr: "must not include a port",
		},
		{
			name:    "zero destination port",
			body:    `{"applications":[{"application_id":"app_dummy_https","fqdn":"dummy-private-app.local","destination_port":0}]}`,
			wantErr: "destination_port",
		},
		{
			name:    "duplicate route",
			body:    `{"applications":[{"application_id":"app_dummy_https","fqdn":"dummy-private-app.local","destination_port":443},{"application_id":"app_dummy_https","fqdn":"DUMMY-PRIVATE-APP.LOCAL","destination_port":443}]}`,
			wantErr: "duplicate",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadConnectorTCPRoutesFromProtectedAppMap(writeConnectorProtectedAppMap(t, test.body))
			if err == nil {
				t.Fatal("loadConnectorTCPRoutesFromProtectedAppMap returned nil error")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestHandleTunnelTCPOpenCallsDialerForAllowedRoute(t *testing.T) {
	dialer := &recordingTCPOpenDialer{}
	response := handleTunnelTCPOpen(context.Background(), validConnectorTCPOpenFrame(), []connectorTCPRoute{{
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}}, dialer)
	if response.Type != tunnel.FrameTCPOpenResult || response.RequestID != "req_tcp_001" || response.Error != "" {
		t.Fatalf("response = %+v, want successful tcp_open_result", response)
	}
	if len(dialer.routes) != 1 || dialer.routes[0].ApplicationID != "app_dummy_https" || dialer.routes[0].Host != "dummy-private-app.local" || dialer.routes[0].Port != 443 {
		t.Fatalf("dialer routes = %+v", dialer.routes)
	}
}

func TestHandleTunnelTCPOpenDeniesBeforeDialer(t *testing.T) {
	dialer := &recordingTCPOpenDialer{}
	response := handleTunnelTCPOpen(context.Background(), validConnectorTCPOpenFrame(), []connectorTCPRoute{{
		ApplicationID: "app_dummy_https",
		Host:          "other-private-app.local",
		Port:          443,
	}}, dialer)
	if response.Type != tunnel.FrameTCPOpenResult || !strings.Contains(response.Error, "tcp dial denied") {
		t.Fatalf("response = %+v, want deny error", response)
	}
	if len(dialer.routes) != 0 {
		t.Fatalf("dialer should not be called on denied route: %+v", dialer.routes)
	}
}

func TestHandleTunnelTCPOpenReturnsDialerError(t *testing.T) {
	dialer := &recordingTCPOpenDialer{err: errors.New("dial failed")}
	response := handleTunnelTCPOpen(context.Background(), validConnectorTCPOpenFrame(), []connectorTCPRoute{{
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}}, dialer)
	if response.Type != tunnel.FrameTCPOpenResult || !strings.Contains(response.Error, "dial failed") {
		t.Fatalf("response = %+v, want dial failed", response)
	}
	if len(dialer.routes) != 1 {
		t.Fatalf("dialer routes = %+v, want one call", dialer.routes)
	}
}

func TestHandleTunnelTCPOpenConnectionDialsAndRegistersConnection(t *testing.T) {
	conn := newRecordingTCPConnection("")
	dialer := &recordingTCPConnectionDialer{conn: conn}
	registry := tunnel.NewTCPConnectionRegistry()
	response, handler := handleTunnelTCPOpenConnection(context.Background(), validConnectorTCPOpenFrame(), allowedConnectorTCPRoutes(), dialer, registry, time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC))
	if response.Type != tunnel.FrameTCPOpenResult || response.RequestID != "req_tcp_001" || response.Error != "" {
		t.Fatalf("response = %+v, want successful tcp_open_result", response)
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}
	if len(dialer.routes) != 1 || dialer.routes[0].ApplicationID != "app_dummy_https" {
		t.Fatalf("dialer routes = %+v, want app_dummy_https", dialer.routes)
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("registry Count = %d, want 1", got)
	}
	if conn.closed {
		t.Fatal("connection was closed on successful open")
	}
}

func TestHandleTunnelTCPOpenConnectionRejectsRegistryConflictBeforeDial(t *testing.T) {
	now := time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC)
	firstConn := newRecordingTCPConnection("")
	dialer := &recordingTCPConnectionDialer{conn: firstConn}
	registry := tunnel.NewTCPConnectionRegistry()
	openFrame := validConnectorTCPOpenFrame()

	response, handler := handleTunnelTCPOpenConnection(context.Background(), openFrame, allowedConnectorTCPRoutes(), dialer, registry, now)
	if response.Error != "" || handler == nil {
		t.Fatalf("open response = %+v handler=%v, want success", response, handler)
	}
	if len(dialer.routes) != 1 {
		t.Fatalf("dialer routes = %+v, want one successful dial", dialer.routes)
	}

	duplicateConn := newRecordingTCPConnection("")
	dialer.conn = duplicateConn
	duplicateResponse, duplicateHandler := handleTunnelTCPOpenConnection(context.Background(), openFrame, allowedConnectorTCPRoutes(), dialer, registry, now.Add(time.Second))
	if duplicateHandler != nil {
		t.Fatalf("duplicate handler = %v, want nil", duplicateHandler)
	}
	if duplicateResponse.Type != tunnel.FrameTCPOpenResult || !strings.Contains(duplicateResponse.Error, "already open") {
		t.Fatalf("duplicate response = %+v, want already-open tcp_open_result", duplicateResponse)
	}
	if len(dialer.routes) != 1 {
		t.Fatalf("dialer routes = %+v, want duplicate rejected before second dial", dialer.routes)
	}
	if duplicateConn.closed {
		t.Fatal("duplicate connection was closed even though it should not be dialed")
	}

	capFrame := openFrame
	capFrame.RequestID = "req_tcp_concurrent_cap_reject"
	capFrame.ConcurrentConnectionCap = 1
	capConn := newRecordingTCPConnection("")
	dialer.conn = capConn
	capResponse, capHandler := handleTunnelTCPOpenConnection(context.Background(), capFrame, allowedConnectorTCPRoutes(), dialer, registry, now.Add(2*time.Second))
	if capHandler != nil {
		t.Fatalf("concurrent cap handler = %v, want nil", capHandler)
	}
	if capResponse.Type != tunnel.FrameTCPOpenResult || !strings.Contains(capResponse.Error, "concurrent connection cap") {
		t.Fatalf("concurrent cap response = %+v, want cap rejection", capResponse)
	}
	if len(dialer.routes) != 1 {
		t.Fatalf("dialer routes = %+v, want concurrent cap rejected before extra dial", dialer.routes)
	}
	if capConn.closed {
		t.Fatal("concurrent cap connection was closed even though it should not be dialed")
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("registry Count = %d, want original open connection preserved", got)
	}
	if firstConn.closed {
		t.Fatal("original connection was closed by rejected opens")
	}
}

func TestHandleTunnelTCPOpenConnectionCleansRegistryOnDialFailure(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{err: errors.New("dial failed")}
	registry := tunnel.NewTCPConnectionRegistry()

	response, handler := handleTunnelTCPOpenConnection(context.Background(), validConnectorTCPOpenFrame(), allowedConnectorTCPRoutes(), dialer, registry, time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC))
	if handler != nil {
		t.Fatalf("handler = %v, want nil after dial failure", handler)
	}
	if response.Type != tunnel.FrameTCPOpenResult || !strings.Contains(response.Error, "dial failed") {
		t.Fatalf("response = %+v, want dial failure tcp_open_result", response)
	}
	if len(dialer.routes) != 1 {
		t.Fatalf("dialer routes = %+v, want one dial attempt after registry reservation", dialer.routes)
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("registry Count = %d, want cleanup after dial failure", got)
	}
}

func TestHandleTunnelTCPOpenConnectionCleansRegistryOnNilConnection(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{}
	registry := tunnel.NewTCPConnectionRegistry()
	now := time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC)

	response, handler := handleTunnelTCPOpenConnection(context.Background(), validConnectorTCPOpenFrame(), allowedConnectorTCPRoutes(), dialer, registry, now)
	if handler != nil {
		t.Fatalf("handler = %v, want nil after nil connection", handler)
	}
	if response.Type != tunnel.FrameTCPOpenResult || !strings.Contains(response.Error, "tcp connection is required") {
		t.Fatalf("response = %+v, want nil-connection tcp_open_result", response)
	}
	if len(dialer.routes) != 1 {
		t.Fatalf("dialer routes = %+v, want one dial attempt after registry reservation", dialer.routes)
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("registry Count = %d, want cleanup after nil connection", got)
	}

	retryConn := newRecordingTCPConnection("")
	dialer.conn = retryConn
	retryResponse, retryHandler := handleTunnelTCPOpenConnection(context.Background(), validConnectorTCPOpenFrame(), allowedConnectorTCPRoutes(), dialer, registry, now.Add(time.Second))
	if retryResponse.Type != tunnel.FrameTCPOpenResult || retryResponse.Error != "" || retryHandler == nil {
		t.Fatalf("retry response = %+v handler=%v, want successful retry open", retryResponse, retryHandler)
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("registry Count after retry = %d, want 1", got)
	}
	if retryConn.closed {
		t.Fatal("retry connection was closed after successful retry open")
	}
}

func TestConnectorTCPConnectionHandlerReadFramesEmitsDownData(t *testing.T) {
	handler, _, _ := openRecordingTCPConnection(t, "private-response")
	frames, err := handler.ReadFrames(time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatalf("ReadFrames returned error: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("ReadFrames returned %d frames, want 1", len(frames))
	}
	frame := frames[0]
	if frame.Type != tunnel.FrameTCPData || frame.Direction != tunnel.TCPDirectionDown || frame.RequestID != "req_tcp_001" {
		t.Fatalf("frame = %+v, want down tcp_data req_tcp_001", frame)
	}
	payload, err := tunnel.TCPDataFramePayload(frame)
	if err != nil {
		t.Fatalf("TCPDataFramePayload returned error: %v", err)
	}
	if string(payload) != "private-response" {
		t.Fatalf("payload = %q, want private-response", string(payload))
	}
}

func TestConnectorTCPConnectionHandlerWriteFrameWritesUpPayload(t *testing.T) {
	handler, conn, _ := openRecordingTCPConnection(t, "")
	frame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, []byte("client-request"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	frames, err := handler.WriteFrame(frame, time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatalf("WriteFrame returned error: %v", err)
	}
	if len(frames) != 0 {
		t.Fatalf("WriteFrame returned frames = %+v, want none", frames)
	}
	if conn.written.String() != "client-request" {
		t.Fatalf("written = %q, want client-request", conn.written.String())
	}
}

func TestConnectorTCPConnectionHandlerWriteFrameRejectsWrongDirectionWithoutWriteOrRegistryMutation(t *testing.T) {
	handler, conn, registry := openRecordingTCPConnection(t, "")
	preservedPayload := []byte("preserved-client")
	validFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, preservedPayload)
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	if _, err := handler.WriteFrame(validFrame, time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC)); err != nil {
		t.Fatalf("WriteFrame returned error before wrong-direction guard: %v", err)
	}

	wrongDirectionFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionDown, []byte("rejected-downstream-on-connector"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	frames, err := handler.WriteFrame(wrongDirectionFrame, time.Date(2026, 5, 26, 10, 0, 2, 0, time.UTC))
	if err == nil {
		t.Fatal("WriteFrame returned nil error for wrong direction")
	}
	if !strings.Contains(err.Error(), "requires up direction") {
		t.Fatalf("error = %q, want up direction rejection", err.Error())
	}
	if len(frames) != 0 {
		t.Fatalf("frames = %+v, want none for rejected wrong direction", frames)
	}
	if conn.closed {
		t.Fatal("connection was closed after rejected wrong direction")
	}
	if conn.written.String() != string(preservedPayload) {
		t.Fatalf("written = %q, want only preserved payload", conn.written.String())
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("registry Count = %d, want open connection preserved", got)
	}

	closeFrame, err := handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, time.Date(2026, 5, 26, 10, 0, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("Close after rejected wrong direction returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len(preservedPayload)) {
		t.Fatalf("closeFrame BytesUp = %d, want %d", closeFrame.BytesUp, len(preservedPayload))
	}
	if closeFrame.BytesDown != 0 {
		t.Fatalf("closeFrame BytesDown = %d, want 0", closeFrame.BytesDown)
	}
	if !conn.closed {
		t.Fatal("connection was not closed after later valid close")
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("registry Count after valid close = %d, want 0", got)
	}
}

func TestConnectorTCPConnectionHandlerWriteFrameRejectsMalformedPayloadWithoutWriteOrRegistryMutation(t *testing.T) {
	handler, conn, registry := openRecordingTCPConnection(t, "")
	preservedPayload := []byte("preserved-client")
	validFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, preservedPayload)
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	if _, err := handler.WriteFrame(validFrame, time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC)); err != nil {
		t.Fatalf("WriteFrame returned error before malformed guard: %v", err)
	}

	malformedFrame := tunnel.Frame{
		Type:      tunnel.FrameTCPData,
		RequestID: "req_tcp_001",
		Direction: tunnel.TCPDirectionUp,
		Data:      "not-base64%%%",
	}
	frames, err := handler.WriteFrame(malformedFrame, time.Date(2026, 5, 26, 10, 0, 2, 0, time.UTC))
	if err == nil {
		t.Fatal("WriteFrame returned nil error for malformed tcp_data payload")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Fatalf("error = %q, want base64", err.Error())
	}
	if len(frames) != 0 {
		t.Fatalf("frames = %+v, want none for rejected malformed payload", frames)
	}
	if conn.written.String() != string(preservedPayload) {
		t.Fatalf("written = %q, want only preserved payload", conn.written.String())
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("registry Count = %d, want open connection preserved", got)
	}

	closeFrame, err := handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, time.Date(2026, 5, 26, 10, 0, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("Close after rejected malformed payload returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len(preservedPayload)) {
		t.Fatalf("closeFrame BytesUp = %d, want %d", closeFrame.BytesUp, len(preservedPayload))
	}
	if closeFrame.BytesDown != 0 {
		t.Fatalf("closeFrame BytesDown = %d, want 0", closeFrame.BytesDown)
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("registry Count after close = %d, want 0", got)
	}
}

func TestConnectorTCPConnectionHandlerWriteFrameRejectsOversizedPayloadWithoutWriteOrRegistryMutation(t *testing.T) {
	handler, conn, registry := openRecordingTCPConnection(t, "")
	preservedPayload := []byte("preserved-client")
	validFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, preservedPayload)
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	if _, err := handler.WriteFrame(validFrame, time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC)); err != nil {
		t.Fatalf("WriteFrame returned error before oversized guard: %v", err)
	}

	oversizedFrame := tunnel.Frame{
		Type:      tunnel.FrameTCPData,
		RequestID: "req_tcp_001",
		Direction: tunnel.TCPDirectionUp,
		Data:      base64.StdEncoding.EncodeToString(make([]byte, tunnel.MaxTCPDataFramePayloadBytes+1)),
	}
	frames, err := handler.WriteFrame(oversizedFrame, time.Date(2026, 5, 26, 10, 0, 2, 0, time.UTC))
	if err == nil {
		t.Fatal("WriteFrame returned nil error for oversized tcp_data payload")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("error = %q, want exceeds limit", err.Error())
	}
	if len(frames) != 0 {
		t.Fatalf("frames = %+v, want none for rejected oversized payload", frames)
	}
	if conn.written.String() != string(preservedPayload) {
		t.Fatalf("written = %q, want only preserved payload", conn.written.String())
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("registry Count = %d, want open connection preserved", got)
	}

	closeFrame, err := handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, time.Date(2026, 5, 26, 10, 0, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("Close after rejected oversized payload returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len(preservedPayload)) {
		t.Fatalf("closeFrame BytesUp = %d, want %d", closeFrame.BytesUp, len(preservedPayload))
	}
	if closeFrame.BytesDown != 0 {
		t.Fatalf("closeFrame BytesDown = %d, want 0", closeFrame.BytesDown)
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("registry Count after close = %d, want 0", got)
	}
}

func TestConnectorTCPConnectionHandlerReadEOFClosesRemote(t *testing.T) {
	handler, conn, registry := openRecordingTCPConnection(t, "")
	frames, err := handler.ReadFrames(time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatalf("ReadFrames returned error: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("ReadFrames returned %d frames, want 1", len(frames))
	}
	if frames[0].Type != tunnel.FrameTCPClose || frames[0].Direction != tunnel.TCPDirectionRemote || frames[0].CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("frame = %+v, want remote eof close", frames[0])
	}
	if !conn.closed {
		t.Fatal("connection was not closed after EOF")
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("registry Count = %d, want 0", got)
	}
}

func TestConnectorTCPConnectionHandlerReadFramesClosesOnByteCap(t *testing.T) {
	conn := newRecordingTCPConnection("over-cap")
	dialer := &recordingTCPConnectionDialer{conn: conn}
	registry := tunnel.NewTCPConnectionRegistry()
	openFrame := validConnectorTCPOpenFrame()
	openFrame.ByteCap = 3
	response, handler := handleTunnelTCPOpenConnection(context.Background(), openFrame, allowedConnectorTCPRoutes(), dialer, registry, time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC))
	if response.Error != "" || handler == nil {
		t.Fatalf("open response = %+v handler=%v, want success", response, handler)
	}
	handler.chunkSize = 8

	frames, err := handler.ReadFrames(time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatalf("ReadFrames returned error: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("ReadFrames returned %d frames, want 1", len(frames))
	}
	if frames[0].Type != tunnel.FrameTCPClose || frames[0].CloseReason != tunnel.TCPCloseReasonByteCapExceeded {
		t.Fatalf("frame = %+v, want byte_cap_exceeded close", frames[0])
	}
	if !conn.closed {
		t.Fatal("connection was not closed after byte cap")
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("registry Count = %d, want 0", got)
	}
}

func TestConnectorTCPConnectionHandlerReadFramesRejectsZeroChunkWithoutReadOrRegistryMutation(t *testing.T) {
	readPayload := "private-response"
	handler, conn, registry := openRecordingTCPConnection(t, readPayload)
	preservedPayload := []byte("preserved-client")
	validFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, preservedPayload)
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	if _, err := handler.WriteFrame(validFrame, time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC)); err != nil {
		t.Fatalf("WriteFrame returned error before zero-chunk read guard: %v", err)
	}

	handler.chunkSize = 0
	frames, err := handler.ReadFrames(time.Date(2026, 5, 26, 10, 0, 2, 0, time.UTC))
	if err == nil {
		t.Fatal("ReadFrames returned nil error for zero chunk size")
	}
	if !strings.Contains(err.Error(), "tcp chunk size") {
		t.Fatalf("error = %q, want tcp chunk size rejection", err.Error())
	}
	if len(frames) != 0 {
		t.Fatalf("frames = %+v, want none for rejected zero chunk read", frames)
	}
	if conn.closed {
		t.Fatal("connection was closed after rejected zero chunk read")
	}
	if conn.reader.Len() != len(readPayload) {
		t.Fatalf("remaining read bytes = %d, want %d", conn.reader.Len(), len(readPayload))
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("registry Count = %d, want open connection preserved", got)
	}

	closeFrame, err := handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, time.Date(2026, 5, 26, 10, 0, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("Close after rejected zero chunk read returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len(preservedPayload)) {
		t.Fatalf("closeFrame BytesUp = %d, want %d", closeFrame.BytesUp, len(preservedPayload))
	}
	if closeFrame.BytesDown != 0 {
		t.Fatalf("closeFrame BytesDown = %d, want 0", closeFrame.BytesDown)
	}
	if !conn.closed {
		t.Fatal("connection was not closed after later valid close")
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("registry Count after valid close = %d, want 0", got)
	}
}

func TestConnectorTCPConnectionHandlerReadFramesRejectsOversizedChunkWithoutReadOrRegistryMutation(t *testing.T) {
	readPayload := "private-response"
	handler, conn, registry := openRecordingTCPConnection(t, readPayload)
	preservedPayload := []byte("preserved-client")
	validFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, preservedPayload)
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	if _, err := handler.WriteFrame(validFrame, time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC)); err != nil {
		t.Fatalf("WriteFrame returned error before oversized-chunk read guard: %v", err)
	}

	handler.chunkSize = tunnel.MaxTCPDataFramePayloadBytes + 1
	frames, err := handler.ReadFrames(time.Date(2026, 5, 26, 10, 0, 2, 0, time.UTC))
	if err == nil {
		t.Fatal("ReadFrames returned nil error for oversized chunk size")
	}
	if !strings.Contains(err.Error(), "tcp chunk size") {
		t.Fatalf("error = %q, want tcp chunk size rejection", err.Error())
	}
	if len(frames) != 0 {
		t.Fatalf("frames = %+v, want none for rejected oversized chunk read", frames)
	}
	if conn.closed {
		t.Fatal("connection was closed after rejected oversized chunk read")
	}
	if conn.reader.Len() != len(readPayload) {
		t.Fatalf("remaining read bytes = %d, want %d", conn.reader.Len(), len(readPayload))
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("registry Count = %d, want open connection preserved", got)
	}

	closeFrame, err := handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, time.Date(2026, 5, 26, 10, 0, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("Close after rejected oversized chunk read returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len(preservedPayload)) {
		t.Fatalf("closeFrame BytesUp = %d, want %d", closeFrame.BytesUp, len(preservedPayload))
	}
	if closeFrame.BytesDown != 0 {
		t.Fatalf("closeFrame BytesDown = %d, want 0", closeFrame.BytesDown)
	}
	if !conn.closed {
		t.Fatal("connection was not closed after later valid close")
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("registry Count after valid close = %d, want 0", got)
	}
}

func TestConnectorTCPConnectionHandlerWriteFrameRejectsWrongRequestID(t *testing.T) {
	handler, conn, _ := openRecordingTCPConnection(t, "")
	frame, err := tunnel.NewTCPDataFrame("req_tcp_other", tunnel.TCPDirectionUp, []byte("client-request"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	_, err = handler.WriteFrame(frame, time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC))
	if err == nil {
		t.Fatal("WriteFrame returned nil error for wrong request_id")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %q, want does not match", err.Error())
	}
	if conn.written.Len() != 0 {
		t.Fatalf("written = %q, want empty", conn.written.String())
	}
}

func TestConnectorTCPConnectionHandlerCloseRejectsUnknownReasonWithoutCloseOrRegistryMutation(t *testing.T) {
	handler, conn, registry := openRecordingTCPConnection(t, "")
	preservedPayload := []byte("preserved-client")
	validFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, preservedPayload)
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	if _, err := handler.WriteFrame(validFrame, time.Date(2026, 5, 26, 10, 0, 1, 0, time.UTC)); err != nil {
		t.Fatalf("WriteFrame returned error before invalid close guard: %v", err)
	}

	closeFrame, err := handler.Close(tunnel.TCPDirectionLocal, "not_allowed", time.Date(2026, 5, 26, 10, 0, 2, 0, time.UTC))
	if err == nil {
		t.Fatal("Close returned nil error for unknown close reason")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("error = %q, want not allowed", err.Error())
	}
	if closeFrame.Type != "" {
		t.Fatalf("closeFrame = %+v, want zero value for rejected close", closeFrame)
	}
	if conn.closed {
		t.Fatal("connection was closed after rejected close")
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("registry Count = %d, want open connection preserved", got)
	}

	closeFrame, err = handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, time.Date(2026, 5, 26, 10, 0, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("Close after rejected close returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len(preservedPayload)) {
		t.Fatalf("closeFrame BytesUp = %d, want %d", closeFrame.BytesUp, len(preservedPayload))
	}
	if closeFrame.BytesDown != 0 {
		t.Fatalf("closeFrame BytesDown = %d, want 0", closeFrame.BytesDown)
	}
	if !conn.closed {
		t.Fatal("connection was not closed after valid close")
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("registry Count after valid close = %d, want 0", got)
	}
}

func TestHandleConnectorTunnelFrameKeepsHTTPPath(t *testing.T) {
	frame := tunnel.Frame{
		Type:      tunnel.FrameHTTPRequest,
		RequestID: "req_http_001",
		Method:    http.MethodGet,
		Path:      "/bad-url",
	}
	responses, err := handleConnectorTunnelFrame(context.Background(), "://bad-base-url", nil, frame)
	if err != nil {
		t.Fatalf("handleConnectorTunnelFrame returned error: %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	if responses[0].Type != tunnel.FrameHTTPResponse || responses[0].RequestID != "req_http_001" {
		t.Fatalf("response = %+v, want http_response req_http_001", responses[0])
	}
}

func TestHandleConnectorTunnelFrameReturnsTCPErrorWhenDispatcherMissing(t *testing.T) {
	responses, err := handleConnectorTunnelFrame(context.Background(), "http://127.0.0.1:1", nil, validConnectorTCPOpenFrame())
	if err != nil {
		t.Fatalf("handleConnectorTunnelFrame returned error: %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	if responses[0].Type != tunnel.FrameTCPOpenResult || !strings.Contains(responses[0].Error, "dispatcher") {
		t.Fatalf("response = %+v, want tcp_open_result dispatcher error", responses[0])
	}
}

func TestConnectorTunnelTCPDispatcherDispatchesOpenDataAndClose(t *testing.T) {
	conn := newRecordingTCPConnection("")
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: conn}, fixedConnectorTestNow())
	openResponses, err := dispatcher.HandleFrame(context.Background(), validConnectorTCPOpenFrame())
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}
	if len(dispatcher.handlers) != 1 {
		t.Fatalf("handlers = %d, want 1", len(dispatcher.handlers))
	}

	dataFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, []byte("client-request"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	dataResponses, err := dispatcher.HandleFrame(context.Background(), dataFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_data returned error: %v", err)
	}
	if len(dataResponses) != 0 {
		t.Fatalf("dataResponses = %+v, want none", dataResponses)
	}
	if conn.written.String() != "client-request" {
		t.Fatalf("written = %q, want client-request", conn.written.String())
	}

	closeResponses, err := dispatcher.HandleFrame(context.Background(), tunnel.Frame{
		Type:        tunnel.FrameTCPClose,
		RequestID:   "req_tcp_001",
		Direction:   tunnel.TCPDirectionLocal,
		CloseReason: tunnel.TCPCloseReasonEOF,
	})
	if err != nil {
		t.Fatalf("HandleFrame tcp_close returned error: %v", err)
	}
	if len(closeResponses) != 0 {
		t.Fatalf("closeResponses = %+v, want none", closeResponses)
	}
	if !conn.closed {
		t.Fatal("connection was not closed")
	}
	if len(dispatcher.handlers) != 0 {
		t.Fatalf("handlers = %d, want 0", len(dispatcher.handlers))
	}
}

func TestConnectorTunnelTCPDispatcherDataWriteFailureCleansHandlerAndRegistry(t *testing.T) {
	requestID := "req_tcp_data_write_failure_cleanup"
	conn := newRecordingTCPConnection("")
	conn.writeErr = errors.New("local tcp write failed")
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: conn}, fixedConnectorTestNow())
	openFrame := validConnectorTCPOpenFrame()
	openFrame.RequestID = requestID
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].RequestID != requestID || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}

	payload := []byte("client-request-before-write-failure")
	dataFrame, err := tunnel.NewTCPDataFrame(requestID, tunnel.TCPDirectionUp, payload)
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	dataResponses, err := dispatcher.HandleFrame(context.Background(), dataFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_data returned error: %v", err)
	}
	if len(dataResponses) != 1 {
		t.Fatalf("dataResponses = %+v, want one local error close", dataResponses)
	}
	closeFrame := dataResponses[0]
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.RequestID != requestID || closeFrame.Direction != tunnel.TCPDirectionLocal || closeFrame.CloseReason != tunnel.TCPCloseReasonError {
		t.Fatalf("closeFrame = %+v, want local error tcp_close", closeFrame)
	}
	if !strings.Contains(closeFrame.Error, "local tcp write failed") {
		t.Fatalf("closeFrame error = %q, want local tcp write failed", closeFrame.Error)
	}
	if closeFrame.BytesUp != int64(len(payload)) {
		t.Fatalf("closeFrame BytesUp = %d, want attempted upstream bytes %d", closeFrame.BytesUp, len(payload))
	}
	if closeFrame.BytesDown != 0 {
		t.Fatalf("closeFrame BytesDown = %d, want 0", closeFrame.BytesDown)
	}
	if conn.written.Len() != 0 {
		t.Fatalf("written = %q, want no bytes after failed local write", conn.written.String())
	}
	if !conn.closed {
		t.Fatal("connection was not closed after local write failure")
	}
	if dispatcher.handlerFor(requestID) != nil {
		t.Fatal("dispatcher handler remained after local write failure")
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after local write failure = %d, want 0", got)
	}
}

func TestConnectorTunnelTCPDispatcherRejectsDataForUnknownConnection(t *testing.T) {
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("")}, fixedConnectorTestNow())
	dataFrame, err := tunnel.NewTCPDataFrame("req_tcp_missing", tunnel.TCPDirectionUp, []byte("payload"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	responses, err := dispatcher.HandleFrame(context.Background(), dataFrame)
	if err != nil {
		t.Fatalf("HandleFrame returned error: %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	if responses[0].Type != tunnel.FrameTCPClose || responses[0].CloseReason != tunnel.TCPCloseReasonError || !strings.Contains(responses[0].Error, "not open") {
		t.Fatalf("response = %+v, want local error close for not open", responses[0])
	}
}

func TestConnectorTunnelTCPDispatcherRejectsUnknownDataWithoutRemovingExistingHandler(t *testing.T) {
	conn := newRecordingTCPConnection("")
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: conn}, fixedConnectorTestNow())
	openResponses, err := dispatcher.HandleFrame(context.Background(), validConnectorTCPOpenFrame())
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}

	preservedPayload := []byte("preserved-client")
	validFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, preservedPayload)
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	if responses, err := dispatcher.HandleFrame(context.Background(), validFrame); err != nil || len(responses) != 0 {
		t.Fatalf("HandleFrame valid tcp_data responses=%+v err=%v, want no response and no error", responses, err)
	}

	unknownFrame, err := tunnel.NewTCPDataFrame("req_tcp_missing", tunnel.TCPDirectionUp, []byte("rejected-unknown-client"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	responses, err := dispatcher.HandleFrame(context.Background(), unknownFrame)
	if err != nil {
		t.Fatalf("HandleFrame unknown tcp_data returned error: %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	if responses[0].Type != tunnel.FrameTCPClose || responses[0].RequestID != "req_tcp_missing" || responses[0].CloseReason != tunnel.TCPCloseReasonError {
		t.Fatalf("response = %+v, want local error tcp_close for unknown request", responses[0])
	}
	if !strings.Contains(responses[0].Error, "not open") {
		t.Fatalf("error = %q, want not open", responses[0].Error)
	}
	if conn.closed {
		t.Fatal("connection was closed after rejected unknown tcp_data")
	}
	if len(dispatcher.handlers) != 1 {
		t.Fatalf("handlers = %d, want existing handler preserved", len(dispatcher.handlers))
	}
	if got := dispatcher.registry.Count(); got != 1 {
		t.Fatalf("registry Count = %d, want open connection preserved", got)
	}
	if conn.written.String() != string(preservedPayload) {
		t.Fatalf("written = %q, want only preserved payload", conn.written.String())
	}

	retainedHandler := dispatcher.handlerFor("req_tcp_001")
	if retainedHandler == nil {
		t.Fatal("handler for req_tcp_001 was removed after rejected unknown tcp_data")
	}
	closeFrame, err := retainedHandler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, time.Date(2026, 5, 26, 10, 0, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("Close after rejected unknown tcp_data returned error: %v", err)
	}
	if closeFrame.BytesUp != int64(len(preservedPayload)) {
		t.Fatalf("closeFrame BytesUp = %d, want %d", closeFrame.BytesUp, len(preservedPayload))
	}
	if closeFrame.BytesDown != 0 {
		t.Fatalf("closeFrame BytesDown = %d, want 0", closeFrame.BytesDown)
	}
	if !conn.closed {
		t.Fatal("connection was not closed after later valid close")
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after valid close = %d, want 0", got)
	}
}

func TestConnectorTunnelTCPDispatcherRejectsInvalidCloseWithoutRemovingHandler(t *testing.T) {
	conn := newRecordingTCPConnection("")
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: conn}, fixedConnectorTestNow())
	openResponses, err := dispatcher.HandleFrame(context.Background(), validConnectorTCPOpenFrame())
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}

	dataFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, []byte("client-request"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	if responses, err := dispatcher.HandleFrame(context.Background(), dataFrame); err != nil || len(responses) != 0 {
		t.Fatalf("HandleFrame tcp_data responses=%+v err=%v, want no response and no error", responses, err)
	}

	responses, err := dispatcher.HandleFrame(context.Background(), tunnel.Frame{
		Type:        tunnel.FrameTCPClose,
		RequestID:   "req_tcp_001",
		Direction:   "sideways",
		CloseReason: tunnel.TCPCloseReasonEOF,
	})
	if err != nil {
		t.Fatalf("HandleFrame invalid tcp_close returned error: %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	if responses[0].Type != tunnel.FrameTCPClose || responses[0].CloseReason != tunnel.TCPCloseReasonError {
		t.Fatalf("response = %+v, want local error tcp_close", responses[0])
	}
	if !strings.Contains(responses[0].Error, "direction") {
		t.Fatalf("error = %q, want direction validation error", responses[0].Error)
	}
	if conn.closed {
		t.Fatal("connection was closed after rejected invalid tcp_close")
	}
	if len(dispatcher.handlers) != 1 {
		t.Fatalf("handlers = %d, want open handler preserved", len(dispatcher.handlers))
	}
	if got := dispatcher.registry.Count(); got != 1 {
		t.Fatalf("registry Count = %d, want open connection preserved", got)
	}
	if conn.written.String() != "client-request" {
		t.Fatalf("written = %q, want prior payload preserved", conn.written.String())
	}

	validCloseResponses, err := dispatcher.HandleFrame(context.Background(), tunnel.Frame{
		Type:        tunnel.FrameTCPClose,
		RequestID:   "req_tcp_001",
		Direction:   tunnel.TCPDirectionLocal,
		CloseReason: tunnel.TCPCloseReasonEOF,
	})
	if err != nil {
		t.Fatalf("HandleFrame valid tcp_close returned error: %v", err)
	}
	if len(validCloseResponses) != 0 {
		t.Fatalf("validCloseResponses = %+v, want none", validCloseResponses)
	}
	if !conn.closed {
		t.Fatal("connection was not closed after later valid tcp_close")
	}
	if len(dispatcher.handlers) != 0 {
		t.Fatalf("handlers after valid close = %d, want 0", len(dispatcher.handlers))
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after valid close = %d, want 0", got)
	}
}

func TestConnectorTunnelTCPDispatcherCloseFailureCleansHandlerAndRegistry(t *testing.T) {
	requestID := "req_tcp_close_failure_cleanup"
	conn := newRecordingTCPConnection("")
	conn.closeErr = errors.New("local tcp close failed")
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: conn}, fixedConnectorTestNow())
	openFrame := validConnectorTCPOpenFrame()
	openFrame.RequestID = requestID
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].RequestID != requestID || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}

	dataFrame, err := tunnel.NewTCPDataFrame(requestID, tunnel.TCPDirectionUp, []byte("preserved-client"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	if responses, err := dispatcher.HandleFrame(context.Background(), dataFrame); err != nil || len(responses) != 0 {
		t.Fatalf("HandleFrame tcp_data responses=%+v err=%v, want no response and no error", responses, err)
	}

	closeResponses, err := dispatcher.HandleFrame(context.Background(), tunnel.Frame{
		Type:        tunnel.FrameTCPClose,
		RequestID:   requestID,
		Direction:   tunnel.TCPDirectionLocal,
		CloseReason: tunnel.TCPCloseReasonEOF,
	})
	if err != nil {
		t.Fatalf("HandleFrame tcp_close returned error: %v", err)
	}
	if len(closeResponses) != 1 {
		t.Fatalf("closeResponses = %+v, want one local error close", closeResponses)
	}
	if closeResponses[0].Type != tunnel.FrameTCPClose || closeResponses[0].RequestID != requestID || closeResponses[0].CloseReason != tunnel.TCPCloseReasonError {
		t.Fatalf("closeResponses[0] = %+v, want local error tcp_close", closeResponses[0])
	}
	if !strings.Contains(closeResponses[0].Error, "local tcp close failed") {
		t.Fatalf("close error = %q, want local tcp close failed", closeResponses[0].Error)
	}
	if !conn.closed {
		t.Fatal("local tcp connection close was not attempted")
	}
	if dispatcher.handlerFor(requestID) != nil {
		t.Fatal("dispatcher handler remained after local close failure")
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after local close failure = %d, want 0", got)
	}
}

func TestConnectorTunnelTCPDispatcherRemovesHandlerOnByteCapClose(t *testing.T) {
	conn := newRecordingTCPConnection("")
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: conn}, fixedConnectorTestNow())
	openFrame := validConnectorTCPOpenFrame()
	openFrame.ByteCap = 3
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want success", openResponses)
	}

	dataFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, []byte("over-cap"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	responses, err := dispatcher.HandleFrame(context.Background(), dataFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_data returned error: %v", err)
	}
	if len(responses) != 1 || responses[0].CloseReason != tunnel.TCPCloseReasonByteCapExceeded {
		t.Fatalf("responses = %+v, want byte cap close", responses)
	}
	if !conn.closed {
		t.Fatal("connection was not closed after byte cap")
	}
	if len(dispatcher.handlers) != 0 {
		t.Fatalf("handlers = %d, want 0", len(dispatcher.handlers))
	}
}

func TestConnectorTunnelTCPDispatcherCloseExpiredClosesConnectionAndHandler(t *testing.T) {
	now := fixedConnectorTestNow()()
	conn := newRecordingTCPConnection("")
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: conn}, func() time.Time { return now })
	openFrame := validConnectorTCPOpenFrame()
	openFrame.IdleTimeoutMillis = 1000
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want success", openResponses)
	}

	closeFrames := dispatcher.CloseExpired(now.Add(1500 * time.Millisecond))
	if len(closeFrames) != 1 {
		t.Fatalf("closeFrames = %+v, want one idle timeout close", closeFrames)
	}
	if closeFrames[0].Type != tunnel.FrameTCPClose || closeFrames[0].CloseReason != tunnel.TCPCloseReasonIdleTimeoutExceeded {
		t.Fatalf("closeFrame = %+v, want idle timeout tcp_close", closeFrames[0])
	}
	if !conn.closed {
		t.Fatal("connection was not closed by expiry")
	}
	if len(dispatcher.handlers) != 0 {
		t.Fatalf("handlers = %d, want 0", len(dispatcher.handlers))
	}
	if dispatcher.registry.Count() != 0 {
		t.Fatalf("registry count = %d, want 0", dispatcher.registry.Count())
	}
}

func TestConnectorTunnelTCPDispatcherExpiryLoopPublishesCloseFrame(t *testing.T) {
	current := fixedConnectorTestNow()()
	var currentMu sync.Mutex
	nowFunc := func() time.Time {
		currentMu.Lock()
		defer currentMu.Unlock()
		return current
	}
	setNow := func(value time.Time) {
		currentMu.Lock()
		defer currentMu.Unlock()
		current = value
	}
	conn := newRecordingTCPConnection("")
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: conn}, nowFunc)
	writeCh := make(chan tunnel.Frame, 2)
	dispatcher.SetResponseWriter(func(frames []tunnel.Frame) error {
		for _, frame := range frames {
			writeCh <- frame
		}
		return nil
	})
	openFrame := validConnectorTCPOpenFrame()
	openFrame.MaxConnectionLifetimeMillis = 1000
	openFrame.IdleTimeoutMillis = 1000
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want success", openResponses)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher.StartExpiryLoop(ctx, time.Millisecond)
	setNow(current.Add(1500 * time.Millisecond))

	closeFrame := waitForTunnelWrite(t, writeCh)
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.CloseReason != tunnel.TCPCloseReasonLifetimeExceeded {
		t.Fatalf("closeFrame = %+v, want lifetime exceeded tcp_close", closeFrame)
	}
	if !conn.closed {
		t.Fatal("connection was not closed by expiry loop")
	}
}

func TestConnectorTunnelTCPDispatcherPublishExpiredWriterFailureCleansHandlerAndRegistry(t *testing.T) {
	now := fixedConnectorTestNow()()
	requestID := "req_tcp_expired_writer_failure"
	conn := newRecordingTCPConnection("")
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: conn}, func() time.Time { return now })
	writerErr := errors.New("tunnel writer unavailable for expired close")
	var writeCalls int
	var attemptedFrames []tunnel.Frame
	dispatcher.SetResponseWriter(func(frames []tunnel.Frame) error {
		writeCalls++
		attemptedFrames = append(attemptedFrames, frames...)
		return writerErr
	})

	openFrame := validConnectorTCPOpenFrame()
	openFrame.RequestID = requestID
	openFrame.MaxConnectionLifetimeMillis = 1000
	openFrame.IdleTimeoutMillis = 1000
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want success", openResponses)
	}
	if got := dispatcher.registry.Count(); got != 1 {
		t.Fatalf("registry Count after open = %d, want 1", got)
	}

	err = dispatcher.PublishExpiredConnections(now.Add(1500 * time.Millisecond))
	if !errors.Is(err, writerErr) {
		t.Fatalf("PublishExpiredConnections error = %v, want writer error", err)
	}
	if writeCalls != 1 {
		t.Fatalf("writeCalls = %d, want one expired close publish attempt", writeCalls)
	}
	if len(attemptedFrames) != 1 {
		t.Fatalf("attemptedFrames = %+v, want one expired close frame", attemptedFrames)
	}
	closeFrame := attemptedFrames[0]
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.RequestID != requestID || closeFrame.Direction != tunnel.TCPDirectionLocal || closeFrame.CloseReason != tunnel.TCPCloseReasonLifetimeExceeded {
		t.Fatalf("closeFrame = %+v, want local lifetime exceeded tcp_close", closeFrame)
	}
	if !conn.closed {
		t.Fatal("connection was not closed before expired close writer failure returned")
	}
	if dispatcher.handlerFor(requestID) != nil {
		t.Fatal("dispatcher handler remained after expired close writer failure")
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after expired close writer failure = %d, want 0", got)
	}
}

func TestHandleConnectorTunnelConnDispatchesRuntimeTCPFrames(t *testing.T) {
	tcpConn := newBlockingRecordingTCPConnection()
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: tcpConn}, fixedConnectorTestNow())
	dataFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionUp, []byte("client-request"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	fakeTunnel := &recordingTunnelJSONConn{reads: []tunnel.Frame{
		validConnectorTCPOpenFrame(),
		dataFrame,
		{Type: tunnel.FrameTCPClose, RequestID: "req_tcp_001", Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonEOF},
	}}

	err = handleConnectorTunnelConn(context.Background(), fakeTunnel, "http://127.0.0.1:1", dispatcher)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("handleConnectorTunnelConn err = %v, want EOF after scripted frames", err)
	}
	if len(fakeTunnel.writes) != 1 {
		t.Fatalf("writes = %+v, want one tcp_open_result", fakeTunnel.writes)
	}
	if fakeTunnel.writes[0].Type != tunnel.FrameTCPOpenResult || fakeTunnel.writes[0].Error != "" {
		t.Fatalf("write[0] = %+v, want successful tcp_open_result", fakeTunnel.writes[0])
	}
	if tcpConn.written.String() != "client-request" {
		t.Fatalf("tcp written = %q, want client-request", tcpConn.written.String())
	}
	if !tcpConn.closed {
		t.Fatal("tcp connection was not closed after tcp_close")
	}
}

func TestHandleConnectorTunnelConnPumpsDownstreamTCPFrames(t *testing.T) {
	tcpConn := newRecordingTCPConnection("private-response")
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: tcpConn}, fixedConnectorTestNow())
	fakeTunnel := &recordingTunnelJSONConn{
		reads:   []tunnel.Frame{validConnectorTCPOpenFrame()},
		writeCh: make(chan tunnel.Frame, 4),
	}

	err := handleConnectorTunnelConn(context.Background(), fakeTunnel, "http://127.0.0.1:1", dispatcher)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("handleConnectorTunnelConn err = %v, want EOF after scripted frames", err)
	}

	openResult := waitForTunnelWrite(t, fakeTunnel.writeCh)
	if openResult.Type != tunnel.FrameTCPOpenResult || openResult.Error != "" {
		t.Fatalf("openResult = %+v, want successful tcp_open_result", openResult)
	}
	dataFrame := waitForTunnelWrite(t, fakeTunnel.writeCh)
	if dataFrame.Type != tunnel.FrameTCPData || dataFrame.Direction != tunnel.TCPDirectionDown {
		t.Fatalf("dataFrame = %+v, want down tcp_data", dataFrame)
	}
	payload, err := tunnel.TCPDataFramePayload(dataFrame)
	if err != nil {
		t.Fatalf("TCPDataFramePayload returned error: %v", err)
	}
	if string(payload) != "private-response" {
		t.Fatalf("payload = %q, want private-response", string(payload))
	}
	closeFrame := waitForTunnelWrite(t, fakeTunnel.writeCh)
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.Direction != tunnel.TCPDirectionRemote || closeFrame.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("closeFrame = %+v, want remote eof tcp_close", closeFrame)
	}
	if !tcpConn.closed {
		t.Fatal("tcp connection was not closed after downstream EOF")
	}
}

func TestConnectorTCPOpenAcceptedOnlyForSuccessfulOpenResult(t *testing.T) {
	openFrame := validConnectorTCPOpenFrame()
	tests := []struct {
		name      string
		frame     tunnel.Frame
		responses []tunnel.Frame
		want      bool
	}{
		{
			name:  "successful open result",
			frame: openFrame,
			responses: []tunnel.Frame{{
				Type:      tunnel.FrameTCPOpenResult,
				RequestID: openFrame.RequestID,
			}},
			want: true,
		},
		{
			name:  "duplicate open rejected",
			frame: openFrame,
			responses: []tunnel.Frame{{
				Type:      tunnel.FrameTCPOpenResult,
				RequestID: openFrame.RequestID,
				Error:     "tcp connection req_tcp_001 is already open",
			}},
			want: false,
		},
		{
			name:  "wrong request id",
			frame: openFrame,
			responses: []tunnel.Frame{{
				Type:      tunnel.FrameTCPOpenResult,
				RequestID: "req_tcp_other",
			}},
			want: false,
		},
		{
			name:  "non open input frame",
			frame: tunnel.Frame{Type: tunnel.FrameTCPData, RequestID: openFrame.RequestID},
			responses: []tunnel.Frame{{
				Type:      tunnel.FrameTCPOpenResult,
				RequestID: openFrame.RequestID,
			}},
			want: false,
		},
		{
			name:      "no responses",
			frame:     openFrame,
			responses: nil,
			want:      false,
		},
		{
			name:  "multiple responses",
			frame: openFrame,
			responses: []tunnel.Frame{
				{Type: tunnel.FrameTCPOpenResult, RequestID: openFrame.RequestID},
				{Type: tunnel.FrameTCPData, RequestID: openFrame.RequestID},
			},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := connectorTCPOpenAccepted(test.frame, test.responses); got != test.want {
				t.Fatalf("connectorTCPOpenAccepted() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestConnectorTCPReadPumpStartsOnceForRequest(t *testing.T) {
	requestID := "req_tcp_read_pump_once"
	tcpConn := newCountingBlockingTCPConnection()
	dialer := &countingTCPConnectionDialer{conn: tcpConn}
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, fixedConnectorTestNow())
	writeCh := make(chan tunnel.Frame, 4)
	dispatcher.SetResponseWriter(func(frames []tunnel.Frame) error {
		for _, frame := range frames {
			writeCh <- frame
		}
		return nil
	})

	openFrame := validConnectorTCPOpenFrame()
	openFrame.RequestID = requestID
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].RequestID != requestID || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}

	dispatcher.StartReadPumpForRequest(requestID)
	if got := waitForTCPReadCall(t, tcpConn.readCallCh); got != 1 {
		t.Fatalf("read call = %d, want first read pump only", got)
	}
	dispatcher.StartReadPumpForRequest(requestID)
	select {
	case got := <-tcpConn.readCallCh:
		t.Fatalf("second StartReadPumpForRequest started another read pump; read call = %d", got)
	case <-time.After(100 * time.Millisecond):
	}
	if got := tcpConn.ReadCallCount(); got != 1 {
		t.Fatalf("ReadCallCount = %d, want 1 after duplicate StartReadPumpForRequest", got)
	}

	if err := tcpConn.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	closeFrame := waitForTunnelWrite(t, writeCh)
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.RequestID != requestID || closeFrame.Direction != tunnel.TCPDirectionRemote || closeFrame.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("closeFrame = %+v, want one remote eof tcp_close", closeFrame)
	}
	if dispatcher.handlerFor(requestID) != nil {
		t.Fatal("dispatcher handler remained after read pump close")
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after read pump close = %d, want 0", got)
	}
}

func TestConnectorTCPReadPumpWriterFailureCleansHandlerAndRegistry(t *testing.T) {
	requestID := "req_tcp_writer_failure_cleanup"
	privateResponse := "private-response-before-writer-failure"
	tcpConn := newRecordingTCPConnection(privateResponse)
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &recordingTCPConnectionDialer{conn: tcpConn}, fixedConnectorTestNow())
	writeCalled := make(chan struct{}, 1)
	var writeMu sync.Mutex
	var writeCalls int
	var attemptedFrames []tunnel.Frame
	dispatcher.SetResponseWriter(func(frames []tunnel.Frame) error {
		writeMu.Lock()
		writeCalls++
		attemptedFrames = append(attemptedFrames, frames...)
		writeMu.Unlock()
		writeCalled <- struct{}{}
		return errors.New("tunnel writer unavailable")
	})

	openFrame := validConnectorTCPOpenFrame()
	openFrame.RequestID = requestID
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].RequestID != requestID || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}
	if got := dispatcher.registry.Count(); got != 1 {
		t.Fatalf("registry Count after open = %d, want 1", got)
	}

	dispatcher.StartReadPumpForRequest(requestID)
	select {
	case <-writeCalled:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for read pump writer failure")
	}
	select {
	case <-tcpConn.closedCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for local tcp connection close after writer failure")
	}

	writeMu.Lock()
	calls := writeCalls
	written := append([]tunnel.Frame(nil), attemptedFrames...)
	writeMu.Unlock()
	if calls != 1 {
		t.Fatalf("writeCalls = %d, want one failed downstream write attempt", calls)
	}
	if len(written) != 1 || written[0].Type != tunnel.FrameTCPData || written[0].RequestID != requestID || written[0].Direction != tunnel.TCPDirectionDown {
		t.Fatalf("attemptedFrames = %+v, want one downstream tcp_data frame", written)
	}
	payload, err := tunnel.TCPDataFramePayload(written[0])
	if err != nil {
		t.Fatalf("TCPDataFramePayload returned error: %v", err)
	}
	if string(payload) != privateResponse {
		t.Fatalf("payload = %q, want %q", string(payload), privateResponse)
	}
	if !tcpConn.closed {
		t.Fatal("tcp connection was not closed after writer failure")
	}
	if dispatcher.handlerFor(requestID) != nil {
		t.Fatal("dispatcher handler remained after writer failure cleanup")
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after writer failure cleanup = %d, want 0", got)
	}
}

func TestConnectorTCPReadPumpReadErrorPublishesErrorCloseAndCleansHandlerAndRegistry(t *testing.T) {
	requestID := "req_tcp_read_error_cleanup"
	tcpConn := newReadErrorTCPConnection(errors.New("synthetic local tcp read failed"))
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &countingTCPConnectionDialer{conn: tcpConn}, fixedConnectorTestNow())
	writeCh := make(chan tunnel.Frame, 4)
	var writeMu sync.Mutex
	var writeCalls int
	dispatcher.SetResponseWriter(func(frames []tunnel.Frame) error {
		writeMu.Lock()
		writeCalls++
		writeMu.Unlock()
		for _, frame := range frames {
			writeCh <- frame
		}
		return nil
	})

	openFrame := validConnectorTCPOpenFrame()
	openFrame.RequestID = requestID
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].RequestID != requestID || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}
	if got := dispatcher.registry.Count(); got != 1 {
		t.Fatalf("registry Count after open = %d, want 1", got)
	}

	dispatcher.StartReadPumpForRequest(requestID)
	closeFrame := waitForTunnelWrite(t, writeCh)
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.RequestID != requestID || closeFrame.Direction != tunnel.TCPDirectionRemote || closeFrame.CloseReason != tunnel.TCPCloseReasonError {
		t.Fatalf("closeFrame = %+v, want remote error tcp_close for read failure", closeFrame)
	}
	if !strings.Contains(closeFrame.Error, "synthetic local tcp read failed") {
		t.Fatalf("closeFrame error = %q, want read failure", closeFrame.Error)
	}
	select {
	case <-tcpConn.closedCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for local tcp connection close after read failure")
	}

	writeMu.Lock()
	calls := writeCalls
	writeMu.Unlock()
	if calls != 1 {
		t.Fatalf("writeCalls = %d, want one remote error close write", calls)
	}
	if !tcpConn.Closed() {
		t.Fatal("tcp connection was not closed after read failure")
	}
	if dispatcher.handlerFor(requestID) != nil {
		t.Fatal("dispatcher handler remained after read failure cleanup")
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after read failure cleanup = %d, want 0", got)
	}
}

func TestConnectorTCPReadPumpReadErrorCloseFailureCleansLocalConnectionAndHandler(t *testing.T) {
	requestID := "req_tcp_read_error_close_failure_cleanup"
	tcpConn := newReadErrorTCPConnection(errors.New("synthetic local tcp read failed after registry loss"))
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), &countingTCPConnectionDialer{conn: tcpConn}, fixedConnectorTestNow())
	writeCh := make(chan tunnel.Frame, 4)
	var writeMu sync.Mutex
	var writeCalls int
	dispatcher.SetResponseWriter(func(frames []tunnel.Frame) error {
		writeMu.Lock()
		writeCalls++
		writeMu.Unlock()
		for _, frame := range frames {
			writeCh <- frame
		}
		return nil
	})

	openFrame := validConnectorTCPOpenFrame()
	openFrame.RequestID = requestID
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].RequestID != requestID || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}
	if _, err := dispatcher.registry.Close(requestID, tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, fixedConnectorTestNow()()); err != nil {
		t.Fatalf("pre-close registry returned error: %v", err)
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after synthetic pre-close = %d, want 0", got)
	}

	dispatcher.StartReadPumpForRequest(requestID)
	closeFrame := waitForTunnelWrite(t, writeCh)
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.RequestID != requestID || closeFrame.Direction != tunnel.TCPDirectionLocal || closeFrame.CloseReason != tunnel.TCPCloseReasonError {
		t.Fatalf("closeFrame = %+v, want local error tcp_close for failed read-error close", closeFrame)
	}
	if !strings.Contains(closeFrame.Error, "synthetic local tcp read failed after registry loss") {
		t.Fatalf("closeFrame error = %q, want read failure", closeFrame.Error)
	}
	select {
	case <-tcpConn.closedCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for local tcp connection close after read-error close failure")
	}

	writeMu.Lock()
	calls := writeCalls
	writeMu.Unlock()
	if calls != 1 {
		t.Fatalf("writeCalls = %d, want one local error close write", calls)
	}
	if !tcpConn.Closed() {
		t.Fatal("tcp connection was not closed after read-error close failure")
	}
	if dispatcher.handlerFor(requestID) != nil {
		t.Fatal("dispatcher handler remained after read-error close failure cleanup")
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after read-error close failure cleanup = %d, want 0", got)
	}
}

func TestConnectorServerSideFlowCopyContractPumpsEdgeOpenDataAndClose(t *testing.T) {
	requestID := "req_tcp_edge_connector_contract"
	clientPayload := []byte("client-request")
	privateResponse := "private-response"
	tcpConn := newRecordingTCPConnection(privateResponse)
	dialer := &recordingTCPConnectionDialer{conn: tcpConn}
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, fixedConnectorTestNow())
	writeCh := make(chan tunnel.Frame, 4)
	dispatcher.SetResponseWriter(func(frames []tunnel.Frame) error {
		for _, frame := range frames {
			writeCh <- frame
		}
		return nil
	})

	openFrame := validConnectorTCPOpenFrame()
	openFrame.RequestID = requestID
	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].RequestID != requestID || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}
	if len(dialer.routes) != 1 || dialer.routes[0].ApplicationID != "app_dummy_https" || dialer.routes[0].Host != "dummy-private-app.local" || dialer.routes[0].Port != 443 {
		t.Fatalf("dialer routes = %+v, want configured route", dialer.routes)
	}
	if got := dispatcher.registry.Count(); got != 1 {
		t.Fatalf("registry Count after open = %d, want 1", got)
	}

	upFrame, err := tunnel.NewTCPDataFrame(requestID, tunnel.TCPDirectionUp, clientPayload)
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	upResponses, err := dispatcher.HandleFrame(context.Background(), upFrame)
	if err != nil {
		t.Fatalf("HandleFrame tcp_data returned error: %v", err)
	}
	if len(upResponses) != 0 {
		t.Fatalf("upResponses = %+v, want no immediate response for upstream write", upResponses)
	}
	if tcpConn.written.String() != string(clientPayload) {
		t.Fatalf("tcp written = %q, want %q", tcpConn.written.String(), string(clientPayload))
	}

	dispatcher.StartReadPumpForRequest(requestID)
	downFrame := waitForTunnelWrite(t, writeCh)
	if downFrame.Type != tunnel.FrameTCPData || downFrame.RequestID != requestID || downFrame.Direction != tunnel.TCPDirectionDown {
		t.Fatalf("downFrame = %+v, want downstream tcp_data for request", downFrame)
	}
	downPayload, err := tunnel.TCPDataFramePayload(downFrame)
	if err != nil {
		t.Fatalf("TCPDataFramePayload returned error: %v", err)
	}
	if string(downPayload) != privateResponse {
		t.Fatalf("down payload = %q, want %q", string(downPayload), privateResponse)
	}

	closeFrame := waitForTunnelWrite(t, writeCh)
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.RequestID != requestID || closeFrame.Direction != tunnel.TCPDirectionRemote || closeFrame.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("closeFrame = %+v, want remote eof tcp_close", closeFrame)
	}
	if closeFrame.BytesUp != int64(len(clientPayload)) {
		t.Fatalf("closeFrame BytesUp = %d, want %d", closeFrame.BytesUp, len(clientPayload))
	}
	if closeFrame.BytesDown != int64(len(privateResponse)) {
		t.Fatalf("closeFrame BytesDown = %d, want %d", closeFrame.BytesDown, len(privateResponse))
	}
	if !tcpConn.closed {
		t.Fatal("tcp connection was not closed after server-side EOF")
	}
	if dispatcher.handlerFor(requestID) != nil {
		t.Fatal("dispatcher handler remained after remote EOF close")
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("registry Count after remote EOF = %d, want 0", got)
	}
}

func TestEdgeConnectorTransportAuditIntegrationContractUsesNEFlowCopyFrames(t *testing.T) {
	runCriticalPathInProcessByteRoundTripKeystone(t)
}

func TestCriticalPathInProcessByteRoundTripKeystone(t *testing.T) {
	runCriticalPathInProcessByteRoundTripKeystone(t)
}

func TestDataPlaneByteRoundTripOverRealTunnelTransport(t *testing.T) {
	t.Helper()

	tenantID := "tenant_lab_001"
	requestID := "req_tcp_real_tunnel_transport"
	clientPayload := []byte("synthetic-client-bytes-over-real-tunnel")
	privateResponse := []byte("synthetic-private-response-over-real-tunnel")
	now := fixedConnectorTestNow()

	edgeContract := neflowcopy.NewContract(now)
	openFrame, err := edgeContract.Open(neflowcopy.OpenMetadata{
		TenantID:      tenantID,
		RequestID:     requestID,
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		Limits:        neflowcopy.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("edge contract Open returned error: %v", err)
	}
	openAudit, err := neflowcopy.MetadataAuditEventFromOpen(tenantID, openFrame)
	if err != nil {
		t.Fatalf("MetadataAuditEventFromOpen returned error: %v", err)
	}
	if openAudit.EventType != neflowcopy.AuditEventFlowCopyStarted || openAudit.RequestID != requestID {
		t.Fatalf("openAudit = %+v, want flow_copy_started for request", openAudit)
	}
	assertMetadataOnlyFlowCopyAuditEvent(t, openAudit)

	edgeRaw, connectorRaw := net.Pipe()
	defer edgeRaw.Close()
	defer connectorRaw.Close()
	edgeConn := tunnel.NewInProcessConn(edgeRaw, true)
	connectorConn := tunnel.NewInProcessConn(connectorRaw, false)
	manager := tunnel.NewManagerWithRequestTimeout(time.Second)
	session, _ := manager.Register("conn_lab_real_tunnel", "tun_lab_real_tunnel", edgeConn)
	sessionRunDone := make(chan error, 1)
	go func() {
		sessionRunDone <- session.Run()
	}()

	privateConn := newWriteTriggeredTCPConnection(privateResponse)
	dialer := &countingTCPConnectionDialer{conn: privateConn}
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, now)
	connectorDone := make(chan error, 1)
	go func() {
		connectorDone <- handleConnectorTunnelConn(context.Background(), connectorConn, "", dispatcher)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	streamCh, cleanup, openResponse, err := session.OpenTCP(ctx, openFrame)
	if err != nil {
		t.Fatalf("OpenTCP over real tunnel transport returned error: %v", err)
	}
	defer cleanup()
	if openResponse.Type != tunnel.FrameTCPOpenResult || openResponse.RequestID != requestID || openResponse.Error != "" {
		t.Fatalf("openResponse = %+v, want successful tcp_open_result", openResponse)
	}
	if len(dialer.routes) != 1 || dialer.routes[0].ApplicationID != "app_dummy_https" ||
		dialer.routes[0].Host != "dummy-private-app.local" || dialer.routes[0].Port != 443 {
		t.Fatalf("dialer routes = %+v, want one configured private TCP route", dialer.routes)
	}
	if got := edgeContract.Count(); got != 1 {
		t.Fatalf("edge registry Count after open = %d, want 1", got)
	}
	if got := dispatcher.registry.Count(); got != 1 {
		t.Fatalf("connector registry Count after open = %d, want 1", got)
	}

	upFrame, closed, err := edgeContract.CopyUpstream(requestID, bytes.NewReader(clientPayload), len(clientPayload))
	if err != nil {
		t.Fatalf("edge contract CopyUpstream returned error: %v", err)
	}
	if closed {
		t.Fatal("edge contract CopyUpstream closed=true, want data frame")
	}
	if upFrame.Type != tunnel.FrameTCPData || upFrame.Direction != tunnel.TCPDirectionUp || upFrame.RequestID != requestID {
		t.Fatalf("upFrame = %+v, want upstream tcp_data for request", upFrame)
	}
	if err := session.WriteTCPStreamFrame(upFrame); err != nil {
		t.Fatalf("WriteTCPStreamFrame over real tunnel transport returned error: %v", err)
	}
	select {
	case <-privateConn.writeReady:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Connector private TCP write")
	}
	if privateConn.Written() != string(clientPayload) {
		t.Fatalf("private TCP written payload = %q, want %q", privateConn.Written(), string(clientPayload))
	}

	downFrame := waitForTunnelStreamFrame(t, streamCh)
	if downFrame.Type != tunnel.FrameTCPData || downFrame.RequestID != requestID || downFrame.Direction != tunnel.TCPDirectionDown {
		t.Fatalf("downFrame = %+v, want downstream tcp_data for request", downFrame)
	}
	downPayload, err := tunnel.TCPDataFramePayload(downFrame)
	if err != nil {
		t.Fatalf("downstream TCPDataFramePayload returned error: %v", err)
	}
	if string(downPayload) != string(privateResponse) {
		t.Fatalf("downstream payload = %q, want %q", string(downPayload), string(privateResponse))
	}
	var downstream bytes.Buffer
	written, closeMaterial, closed, err := edgeContract.CopyDownstream(downFrame, &downstream)
	if err != nil {
		t.Fatalf("edge contract CopyDownstream returned error: %v", err)
	}
	if closed || closeMaterial.Type != "" {
		t.Fatalf("CopyDownstream closed=%v closeMaterial=%+v, want data copy only", closed, closeMaterial)
	}
	if written != len(privateResponse) || downstream.String() != string(privateResponse) {
		t.Fatalf("downstream written=%d payload=%q, want %d %q", written, downstream.String(), len(privateResponse), string(privateResponse))
	}

	connectorCloseFrame := waitForTunnelStreamFrame(t, streamCh)
	if connectorCloseFrame.Type != tunnel.FrameTCPClose || connectorCloseFrame.RequestID != requestID ||
		connectorCloseFrame.Direction != tunnel.TCPDirectionRemote || connectorCloseFrame.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("connectorCloseFrame = %+v, want remote eof tcp_close", connectorCloseFrame)
	}
	edgeCloseFrame, closeAudit, err := edgeContract.CloseWithMetadataAudit(requestID, connectorCloseFrame.Direction, connectorCloseFrame.CloseReason)
	if err != nil {
		t.Fatalf("edge contract CloseWithMetadataAudit returned error: %v", err)
	}
	if edgeCloseFrame.BytesUp != int64(len(clientPayload)) || edgeCloseFrame.BytesDown != int64(len(privateResponse)) {
		t.Fatalf("edgeCloseFrame bytes up/down = %d/%d, want %d/%d", edgeCloseFrame.BytesUp, edgeCloseFrame.BytesDown, len(clientPayload), len(privateResponse))
	}
	if connectorCloseFrame.BytesUp != edgeCloseFrame.BytesUp || connectorCloseFrame.BytesDown != edgeCloseFrame.BytesDown {
		t.Fatalf("connectorCloseFrame = %+v edgeCloseFrame = %+v, want matching aggregate byte metrics", connectorCloseFrame, edgeCloseFrame)
	}
	if closeAudit.EventType != neflowcopy.AuditEventFlowCopyClosed || closeAudit.TenantID != tenantID ||
		closeAudit.ApplicationID != "app_dummy_https" || closeAudit.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("closeAudit = %+v, want metadata-only eof close audit for retained scope", closeAudit)
	}
	if closeAudit.BytesUp != int64(len(clientPayload)) || closeAudit.BytesDown != int64(len(privateResponse)) {
		t.Fatalf("closeAudit bytes up/down = %d/%d, want %d/%d", closeAudit.BytesUp, closeAudit.BytesDown, len(clientPayload), len(privateResponse))
	}
	assertMetadataOnlyFlowCopyAuditEvent(t, closeAudit)
	if !privateConn.Closed() {
		t.Fatal("private TCP connection was not closed after remote EOF")
	}
	waitForConnectorTCPDispatcherCleanup(t, dispatcher, requestID)
	if got := edgeContract.Count(); got != 0 {
		t.Fatalf("edge registry Count after metadata audit close = %d, want 0", got)
	}

	edgeRaw.Close()
	if err := <-sessionRunDone; err != nil && !strings.Contains(err.Error(), "closed pipe") {
		t.Fatalf("session Run returned error: %v", err)
	}
	if err := <-connectorDone; err != nil && !strings.Contains(err.Error(), "closed pipe") && err != io.EOF {
		t.Fatalf("connector tunnel returned error: %v", err)
	}
}

func TestRealEdgeProviderSeamBytesMatchConnectorPackageFramePath(t *testing.T) {
	t.Helper()

	tenantID := "tenant_lab_001"
	requestID := "req_phase2_seam_001"
	clientPayload := []byte("phase2-client-byte-check")
	privateResponse := []byte("phase2-lab-endpoint-response")
	now := fixedConnectorTestNow()

	edgeContract := neflowcopy.NewContract(now)
	openFrame, err := edgeContract.Open(neflowcopy.OpenMetadata{
		TenantID:      tenantID,
		RequestID:     requestID,
		ApplicationID: "app_dummy_postgres",
		Host:          "dummy-postgres.local",
		Port:          5432,
		Limits:        neflowcopy.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("edge contract Open returned error: %v", err)
	}
	if openFrame.Type != tunnel.FrameTCPOpen || openFrame.RequestID != requestID ||
		openFrame.ApplicationID != "app_dummy_postgres" || openFrame.Host != "dummy-postgres.local" || openFrame.Port != 5432 {
		t.Fatalf("openFrame = %+v, want postgres real-edge package-frame tcp_open", openFrame)
	}
	openAudit, err := neflowcopy.MetadataAuditEventFromOpen(tenantID, openFrame)
	if err != nil {
		t.Fatalf("MetadataAuditEventFromOpen returned error: %v", err)
	}
	if openAudit.EventType != neflowcopy.AuditEventFlowCopyStarted || openAudit.RequestID != requestID ||
		openAudit.ApplicationID != "app_dummy_postgres" {
		t.Fatalf("openAudit = %+v, want flow_copy_started audit", openAudit)
	}
	assertMetadataOnlyFlowCopyAuditEvent(t, openAudit)

	edgeRaw, connectorRaw := net.Pipe()
	defer edgeRaw.Close()
	defer connectorRaw.Close()
	edgeConn := tunnel.NewInProcessConn(edgeRaw, true)
	connectorConn := tunnel.NewInProcessConn(connectorRaw, false)
	manager := tunnel.NewManagerWithRequestTimeout(time.Second)
	session, _ := manager.Register("conn_lab_m1135", "tun_lab_m1135", edgeConn)
	sessionRunDone := make(chan error, 1)
	go func() {
		sessionRunDone <- session.Run()
	}()

	privateConn := newWriteTriggeredTCPConnection(privateResponse)
	dialer := &countingTCPConnectionDialer{conn: privateConn}
	dispatcher := newConnectorTunnelTCPDispatcher([]connectorTCPRoute{{
		ApplicationID: "app_dummy_postgres",
		Host:          "dummy-postgres.local",
		Port:          5432,
	}}, dialer, now)
	connectorDone := make(chan error, 1)
	go func() {
		connectorDone <- handleConnectorTunnelConn(context.Background(), connectorConn, "", dispatcher)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	streamCh, cleanup, openResponse, err := session.OpenTCP(ctx, openFrame)
	if err != nil {
		t.Fatalf("OpenTCP over package-frame seam returned error: %v", err)
	}
	defer cleanup()
	if openResponse.Type != tunnel.FrameTCPOpenResult || openResponse.RequestID != requestID || openResponse.Error != "" {
		t.Fatalf("openResponse = %+v, want successful tcp_open_result", openResponse)
	}
	if len(dialer.routes) != 1 || dialer.routes[0].ApplicationID != "app_dummy_postgres" ||
		dialer.routes[0].Host != "dummy-postgres.local" || dialer.routes[0].Port != 5432 {
		t.Fatalf("dialer routes = %+v, want one configured postgres private TCP route", dialer.routes)
	}
	if got := edgeContract.Count(); got != 1 {
		t.Fatalf("edge registry Count after open = %d, want 1", got)
	}
	if got := dispatcher.registry.Count(); got != 1 {
		t.Fatalf("connector registry Count after open = %d, want 1", got)
	}

	upFrame, closed, err := edgeContract.CopyUpstream(requestID, bytes.NewReader(clientPayload), len(clientPayload))
	if err != nil {
		t.Fatalf("edge contract CopyUpstream returned error: %v", err)
	}
	if closed {
		t.Fatal("edge contract CopyUpstream closed=true, want data frame")
	}
	if upFrame.Type != tunnel.FrameTCPData || upFrame.RequestID != requestID || upFrame.Direction != tunnel.TCPDirectionUp {
		t.Fatalf("upFrame = %+v, want upstream tcp_data for request", upFrame)
	}
	upPayload, err := tunnel.TCPDataFramePayload(upFrame)
	if err != nil {
		t.Fatalf("upstream TCPDataFramePayload returned error: %v", err)
	}
	if string(upPayload) != string(clientPayload) {
		t.Fatalf("upstream payload = %q, want provider seam bytes %q", string(upPayload), string(clientPayload))
	}
	if err := session.WriteTCPStreamFrame(upFrame); err != nil {
		t.Fatalf("WriteTCPStreamFrame over package-frame seam returned error: %v", err)
	}
	select {
	case <-privateConn.writeReady:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Connector private TCP write")
	}
	if privateConn.Written() != string(clientPayload) {
		t.Fatalf("private TCP written payload = %q, want %q", privateConn.Written(), string(clientPayload))
	}

	downFrame := waitForTunnelStreamFrame(t, streamCh)
	if downFrame.Type != tunnel.FrameTCPData || downFrame.RequestID != requestID || downFrame.Direction != tunnel.TCPDirectionDown {
		t.Fatalf("downFrame = %+v, want downstream tcp_data for request", downFrame)
	}
	downPayload, err := tunnel.TCPDataFramePayload(downFrame)
	if err != nil {
		t.Fatalf("downstream TCPDataFramePayload returned error: %v", err)
	}
	if string(downPayload) != string(privateResponse) {
		t.Fatalf("downstream payload = %q, want provider seam response bytes %q", string(downPayload), string(privateResponse))
	}
	var downstream bytes.Buffer
	written, closeMaterial, closed, err := edgeContract.CopyDownstream(downFrame, &downstream)
	if err != nil {
		t.Fatalf("edge contract CopyDownstream returned error: %v", err)
	}
	if closed || closeMaterial.Type != "" {
		t.Fatalf("CopyDownstream closed=%v closeMaterial=%+v, want data copy only", closed, closeMaterial)
	}
	if written != len(privateResponse) || downstream.String() != string(privateResponse) {
		t.Fatalf("downstream written=%d payload=%q, want %d %q", written, downstream.String(), len(privateResponse), string(privateResponse))
	}

	connectorCloseFrame := waitForTunnelStreamFrame(t, streamCh)
	if connectorCloseFrame.Type != tunnel.FrameTCPClose || connectorCloseFrame.RequestID != requestID ||
		connectorCloseFrame.Direction != tunnel.TCPDirectionRemote || connectorCloseFrame.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("connectorCloseFrame = %+v, want remote eof tcp_close", connectorCloseFrame)
	}
	edgeCloseFrame, closeAudit, err := edgeContract.CloseWithMetadataAudit(requestID, connectorCloseFrame.Direction, connectorCloseFrame.CloseReason)
	if err != nil {
		t.Fatalf("edge contract CloseWithMetadataAudit returned error: %v", err)
	}
	if edgeCloseFrame.BytesUp != int64(len(clientPayload)) || edgeCloseFrame.BytesDown != int64(len(privateResponse)) {
		t.Fatalf("edgeCloseFrame bytes up/down = %d/%d, want exact bytes %d/%d", edgeCloseFrame.BytesUp, edgeCloseFrame.BytesDown, len(clientPayload), len(privateResponse))
	}
	if connectorCloseFrame.BytesUp != edgeCloseFrame.BytesUp || connectorCloseFrame.BytesDown != edgeCloseFrame.BytesDown {
		t.Fatalf("connectorCloseFrame = %+v edgeCloseFrame = %+v, want matching package-frame byte metrics", connectorCloseFrame, edgeCloseFrame)
	}
	if closeAudit.EventType != neflowcopy.AuditEventFlowCopyClosed || closeAudit.TenantID != tenantID ||
		closeAudit.ApplicationID != "app_dummy_postgres" || closeAudit.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("closeAudit = %+v, want metadata-only eof close audit for scope", closeAudit)
	}
	if closeAudit.BytesUp != int64(len(clientPayload)) || closeAudit.BytesDown != int64(len(privateResponse)) {
		t.Fatalf("closeAudit bytes up/down = %d/%d, want %d/%d", closeAudit.BytesUp, closeAudit.BytesDown, len(clientPayload), len(privateResponse))
	}
	assertMetadataOnlyFlowCopyAuditEvent(t, closeAudit)
	if !privateConn.Closed() {
		t.Fatal("private TCP connection was not closed after remote EOF")
	}
	waitForConnectorTCPDispatcherCleanup(t, dispatcher, requestID)
	if got := edgeContract.Count(); got != 0 {
		t.Fatalf("edge registry Count after metadata audit close = %d, want 0", got)
	}
	if _, ok := edgeContract.OpenRecord(requestID); ok {
		t.Fatal("edge open record remained after metadata audit close")
	}

	edgeRaw.Close()
	if err := <-sessionRunDone; err != nil && !strings.Contains(err.Error(), "closed pipe") {
		t.Fatalf("session Run returned error: %v", err)
	}
	if err := <-connectorDone; err != nil && !strings.Contains(err.Error(), "closed pipe") && err != io.EOF {
		t.Fatalf("connector tunnel returned error: %v", err)
	}
}

func runCriticalPathInProcessByteRoundTripKeystone(t *testing.T) {
	t.Helper()

	tenantID := "tenant_lab_001"
	requestID := "req_tcp_edge_connector_transport_audit"
	clientPayload := []byte("client-request")
	privateResponse := "private-response"
	now := fixedConnectorTestNow()

	edgeContract := neflowcopy.NewContract(now)
	openFrame, err := edgeContract.Open(neflowcopy.OpenMetadata{
		TenantID:      tenantID,
		RequestID:     requestID,
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		Limits:        neflowcopy.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("edge contract Open returned error: %v", err)
	}
	openAudit, err := neflowcopy.MetadataAuditEventFromOpen(tenantID, openFrame)
	if err != nil {
		t.Fatalf("MetadataAuditEventFromOpen returned error: %v", err)
	}
	if openAudit.EventType != neflowcopy.AuditEventFlowCopyStarted || openAudit.RequestID != requestID || openAudit.ApplicationID != "app_dummy_https" {
		t.Fatalf("openAudit = %+v, want flow_copy_started for request/application", openAudit)
	}
	assertMetadataOnlyFlowCopyAuditEvent(t, openAudit)

	tcpConn := newRecordingTCPConnection(privateResponse)
	dialer := &recordingTCPConnectionDialer{conn: tcpConn}
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, now)
	writeCh := make(chan tunnel.Frame, 4)
	dispatcher.SetResponseWriter(func(frames []tunnel.Frame) error {
		for _, frame := range frames {
			writeCh <- frame
		}
		return nil
	})

	openResponses, err := dispatcher.HandleFrame(context.Background(), openFrame)
	if err != nil {
		t.Fatalf("HandleFrame edge tcp_open returned error: %v", err)
	}
	if len(openResponses) != 1 || openResponses[0].Type != tunnel.FrameTCPOpenResult || openResponses[0].RequestID != requestID || openResponses[0].Error != "" {
		t.Fatalf("openResponses = %+v, want successful tcp_open_result", openResponses)
	}
	if len(dialer.routes) != 1 || dialer.routes[0].ApplicationID != "app_dummy_https" || dialer.routes[0].Host != "dummy-private-app.local" || dialer.routes[0].Port != 443 {
		t.Fatalf("dialer routes = %+v, want configured route", dialer.routes)
	}
	if got := edgeContract.Count(); got != 1 {
		t.Fatalf("edge registry Count after open = %d, want 1", got)
	}
	if got := dispatcher.registry.Count(); got != 1 {
		t.Fatalf("connector registry Count after open = %d, want 1", got)
	}

	upFrame, closed, err := edgeContract.CopyUpstream(requestID, bytes.NewReader(clientPayload), len(clientPayload))
	if err != nil {
		t.Fatalf("edge contract CopyUpstream returned error: %v", err)
	}
	if closed {
		t.Fatal("edge contract CopyUpstream closed=true, want data frame")
	}
	if upFrame.Type != tunnel.FrameTCPData || upFrame.RequestID != requestID || upFrame.Direction != tunnel.TCPDirectionUp {
		t.Fatalf("upFrame = %+v, want upstream tcp_data tunnel frame for request", upFrame)
	}
	upPayload, err := tunnel.TCPDataFramePayload(upFrame)
	if err != nil {
		t.Fatalf("upstream TCPDataFramePayload returned error: %v", err)
	}
	if string(upPayload) != string(clientPayload) {
		t.Fatalf("upstream payload = %q, want %q", string(upPayload), string(clientPayload))
	}
	upResponses, err := dispatcher.HandleFrame(context.Background(), upFrame)
	if err != nil {
		t.Fatalf("HandleFrame edge tcp_data returned error: %v", err)
	}
	if len(upResponses) != 0 {
		t.Fatalf("upResponses = %+v, want no immediate response for upstream write", upResponses)
	}
	if tcpConn.written.String() != string(clientPayload) {
		t.Fatalf("tcp written = %q, want %q", tcpConn.written.String(), string(clientPayload))
	}

	dispatcher.StartReadPumpForRequest(requestID)
	downFrame := waitForTunnelWrite(t, writeCh)
	if downFrame.Type != tunnel.FrameTCPData || downFrame.RequestID != requestID || downFrame.Direction != tunnel.TCPDirectionDown {
		t.Fatalf("downFrame = %+v, want downstream tcp_data for request", downFrame)
	}
	downPayload, err := tunnel.TCPDataFramePayload(downFrame)
	if err != nil {
		t.Fatalf("downstream TCPDataFramePayload returned error: %v", err)
	}
	if string(downPayload) != privateResponse {
		t.Fatalf("downstream payload = %q, want %q", string(downPayload), privateResponse)
	}
	var downstream bytes.Buffer
	written, closeMaterial, closed, err := edgeContract.CopyDownstream(downFrame, &downstream)
	if err != nil {
		t.Fatalf("edge contract CopyDownstream returned error: %v", err)
	}
	if closed || closeMaterial.Type != "" {
		t.Fatalf("CopyDownstream closed=%v closeMaterial=%+v, want data copy only", closed, closeMaterial)
	}
	if written != len(privateResponse) || downstream.String() != privateResponse {
		t.Fatalf("downstream written=%d payload=%q, want %d %q", written, downstream.String(), len(privateResponse), privateResponse)
	}

	connectorCloseFrame := waitForTunnelWrite(t, writeCh)
	if connectorCloseFrame.Type != tunnel.FrameTCPClose || connectorCloseFrame.RequestID != requestID || connectorCloseFrame.Direction != tunnel.TCPDirectionRemote || connectorCloseFrame.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("connectorCloseFrame = %+v, want remote eof tcp_close", connectorCloseFrame)
	}
	edgeCloseFrame, closeAudit, err := edgeContract.CloseWithMetadataAudit(requestID, connectorCloseFrame.Direction, connectorCloseFrame.CloseReason)
	if err != nil {
		t.Fatalf("edge contract CloseWithMetadataAudit returned error: %v", err)
	}
	if edgeCloseFrame.BytesUp != connectorCloseFrame.BytesUp || edgeCloseFrame.BytesDown != connectorCloseFrame.BytesDown {
		t.Fatalf("edgeCloseFrame = %+v connectorCloseFrame = %+v, want matching aggregate byte metrics", edgeCloseFrame, connectorCloseFrame)
	}
	if edgeCloseFrame.BytesUp != int64(len(clientPayload)) || edgeCloseFrame.BytesDown != int64(len(privateResponse)) {
		t.Fatalf("edgeCloseFrame bytes up/down = %d/%d, want %d/%d", edgeCloseFrame.BytesUp, edgeCloseFrame.BytesDown, len(clientPayload), len(privateResponse))
	}
	if closeAudit.EventType != neflowcopy.AuditEventFlowCopyClosed || closeAudit.TenantID != tenantID || closeAudit.ApplicationID != "app_dummy_https" || closeAudit.CloseReason != tunnel.TCPCloseReasonEOF {
		t.Fatalf("closeAudit = %+v, want metadata-only eof close audit for retained scope", closeAudit)
	}
	if closeAudit.BytesUp != int64(len(clientPayload)) || closeAudit.BytesDown != int64(len(privateResponse)) {
		t.Fatalf("closeAudit bytes up/down = %d/%d, want %d/%d", closeAudit.BytesUp, closeAudit.BytesDown, len(clientPayload), len(privateResponse))
	}
	assertMetadataOnlyFlowCopyAuditEvent(t, closeAudit)
	if !tcpConn.closed {
		t.Fatal("tcp connection was not closed after server-side EOF")
	}
	if dispatcher.handlerFor(requestID) != nil {
		t.Fatal("dispatcher handler remained after remote EOF close")
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("connector registry Count after remote EOF = %d, want 0", got)
	}
	if got := edgeContract.Count(); got != 0 {
		t.Fatalf("edge registry Count after metadata audit close = %d, want 0", got)
	}
	if _, ok := edgeContract.OpenRecord(requestID); ok {
		t.Fatal("edge open record remained after metadata audit close")
	}

	deniedContract := neflowcopy.NewContract(now)
	deniedFrame, err := deniedContract.Open(neflowcopy.OpenMetadata{
		TenantID:      tenantID,
		RequestID:     "req_tcp_edge_connector_transport_denied",
		ApplicationID: "app_dummy_https",
		Host:          "blocked-private-app.local",
		Port:          443,
		Limits:        neflowcopy.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("denied edge contract Open returned error: %v", err)
	}
	deniedResponses, err := dispatcher.HandleFrame(context.Background(), deniedFrame)
	if err != nil {
		t.Fatalf("HandleFrame denied edge tcp_open returned error: %v", err)
	}
	if len(deniedResponses) != 1 || deniedResponses[0].Type != tunnel.FrameTCPOpenResult || !strings.Contains(deniedResponses[0].Error, "tcp dial denied") {
		t.Fatalf("deniedResponses = %+v, want tcp dial denied tcp_open_result", deniedResponses)
	}
	if len(dialer.routes) != 1 {
		t.Fatalf("dialer routes = %+v, want denied route to avoid new dial", dialer.routes)
	}
	if got := dispatcher.registry.Count(); got != 0 {
		t.Fatalf("connector registry Count after denied open = %d, want 0", got)
	}
	deniedCloseFrame, deniedAudit, err := deniedContract.CloseWithMetadataAudit(deniedFrame.RequestID, tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonDenied)
	if err != nil {
		t.Fatalf("denied CloseWithMetadataAudit returned error: %v", err)
	}
	if deniedCloseFrame.BytesUp != 0 || deniedCloseFrame.BytesDown != 0 ||
		deniedCloseFrame.CloseReason != tunnel.TCPCloseReasonDenied ||
		deniedAudit.EventType != neflowcopy.AuditEventFlowCopyClosed ||
		deniedAudit.CloseReason != tunnel.TCPCloseReasonDenied {
		t.Fatalf("deniedCloseFrame=%+v deniedAudit=%+v, want metadata-only zero-byte denied close", deniedCloseFrame, deniedAudit)
	}
	assertMetadataOnlyFlowCopyAuditEvent(t, deniedAudit)
	if got := deniedContract.Count(); got != 0 {
		t.Fatalf("denied edge registry Count after metadata audit close = %d, want 0", got)
	}
}

func TestHandleConnectorTunnelConnDeniesRuntimeTCPWithoutRoutes(t *testing.T) {
	dispatcher := newConnectorTunnelTCPDispatcher(nil, &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("")}, fixedConnectorTestNow())
	fakeTunnel := &recordingTunnelJSONConn{reads: []tunnel.Frame{validConnectorTCPOpenFrame()}}

	err := handleConnectorTunnelConn(context.Background(), fakeTunnel, "http://127.0.0.1:1", dispatcher)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("handleConnectorTunnelConn err = %v, want EOF after scripted frames", err)
	}
	if len(fakeTunnel.writes) != 1 {
		t.Fatalf("writes = %+v, want one tcp_open_result", fakeTunnel.writes)
	}
	if fakeTunnel.writes[0].Type != tunnel.FrameTCPOpenResult || !strings.Contains(fakeTunnel.writes[0].Error, "tcp dial denied") {
		t.Fatalf("write[0] = %+v, want tcp dial denied", fakeTunnel.writes[0])
	}
}

type recordingTCPOpenDialer struct {
	routes []connectorTCPRoute
	err    error
}

func (dialer *recordingTCPOpenDialer) OpenTCP(ctx context.Context, route connectorTCPRoute) error {
	dialer.routes = append(dialer.routes, route)
	return dialer.err
}

type recordingTCPConnectionDialer struct {
	routes []connectorTCPRoute
	conn   *recordingTCPConnection
	err    error
}

func (dialer *recordingTCPConnectionDialer) OpenTCPConnection(ctx context.Context, route connectorTCPRoute) (io.ReadWriteCloser, error) {
	dialer.routes = append(dialer.routes, route)
	if dialer.err != nil {
		return nil, dialer.err
	}
	return dialer.conn, nil
}

type countingTCPConnectionDialer struct {
	routes []connectorTCPRoute
	conn   io.ReadWriteCloser
}

func (dialer *countingTCPConnectionDialer) OpenTCPConnection(ctx context.Context, route connectorTCPRoute) (io.ReadWriteCloser, error) {
	dialer.routes = append(dialer.routes, route)
	return dialer.conn, nil
}

type recordingTCPConnection struct {
	reader     *bytes.Reader
	written    bytes.Buffer
	closed     bool
	blockReads bool
	closedCh   chan struct{}
	closeOnce  sync.Once
	closeErr   error
	writeErr   error
}

func newRecordingTCPConnection(readPayload string) *recordingTCPConnection {
	return &recordingTCPConnection{reader: bytes.NewReader([]byte(readPayload)), closedCh: make(chan struct{})}
}

func newBlockingRecordingTCPConnection() *recordingTCPConnection {
	return &recordingTCPConnection{reader: bytes.NewReader(nil), blockReads: true, closedCh: make(chan struct{})}
}

func (conn *recordingTCPConnection) Read(p []byte) (int, error) {
	if conn.blockReads {
		<-conn.closedCh
		return 0, io.EOF
	}
	return conn.reader.Read(p)
}

func (conn *recordingTCPConnection) Write(p []byte) (int, error) {
	if conn.writeErr != nil {
		return 0, conn.writeErr
	}
	return conn.written.Write(p)
}

func (conn *recordingTCPConnection) Close() error {
	conn.closeOnce.Do(func() {
		conn.closed = true
		close(conn.closedCh)
	})
	return conn.closeErr
}

type writeTriggeredTCPConnection struct {
	mu         sync.Mutex
	response   []byte
	readOffset int
	written    bytes.Buffer
	writeReady chan struct{}
	closed     bool
	closedCh   chan struct{}
	closeOnce  sync.Once
	writeOnce  sync.Once
}

func newWriteTriggeredTCPConnection(response []byte) *writeTriggeredTCPConnection {
	return &writeTriggeredTCPConnection{
		response:   append([]byte(nil), response...),
		writeReady: make(chan struct{}),
		closedCh:   make(chan struct{}),
	}
}

func (conn *writeTriggeredTCPConnection) Read(p []byte) (int, error) {
	select {
	case <-conn.writeReady:
	case <-conn.closedCh:
		return 0, io.EOF
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.readOffset >= len(conn.response) {
		return 0, io.EOF
	}
	n := copy(p, conn.response[conn.readOffset:])
	conn.readOffset += n
	return n, nil
}

func (conn *writeTriggeredTCPConnection) Write(p []byte) (int, error) {
	conn.mu.Lock()
	n, err := conn.written.Write(p)
	conn.mu.Unlock()
	conn.writeOnce.Do(func() {
		close(conn.writeReady)
	})
	return n, err
}

func (conn *writeTriggeredTCPConnection) Close() error {
	conn.closeOnce.Do(func() {
		conn.mu.Lock()
		conn.closed = true
		conn.mu.Unlock()
		close(conn.closedCh)
	})
	return nil
}

func (conn *writeTriggeredTCPConnection) Written() string {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.written.String()
}

func (conn *writeTriggeredTCPConnection) Closed() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.closed
}

type countingBlockingTCPConnection struct {
	mu         sync.Mutex
	readCalls  int
	readCallCh chan int
	closed     bool
	closedCh   chan struct{}
	closeOnce  sync.Once
}

func newCountingBlockingTCPConnection() *countingBlockingTCPConnection {
	return &countingBlockingTCPConnection{
		readCallCh: make(chan int, 4),
		closedCh:   make(chan struct{}),
	}
}

func (conn *countingBlockingTCPConnection) Read(p []byte) (int, error) {
	conn.mu.Lock()
	conn.readCalls++
	readCall := conn.readCalls
	conn.mu.Unlock()
	conn.readCallCh <- readCall
	<-conn.closedCh
	return 0, io.EOF
}

func (conn *countingBlockingTCPConnection) Write(p []byte) (int, error) {
	return len(p), nil
}

func (conn *countingBlockingTCPConnection) Close() error {
	conn.closeOnce.Do(func() {
		conn.mu.Lock()
		conn.closed = true
		conn.mu.Unlock()
		close(conn.closedCh)
	})
	return nil
}

func (conn *countingBlockingTCPConnection) ReadCallCount() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.readCalls
}

type readErrorTCPConnection struct {
	readErr   error
	mu        sync.Mutex
	closed    bool
	closedCh  chan struct{}
	closeOnce sync.Once
}

func newReadErrorTCPConnection(readErr error) *readErrorTCPConnection {
	return &readErrorTCPConnection{
		readErr:  readErr,
		closedCh: make(chan struct{}),
	}
}

func (conn *readErrorTCPConnection) Read(p []byte) (int, error) {
	return 0, conn.readErr
}

func (conn *readErrorTCPConnection) Write(p []byte) (int, error) {
	return len(p), nil
}

func (conn *readErrorTCPConnection) Close() error {
	conn.closeOnce.Do(func() {
		conn.mu.Lock()
		conn.closed = true
		conn.mu.Unlock()
		close(conn.closedCh)
	})
	return nil
}

func (conn *readErrorTCPConnection) Closed() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.closed
}

type recordingTunnelJSONConn struct {
	mu      sync.Mutex
	reads   []tunnel.Frame
	writes  []tunnel.Frame
	writeCh chan tunnel.Frame
}

func (conn *recordingTunnelJSONConn) ReadJSON(value any) error {
	if len(conn.reads) == 0 {
		return io.EOF
	}
	frame := conn.reads[0]
	conn.reads = conn.reads[1:]
	target, ok := value.(*tunnel.Frame)
	if !ok {
		return errors.New("recording tunnel only supports *tunnel.Frame")
	}
	*target = frame
	return nil
}

func (conn *recordingTunnelJSONConn) WriteJSON(value any) error {
	frame, ok := value.(tunnel.Frame)
	if !ok {
		return errors.New("recording tunnel only supports tunnel.Frame writes")
	}
	conn.mu.Lock()
	conn.writes = append(conn.writes, frame)
	conn.mu.Unlock()
	if conn.writeCh != nil {
		conn.writeCh <- frame
	}
	return nil
}

func waitForTunnelWrite(t *testing.T, ch <-chan tunnel.Frame) tunnel.Frame {
	t.Helper()
	select {
	case frame := <-ch:
		return frame
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for tunnel write")
		return tunnel.Frame{}
	}
}

func waitForTunnelStreamFrame(t *testing.T, ch <-chan tunnel.Frame) tunnel.Frame {
	t.Helper()
	select {
	case frame := <-ch:
		return frame
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for tunnel stream frame")
		return tunnel.Frame{}
	}
}

func waitForConnectorTCPDispatcherCleanup(t *testing.T, dispatcher *connectorTunnelTCPDispatcher, requestID string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if dispatcher.handlerFor(requestID) == nil && dispatcher.registry.Count() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dispatcher cleanup did not complete: handler=%v registry_count=%d", dispatcher.handlerFor(requestID), dispatcher.registry.Count())
}

func waitForTCPReadCall(t *testing.T, ch <-chan int) int {
	t.Helper()
	select {
	case readCall := <-ch:
		return readCall
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for tcp read call")
		return 0
	}
}

func assertMetadataOnlyFlowCopyAuditEvent(t *testing.T, event neflowcopy.MetadataAuditEvent) {
	t.Helper()
	if !event.MetadataOnly {
		t.Fatalf("event = %+v, want metadata_only=true", event)
	}
	if event.NetworkExtensionRuntimeUsed || event.NetworkExtensionFlowReadStarted || event.NetworkExtensionFlowWriteStarted ||
		event.EdgeTunnelOpenStarted || event.TCPPayloadCopyStarted ||
		event.RawPayloadIncluded || event.RawNEFlowIncluded || event.RawDestinationIPIncluded ||
		event.CredentialsIncluded || event.SessionIDIncluded {
		t.Fatalf("event = %+v, want all runtime/copy/raw-material flags false", event)
	}
}

func openRecordingTCPConnection(t *testing.T, readPayload string) (*connectorTCPConnectionHandler, *recordingTCPConnection, *tunnel.TCPConnectionRegistry) {
	t.Helper()
	conn := newRecordingTCPConnection(readPayload)
	dialer := &recordingTCPConnectionDialer{conn: conn}
	registry := tunnel.NewTCPConnectionRegistry()
	response, handler := handleTunnelTCPOpenConnection(context.Background(), validConnectorTCPOpenFrame(), allowedConnectorTCPRoutes(), dialer, registry, time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC))
	if response.Error != "" || handler == nil {
		t.Fatalf("open response = %+v handler=%v, want success", response, handler)
	}
	return handler, conn, registry
}

func allowedConnectorTCPRoutes() []connectorTCPRoute {
	return []connectorTCPRoute{{
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
	}}
}

func fixedConnectorTestNow() func() time.Time {
	return func() time.Time {
		return time.Date(2026, 5, 26, 10, 30, 0, 0, time.UTC)
	}
}

func writeConnectorProtectedAppMap(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "protected_app_map.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write protected app map: %v", err)
	}
	return path
}

func validConnectorTCPOpenFrame() tunnel.Frame {
	return tunnel.Frame{
		Type:                        tunnel.FrameTCPOpen,
		RequestID:                   "req_tcp_001",
		ApplicationID:               "app_dummy_https",
		Host:                        "dummy-private-app.local",
		Port:                        443,
		ConnectTimeoutMillis:        int((5 * time.Second) / time.Millisecond),
		MaxConnectionLifetimeMillis: int((5 * time.Minute) / time.Millisecond),
		IdleTimeoutMillis:           int((30 * time.Second) / time.Millisecond),
		ByteCap:                     64 << 20,
		ConcurrentConnectionCap:     32,
	}
}
