package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

type connectorTCPRoute struct {
	ApplicationID string
	Host          string
	Port          int
}

type connectorProtectedAppMap struct {
	Applications []connectorProtectedApplication `json:"applications"`
}

type connectorProtectedApplication struct {
	ApplicationID   string `json:"application_id"`
	FQDN            string `json:"fqdn"`
	DestinationPort int    `json:"destination_port"`
}

type connectorTCPOpenDialer interface {
	OpenTCP(ctx context.Context, route connectorTCPRoute) error
}

type connectorTCPConnectionDialer interface {
	OpenTCPConnection(ctx context.Context, route connectorTCPRoute) (io.ReadWriteCloser, error)
}

type connectorTCPConnectionHandler struct {
	requestID       string
	conn            io.ReadWriteCloser
	registry        *tunnel.TCPConnectionRegistry
	chunkSize       int
	mu              sync.Mutex
	readPumpStarted bool
}

type connectorTunnelTCPDispatcher struct {
	mu          sync.Mutex
	routes      []connectorTCPRoute
	reachable   model.ConnectorReachableRoutes
	dialer      connectorTCPConnectionDialer
	registry    *tunnel.TCPConnectionRegistry
	handlers    map[string]*connectorTCPConnectionHandler
	writeFrames func([]tunnel.Frame) error
	now         func() time.Time
}

func newConnectorTunnelTCPDispatcher(routes []connectorTCPRoute, dialer connectorTCPConnectionDialer, now func() time.Time) *connectorTunnelTCPDispatcher {
	if now == nil {
		now = time.Now
	}
	return &connectorTunnelTCPDispatcher{
		routes:   routes,
		dialer:   dialer,
		registry: tunnel.NewTCPConnectionRegistry(),
		handlers: map[string]*connectorTCPConnectionHandler{},
		now:      now,
	}
}

func (dispatcher *connectorTunnelTCPDispatcher) SetResponseWriter(writeFrames func([]tunnel.Frame) error) {
	if dispatcher == nil {
		return
	}
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	dispatcher.writeFrames = writeFrames
}

// SetReachableRoutes configures the connector's reachable routes (the destination-driven authorization layer):
// a TCP open whose destination falls under one of these routes is authorized to dial even without an explicit
// protected-app-map entry. Empty routes = the connector authorizes by protected-app-map only (unchanged).
func (dispatcher *connectorTunnelTCPDispatcher) SetReachableRoutes(reachable model.ConnectorReachableRoutes) {
	if dispatcher == nil {
		return
	}
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	dispatcher.reachable = reachable
}

func (dispatcher *connectorTunnelTCPDispatcher) reachableRoutes() model.ConnectorReachableRoutes {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	return dispatcher.reachable
}

// routesForFrame returns the authorization route set for a TCP open. It is the protected-app-map allowlist plus,
// when the destination is fronted by one of the connector's reachable routes, a synthesized allow entry for
// exactly this destination. This is how a destination-driven (route layer) open is authorized: the Edge picked
// THIS connector because it fronts the destination, and the connector confirms it independently against its own
// reachable routes (defense in depth — the connector never relies solely on the Edge's selection).
func (dispatcher *connectorTunnelTCPDispatcher) routesForFrame(frame tunnel.Frame) []connectorTCPRoute {
	if dispatcher == nil {
		return nil
	}
	routes := dispatcher.routes
	if reachableRouteAuthorizes(frame, dispatcher.reachableRoutes()) {
		routes = append(append([]connectorTCPRoute{}, routes...), connectorTCPRoute{
			ApplicationID: frame.ApplicationID,
			Host:          strings.TrimSpace(frame.Host),
			Port:          frame.Port,
		})
	}
	return routes
}

// reachableRouteAuthorizes reports whether the connector's reachable routes front the frame's destination. It
// reuses the SAME resolver the Edge uses to PICK a connector, so the connector's admission and the Edge's
// selection share one matching rule (FQDN by name; CIDR scoped by namespace).
func reachableRouteAuthorizes(frame tunnel.Frame, reachable model.ConnectorReachableRoutes) bool {
	host := strings.TrimSpace(frame.Host)
	if host == "" {
		return false
	}
	if len(reachable.FQDNDomains) == 0 && len(reachable.CIDRs) == 0 {
		return false
	}
	self := model.ConnectorRegistration{ID: "self", ReachableRoutes: reachable}
	_, ok := connector.ResolveConnectorForDestination(host, reachable.Namespace, []model.ConnectorRegistration{self})
	return ok
}

func loadConnectorTCPRoutesFromProtectedAppMap(path string) ([]connectorTCPRoute, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read protected app map: %w", err)
	}
	var appMap connectorProtectedAppMap
	if err := json.Unmarshal(data, &appMap); err != nil {
		return nil, fmt.Errorf("parse protected app map: %w", err)
	}
	routes := make([]connectorTCPRoute, 0, len(appMap.Applications))
	seen := map[string]bool{}
	for index, app := range appMap.Applications {
		route, err := connectorTCPRouteFromProtectedApplication(app, index)
		if err != nil {
			return nil, err
		}
		key := fmt.Sprintf("%s\x00%s\x00%d", route.ApplicationID, strings.ToLower(route.Host), route.Port)
		if seen[key] {
			return nil, fmt.Errorf("protected app map contains duplicate tcp route for application %s host %s port %d", route.ApplicationID, route.Host, route.Port)
		}
		seen[key] = true
		routes = append(routes, route)
	}
	return routes, nil
}

func connectorTCPRouteFromProtectedApplication(app connectorProtectedApplication, index int) (connectorTCPRoute, error) {
	applicationID := strings.TrimSpace(app.ApplicationID)
	if applicationID == "" {
		return connectorTCPRoute{}, fmt.Errorf("protected app map application[%d] application_id is required", index)
	}
	host := strings.ToLower(strings.TrimSpace(app.FQDN))
	if host == "" {
		return connectorTCPRoute{}, fmt.Errorf("protected app map application[%d] fqdn is required", index)
	}
	if strings.Contains(host, ":") {
		return connectorTCPRoute{}, fmt.Errorf("protected app map application[%d] fqdn must not include a port", index)
	}
	if app.DestinationPort < 1 || app.DestinationPort > 65535 {
		return connectorTCPRoute{}, fmt.Errorf("protected app map application[%d] destination_port must be between 1 and 65535", index)
	}
	return connectorTCPRoute{ApplicationID: applicationID, Host: host, Port: app.DestinationPort}, nil
}

func validateConnectorTCPDialRequest(frame tunnel.Frame, routes []connectorTCPRoute) error {
	_, err := connectorTCPRouteForFrame(frame, routes)
	return err
}

func connectorTCPRouteForFrame(frame tunnel.Frame, routes []connectorTCPRoute) (connectorTCPRoute, error) {
	if err := tunnel.ValidateTCPOpenFrame(frame); err != nil {
		return connectorTCPRoute{}, err
	}
	for _, route := range routes {
		if route.ApplicationID == frame.ApplicationID &&
			strings.EqualFold(strings.TrimSpace(route.Host), strings.TrimSpace(frame.Host)) &&
			route.Port == frame.Port {
			return route, nil
		}
	}
	return connectorTCPRoute{}, fmt.Errorf("tcp dial denied for application %s host %s port %d", frame.ApplicationID, frame.Host, frame.Port)
}

func handleTunnelTCPOpen(ctx context.Context, frame tunnel.Frame, routes []connectorTCPRoute, dialer connectorTCPOpenDialer) tunnel.Frame {
	route, err := connectorTCPRouteForFrame(frame, routes)
	if err != nil {
		return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: err.Error()}
	}
	if dialer == nil {
		return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: "tcp dialer is required"}
	}
	if err := dialer.OpenTCP(ctx, route); err != nil {
		return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: err.Error()}
	}
	return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID}
}

func handleConnectorTunnelFrame(ctx context.Context, privateBaseURL string, tcpDispatcher *connectorTunnelTCPDispatcher, frame tunnel.Frame) ([]tunnel.Frame, error) {
	switch frame.Type {
	case tunnel.FrameHTTPRequest:
		return []tunnel.Frame{handleTunnelHTTPRequest(privateBaseURL, frame)}, nil
	case tunnel.FrameProbeRequest:
		// Slice 3 reachability diagnostics: probe ONE destination, scoped to reachable_routes (SSRF guard).
		reachable := model.ConnectorReachableRoutes{}
		if tcpDispatcher != nil {
			reachable = tcpDispatcher.reachableRoutes()
		}
		return []tunnel.Frame{runConnectorProbe(ctx, frame, reachable)}, nil
	case tunnel.FrameDNSQuery:
		// Conditional DNS forwarding: resolve a RAW internal DNS query inside the private network, scoped to
		// reachable_routes (same SSRF guard as the probe). See docs/dns_conditional_forwarding_design.md.
		reachable := model.ConnectorReachableRoutes{}
		if tcpDispatcher != nil {
			reachable = tcpDispatcher.reachableRoutes()
		}
		return []tunnel.Frame{runConnectorDNS(ctx, frame, reachable)}, nil
	case tunnel.FrameTCPOpen, tunnel.FrameTCPData, tunnel.FrameTCPClose:
		if tcpDispatcher == nil {
			return []tunnel.Frame{connectorTCPDispatchErrorFrame(frame, "tcp dispatcher is not configured")}, nil
		}
		return tcpDispatcher.HandleFrame(ctx, frame)
	default:
		return nil, nil
	}
}

func (dispatcher *connectorTunnelTCPDispatcher) HandleFrame(ctx context.Context, frame tunnel.Frame) ([]tunnel.Frame, error) {
	if dispatcher == nil {
		return []tunnel.Frame{connectorTCPDispatchErrorFrame(frame, "tcp dispatcher is not configured")}, nil
	}
	switch frame.Type {
	case tunnel.FrameTCPOpen:
		response, handler := handleTunnelTCPOpenConnection(ctx, frame, dispatcher.routesForFrame(frame), dispatcher.dialer, dispatcher.registry, dispatcher.now())
		if handler != nil {
			dispatcher.storeHandler(frame.RequestID, handler)
		}
		return []tunnel.Frame{response}, nil
	case tunnel.FrameTCPData:
		handler := dispatcher.handlerFor(frame.RequestID)
		if handler == nil {
			return []tunnel.Frame{connectorTCPDispatchErrorFrame(frame, fmt.Sprintf("tcp connection %s is not open", frame.RequestID))}, nil
		}
		frames, err := handler.WriteFrame(frame, dispatcher.now())
		if err != nil {
			return []tunnel.Frame{connectorTCPDispatchErrorFrame(frame, err.Error())}, nil
		}
		if containsTCPClose(frames) {
			dispatcher.removeHandler(frame.RequestID)
		}
		return frames, nil
	case tunnel.FrameTCPClose:
		if err := tunnel.ValidateTCPCloseFrame(frame); err != nil {
			return []tunnel.Frame{connectorTCPDispatchErrorFrame(frame, err.Error())}, nil
		}
		handler := dispatcher.handlerFor(frame.RequestID)
		if handler == nil {
			return nil, nil
		}
		closeFrame, err := handler.Close(frame.Direction, frame.CloseReason, dispatcher.now())
		if err != nil {
			if closeFrame.Type != "" {
				dispatcher.removeHandler(frame.RequestID)
			}
			return []tunnel.Frame{connectorTCPDispatchErrorFrame(frame, err.Error())}, nil
		}
		dispatcher.removeHandler(frame.RequestID)
		return nil, nil
	default:
		return nil, nil
	}
}

func (dispatcher *connectorTunnelTCPDispatcher) storeHandler(requestID string, handler *connectorTCPConnectionHandler) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	dispatcher.handlers[requestID] = handler
}

func (dispatcher *connectorTunnelTCPDispatcher) handlerFor(requestID string) *connectorTCPConnectionHandler {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	return dispatcher.handlers[requestID]
}

func (dispatcher *connectorTunnelTCPDispatcher) removeHandler(requestID string) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	delete(dispatcher.handlers, requestID)
}

func (dispatcher *connectorTunnelTCPDispatcher) takeHandler(requestID string) *connectorTCPConnectionHandler {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	handler := dispatcher.handlers[requestID]
	delete(dispatcher.handlers, requestID)
	return handler
}

func (dispatcher *connectorTunnelTCPDispatcher) responseWriter() func([]tunnel.Frame) error {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	return dispatcher.writeFrames
}

func (dispatcher *connectorTunnelTCPDispatcher) StartReadPumpForRequest(requestID string) {
	if dispatcher == nil {
		return
	}
	dispatcher.startReadPump(dispatcher.handlerFor(requestID))
}

func (dispatcher *connectorTunnelTCPDispatcher) StartExpiryLoop(ctx context.Context, interval time.Duration) {
	if dispatcher == nil {
		return
	}
	if interval <= 0 {
		interval = time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = dispatcher.PublishExpiredConnections(dispatcher.now())
			}
		}
	}()
}

func (dispatcher *connectorTunnelTCPDispatcher) PublishExpiredConnections(now time.Time) error {
	if dispatcher == nil {
		return nil
	}
	frames := dispatcher.CloseExpired(now)
	if len(frames) == 0 {
		return nil
	}
	writeFrames := dispatcher.responseWriter()
	if writeFrames == nil {
		return nil
	}
	return writeFrames(frames)
}

func (dispatcher *connectorTunnelTCPDispatcher) CloseExpired(now time.Time) []tunnel.Frame {
	if dispatcher == nil || dispatcher.registry == nil {
		return nil
	}
	frames := dispatcher.registry.CloseExpired(now)
	for _, frame := range frames {
		if handler := dispatcher.takeHandler(frame.RequestID); handler != nil && handler.conn != nil {
			_ = handler.conn.Close()
		}
	}
	return frames
}

func (dispatcher *connectorTunnelTCPDispatcher) startReadPump(handler *connectorTCPConnectionHandler) {
	writeFrames := dispatcher.responseWriter()
	if writeFrames == nil || handler == nil {
		return
	}
	if !handler.claimReadPumpStart() {
		return
	}
	go dispatcher.pumpTCPReads(handler, writeFrames)
}

func (handler *connectorTCPConnectionHandler) claimReadPumpStart() bool {
	if handler == nil {
		return false
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.readPumpStarted {
		return false
	}
	handler.readPumpStarted = true
	return true
}

func (dispatcher *connectorTunnelTCPDispatcher) pumpTCPReads(handler *connectorTCPConnectionHandler, writeFrames func([]tunnel.Frame) error) {
	for {
		frames, err := handler.ReadFrames(dispatcher.now())
		if err != nil {
			if dispatcher.handlerFor(handler.requestID) != handler {
				return
			}
			closeFrame, closeErr := handler.Close(tunnel.TCPDirectionRemote, tunnel.TCPCloseReasonError, dispatcher.now())
			if closeErr != nil {
				_ = handler.conn.Close()
				closeFrame = connectorTCPDispatchErrorFrame(tunnel.Frame{Type: tunnel.FrameTCPData, RequestID: handler.requestID}, err.Error())
			} else {
				closeFrame.Error = err.Error()
			}
			frames = []tunnel.Frame{closeFrame}
		}
		if len(frames) > 0 {
			if writeErr := writeFrames(frames); writeErr != nil {
				_, _ = handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, dispatcher.now())
				dispatcher.removeHandler(handler.requestID)
				return
			}
		}
		if err != nil || containsTCPClose(frames) {
			dispatcher.removeHandler(handler.requestID)
			return
		}
	}
}

func connectorTCPDispatchErrorFrame(frame tunnel.Frame, message string) tunnel.Frame {
	if frame.Type == tunnel.FrameTCPOpen {
		return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: message}
	}
	return tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: frame.RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonError, Error: message}
}

func containsTCPClose(frames []tunnel.Frame) bool {
	for _, frame := range frames {
		if frame.Type == tunnel.FrameTCPClose {
			return true
		}
	}
	return false
}

func handleTunnelTCPOpenConnection(ctx context.Context, frame tunnel.Frame, routes []connectorTCPRoute, dialer connectorTCPConnectionDialer, registry *tunnel.TCPConnectionRegistry, now time.Time) (tunnel.Frame, *connectorTCPConnectionHandler) {
	route, err := connectorTCPRouteForFrame(frame, routes)
	if err != nil {
		return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: err.Error()}, nil
	}
	if dialer == nil {
		return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: "tcp connection dialer is required"}, nil
	}
	if registry == nil {
		return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: "tcp connection registry is required"}, nil
	}
	if err := registry.Open(frame, now); err != nil {
		return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: err.Error()}, nil
	}
	conn, err := dialer.OpenTCPConnection(ctx, route)
	if err != nil {
		_, _ = registry.Close(frame.RequestID, tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, now)
		return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: err.Error()}, nil
	}
	if connectorTCPConnectionMissing(conn) {
		_, _ = registry.Close(frame.RequestID, tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, now)
		return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: "tcp connection is required"}, nil
	}
	return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID}, &connectorTCPConnectionHandler{
		requestID: frame.RequestID,
		conn:      conn,
		registry:  registry,
		chunkSize: tunnel.DefaultTCPDataFrameChunkBytes,
	}
}

func connectorTCPConnectionMissing(conn io.ReadWriteCloser) bool {
	if conn == nil {
		return true
	}
	value := reflect.ValueOf(conn)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (handler *connectorTCPConnectionHandler) ReadFrames(now time.Time) ([]tunnel.Frame, error) {
	if handler == nil || handler.conn == nil || handler.registry == nil {
		return nil, fmt.Errorf("tcp connection handler is required")
	}
	frame, _, err := tunnel.ReadTCPDataFrame(handler.conn, handler.requestID, tunnel.TCPDirectionDown, handler.chunkSize)
	if err == io.EOF {
		closeFrame, closeErr := handler.Close(tunnel.TCPDirectionRemote, tunnel.TCPCloseReasonEOF, now)
		if closeErr != nil {
			return nil, closeErr
		}
		return []tunnel.Frame{closeFrame}, nil
	}
	if err != nil {
		return nil, err
	}
	closeFrame, closed, err := handler.registry.RecordData(frame, now)
	if err != nil {
		return nil, err
	}
	if closed {
		_ = handler.conn.Close()
		return []tunnel.Frame{closeFrame}, nil
	}
	return []tunnel.Frame{frame}, nil
}

func (handler *connectorTCPConnectionHandler) WriteFrame(frame tunnel.Frame, now time.Time) ([]tunnel.Frame, error) {
	if handler == nil || handler.conn == nil || handler.registry == nil {
		return nil, fmt.Errorf("tcp connection handler is required")
	}
	if frame.RequestID != handler.requestID {
		return nil, fmt.Errorf("tcp_data request_id %s does not match open connection %s", frame.RequestID, handler.requestID)
	}
	if frame.Direction != tunnel.TCPDirectionUp {
		return nil, fmt.Errorf("connector tcp write requires up direction")
	}
	closeFrame, closed, err := handler.registry.RecordData(frame, now)
	if err != nil {
		return nil, err
	}
	if closed {
		_ = handler.conn.Close()
		return []tunnel.Frame{closeFrame}, nil
	}
	if _, err := tunnel.WriteTCPDataFrame(handler.conn, frame); err != nil {
		closeFrame, closeErr := handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, now)
		if closeErr != nil {
			_ = handler.conn.Close()
			closeFrame = connectorTCPDispatchErrorFrame(frame, err.Error())
		} else {
			closeFrame.Error = err.Error()
		}
		return []tunnel.Frame{closeFrame}, nil
	}
	return nil, nil
}

func (handler *connectorTCPConnectionHandler) Close(direction, reason string, now time.Time) (tunnel.Frame, error) {
	if handler == nil || handler.conn == nil || handler.registry == nil {
		return tunnel.Frame{}, fmt.Errorf("tcp connection handler is required")
	}
	closeFrame, err := handler.registry.Close(handler.requestID, direction, reason, now)
	if err != nil {
		return tunnel.Frame{}, err
	}
	if err := handler.conn.Close(); err != nil {
		return closeFrame, err
	}
	return closeFrame, nil
}
