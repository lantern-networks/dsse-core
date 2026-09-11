package main

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// mesh_ingress.go is the RECEIVER half of an inter-region mesh link (docs/multi_region_edge_architecture_design.md
//). The origin edge (region Y) decrypts a mesh-eligible flow, then relays it Y->X over a peer-edge tunnel by
// driving session.OpenTCP (the same machinery the Edge uses to drive a connector). This file is the X side: it
// reads the relayed frames and bridges each TCP open into X's LOCAL connector egress, so the connector that lives
// in X fronts the backend. Decryption already happened in Y; X only relays raw bytes, never re-decrypting — the
// residency-clean property of the mesh path holds by construction.
//
// It deliberately mirrors the connector agent's TCP serve loop (oss/cmd/dsse-connector/tcp_dialer.go) — the same
// open/data/close handling, byte-cap and close bookkeeping via tunnel.TCPConnectionRegistry — but the dialer is
// the edge's own connector-aware egress instead of a direct backend dial, and route authorization is delegated to
// X's local connector (the mesh link itself is mutually-authenticated edge-to-edge infrastructure).

// meshIngressDialer dials a destination through THIS edge's local egress. On the mesh receiver it is the edge's
// connector-aware dialer (localRegion = X, no peer edges) so the relayed flow resolves to X's local connector.
type meshIngressDialer interface {
	OpenTCPConnection(ctx context.Context, route edgeplane.NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error)
}

// meshIngressConnHandler bridges one relayed TCP stream to a dialed local-egress connection. Ported from the
// connector's connectorTCPConnectionHandler.
type meshIngressConnHandler struct {
	requestID string
	conn      io.ReadWriteCloser
	registry  *tunnel.TCPConnectionRegistry
	chunkSize int
}

// serveMeshIngressTunnel runs the receiver side of a peer-edge mesh link until the transport closes. tenantID is
// the flow tenant the relayed opens are dialed under (the lab/default tenant on the receiving edge).
func serveMeshIngressTunnel(ctx context.Context, transport tunnel.FrameTransport, dialer meshIngressDialer, tenantID string, probe reachabilityProber) error {
	if transport == nil {
		return fmt.Errorf("mesh ingress transport is required")
	}
	if dialer == nil {
		return fmt.Errorf("mesh ingress dialer is required")
	}
	registry := tunnel.NewTCPConnectionRegistry()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	probeSlots := make(chan struct{}, 8)

	var writeMu sync.Mutex
	write := func(frames []tunnel.Frame) error {
		if len(frames) == 0 {
			return nil
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		for _, frame := range frames {
			if err := transport.WriteJSON(frame); err != nil {
				return err
			}
		}
		return nil
	}

	var mu sync.Mutex
	handlers := map[string]*meshIngressConnHandler{}
	store := func(id string, h *meshIngressConnHandler) { mu.Lock(); handlers[id] = h; mu.Unlock() }
	load := func(id string) *meshIngressConnHandler { mu.Lock(); defer mu.Unlock(); return handlers[id] }
	drop := func(id string) { mu.Lock(); delete(handlers, id); mu.Unlock() }

	for {
		var frame tunnel.Frame
		if err := transport.ReadJSON(&frame); err != nil {
			return err
		}
		switch frame.Type {
		case tunnel.FrameProbeRequest:
			// A slow diagnostic must not stall TCP data carried by this same mesh link.
			select {
			case probeSlots <- struct{}{}:
				go func(frame tunnel.Frame) {
					defer func() { <-probeSlots }()
					result := meshProbeError(frame, "connector diagnostics are unavailable")
					if probe != nil {
						var err error
						result, err = probe(ctx, frame)
						if err != nil {
							result = meshProbeError(frame, err.Error())
						}
					}
					_ = write([]tunnel.Frame{result})
				}(frame)
			default:
				if err := write([]tunnel.Frame{meshProbeError(frame, "connector diagnostic capacity reached")}); err != nil {
					return err
				}
			}
		case tunnel.FrameTCPOpen:
			result, handler := meshIngressOpen(ctx, frame, dialer, registry, tenantID)
			if werr := write([]tunnel.Frame{result}); werr != nil {
				if handler != nil {
					_ = handler.conn.Close()
				}
				return werr
			}
			if handler != nil {
				store(frame.RequestID, handler)
				go meshIngressReadPump(handler, write, drop)
			}
		case tunnel.FrameTCPData:
			handler := load(frame.RequestID)
			if handler == nil {
				_ = write([]tunnel.Frame{meshIngressDataErrorClose(frame.RequestID)})
				continue
			}
			frames := handler.write(frame, time.Now())
			_ = write(frames)
			if containsMeshTCPClose(frames) {
				drop(frame.RequestID)
			}
		case tunnel.FrameTCPClose:
			handler := load(frame.RequestID)
			if handler == nil {
				continue
			}
			_, _ = handler.close(tunnel.TCPDirectionRemote, tunnel.TCPCloseReasonEOF, time.Now())
			drop(frame.RequestID)
		default:
			// HTTP frames are not used on the mesh path; ignore.
		}
	}
}

// meshIngressOpen dials the relayed destination through the edge's local egress and returns the open-result frame
// plus a handler (nil on failure). Ported from handleTunnelTCPOpenConnection, with the protected-app-map check
// dropped (the receiving edge's connector enforces its own route authorization downstream).
func meshIngressOpen(ctx context.Context, frame tunnel.Frame, dialer meshIngressDialer, registry *tunnel.TCPConnectionRegistry, tenantID string) (tunnel.Frame, *meshIngressConnHandler) {
	if err := tunnel.ValidateTCPOpenFrame(frame); err != nil {
		return meshIngressOpenResult(frame, err.Error()), nil
	}
	if err := registry.Open(frame, time.Now()); err != nil {
		return meshIngressOpenResult(frame, err.Error()), nil
	}
	// ★★★ THE ORGANIZATION COMES WITH THE FLOW, NOT FROM THIS NODE (2026-09-01, measured on a customer's
	// connector pair). This dialled every relayed open under the RECEIVING edge's own default organization —
	// its own doc comment said so — and a connector is matched WITHIN an organization, so a customer's
	// connector was never found at the far end: the flow was dialled directly and refused by the egress guard.
	// Stopping one connector of a pair then took the site down, because the surviving one was on the node the
	// relay lands on.
	//
	// The sending Edge now puts it on the open frame; both ends are this deployment's own Edges, proven to
	// each other by the management CA, so the value is as trustworthy on arrival as it was on departure. An
	// older peer sends none and the receiver keeps its own, which is the previous behaviour exactly.
	flowTenant := strings.TrimSpace(frame.TenantID)
	if flowTenant == "" {
		flowTenant = tenantID
	}
	route := edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: frame.Host, Port: frame.Port, SNI: frame.Host,
		TenantID: flowTenant, BuiltBy: "mesh-ingress"}
	conn, err := dialer.OpenTCPConnection(ctx, route)
	if err != nil {
		_, _ = registry.Close(frame.RequestID, tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, time.Now())
		return meshIngressOpenResult(frame, err.Error()), nil
	}
	if meshIngressConnMissing(conn) {
		_, _ = registry.Close(frame.RequestID, tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, time.Now())
		return meshIngressOpenResult(frame, "mesh ingress dial returned no connection"), nil
	}
	return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID},
		&meshIngressConnHandler{requestID: frame.RequestID, conn: conn, registry: registry, chunkSize: tunnel.DefaultTCPDataFrameChunkBytes}
}

func meshIngressOpenResult(frame tunnel.Frame, errMsg string) tunnel.Frame {
	return tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: errMsg}
}

func meshIngressDataErrorClose(requestID string) tunnel.Frame {
	return tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: requestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonError, Error: fmt.Sprintf("tcp connection %s is not open", requestID)}
}

// write relays an upstream (Y->backend) data frame into the dialed connection. Mirrors the connector handler.
func (h *meshIngressConnHandler) write(frame tunnel.Frame, now time.Time) []tunnel.Frame {
	if h == nil || h.conn == nil || h.registry == nil {
		return []tunnel.Frame{meshIngressDataErrorClose(frame.RequestID)}
	}
	closeFrame, closed, err := h.registry.RecordData(frame, now)
	if err != nil {
		cf, cerr := h.close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, now)
		if cerr != nil {
			cf = tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: frame.RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonError, Error: err.Error()}
		} else {
			cf.Error = err.Error()
		}
		return []tunnel.Frame{cf}
	}
	if closed {
		_ = h.conn.Close()
		return []tunnel.Frame{closeFrame}
	}
	if _, err := tunnel.WriteTCPDataFrame(h.conn, frame); err != nil {
		cf, cerr := h.close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, now)
		if cerr != nil {
			cf = tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: frame.RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonError, Error: err.Error()}
		} else {
			cf.Error = err.Error()
		}
		return []tunnel.Frame{cf}
	}
	return nil
}

func (h *meshIngressConnHandler) close(direction, reason string, now time.Time) (tunnel.Frame, error) {
	if h == nil || h.conn == nil || h.registry == nil {
		return tunnel.Frame{}, fmt.Errorf("mesh ingress handler is required")
	}
	closeFrame, err := h.registry.Close(h.requestID, direction, reason, now)
	if err != nil {
		_ = h.conn.Close()
		return tunnel.Frame{}, err
	}
	if cerr := h.conn.Close(); cerr != nil {
		return closeFrame, cerr
	}
	return closeFrame, nil
}

// meshIngressReadPump streams downstream (backend->Y) bytes from the dialed connection back over the mesh link as
// tcp_data frames, emitting a tcp_close on EOF/error. Mirrors connector pumpTCPReads.
func meshIngressReadPump(handler *meshIngressConnHandler, write func([]tunnel.Frame) error, drop func(string)) {
	for {
		frame, _, err := tunnel.ReadTCPDataFrame(handler.conn, handler.requestID, tunnel.TCPDirectionDown, handler.chunkSize)
		if err == io.EOF {
			closeFrame, cerr := handler.close(tunnel.TCPDirectionRemote, tunnel.TCPCloseReasonEOF, time.Now())
			if cerr == nil {
				_ = write([]tunnel.Frame{closeFrame})
			}
			drop(handler.requestID)
			return
		}
		if err != nil {
			closeFrame, cerr := handler.close(tunnel.TCPDirectionRemote, tunnel.TCPCloseReasonError, time.Now())
			if cerr == nil {
				closeFrame.Error = err.Error()
				_ = write([]tunnel.Frame{closeFrame})
			}
			drop(handler.requestID)
			return
		}
		recClose, closed, recErr := handler.registry.RecordData(frame, time.Now())
		if recErr != nil {
			_, _ = handler.close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, time.Now())
			drop(handler.requestID)
			return
		}
		if closed {
			_ = handler.conn.Close()
			_ = write([]tunnel.Frame{recClose})
			drop(handler.requestID)
			return
		}
		if werr := write([]tunnel.Frame{frame}); werr != nil {
			_, _ = handler.close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonError, time.Now())
			drop(handler.requestID)
			return
		}
	}
}

func containsMeshTCPClose(frames []tunnel.Frame) bool {
	for _, frame := range frames {
		if frame.Type == tunnel.FrameTCPClose {
			return true
		}
	}
	return false
}

func meshIngressConnMissing(conn io.ReadWriteCloser) bool {
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
