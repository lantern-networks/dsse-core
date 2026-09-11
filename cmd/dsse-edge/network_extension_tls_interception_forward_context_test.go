package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// #28: the interception egress must NOT be canceled when the client half-closes its send side. Go's http.Server
// cancels the request context the instant the client's send reaches EOF — which a client does the moment it
// finishes sending and starts waiting for the reply (the ChatGPT desktop app). If the forward request inherited
// that cancellation, the egress round-trip fetching the streamed reply would be canceled and the Edge would
// send headers and nothing else. edgeplane.BuildNetworkExtensionLabTLSForwardRequest detaches the cancellation while
// keeping the request's values.
func TestForwardRequestContextSurvivesClientCancellation(t *testing.T) {
	clientCtx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(clientCtx, http.MethodPost, "https://chatgpt.com/backend-api/conversation", nil)
	if err != nil {
		t.Fatal(err)
	}
	route := edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "chatgpt.com", Port: 443, DeviceIdentity: "win-dev-1", OSUser: "u", SourceApp: "ChatGPT.exe"}

	forwardReq, err := edgeplane.BuildNetworkExtensionLabTLSForwardRequest(req, route)
	if err != nil {
		t.Fatalf("build forward request: %v", err)
	}

	// The client half-closes → Go cancels the client request context.
	cancel()

	// The egress (forward) context must NOT be canceled by that — otherwise the streamed reply is aborted (#28).
	select {
	case <-forwardReq.Context().Done():
		t.Fatal("forward (egress) context was canceled when the client cancelled — the reply stream would abort (#28)")
	case <-time.After(50 * time.Millisecond):
	}

	// The request's VALUES must still be carried (the egress metadata rides the context).
	if !edgeplane.SWGNERuntimeUsedFromContext(forwardReq.Context()) {
		t.Fatal("egress runtime marker lost from the forward context")
	}
	if v := edgeplane.TransportDeviceFromContext(forwardReq.Context()); v != "win-dev-1" {
		t.Fatalf("device identity lost from the forward context: %q", v)
	}
	if v := edgeplane.SourceAppFromContext(forwardReq.Context()); v != "ChatGPT.exe" {
		t.Fatalf("source app lost from the forward context: %q", v)
	}
}
