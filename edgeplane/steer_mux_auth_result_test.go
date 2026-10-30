package edgeplane

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

func TestAuthResultFrameIsBoundToHeldFlow(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go NewSteerMux(server).Run(func(_ uint32, _ string, flow *MuxVirtualConn) {
		done <- flow.SendAuthResult("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "resumed")
	})
	open := make([]byte, muxHeaderLen+len("app:22"))
	binary.BigEndian.PutUint32(open[:4], 7)
	open[4] = muxFrameOpen
	binary.BigEndian.PutUint32(open[5:9], uint32(len("app:22")))
	copy(open[9:], "app:22")
	if _, err := client.Write(open); err != nil {
		t.Fatal(err)
	}
	h := make([]byte, muxHeaderLen)
	if _, err := io.ReadFull(client, h); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(h[:4]) != 7 || h[4] != muxFrameAuthResult || binary.BigEndian.Uint32(h[5:9]) > 128 {
		t.Fatalf("unexpected frame header: %v", h)
	}
	payload := make([]byte, binary.BigEndian.Uint32(h[5:9]))
	if _, err := io.ReadFull(client, payload); err != nil {
		t.Fatal(err)
	}
	var result struct {
		RequestID string `json:"request_id"`
		Result    string `json:"result"`
	}
	if err := json.Unmarshal(payload, &result); err != nil || result.RequestID != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" || result.Result != "resumed" {
		t.Fatalf("unexpected result: %+v %v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAuthQueryUsesControlFlowAndBoundedReply(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	const query = `{"request_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","os_principal":"owner","os_session":"login"}`
	go NewSteerMux(server).Run(func(uint32, string, *MuxVirtualConn) {
		t.Error("query must not open an application flow")
	}, func(payload []byte) []byte {
		if string(payload) != query {
			t.Errorf("query=%q", payload)
			return nil
		}
		return []byte(`{"request_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","result":"resumed"}`)
	})
	frame := make([]byte, muxHeaderLen+len(query))
	frame[4] = muxFrameAuthQuery
	binary.BigEndian.PutUint32(frame[5:9], uint32(len(query)))
	copy(frame[9:], query)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, muxHeaderLen)
	if _, err := io.ReadFull(client, header); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(header[:4]) != 0 || header[4] != muxFrameAuthResult {
		t.Fatalf("unexpected control result header: %v", header)
	}
	answer := make([]byte, binary.BigEndian.Uint32(header[5:9]))
	if _, err := io.ReadFull(client, answer); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(answer) {
		t.Fatal("invalid result")
	}
}
