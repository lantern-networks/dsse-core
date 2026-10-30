package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/grantstore"
)

func readAuthWaitFrame(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	header := make([]byte, 9)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(header[:4]) != 1 || binary.BigEndian.Uint32(header[5:9]) > 1024 {
		t.Fatalf("unexpected frame header: %v", header)
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[5:9]))
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatal(err)
	}
	return header[4], payload
}

func TestAuthWaitReportsOnlyHeldFlowOutcome(t *testing.T) {
	const requestID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "resumed", false: "not_resumed"}[success], func(t *testing.T) {
			b, gate := ceremonyFixture(t)
			if success {
				_, err := b.grants.Mint(authTestBindGrant(t, gate, grantstore.Grant{GrantID: "live", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Scope: "app:22"}), time.Minute, time.Now())
				if err != nil {
					t.Fatal(err)
				}
			}
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			done := make(chan bool, 1)
			go edgeplane.NewSteerMux(server).Run(func(_ uint32, _ string, flow *edgeplane.MuxVirtualConn) {
				done <- waitForStepUpGrantChecked(context.Background(), gate, "tenant", "device", federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, Scope: "app:22", RequestID: requestID}, flow, 40*time.Millisecond, "https://portal.example/clientless/auth/start?request_id="+requestID, func() bool { return true })
			})
			if err := authTestFrame(client, 1, 0, []byte("app:22")); err != nil {
				t.Fatal(err)
			}
			if typ, _ := readAuthWaitFrame(t, client); typ != 3 {
				t.Fatalf("first frame=%d want STEPUP", typ)
			}
			if success {
				if got := <-done; !got {
					t.Fatal("held flow not released")
				}
				// An upstream dial still has to succeed before the caller may report resumed.
				_ = client.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
				var header [9]byte
				if _, err := io.ReadFull(client, header[:]); err == nil {
					t.Fatal("wait alone reported success before upstream dial")
				}
				return
			}
			typ, payload := readAuthWaitFrame(t, client)
			if typ != 5 {
				t.Fatalf("second frame=%d want AUTH_RESULT", typ)
			}
			var result struct {
				RequestID string `json:"request_id"`
				Result    string `json:"result"`
			}
			if err := json.Unmarshal(payload, &result); err != nil || result.RequestID != requestID || result.Result != "not_resumed" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if typ, _ := readAuthWaitFrame(t, client); typ != 2 {
				t.Fatalf("third frame=%d want CLOSE", typ)
			}
			if got := <-done; got != success {
				t.Fatalf("wait result=%v want=%v", got, success)
			}
		})
	}
}
