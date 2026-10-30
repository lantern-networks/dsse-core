package tunnel

import "testing"

func TestOldStreamCleanupCannotCloseReplacement(t *testing.T) {
	session := &Session{streams: make(map[string]chan Frame)}
	_, cleanupOld, err := session.RegisterTCPStream("reused")
	if err != nil {
		t.Fatal(err)
	}
	cleanupOld()
	replacement, cleanupNew, err := session.RegisterTCPStream("reused")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupNew()
	// Cleanup is idempotent for its own stream, including after the ID is
	// re-registered. It must not act on a different stream with the same name.
	cleanupOld()
	session.deliverTCPStream(Frame{Type: FrameTCPData, RequestID: "reused", Data: "replacement"})
	select {
	case frame, ok := <-replacement:
		if !ok || frame.Data != "replacement" {
			t.Fatal("old cleanup closed or changed the replacement stream")
		}
	default:
		t.Fatal("replacement stream no longer receives its frames")
	}
}
