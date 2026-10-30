package edgeplane

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestBufferedInterceptionPipeWriteDeadline(t *testing.T) {
	writer, reader := NewBufferedInterceptionPipe(1)
	defer writer.Close()
	defer reader.Close()
	if _, err := writer.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := writer.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := writer.Write([]byte("b")); result <- err }()
	select {
	case err := <-result:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("write deadline result: %v", err)
		}
	case <-time.After(time.Second):
		_ = writer.Close()
		t.Fatal("write ignored deadline while buffer was full")
	}
	if err := writer.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := reader.Read(buf); err != nil || string(buf) != "a" {
		t.Fatalf("first read %q: %v", buf, err)
	}
	if _, err := writer.Write([]byte("b")); err != nil {
		t.Fatalf("cleared deadline blocked next write: %v", err)
	}
}

func TestBufferedInterceptionPipeSetDeadlineBoundsReadsAndWrites(t *testing.T) {
	writer, reader := NewBufferedInterceptionPipe(1)
	defer writer.Close()
	defer reader.Close()
	if _, err := writer.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := writer.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	writeResult := make(chan error, 1)
	go func() { _, err := writer.Write([]byte("b")); writeResult <- err }()
	select {
	case err := <-writeResult:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("write deadline result: %v", err)
		}
	case <-time.After(time.Second):
		_ = writer.Close()
		t.Fatal("SetDeadline did not bound Write")
	}
	if _, err := writer.Read(make([]byte, 1)); err == nil {
		t.Fatal("SetDeadline did not bound Read")
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("read deadline result: %v", err)
		}
	}
}
