package tunnel

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReadTCPDataFrameChunksReaderPayload(t *testing.T) {
	reader := strings.NewReader("abcdef")
	frame, n, err := ReadTCPDataFrame(reader, "req_tcp_copy_001", TCPDirectionUp, 3)
	if err != nil {
		t.Fatalf("ReadTCPDataFrame returned error: %v", err)
	}
	if n != 3 {
		t.Fatalf("n = %d, want 3", n)
	}
	if frame.Type != FrameTCPData || frame.RequestID != "req_tcp_copy_001" || frame.Direction != TCPDirectionUp {
		t.Fatalf("frame = %+v, want tcp_data req_tcp_copy_001 direction up", frame)
	}
	payload, err := TCPDataFramePayload(frame)
	if err != nil {
		t.Fatalf("TCPDataFramePayload returned error: %v", err)
	}
	if string(payload) != "abc" {
		t.Fatalf("payload = %q, want abc", string(payload))
	}
}

func TestReadTCPDataFrameRejectsInvalidChunkSize(t *testing.T) {
	tests := []int{0, MaxTCPDataFramePayloadBytes + 1}
	for _, chunkSize := range tests {
		_, _, err := ReadTCPDataFrame(strings.NewReader("abc"), "req_tcp_copy_001", TCPDirectionUp, chunkSize)
		if err == nil {
			t.Fatalf("ReadTCPDataFrame chunkSize=%d returned nil error", chunkSize)
		}
		if !strings.Contains(err.Error(), "tcp chunk size") {
			t.Fatalf("error = %q, want tcp chunk size", err.Error())
		}
	}
}

func TestTCPFrameBufferPoolReadsFramesWithConfiguredChunk(t *testing.T) {
	pool, err := NewTCPFrameBufferPool(3)
	if err != nil {
		t.Fatalf("NewTCPFrameBufferPool returned error: %v", err)
	}
	if pool.ChunkSize() != 3 {
		t.Fatalf("ChunkSize = %d, want 3", pool.ChunkSize())
	}
	reader := strings.NewReader("abcdef")
	first, n, err := pool.ReadTCPDataFrame(reader, "req_tcp_pool_001", TCPDirectionUp)
	if err != nil {
		t.Fatalf("first ReadTCPDataFrame returned error: %v", err)
	}
	if n != 3 {
		t.Fatalf("first n = %d, want 3", n)
	}
	firstPayload, err := TCPDataFramePayload(first)
	if err != nil {
		t.Fatalf("first TCPDataFramePayload returned error: %v", err)
	}
	if string(firstPayload) != "abc" {
		t.Fatalf("first payload = %q, want abc", string(firstPayload))
	}
	second, n, err := pool.ReadTCPDataFrame(reader, "req_tcp_pool_001", TCPDirectionUp)
	if err != nil {
		t.Fatalf("second ReadTCPDataFrame returned error: %v", err)
	}
	if n != 3 {
		t.Fatalf("second n = %d, want 3", n)
	}
	secondPayload, err := TCPDataFramePayload(second)
	if err != nil {
		t.Fatalf("second TCPDataFramePayload returned error: %v", err)
	}
	if string(secondPayload) != "def" {
		t.Fatalf("second payload = %q, want def", string(secondPayload))
	}
	_, _, err = pool.ReadTCPDataFrame(reader, "req_tcp_pool_001", TCPDirectionUp)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want EOF", err)
	}
}

func TestTCPFrameBufferPoolRejectsInvalidChunkSize(t *testing.T) {
	for _, chunkSize := range []int{0, MaxTCPDataFramePayloadBytes + 1} {
		if _, err := NewTCPFrameBufferPool(chunkSize); err == nil {
			t.Fatalf("NewTCPFrameBufferPool chunkSize=%d returned nil error", chunkSize)
		}
	}
}

func TestDefaultTCPStreamCopyPatternPreservesCapsWithoutTuning(t *testing.T) {
	pattern := DefaultTCPStreamCopyPattern()
	if err := pattern.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if !pattern.BufferPoolEnabled || pattern.FrameChunkBytes != DefaultTCPDataFrameChunkBytes {
		t.Fatalf("buffer pool pattern = %+v, want enabled default chunk", pattern)
	}
	if pattern.StreamChannelBufferFrames != DefaultTCPStreamChannelBufferFrames {
		t.Fatalf("stream channel buffer frames = %d, want %d", pattern.StreamChannelBufferFrames, DefaultTCPStreamChannelBufferFrames)
	}
	if pattern.ZeroCopyEnabled || pattern.TuningPerformed {
		t.Fatalf("pattern enabled deferred optimization: %+v", pattern)
	}

	pattern.TuningPerformed = true
	if err := pattern.Validate(); err == nil {
		t.Fatal("Validate returned nil error after tuning flag")
	}
}

func TestReadTCPDataFramePropagatesEOFAndNoProgress(t *testing.T) {
	_, _, err := ReadTCPDataFrame(strings.NewReader(""), "req_tcp_copy_001", TCPDirectionUp, DefaultTCPDataFrameChunkBytes)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want EOF", err)
	}

	_, _, err = ReadTCPDataFrame(zeroProgressReader{}, "req_tcp_copy_001", TCPDirectionUp, DefaultTCPDataFrameChunkBytes)
	if !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("err = %v, want ErrNoProgress", err)
	}
}

func TestWriteTCPDataFrameWritesDecodedPayload(t *testing.T) {
	frame, err := NewTCPDataFrame("req_tcp_copy_001", TCPDirectionDown, []byte("hello"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	var out bytes.Buffer
	n, err := WriteTCPDataFrame(&out, frame)
	if err != nil {
		t.Fatalf("WriteTCPDataFrame returned error: %v", err)
	}
	if n != 5 || out.String() != "hello" {
		t.Fatalf("written=%d payload=%q, want 5 hello", n, out.String())
	}
}

func TestWriteTCPDataFrameRejectsMalformedFrame(t *testing.T) {
	var out bytes.Buffer
	_, err := WriteTCPDataFrame(&out, Frame{
		Type:      FrameTCPData,
		RequestID: "req_tcp_copy_001",
		Direction: TCPDirectionLocal,
		Data:      base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if err == nil {
		t.Fatal("WriteTCPDataFrame returned nil error for malformed frame")
	}
	if !strings.Contains(err.Error(), "direction") {
		t.Fatalf("error = %q, want direction", err.Error())
	}
}

func TestTCPStreamCopyContractRecordsByteCapClose(t *testing.T) {
	registry := NewTCPConnectionRegistry()
	now := time.Date(2026, 5, 26, 9, 30, 0, 0, time.UTC)
	openFrame := validTCPOpenFrameWithRequestID("req_tcp_copy_cap_001")
	openFrame.ByteCap = 5
	if err := registry.Open(openFrame, now); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	reader := strings.NewReader("hello!")
	frame, n, err := ReadTCPDataFrame(reader, "req_tcp_copy_cap_001", TCPDirectionUp, 6)
	if err != nil {
		t.Fatalf("ReadTCPDataFrame returned error: %v", err)
	}
	if n != 6 {
		t.Fatalf("n = %d, want 6", n)
	}
	closeFrame, closed, err := registry.RecordData(frame, now.Add(time.Second))
	if err != nil {
		t.Fatalf("RecordData returned error: %v", err)
	}
	if !closed {
		t.Fatal("RecordData closed=false, want byte cap close")
	}
	if closeFrame.CloseReason != TCPCloseReasonByteCapExceeded || closeFrame.BytesUp != 6 {
		t.Fatalf("closeFrame = %+v, want byte cap close with bytes_up=6", closeFrame)
	}
}

type zeroProgressReader struct{}

func (zeroProgressReader) Read([]byte) (int, error) {
	return 0, nil
}
