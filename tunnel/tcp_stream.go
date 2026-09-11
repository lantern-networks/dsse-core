package tunnel

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
)

const DefaultTCPDataFrameChunkBytes = MaxTCPDataFramePayloadBytes
const DefaultTCPStreamChannelBufferFrames = 16

var defaultTCPFrameBufferPool = mustNewTCPFrameBufferPool(DefaultTCPDataFrameChunkBytes)

type TCPFrameBufferPool struct {
	chunkSize int
	pool      sync.Pool
}

type TCPStreamCopyPattern struct {
	BufferPoolEnabled         bool  `json:"buffer_pool_enabled"`
	FrameChunkBytes           int   `json:"frame_chunk_bytes"`
	StreamChannelBufferFrames int   `json:"stream_channel_buffer_frames"`
	MaxFramePayloadBytes      int   `json:"max_frame_payload_bytes"`
	MaxConcurrentConnections  int   `json:"max_concurrent_connections"`
	MaxByteCap                int64 `json:"max_byte_cap"`
	ZeroCopyEnabled           bool  `json:"zero_copy_enabled"`
	TuningPerformed           bool  `json:"tuning_performed"`
}

func NewTCPFrameBufferPool(chunkSize int) (*TCPFrameBufferPool, error) {
	if chunkSize <= 0 || chunkSize > MaxTCPDataFramePayloadBytes {
		return nil, fmt.Errorf("tcp frame buffer pool chunk size must be between 1 and %d", MaxTCPDataFramePayloadBytes)
	}
	pool := &TCPFrameBufferPool{chunkSize: chunkSize}
	pool.pool.New = func() any {
		return make([]byte, chunkSize)
	}
	return pool, nil
}

func mustNewTCPFrameBufferPool(chunkSize int) *TCPFrameBufferPool {
	pool, err := NewTCPFrameBufferPool(chunkSize)
	if err != nil {
		panic(err)
	}
	return pool
}

func DefaultTCPFrameBufferPool() *TCPFrameBufferPool {
	return defaultTCPFrameBufferPool
}

func DefaultTCPStreamCopyPattern() TCPStreamCopyPattern {
	return TCPStreamCopyPattern{
		BufferPoolEnabled:         true,
		FrameChunkBytes:           DefaultTCPDataFrameChunkBytes,
		StreamChannelBufferFrames: DefaultTCPStreamChannelBufferFrames,
		MaxFramePayloadBytes:      MaxTCPDataFramePayloadBytes,
		MaxConcurrentConnections:  MaxTCPConcurrentConnections,
		MaxByteCap:                MaxTCPByteCap,
		ZeroCopyEnabled:           false,
		TuningPerformed:           false,
	}
}

func (pattern TCPStreamCopyPattern) Validate() error {
	if !pattern.BufferPoolEnabled {
		return fmt.Errorf("buffer pool must be enabled")
	}
	if pattern.FrameChunkBytes <= 0 || pattern.FrameChunkBytes > MaxTCPDataFramePayloadBytes {
		return fmt.Errorf("frame chunk bytes must be between 1 and %d", MaxTCPDataFramePayloadBytes)
	}
	if pattern.StreamChannelBufferFrames != DefaultTCPStreamChannelBufferFrames {
		return fmt.Errorf("stream channel buffer frames must remain %d until measured tuning", DefaultTCPStreamChannelBufferFrames)
	}
	if pattern.MaxFramePayloadBytes != MaxTCPDataFramePayloadBytes {
		return fmt.Errorf("max frame payload bytes must remain %d", MaxTCPDataFramePayloadBytes)
	}
	if pattern.MaxConcurrentConnections != MaxTCPConcurrentConnections {
		return fmt.Errorf("max concurrent connections must remain %d", MaxTCPConcurrentConnections)
	}
	if pattern.MaxByteCap != MaxTCPByteCap {
		return fmt.Errorf("max byte cap must remain %d", MaxTCPByteCap)
	}
	if pattern.ZeroCopyEnabled || pattern.TuningPerformed {
		return fmt.Errorf("zero-copy and tuning are deferred until measured boundaries")
	}
	return nil
}

func (p *TCPFrameBufferPool) ChunkSize() int {
	if p == nil {
		return 0
	}
	return p.chunkSize
}

func (p *TCPFrameBufferPool) ReadTCPDataFrame(reader io.Reader, requestID, direction string) (Frame, int, error) {
	if p == nil {
		return Frame{}, 0, fmt.Errorf("tcp frame buffer pool is required")
	}
	if reader == nil {
		return Frame{}, 0, fmt.Errorf("tcp reader is required")
	}
	buffer, ok := p.pool.Get().([]byte)
	if !ok || cap(buffer) < p.chunkSize {
		buffer = make([]byte, p.chunkSize)
	}
	buffer = buffer[:p.chunkSize]
	defer p.pool.Put(buffer)

	n, err := reader.Read(buffer)
	if n > 0 {
		frame, frameErr := NewTCPDataFrame(requestID, direction, buffer[:n])
		if frameErr != nil {
			return Frame{}, n, frameErr
		}
		return frame, n, nil
	}
	if err != nil {
		return Frame{}, 0, err
	}
	return Frame{}, 0, io.ErrNoProgress
}

func NewTCPDataFrame(requestID, direction string, payload []byte) (Frame, error) {
	frame := Frame{
		Type:      FrameTCPData,
		RequestID: requestID,
		Direction: direction,
		Data:      base64.StdEncoding.EncodeToString(payload),
	}
	if err := ValidateTCPDataFrame(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func ReadTCPDataFrame(reader io.Reader, requestID, direction string, maxChunkBytes int) (Frame, int, error) {
	if reader == nil {
		return Frame{}, 0, fmt.Errorf("tcp reader is required")
	}
	if maxChunkBytes <= 0 || maxChunkBytes > MaxTCPDataFramePayloadBytes {
		return Frame{}, 0, fmt.Errorf("tcp chunk size must be between 1 and %d", MaxTCPDataFramePayloadBytes)
	}
	chunk := make([]byte, maxChunkBytes)
	n, err := reader.Read(chunk)
	if n > 0 {
		frame, frameErr := NewTCPDataFrame(requestID, direction, chunk[:n])
		if frameErr != nil {
			return Frame{}, n, frameErr
		}
		return frame, n, nil
	}
	if err != nil {
		return Frame{}, 0, err
	}
	return Frame{}, 0, io.ErrNoProgress
}

func TCPDataFramePayload(frame Frame) ([]byte, error) {
	if err := ValidateTCPDataFrame(frame); err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(frame.Data)
	if err != nil {
		return nil, fmt.Errorf("tcp_data payload must be base64: %w", err)
	}
	return payload, nil
}

func WriteTCPDataFrame(writer io.Writer, frame Frame) (int, error) {
	if writer == nil {
		return 0, fmt.Errorf("tcp writer is required")
	}
	payload, err := TCPDataFramePayload(frame)
	if err != nil {
		return 0, err
	}
	written, err := io.Copy(writer, bytes.NewReader(payload))
	return int(written), err
}
