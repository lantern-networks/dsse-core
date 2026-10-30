package dlp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// encryptedSpill holds bytes that the guard has scanned but cannot release
// until an unfinished email's full value and allowlist identity are known.
// Each independently authenticated frame is at most chunkSize plaintext bytes.
// Neither the body nor its encryption key is written to a log or another file.
type encryptedSpill struct {
	dir, path string
	file      spillFile
	aead      cipher.AEAD
	key       [32]byte
	writeAt   int64
	readAt    int64
	end       int64 // logical, absolute body offset after the last appended byte
	readPos   int64 // logical offset of the next byte to release
	plain     []byte
	lease     *retentionLease
	charged   int64
	ownLease  bool
}

type spillFile interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
	Truncate(int64) error
	Stat() (os.FileInfo, error)
}

const spillHeaderSize = 8 + 4 + 12 // logical offset, plaintext length, random GCM nonce

// A compaction threshold controls file layout, not how much traffic may be
// inspected. Undecided bytes additionally obey the shared retention budget;
// consumed authenticated frames must not accumulate over a long connection.
const spillCompactThreshold = 2 * 1024 * 1024

func newEncryptedSpill(start int64) (_ *encryptedSpill, err error) {
	lease, err := processRetention.acquire()
	if err != nil {
		return nil, err
	}
	s, err := newEncryptedSpillWithLease(start, lease)
	if err != nil {
		lease.releaseWorking()
		return nil, err
	}
	s.ownLease = true
	return s, nil
}

func newEncryptedSpillWithLease(start int64, lease *retentionLease) (_ *encryptedSpill, err error) {
	if lease == nil {
		return nil, ErrRetentionLimit
	}
	dir, err := os.MkdirTemp("", "dsse-dlp-spill-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "body.enc")
	f, err := openEphemeralSpill(dir, path)
	if err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	s := &encryptedSpill{dir: dir, path: path, file: f, end: start, readPos: start, lease: lease}
	defer func() {
		if err != nil {
			_ = s.close()
		}
	}()
	if _, err = rand.Read(s.key[:]); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}
	s.aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *encryptedSpill) append(p []byte) error {
	for len(p) > 0 {
		n := len(p)
		if n > chunkSize {
			n = chunkSize
		}
		frameBytes := int64(spillHeaderSize + n + s.aead.Overhead())
		if err := s.lease.reserveDisk(frameBytes); err != nil {
			// Reclaim already consumed ciphertext before refusing; these limits
			// bound retained resources, never cumulative transfer volume.
			if s.readAt == 0 {
				return err
			}
			if err := s.compactConsumed(true); err != nil {
				return err
			}
			if err := s.lease.reserveDisk(frameBytes); err != nil {
				return err
			}
		}
		s.charged += frameBytes
		var header [spillHeaderSize]byte
		binary.BigEndian.PutUint64(header[:8], uint64(s.end))
		binary.BigEndian.PutUint32(header[8:12], uint32(n))
		if _, err := rand.Read(header[12:]); err != nil {
			return err
		}
		ciphertext := s.aead.Seal(nil, header[12:], p[:n], header[:])
		frame := make([]byte, 0, len(header)+len(ciphertext))
		frame = append(frame, header[:]...)
		frame = append(frame, ciphertext...)
		written, err := s.file.WriteAt(frame, s.writeAt)
		if err != nil {
			return err
		}
		if written != len(frame) {
			return io.ErrShortWrite
		}
		s.writeAt += int64(len(frame))
		s.end += int64(n)
		p = p[n:]
	}
	return nil
}

// readSafe authenticates a complete frame before returning even one byte of
// it. safeUntil may stop within a frame; its remainder stays private.
func (s *encryptedSpill) readSafe(p []byte, safeUntil int64) (int, error) {
	if safeUntil > s.end {
		safeUntil = s.end
	}
	if len(p) == 0 || s.readPos >= safeUntil {
		return 0, nil
	}
	if len(s.plain) == 0 {
		var header [spillHeaderSize]byte
		if n, err := s.file.ReadAt(header[:], s.readAt); err != nil || n != len(header) {
			return 0, errors.New("dlp spill: unreadable frame")
		}
		start := int64(binary.BigEndian.Uint64(header[:8]))
		length := binary.BigEndian.Uint32(header[8:12])
		if start != s.readPos || length == 0 || length > chunkSize || start+int64(length) > s.end {
			return 0, errors.New("dlp spill: invalid frame")
		}
		ciphertext := make([]byte, int(length)+s.aead.Overhead())
		if n, err := s.file.ReadAt(ciphertext, s.readAt+spillHeaderSize); err != nil || n != len(ciphertext) {
			return 0, errors.New("dlp spill: unreadable payload")
		}
		plain, err := s.aead.Open(nil, header[12:], ciphertext, header[:])
		if err != nil {
			return 0, errors.New("dlp spill: authentication failed")
		}
		s.plain = plain
		s.readAt += spillHeaderSize + int64(len(ciphertext))
	}
	n := len(p)
	if n > len(s.plain) {
		n = len(s.plain)
	}
	if remaining := safeUntil - s.readPos; int64(n) > remaining {
		n = int(remaining)
	}
	copy(p, s.plain[:n])
	for i := 0; i < n; i++ {
		s.plain[i] = 0
	}
	s.plain = s.plain[n:]
	s.readPos += int64(n)
	if len(s.plain) == 0 && s.readPos < s.end {
		if err := s.compactConsumed(false); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// compactConsumed moves only unread encrypted frames. It never decrypts them
// or creates a second plaintext copy. A failure invalidates the spill and
// callers abort forwarding rather than trusting a partly rewritten file.
func (s *encryptedSpill) compactConsumed(force bool) error {
	remaining := s.writeAt - s.readAt
	if !force && (s.readAt < spillCompactThreshold || s.readAt < remaining) {
		return nil
	}
	var buf [chunkSize]byte
	var copied int64
	for copied < remaining {
		n := int64(len(buf))
		if remaining-copied < n {
			n = remaining - copied
		}
		if read, err := s.file.ReadAt(buf[:int(n)], s.readAt+copied); err != nil || int64(read) != n {
			return errors.New("dlp spill: compaction read failed")
		}
		if written, err := s.file.WriteAt(buf[:int(n)], copied); err != nil || int64(written) != n {
			return errors.New("dlp spill: compaction write failed")
		}
		copied += n
	}
	if err := s.file.Truncate(remaining); err != nil {
		return err
	}
	released := s.writeAt - remaining
	s.lease.releaseDisk(released)
	s.charged -= released
	s.readAt = 0
	s.writeAt = remaining
	return nil
}

func (s *encryptedSpill) close() error {
	if s == nil {
		return nil
	}
	for i := range s.key {
		s.key[i] = 0
	}
	for i := range s.plain {
		s.plain[i] = 0
	}
	s.plain = nil
	var result error
	if s.file != nil {
		closeErr := s.file.Close()
		if closeErr == nil || errors.Is(closeErr, os.ErrClosed) {
			// The file was unlinked at creation (Unix) or has delete-on-close
			// semantics (Windows). Confirmed close reclaims its physical bytes.
			s.lease.releaseDisk(s.charged)
			s.charged = 0
		}
		result = errors.Join(result, closeErr)
		s.file = nil
	}
	result = errors.Join(result, retireEphemeralSpill(s.dir))
	if s.ownLease {
		s.lease.releaseWorking()
	}
	return result
}
