//go:build !windows

package dlp

import "os"

// Unlink before storing any body bytes. Both ordinary Close and abrupt process
// death then reclaim the file, with no orphan ciphertext outside accounting.
// Filesystems that do not support this fail closed; there is no named fallback.
func openEphemeralSpill(dir, path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = os.Remove(path); err == nil {
		err = os.Remove(dir)
	}
	if err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		_ = os.Remove(dir)
		return nil, err
	}
	return f, nil
}

func retireEphemeralSpill(_ string) error { return nil }
