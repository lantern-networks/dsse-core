package objectstore

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type LocalStore struct {
	dir string
	mu  sync.Mutex
}

func NewLocalStore(dir string) (*LocalStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create object store dir: %w", err)
	}
	return &LocalStore{dir: dir}, nil
}

func (s *LocalStore) WriteGzipJSONL(filename string, values []map[string]any) (string, error) {
	index := 0
	return s.WriteGzipJSONLStream(filename, func() (map[string]any, bool, error) {
		if index >= len(values) {
			return nil, false, nil
		}
		value := values[index]
		index++
		return value, true, nil
	})
}

func (s *LocalStore) WriteGzipJSONLStream(filename string, next func() (map[string]any, bool, error)) (string, error) {
	return s.WriteGzipJSONLStreamWithComment(filename, "", next)
}

func (s *LocalStore) WriteGzipJSONLStreamWithComment(filename, comment string, next func() (map[string]any, bool, error)) (string, error) {
	if s == nil {
		return "", fmt.Errorf("object store is not configured")
	}
	if next == nil {
		return "", fmt.Errorf("object store stream source is required")
	}
	clean, err := safeRelativePath(filename)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, clean)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create object export dir: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create object export: %w", err)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()

	hash := sha256.New()
	gzipWriter := gzip.NewWriter(io.MultiWriter(file, hash))
	gzipWriter.Comment = comment
	encoder := json.NewEncoder(gzipWriter)
	for {
		value, ok, err := next()
		if err != nil {
			gzipWriter.Close()
			return "", fmt.Errorf("read object export row: %w", err)
		}
		if !ok {
			break
		}
		if err := encoder.Encode(value); err != nil {
			gzipWriter.Close()
			return "", fmt.Errorf("encode object export row: %w", err)
		}
	}
	if err := gzipWriter.Close(); err != nil {
		return "", fmt.Errorf("close object export gzip: %w", err)
	}
	committed = true

	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *LocalStore) ReadGeneratedFile(filename string) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("object store is not configured")
	}
	clean, err := safeRelativePath(filename)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(filepath.Join(s.dir, clean))
	if err != nil {
		return nil, fmt.Errorf("read generated object: %w", err)
	}
	return data, nil
}

func (s *LocalStore) ListGeneratedFiles(prefix, suffix string, limit int) ([]string, error) {
	if s == nil {
		return nil, fmt.Errorf("object store is not configured")
	}
	cleanPrefix, err := safeRelativePath(strings.TrimSuffix(prefix, "/"))
	if err != nil {
		return nil, err
	}
	if limit < 1 {
		return nil, fmt.Errorf("generated file list limit must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	root := filepath.Join(s.dir, cleanPrefix)
	files := make([]string, 0)
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return files, nil
		}
		return nil, fmt.Errorf("stat generated object prefix: %w", err)
	}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if suffix != "" && !strings.HasSuffix(rel, suffix) {
			return nil
		}
		files = append(files, rel)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("list generated objects: %w", err)
	}
	sort.Strings(files)
	if len(files) > limit {
		files = files[:limit]
	}
	return files, nil
}

func safeRelativePath(filename string) (string, error) {
	clean := filepath.Clean(filename)
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("generated filename is outside object store")
	}
	return clean, nil
}
