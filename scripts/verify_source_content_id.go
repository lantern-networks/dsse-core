// Verify that a history-free OSS export is exactly the tree named by its
// source-<sha256> content identity. Run before a package build creates files.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type row struct {
	Mode   string `json:"mode"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func validateExpected(expected string) error {
	if !strings.HasPrefix(expected, "source-") || len(expected) != 71 {
		return errors.New("expected a source-<64 lowercase hex> content identity")
	}
	for _, c := range expected[len("source-"):] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return errors.New("expected a source-<64 lowercase hex> content identity")
		}
	}
	return nil
}

func contentID(rows []row) (string, error) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(rows); err != nil {
		return "", err
	}
	actual := sha256.Sum256(bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}))
	return "source-" + hex.EncodeToString(actual[:]), nil
}

func verify(root, expected string) error {
	if err := validateExpected(expected); err != nil {
		return err
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		return errors.New("content-ID builds require a history-free OSS export")
	} else if !os.IsNotExist(err) {
		return err
	}
	rows := make([]row, 0, 4096)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("export contains a non-regular file")
		}
		mode := ""
		switch info.Mode().Perm() {
		case 0o644:
			mode = "100644"
		case 0o755:
			mode = "100755"
		default:
			return errors.New("export contains an unexpected file mode")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		for _, c := range name {
			if c < 0x20 || c > 0x7e {
				return errors.New("export contains a non-ASCII or control-character path")
			}
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		rows = append(rows, row{Mode: mode, Path: name, SHA256: hex.EncodeToString(h.Sum(nil))})
		return nil
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errors.New("export has no files")
	}
	actual, err := contentID(rows)
	if err != nil {
		return err
	}
	if expected != actual {
		return errors.New("OSS export content does not match the supplied source identity")
	}
	return nil
}

// An authenticated source tar carries the issuer's Unix file modes, which
// Windows cannot recover from os.Stat after extraction. Both the tar's exact
// SHA-256 and the source content ID must be pinned by a separate handoff.
func verifyArchive(root, expected, archivePath, expectedArchiveSHA256 string) error {
	if err := validateExpected(expected); err != nil {
		return err
	}
	if len(expectedArchiveSHA256) != 64 {
		return errors.New("expected a 64-character lowercase archive SHA-256")
	}
	for _, c := range expectedArchiveSHA256 {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return errors.New("expected a 64-character lowercase archive SHA-256")
		}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("source root must be an ordinary directory")
	}
	archivePath, err = filepath.Abs(archivePath)
	if err != nil {
		return err
	}
	if rel, err := filepath.Rel(root, archivePath); err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("authenticated source archive must be outside the source root")
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, archive)
	closeErr := archive.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if hex.EncodeToString(h.Sum(nil)) != expectedArchiveSHA256 {
		return errors.New("source archive does not match its authenticated SHA-256")
	}
	archive, err = os.Open(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return err
	}
	defer gz.Close()
	t := tar.NewReader(gz)
	rows := make([]row, 0, 4096)
	listed := make(map[string]string)
	caseFolded := make(map[string]string)
	for {
		header, err := t.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return errors.New("source archive contains a non-regular member")
		}
		name := header.Name
		if name == "" || name != path.Clean(name) || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\:") || name == ".git" || strings.HasPrefix(name, ".git/") {
			return errors.New("source archive contains an unsafe path or Git history")
		}
		for _, component := range strings.Split(name, "/") {
			if component == ".." || component == "." || component == "" {
				return errors.New("source archive contains an unsafe path")
			}
		}
		for _, c := range name {
			if c < 0x20 || c > 0x7e {
				return errors.New("source archive contains a non-ASCII or control-character path")
			}
		}
		if _, exists := listed[name]; exists {
			return errors.New("source archive contains a duplicate path")
		}
		lower := strings.ToLower(name)
		if prior, exists := caseFolded[lower]; exists && prior != name {
			return errors.New("source archive contains case-insensitively colliding paths")
		}
		caseFolded[lower] = name
		mode := ""
		switch header.Mode {
		case 0o644:
			mode = "100644"
		case 0o755:
			mode = "100755"
		default:
			return errors.New("source archive contains an unexpected Unix file mode")
		}
		if header.Size < 0 {
			return errors.New("source archive contains a negative file size")
		}
		fileHash := sha256.New()
		if _, err := io.Copy(fileHash, io.LimitReader(t, header.Size)); err != nil {
			return err
		}
		sha := hex.EncodeToString(fileHash.Sum(nil))
		listed[name] = sha
		rows = append(rows, row{Mode: mode, Path: name, SHA256: sha})
	}
	if len(rows) == 0 {
		return errors.New("source archive contains no files")
	}
	actual, err := contentID(rows)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("source archive modes, paths or bytes do not match the supplied source identity")
	}
	seen := make(map[string]bool, len(rows))
	err = filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == root {
			return nil
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if name == ".git" || strings.HasPrefix(name, ".git/") {
			return errors.New("source tree contains Git history")
		}
		info, err := os.Lstat(filePath)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("source tree contains a non-regular file")
		}
		expectedSHA, exists := listed[name]
		if !exists {
			return errors.New("source tree contains an unlisted file")
		}
		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		fileHash := sha256.New()
		_, copyErr := io.Copy(fileHash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(fileHash.Sum(nil)) != expectedSHA {
			return errors.New("source tree contains a changed file")
		}
		seen[name] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(listed) {
		return errors.New("source tree is missing archived files")
	}
	return nil
}

func main() {
	root := flag.String("root", "", "history-free OSS source tree")
	expected := flag.String("expected", "", "source-<64 lowercase hex> content identity")
	archive := flag.String("archive", "", "authenticated tar.gz with canonical Unix file modes")
	archiveSHA256 := flag.String("archive-sha256", "", "authenticated lowercase tar.gz SHA-256")
	flag.Parse()
	if *root == "" || *expected == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "verify_source_content_id: -root and -expected are required")
		os.Exit(2)
	}
	var err error
	if *archive == "" && *archiveSHA256 == "" {
		err = verify(*root, *expected)
	} else if *archive != "" && *archiveSHA256 != "" {
		err = verifyArchive(*root, *expected, *archive, *archiveSHA256)
	} else {
		err = errors.New("archive and archive-sha256 must be supplied together")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify_source_content_id:", err)
		os.Exit(1)
	}
	fmt.Println("verify_source_content_id: content identity verified")
}
