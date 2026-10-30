package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func readOperatorToken(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("read operator token file: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > 16384 {
		return "", fmt.Errorf("operator token must be a private regular file (mode 0600, at most 16 KiB), not a symlink")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("operator token file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || len(raw) > 16384 || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("operator token file must contain one nonempty token")
	}
	return token, nil
}
