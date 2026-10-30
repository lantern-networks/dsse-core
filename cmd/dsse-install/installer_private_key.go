package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func checkPrivateInstallerKeyParent(path string) error {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("private-key directory must be a regular directory without group or world write access")
	}
	return nil
}

func checkPrivateInstallerKey(path string) error {
	if err := checkPrivateInstallerKeyParent(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("private key must be a regular file with mode 0600")
	}
	return nil
}

func publishPrivateInstallerKey(path string, body []byte) error {
	if err := checkPrivateInstallerKeyParent(path); err != nil {
		return err
	}
	return publishInstallerFile(path, body, 0600)
}
