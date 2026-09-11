//go:build windows

package main

// reportPinAgreement reads both records off this machine and compares them. Best effort by construction: a
// service that cannot be opened, or a file that cannot be read, is reported as an absence, because that is
// what it looks like from where the agent stands too.

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/svc/mgr"
)

func reportPinAgreement(dataDir, service string) pinAgreement {
	recorded := ""
	if raw, err := os.ReadFile(filepath.Join(dataDir, signingKeyFileName)); err == nil {
		recorded = strings.TrimSpace(string(raw))
	}
	return comparePins(recorded, serviceArgsOf(service))
}

func serviceArgsOf(service string) []string {
	m, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer m.Disconnect()
	s, err := m.OpenService(service)
	if err != nil {
		return nil
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return nil
	}
	_, args := splitServiceCommand(cfg.BinaryPathName)
	return args
}
