package main

import (
	"os"
	"path/filepath"
)

// dnsResidueFileName must match resolverBackupPath() in steer/dns_resolver_windows.go.
const dnsResidueFileName = "dsse_dns_resolver_backup.json"

// dnsTakeoverResidueWithStat keeps the three-state filesystem decision testable off Windows.
func dnsTakeoverResidueWithStat(dirs []string, stat func(string) (os.FileInfo, error),
	report func(string, error)) (bool, bool) {
	if len(dirs) == 0 {
		return false, false
	}
	unknown := false
	for _, dir := range dirs {
		path := filepath.Join(dir, dnsResidueFileName)
		switch _, serr := stat(path); {
		case serr == nil:
			return true, true
		case os.IsNotExist(serr):
			// This candidate is absent; other candidates still need readable answers.
		default:
			unknown = true
			if report != nil {
				report(path, serr)
			}
		}
	}
	return false, !unknown
}
