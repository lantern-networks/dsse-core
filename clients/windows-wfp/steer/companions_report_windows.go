//go:build windows

package main

import (
	"log"
	"os"
	"path/filepath"
)

// reportCompanions logs, once at startup, which declared companion executables are actually installed beside
// this binary. The step-up window was implemented and shipped nowhere for weeks precisely because its absence
// was only observable at the moment someone needed it, and even then it looked like a working ceremony that
// happened to use the browser. Saying it at startup turns "nobody noticed" into one line in the log.
//
// Best-effort and never fatal: a missing companion degrades a feature, it does not stop steering.
func reportCompanions() {
	if len(runtimeCompanions) == 0 {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		log.Printf("companions: cannot resolve own path (%v) — skipping the presence check", err)
		return
	}
	dir := filepath.Dir(exe)
	for _, c := range runtimeCompanions {
		if _, serr := os.Stat(filepath.Join(dir, c.Exe)); serr == nil {
			log.Printf("companion %s present — %s", c.Exe, c.Purpose)
			continue
		}
		// WARNING, not info: this is a feature the operator believes they installed.
		log.Printf("WARNING: companion %s is NOT installed beside the agent — %s. Consequence: %s",
			c.Exe, c.Purpose, c.IfMissing)
	}
}
