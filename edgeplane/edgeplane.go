// Package edgeplane holds the Edge data-plane hot path, extracted from cmd/edge
// (Phase 3 of docs/dev_advisory_2026-08-03_edge_main_split_plan.md, re-scoped in).
// The dependency direction is fixed: edgeplane never imports cmd/edge; cmd/edge is
// the composition root that constructs and wires these units. Keep this package the
// COMPOSITION of the dsse-core domain packages for the data plane — it must not
// become a second dumping ground.
package edgeplane

// Debugf is the package's debug-logging seam. The composition root (cmd/edge)
// installs its logger at startup; the default is a no-op so the package is usable
// (and testable) standalone.
var Debugf = func(format string, args ...any) {}

// Warnf is the warn-level counterpart of Debugf; same contract.
var Warnf = func(format string, args ...any) {}

// Infof / Errorf complete the leveled-logging seam.
var Infof = func(format string, args ...any) {}
var Errorf = func(format string, args ...any) {}
