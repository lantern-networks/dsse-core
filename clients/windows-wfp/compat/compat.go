// Package compat is the install-time compatibility gate. Before an install proceeds, the bootstrapper detects
// the machine's real facts (CPU arch, S Mode, Secure Boot, HVCI/memory-integrity, Windows build) and this pure
// evaluator decides: proceed, or stop with a specific human reason. Kernel-driver products live or die on this
// gate — an x86-only machine, S Mode, or (for a test-signed build) Secure Boot ON each mean "the driver will not
// load", and a silent failure there is the worst support outcome.
//
// The evaluation is pure + platform-neutral so it is table-tested here; the actual registry/API probing is
// detect_windows.go behind a build tag.
package compat

import (
	"fmt"
	"sort"
	"strings"
)

// Arch is the machine's NATIVE processor architecture (not the running binary's — a x64 binary on an ARM64
// machine still reports arm64, because the kernel driver must be the native arch; drivers cannot be emulated).
type Arch string

const (
	ArchAMD64   Arch = "amd64"
	ArchARM64   Arch = "arm64"
	ArchX86     Arch = "x86"
	ArchUnknown Arch = "unknown"
)

// MinSupportedBuild is the Windows 11 RTM build (21H2 = 22000). Below it we warn (design is Win11-first; whether
// Windows 10 is in scope is a separate decision). It is a warning, not a block, so a Win10 pilot can proceed.
const MinSupportedBuild = 22000

// Facts are the detected machine properties the gate reasons over. Zero values mean "not detected / absent",
// which is the safe assumption for the boolean signals (treated as off).
type Facts struct {
	Arch           Arch
	SMode          bool // Windows 11 in S Mode — Win32/driver installs are categorically blocked
	SecureBoot     bool // UEFI Secure Boot enabled
	HVCI           bool // memory integrity / HypervisorEnforcedCodeIntegrity enabled
	WindowsBuild   int  // CurrentBuildNumber (0 = unknown)
	DisplayVersion string
}

// Result is the gate decision. OK is false iff there is at least one Block. Blocks are categorical ("cannot
// install"); Warnings are proceed-with-note. Both are sorted + de-duplicated for a stable, testable output.
type Result struct {
	OK       bool
	Blocks   []string
	Warnings []string
	Facts    Facts
}

// Evaluate decides whether an install may proceed on the detected machine. attestationSigned reports whether
// the driver being installed carries a Microsoft attestation signature (production) vs a self-signed test
// signature (dev): a test-signed driver will NOT load while Secure Boot or HVCI is ON, so on this build those
// become hard blocks — which is exactly the configuration a test-signed build hits on a stock Secure Boot machine.
func Evaluate(f Facts, attestationSigned bool) Result {
	r := Result{Facts: f}
	block := func(s string) { r.Blocks = append(r.Blocks, s) }
	warn := func(s string) { r.Warnings = append(r.Warnings, s) }

	// C5 — S Mode: Win32 apps and drivers cannot be installed at all.
	if f.SMode {
		block("Windows 11 in S Mode: Win32 アプリ/ドライバを導入できません。S Mode の解除が必要です。")
	}

	// C1 — architecture: the kernel driver must be the machine's native arch (drivers cannot be emulated).
	switch f.Arch {
	case ArchAMD64, ArchARM64:
		// supported — the installer selects the matching x64/ARM64 artifacts.
	case ArchX86:
		block("32bit(x86) Windows は非対応です(64bit カーネルドライバのみ)。")
	default:
		block(fmt.Sprintf("CPU アーキテクチャを判定できません(%q)。x64 または ARM64 が必要です。", string(f.Arch)))
	}

	// C2/C3 — Secure Boot / HVCI vs the driver's signature.
	if !attestationSigned {
		// Test-signed (dev) driver: Secure Boot and HVCI each prevent it from loading.
		if f.SecureBoot {
			block("テスト署名ドライバは Secure Boot 有効ではロードされません(本番の attestation 署名、または Secure Boot OFF+testsigning が必要)。")
		}
		if f.HVCI {
			block("テスト署名ドライバはメモリ整合性(HVCI)有効ではロードされません。")
		}
	} else {
		// Attestation-signed (production) driver: Secure Boot ON is fine; HVCI ON is fine IF the driver is
		// HVCI-compliant — surface a note so that compliance is actually verified (design C3).
		if f.HVCI {
			warn("メモリ整合性(HVCI)が有効です。ドライバが HVCI 準拠であることを確認してください(§C3)。")
		}
	}

	// Windows build floor — warn below Win11 RTM (design is Win11-first).
	if f.WindowsBuild > 0 && f.WindowsBuild < MinSupportedBuild {
		v := f.DisplayVersion
		if v == "" {
			v = fmt.Sprintf("build %d", f.WindowsBuild)
		}
		warn(fmt.Sprintf("Windows 11 未満(%s)です。サポート対象は Windows 11(build %d 以上)です。", v, MinSupportedBuild))
	}

	r.Blocks = dedupeSorted(r.Blocks)
	r.Warnings = dedupeSorted(r.Warnings)
	r.OK = len(r.Blocks) == 0
	return r
}

// Summary renders a one-line human summary (for the installer log / bootstrapper UI).
func (r Result) Summary() string {
	if r.OK {
		if len(r.Warnings) == 0 {
			return "compat gate: OK"
		}
		return fmt.Sprintf("compat gate: OK (%d warning(s))", len(r.Warnings))
	}
	return fmt.Sprintf("compat gate: BLOCKED — %s", strings.Join(r.Blocks, " / "))
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
