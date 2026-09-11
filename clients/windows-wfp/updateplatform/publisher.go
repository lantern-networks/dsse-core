package updateplatform

// publisher.go — the second question, asked on the device: not "which version may run" but "who built these
// bytes".
//
// ★ WHY THIS EXISTS (2026-08-14). macOS has asked it
// since 0.3.0; Windows never has. `VerifyStaged` proves the staged file is the bytes the manifest NAMED, and
// then `msiexec /i` runs it as SYSTEM. So whoever held the update-signing key held SYSTEM on every Windows box
// in the fleet: a manifest signer can name the digest of whatever it likes, and a digest check written by the
// attacker's own manifest passes trivially. That is not a bounded incident.
//
// It was demonstrated by accident rather than argued: unsigned MSIs (0.2.2, 0.2.3) were built and installed on
// win-dev-1 and nothing in the product objected. What caught it was a person reading
// Get-AuthenticodeSignature by hand.
//
// Two keys, in two custodies, which is the whole point:
//
//	update manifest key  — says WHICH VERSION may run  — lives in the CP's HSM token
//	Authenticode EV cert — says WHO BUILT THESE BYTES  — lives on the build side, in the operator's token
//
// An attacker who takes the control plane gets the first and not the second, so the worst they can choose is
// one of the versions this publisher really built.
//
// ★ ONE TOOL HERE, TWO ON macOS, AND THAT IS NOT AN OVERSIGHT. clients/macos/updateplatform/publisher.go
// records the measurement: on Windows, flipping one byte inside a signed MSI makes WinVerifyTrust return
// TRUST_E_BAD_DIGEST, so Authenticode answers BOTH "who built this" and "have the covered bytes changed".
// macOS needs spctl beside pkgutil because Gatekeeper's assessment is a quarantine-time story and nothing
// quarantines a file a daemon downloaded. Copying the two-tool shape across would be copying a fact about
// Gatekeeper into a platform that does not share it.
//
// The judgement lives in this file WITHOUT a build tag, and only the wintrust call is windows-only. What makes
// a gate like this wrong is the comparison, not the syscall — and a comparison that can only be exercised on
// the platform where a mistake installs something is one nobody exercises.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/authenticode"
)

// ErrPublisherUntrusted is what a caller can test for: the bytes on disk are not a package this device's
// publisher built. It is deliberately DISTINCT from a digest mismatch — those bytes were not the ones named,
// these are the ones named by a manifest that should not have named them.
var ErrPublisherUntrusted = errors.New("the package was not built by the publisher this device trusts")

// The accepted identifier forms. They are the steer-exclusion vocabulary
// (clients/windows-wfp/steer/authverify_windows.go) so that an operator who has learned how to name Lantern
// once does not learn it again — but this gate accepts a STRICT SUBSET of it, and the omissions are the point:
//
//   - `publisher:<name>` matches the display name as a SUBSTRING, and a certificate issued to a
//     similarly-named company satisfies it. That is a reasonable trade for deciding whether one app's traffic
//     is inspected. It is not a reasonable trade for deciding whether code runs as SYSTEM.
//   - `signed:<exe>` binds no signer at all — it means "signed by anyone", which is what Windows already
//     required of nothing and what an attacker with any code-signing certificate satisfies.
//
// A requirement naming either is refused when it is PARSED, so the refusal reaches whoever wrote it rather
// than becoming a gate that quietly matches more than they meant.
const (
	FormSubject    = "subject:"
	FormThumbprint = "thumbprint:"
)

// PublisherRequirement is what this device demands of an installer package before a privileged installer is
// pointed at it.
//
// It arrives as a service argument baked into the MSI (`--update-publisher`, beside `--update-pin` and
// `--plan-pin`), NOT as a file on disk. Deliberate: the requirement then travels inside an Authenticode-signed
// package, so changing what this device will accept requires an install that the gate itself governs, rather
// than a write by anything that already reached %ProgramData%.
type PublisherRequirement struct {
	// Kind is FormSubject or FormThumbprint, empty when this device has no usable requirement.
	Kind string
	// Want is the value to match, already normalised for comparison.
	Want string
	// Defect is why a NON-EMPTY requirement could not be used, empty otherwise. It is a separate field from
	// "unset" because the two are different operator situations and must not render the same: one is a choice
	// nobody has made yet, the other is a typo that is silently protecting nothing.
	Defect string
	// Raw is what was configured, for messages. Reported verbatim so a typo is visible as itself.
	Raw string
}

// Configured reports whether this device actually has a publisher to check against.
func (r PublisherRequirement) Configured() bool { return r.Kind != "" && r.Want != "" }

// RequirementMissingNote is what an operator needs to read when a device has no publisher requirement. It is a
// sentence rather than a flag because the previous version of this failure — "no update-signing key is pinned"
// — was correct, was logged every thirty minutes, and was never read by anyone, so the wording has to carry
// the consequence and not just the state.
const RequirementMissingNote = "★ this device names no --update-publisher, so an MSI is installed as SYSTEM on " +
	"the strength of the manifest signature ALONE — anyone able to sign a manifest can run arbitrary code here. " +
	"Build the MSI with -UpdatePublisher."

// ParsePublisherRequirement reads the configured identifier.
//
// ★★ A MALFORMED REQUIREMENT DOES NOT REFUSE, AND THIS IS THE ONE PLACE THIS FILE DIVERGES FROM macOS. There,
// an unreadable publisher configuration refuses every install, and that is right: the file is root-owned, on
// disk, and an operator can correct it in place. Here the requirement is baked into the MSI, so the only way to
// correct it is to install a package — the very act the refusal would block. A gate whose sole repair path is
// the thing it refuses is not a strict gate, it is a device that can never be updated again, and this product
// has already built that shape twice (the keyless updater, and WithdrawIf's self-deadlock).
//
// So a defect degrades to "install, and say so LOUDLY" — the same landing as unset, with a different sentence
// naming the typo. The population that can reach this state is bounded on the other side instead:
// build-msi.ps1 validates -UpdatePublisher at packaging time, the way it validates -UpdatePin, so only a
// hand-registered service can carry a broken one.
func ParsePublisherRequirement(identifier string) PublisherRequirement {
	raw := strings.TrimSpace(identifier)
	if raw == "" {
		return PublisherRequirement{}
	}
	req := PublisherRequirement{Raw: raw}
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, FormSubject):
		// NOT lowercased for storage, only for comparison: a Subject O= is a name, and echoing it back
		// mangled in an error message is how an operator concludes the value was mistyped when it was not.
		want := strings.TrimSpace(raw[len(FormSubject):])
		if want == "" {
			req.Defect = "it is `subject:` with nothing after it, so it names no organisation"
			return req
		}
		req.Kind, req.Want = FormSubject, want
		return req
	case strings.HasPrefix(lower, FormThumbprint):
		// Colons stripped, because every Windows UI that shows a thumbprint shows it colon-separated and
		// somebody will paste that.
		want := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw[len(FormThumbprint):]), ":", ""))
		want = strings.ReplaceAll(want, " ", "")
		switch {
		case want == "":
			req.Defect = "it is `thumbprint:` with nothing after it"
			return req
		case len(want) != 64 || !isHex(want):
			req.Defect = fmt.Sprintf("a leaf certificate SHA-256 is 64 hex characters and this is %d (%q). A "+
				"thumbprint that cannot match any certificate would refuse every package", len(want), want)
			return req
		}
		req.Kind, req.Want = FormThumbprint, want
		return req
	case strings.HasPrefix(lower, "publisher:"):
		req.Defect = "`publisher:` matches the signer's display name as a SUBSTRING, which a certificate issued " +
			"to a similarly-named company satisfies. That is not an identity to run code as SYSTEM on. Use " +
			"`subject:<Subject O=>` — the durable one — or `thumbprint:<leaf SHA-256>`"
		return req
	case strings.HasPrefix(lower, "signed:"):
		req.Defect = "`signed:` binds no signer: it means \"signed by anybody\", which any code-signing " +
			"certificate satisfies. Use `subject:<Subject O=>` or `thumbprint:<leaf SHA-256>`"
		return req
	default:
		req.Defect = "it names no form. Write `subject:<Subject O= of the signing certificate>` (durable across " +
			"certificate renewals — the macOS Team ID analog) or `thumbprint:<leaf certificate SHA-256>` (exact, " +
			"and it changes when the certificate is renewed)"
		return req
	}
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// Check is the judgement: does this signature satisfy this requirement?
//
// The caller must not reach it with an unconfigured requirement — Configured() decides that, and the
// difference matters because "no requirement" installs and "requirement not met" refuses.
func (r PublisherRequirement) Check(sig authenticode.Sig) error {
	if !sig.Valid {
		// One sentence for unsigned, tampered, and untrusted-chain, because Authenticode does not distinguish
		// them to us and inventing a distinction would be describing a check we did not perform. What it does
		// say is the consequence, since "not valid" reads as a formality and this one is not.
		return fmt.Errorf("%w: it carries no Authenticode signature that verifies and chains to a trusted root "+
			"(unsigned, tampered with, or signed by a chain this machine does not trust). The manifest may say to "+
			"install it; nothing here says Lantern built it", ErrPublisherUntrusted)
	}
	switch r.Kind {
	case FormSubject:
		if sig.Org == "" {
			// ★ VALID AND UNREADABLE IS ITS OWN CASE, and it is the one most likely to be a defect in this gate
			// rather than in the package: the signer identity is pulled with CryptQueryObject, and an MSI carries
			// its signature in a stream rather than in a PE certificate table. If that read ever fails on a
			// correctly signed MSI, EVERY update stops — so the message names that possibility instead of leaving
			// an operator to conclude their own release is untrusted.
			return fmt.Errorf("%w: its Authenticode signature is valid but no Subject Organization could be read "+
				"from the signing certificate, so who built it is UNKNOWN — and unknown must not install as SYSTEM. "+
				"If this is a package the release pipeline signed, the fault is in this check reading the signer of "+
				"an MSI, not in the package: verify with Get-AuthenticodeSignature and report it", ErrPublisherUntrusted)
		}
		if !strings.EqualFold(sig.Org, r.Want) {
			return fmt.Errorf("%w: it was signed by %q and this device installs only packages from %q",
				ErrPublisherUntrusted, sig.Org, r.Want)
		}
		return nil
	case FormThumbprint:
		if sig.Thumbprint == "" {
			return fmt.Errorf("%w: its Authenticode signature is valid but the signing certificate's SHA-256 could "+
				"not be read, so which certificate signed it is UNKNOWN. If this is a package the release pipeline "+
				"signed, the fault is in this check rather than in the package", ErrPublisherUntrusted)
		}
		if !strings.EqualFold(sig.Thumbprint, r.Want) {
			return fmt.Errorf("%w: it was signed by the certificate %s and this device pins %s. A certificate "+
				"RENEWAL looks exactly like this — if the release pipeline's certificate was reissued, the pin is "+
				"what is stale, and `subject:` is the form that survives that", ErrPublisherUntrusted, sig.Thumbprint, r.Want)
		}
		return nil
	default:
		// Unreachable through Configured(), and it refuses rather than passing: a requirement this code does not
		// understand must never be the reason something installed.
		return fmt.Errorf("%w: this device's publisher requirement %q is not one this build understands, and an "+
			"unrecognised requirement is not a satisfied one", ErrPublisherUntrusted, r.Raw)
	}
}

// Describe is the one-line answer for --status and for the service's start banner.
//
// It exists because the requirement is a security control whose ABSENCE is invisible: a device with no
// publisher pinned updates perfectly happily and looks identical to one that checks. This product has already
// shipped that exact shape — an update daemon that could never update, refusing correctly, into a log nobody
// read.
func (r PublisherRequirement) Describe() string {
	switch {
	case r.Defect != "":
		return "★ NOT CHECKED — --update-publisher " + r.Raw + " is unusable: " + r.Defect +
			". Packages install on the manifest signature alone until this is corrected, because refusing would " +
			"leave this device unable to install the MSI that would fix it"
	case !r.Configured():
		return RequirementMissingNote
	case r.Kind == FormThumbprint:
		return "leaf certificate " + r.Want + " (checked immediately before msiexec runs; a certificate renewal " +
			"invalidates this pin)"
	default:
		return "Authenticode Subject O=" + r.Want + " (checked immediately before msiexec runs)"
	}
}
