package main

// pin_agreement.go — the recorded key and the key actually in force must be the same, and a difference has to
// be loud.
//
// ★★★ A STALE HUMAN-READABLE COPY IS WORSE THAN NONE (2026-08-29). The key is written twice on purpose: into
// the service's arguments, which is what the agent reads, and into profile_signing_key.txt, which is what a
// person reads when asked "which authority does this box verify its configuration against". Two copies of one
// fact is a way to have them stop being the same fact.
//
// The failure that matters is not the device's — it verifies against its arguments and is either right or
// fail-closed, and says so. The failure is the OPERATOR's: they read the file, believe it, and reason from a
// value that is not in force. Someone confidently wrong takes longer to correct than someone who knows they do
// not know.
//
// So the comparison exists, it runs where the second copy is written, and an operator can ask for it at any
// time. It is a report: it changes nothing, because deciding on its own which of two copies is right is how a
// discrepancy gets papered over instead of looked at.

import (
	"strings"
)

// pinAgreement is what the two records say, and whether they agree.
type pinAgreement struct {
	Recorded string // what profile_signing_key.txt holds ("" = absent or unreadable)
	InForce  string // what the service's arguments name ("" = the service names none)
	Note     string // the sentence to print
	Agree    bool
}

// comparePins reports the relationship between the key on disk and the key the agent will actually use.
//
// serviceArgs is the service's argument list as configured; recorded is the contents of the key file. Both are
// passed in rather than read here so the whole judgement is testable without a registry or a service.
func comparePins(recorded string, serviceArgs []string) pinAgreement {
	a := pinAgreement{
		Recorded: strings.ToLower(strings.TrimSpace(recorded)),
		InForce:  strings.ToLower(strings.TrimSpace(pinFromArgs(serviceArgs))),
	}
	switch {
	case a.Recorded == "" && a.InForce == "":
		a.Note = "no profile signing key anywhere: the file is absent and the service names none, so this " +
			"device cannot verify any configuration it is given and will hold SAFE fail-closed defaults"
	case a.Recorded == "" && a.InForce != "":
		a.Agree = true
		a.Note = "the service verifies profiles against " + short(a.InForce) + ", and " + signingKeyFileName +
			" is absent — in force but undiscoverable; re-run the provision with PIN= to leave a copy a person can read"
	case a.InForce == "":
		a.Note = "★ " + signingKeyFileName + " records " + short(a.Recorded) + " but the service names NO key. " +
			"The file describes an intention, not what is in force: this device verifies nothing"
	case a.Recorded == a.InForce:
		a.Agree = true
		a.Note = "the recorded key and the key in force agree (" + short(a.InForce) + ")"
	default:
		a.Note = "★ " + signingKeyFileName + " records " + short(a.Recorded) + " but the service verifies " +
			"against " + short(a.InForce) + ". The file is the one an operator reads, and it is wrong. " +
			"Nothing is changed here: which of the two is correct is not a thing this can decide"
	}
	return a
}

// pinFromArgs reads the config pin out of a service argument list, in either the separated or joined form.
// The LAST one wins, because that is what Go's flag package does with a repeated flag — the report has to
// describe the value that will actually be used, not the one a reader would guess.
func pinFromArgs(args []string) string {
	found := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config-pin" || a == "-config-pin":
			if i+1 < len(args) {
				found = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--config-pin="):
			found = strings.TrimPrefix(a, "--config-pin=")
		case strings.HasPrefix(a, "-config-pin="):
			found = strings.TrimPrefix(a, "-config-pin=")
		}
	}
	return found
}

// short is the readable prefix. The whole key in a log line is noise; sixteen characters distinguish any two
// keys a deployment will ever hold, and the full value is in the file and the service configuration.
func short(k string) string {
	if len(k) <= 16 {
		return k
	}
	return k[:16] + "…"
}
