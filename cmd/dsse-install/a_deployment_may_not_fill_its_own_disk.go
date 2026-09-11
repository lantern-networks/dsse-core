package main

// a_deployment_may_not_fill_its_own_disk.go — every service this deployment runs has a bounded log.
//
// ★★★ IT FILLED A 59 GB HOST AND TOOK THE DEPLOYMENT DOWN (2026-08-26, measured on the deployment this
// installer generates). Nothing capped any service's log. One of them — the database's cluster manager,
// writing "no action. I am the leader with the lock" every ten seconds — had produced 2.4 GB on its own, and
// the images left behind by a day of rebuilding did the rest. What the operator sees when the disk fills is
// not "the disk is full":
//
//	postgres      OSError: [Errno 28] No space left on device   -> refuses to start
//	its front door  backend 'pg_primary' has no server available -> the database has no address
//	both control planes  open CP-state blob store: ping ... EOF  -> exit 1
//	every Edge    control_channel state=fail_closed              -> running on what it last applied
//
// A whole deployment down, four different messages, none of them naming the cause. And it is the SECOND time
// this shape has been measured here: a ClickHouse instance once wrote 9.6 GB of trace logs about itself.
//
// ★ SO THE CAP IS APPLIED CENTRALLY, NOT SERVICE BY SERVICE. A list of services to remember is a list
// somebody adds to without remembering; this walks the rendered file and gives EVERY service the same bounded
// logging, so a service added later cannot be the one that was missed.
//
// ★★ AND IT BOUNDS, IT DOES NOT SILENCE. Three files of 20 MB is an hour of a busy node and days of a quiet
// one, which is what an incident is read from. The durable record does not live here at all — audit goes to
// the control plane and the archive — so what is capped is the process's own stdout, and nothing that has to
// be kept is kept only here.

import (
	"regexp"
	"strings"
)

// composeLogRotationAnchor is the one definition every service points at.
const composeLogRotationAnchor = `# ★★★ EVERY SERVICE'S LOG IS BOUNDED, AND THIS IS WHY. Uncapped, one service can write gigabytes about
# itself, fill the host's disk, and bring the deployment down reporting four different things — none of them
# "the disk is full". Bounded, not silenced: three files of 20 MB is what an incident is read from, and the
# durable record is shipped to the control plane and the archive, never kept only here.
x-dsse-logging: &dsse-logging
  driver: json-file
  options:
    max-size: "20m"
    max-file: "3"

`

// composeServiceLine matches a service key: exactly two spaces of indent, a name, a colon, and optionally a
// YAML anchor that the services below it merge from.
//
// ★★★ WITHOUT THE ANCHOR THIS MISSED THE SERVICE THAT CAUSED THE INCIDENT (2026-08-26, caught by counting
// what the cap actually reached on the generated deployment: 15 of 17). The two services that declare an
// anchor are the consensus store and THE DATABASE — and the database's cluster manager is the process that
// wrote 2.4 GB about itself and filled the disk. A gate that covers everything except the thing it was
// written for is worse than none, because the count looks like coverage.
var composeServiceLine = regexp.MustCompile(`^  [A-Za-z0-9][A-Za-z0-9._-]*:(\s+&[A-Za-z0-9._-]+)?\s*$`)

// boundEveryServicesLog inserts the shared logging anchor and gives every service in the rendered compose file
// the same bounded logging. A service that already declares its own is left alone.
func boundEveryServicesLog(compose string) string {
	lines := strings.Split(compose, "\n")
	out := make([]string, 0, len(lines)+len(lines)/8)
	inServices := false
	for i, line := range lines {
		out = append(out, line)
		if strings.TrimRight(line, " \t") == "services:" {
			inServices = true
			continue
		}
		// A top-level key other than services: ends the block — volumes:, networks:, and so on.
		if inServices && line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
			inServices = false
		}
		if !inServices || !composeServiceLine.MatchString(line) {
			continue
		}
		if serviceAlreadyDeclaresLogging(lines[i+1:]) {
			continue
		}
		out = append(out, "    logging: *dsse-logging")
	}
	body := strings.Join(out, "\n")
	// The anchor has to be defined before it is used, so it goes above `services:`.
	if idx := strings.Index(body, "\nservices:\n"); idx >= 0 {
		return body[:idx+1] + composeLogRotationAnchor + body[idx+1:]
	}
	return body
}

// serviceAlreadyDeclaresLogging looks ahead within one service block for a logging: key of its own, so a
// service that has been given deliberate settings keeps them.
func serviceAlreadyDeclaresLogging(rest []string) bool {
	for _, line := range rest {
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		// Left this service block: either the next service key or something less indented.
		if !strings.HasPrefix(line, "    ") {
			return false
		}
		if strings.HasPrefix(strings.TrimSpace(line), "logging:") {
			return true
		}
	}
	return false
}
