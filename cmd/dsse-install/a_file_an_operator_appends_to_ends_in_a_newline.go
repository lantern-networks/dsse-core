package main

import "strings"

// a_file_an_operator_appends_to_ends_in_a_newline.go — the last line of deployment.env.
//
// ★★★ A GENERATED deployment.env ENDED WITHOUT A NEWLINE, AND THE NEXT LINE SOMEBODY ADDED JOINED THE LAST
// ONE (found by standing up one region on one machine and following the instructions this deployment
// prints). The file ended:
//
//	DSSE_PG_PEERS=''
//
// with no newline after it, so an operator adding a setting the deployment itself asks for — the host
// aliases for a machine whose DNS does not answer, a subnet that is already taken, the region map — got:
//
//	DSSE_PG_PEERS=''DSSE_HOST_ALIAS_1='admin.tokyo.example.lab:host-gateway'
//
// Nothing refused it. DSSE_PG_PEERS was now non-empty, which is one of the three things that make a
// deployment more than one machine — so -verify asked a ONE-MACHINE deployment whether its authority was
// redundant, whether more than one control plane was running and whether its doorway was a single point, and
// reported three failures for a shape that had been installed exactly as intended.
//
// ★ THE SHAPES DISAGREED, WHICH IS WHY IT SURVIVED. -region writes this file with a trailing newline and the
// plan-driven path did not, so the same deployment described two ways behaved differently at the one moment
// an operator touches the file.
//
// withTrailingNewline is what every writer of an operator-editable file returns through.
func withTrailingNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
