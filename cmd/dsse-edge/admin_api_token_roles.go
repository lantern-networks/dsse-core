package main

import (
	"sort"
	"strings"
)

// adminAPITokenRoles are the roles a token may carry.
//
// ★ super_admin WAS MISSING, AND ITS ABSENCE FORCED THE WRONG ANSWER (2026-08-16). It is a valid PRINCIPAL
// role — the operator's — and was not a valid TOKEN role, so the operator could not have a named machine
// credential at all. Anything automated therefore ran as `owner` (which is "*", strictly more) or as the
// shared break-glass token (which is "*" AND anonymous). A list that omits the least-privileged option for a
// job is a list that pushes every caller to the most-privileged one.
var adminAPITokenRoles = map[string]bool{
	"owner":       true,
	"super_admin": true,
	"admin":       true,
	"analyst":     true,
	"approver":    true,
	"auditor":     true,
}

// adminUnknownTokenRoles names the requested roles this deployment does not know.
//
// ★ THEY USED TO BE DROPPED SILENTLY. normalizedAdminRoles skips what it does not recognise, so asking for
// ["admin","super_admin"] produced a token holding ["admin"] — weaker than the one asked for, with a 201 and
// no mention of it. A credential that is quietly not what its holder believes is how an automation runs for
// months and then fails at the one moment it matters.
func adminUnknownTokenRoles(requested []string) []string {
	unknown := []string{}
	seen := map[string]bool{}
	for _, role := range requested {
		role = strings.TrimSpace(role)
		if role == "" || adminAPITokenRoles[role] || seen[role] {
			continue
		}
		seen[role] = true
		unknown = append(unknown, role)
	}
	sort.Strings(unknown)
	return unknown
}

// adminRolesBeyondPrincipal names the requested roles whose permissions the minting principal does not hold.
//
// Compared by PERMISSION rather than by role name: two roles can differ in name and be identical in what they
// allow, and a rule written on names would refuse the harmless case and miss the renamed one. An `owner`
// principal holds "*" and therefore may mint anything.
func adminRolesBeyondPrincipal(requested, principalRoles []string) []string {
	beyond := []string{}
	seen := map[string]bool{}
	for _, role := range requested {
		role = strings.TrimSpace(role)
		if role == "" || seen[role] {
			continue
		}
		seen[role] = true
		for permission := range adminPermissionsByRole[role] {
			if !adminPermissionAllowed(principalRoles, permission) {
				beyond = append(beyond, role)
				break
			}
		}
	}
	sort.Strings(beyond)
	return beyond
}
