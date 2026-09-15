package main

import (
	"errors"
	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/humanapproval"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"strings"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"
)

func statusForDecision(decision string) int {
	switch decision {
	case "require_reauthentication", "require_step_up_mfa", "require_interactive_mfa", "authenticate_required":
		return http.StatusUnauthorized
	default:
		return http.StatusForbidden
	}
}

func statusForAdminDecisionDetailError(err error) int {
	if strings.Contains(err.Error(), "is absent") {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

func statusForDelegatedGrantError(err error) int {
	if errors.Is(err, delegatedgrant.ErrPersistence) {
		return http.StatusInternalServerError
	}
	if strings.Contains(err.Error(), "cannot transition") {
		return http.StatusConflict
	}
	if strings.Contains(err.Error(), "is absent") {
		return http.StatusNotFound
	}
	return statusForTenantScopedError(err)
}

func statusForInspectionEventError(err error) int {
	if strings.Contains(err.Error(), "is absent") {
		return http.StatusNotFound
	}
	if strings.Contains(err.Error(), "does not match") {
		return http.StatusForbidden
	}
	return statusForTenantScopedError(err)
}

func statusForToolCallEventError(err error) int {
	if strings.Contains(err.Error(), "is absent") {
		return http.StatusNotFound
	}
	if strings.Contains(err.Error(), "not active") || strings.Contains(err.Error(), "does not match") || strings.Contains(err.Error(), "does not allow") {
		return http.StatusForbidden
	}
	return statusForTenantScopedError(err)
}

func statusForHumanApprovalEventError(err error) int {
	if errors.Is(err, humanapproval.ErrPersistence) {
		return http.StatusInternalServerError
	}
	if strings.Contains(err.Error(), "cannot transition") {
		return http.StatusConflict
	}
	return statusForTenantScopedError(err)
}

func statusForTenantScopedError(err error) int {
	if strings.Contains(err.Error(), "does not match edge tenant_id") {
		return http.StatusForbidden
	}
	return http.StatusBadRequest
}
