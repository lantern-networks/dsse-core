package main

import (
	"fmt"
	"net/http"
)

// An optional precondition binds the page's loaded organization to the request's
// authenticated context, including retries after operator elevation. It grants
// no authority and leaves legacy clients scoped by the normal middleware.
func pinnedTenantContextMatches(w http.ResponseWriter, r *http.Request) bool {
	if expected := r.URL.Query().Get("expected_tenant_id"); expected != "" && expected != adminTenantIDFromRequest(r) {
		writeError(w, http.StatusConflict, fmt.Errorf("the organization changed; reload before continuing"))
		return false
	}
	return true
}
