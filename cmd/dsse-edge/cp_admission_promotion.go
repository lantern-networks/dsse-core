package main

import (
	"fmt"
	"net/http"

	"github.com/lantern-networks/dsse-core/revocation"
)

// A shared backend does not refresh an already loaded overlay. Install this
// before election starts, including postgres+import deployments. Node-local and
// database-free stores keep their existing ownership and startup behavior.
func configureAdmissionPromotion(e *cpLeaderElector, backend string, a *revocation.AdmissionRevocations) {
	if e != nil && a != nil && storeBackend(backend) == "postgres" {
		e.prepareLeadership = a.ReloadFromStore
	}
}

func admissionReadRefusedOnAStandby(w http.ResponseWriter) bool {
	if !edgeIsControlPlane || cpLeaderElectorInstance == nil || cpLeaderElectorInstance.IsLeader() {
		return false
	}
	writeError(w, http.StatusConflict, fmt.Errorf("this control plane does not hold leadership; admission state is not authoritative here. Retry through the active management server"))
	return true
}
