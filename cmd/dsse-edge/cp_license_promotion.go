package main

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
)

// Refresh before publishing leadership; never advertise an old serial or pool.
func configureLicensePromotion(e *cpLeaderElector, backend string, s *licenseStore, gate *enrolmentLicensing, keys []*ecdsa.PublicKey, mssp string) {
	if e == nil || s == nil || storeBackend(backend) != "postgres" {
		return
	}
	previous := e.prepareLeadership
	e.prepareLeadership = func() error {
		if previous != nil {
			if err := previous(); err != nil {
				return err
			}
		}
		if err := s.ReloadFromStore(); err != nil {
			return err
		}
		p, ok, err := s.CurrentWithReason(keys, mssp)
		if err != nil {
			return err
		}
		if gate != nil && ok {
			gate.Apply(p)
		}
		return nil
	}
}
func licenseReadRefusedOnAStandby(w http.ResponseWriter) bool {
	if !edgeIsControlPlane || cpLeaderElectorInstance == nil || cpLeaderElectorInstance.IsLeader() {
		return false
	}
	writeError(w, http.StatusConflict, fmt.Errorf("this control plane does not hold leadership; licensing and seat state is not authoritative here. Retry through the active management server"))
	return true
}
