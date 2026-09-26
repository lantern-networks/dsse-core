package main

import "github.com/lantern-networks/dsse-core/policycandidate"

// A derived projection, deliberately not a persisted candidate property. The
// Console registers this validated name at the CP, where Edge-local IDs may not exist.
type policyCandidateView struct {
	policycandidate.Candidate
	RegistrationHost string `json:"registration_host,omitempty"`
}

func policyCandidateForView(c policycandidate.Candidate) policyCandidateView {
	v := policyCandidateView{Candidate: c}
	if c.Source == policycandidate.SourceCertPinningDetection {
		if host, highRisk, err := policycandidate.CertPinBypassTarget(c); err == nil && !highRisk {
			v.RegistrationHost = host
		}
	}
	return v
}
