package main

import (
	"crypto/tls"
	"net/http"
)

// The generated deployment uses the main agent door, so its handshake and
// HTTP dispatch must apply the same enrollment/recovery rules as (T).
func mainEdgeListenerClientTLSConfig(base *tls.Config, door string) *tls.Config {
	out := base.Clone()
	out.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if door == "agent-plane" {
			if recovery := recoveryConfigFor(base, hello); recovery != nil {
				return recovery, nil
			}
			if enrollment := enrolmentConfigFor(base, hello); enrollment != nil {
				return enrollment, nil
			}
		}
		per := base.Clone()
		per.GetConfigForClient = nil
		if current := edgeClientCAPool(); current != nil {
			per.ClientAuth = tls.VerifyClientCertIfGiven
			per.ClientCAs = current
			if door == "agent-plane" && agentDoorAdmission != nil {
				per.VerifyConnection = agentDoorAdmission
			}
		}
		return per, nil
	}
	return out
}
func mainEdgeListenerHandlerForDoor(door string, handler http.Handler) http.Handler {
	if door == "agent-plane" {
		return renewalRecoveryAwareHandler(handler)
	}
	return handler
}
