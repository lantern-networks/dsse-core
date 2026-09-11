package main

import "flag"

// Transport admission flags, in a sibling file because main.go's decomposition ratchet holds its flag count
// frozen — new configuration belongs beside the thing it configures, not in the file everything already is.

// transportAdmissionFlags is how many tenants this (T) listener will admit.
type transportAdmissionFlags struct {
	// multiTenant admits devices from EVERY tenant in the Tenant CA registry, keying each connection to the
	// tenant its certificate chains to, instead of pinning the Edge to its own bundle tenant.
	//
	// ★ WITHOUT IT AN EDGE COULD ONLY EVER SERVE ONE TENANT (2026-08-15). Configuring a Tenant CA registry
	// pinned admission to the node's own bundle tenant, so a second organization's device was refused at the
	// handshake as cross-tenant — on the Edge an MSSP would use to serve several customers. The transport
	// documented the other mode and the downstream half was already right (every decision is keyed to the
	// tenant the CERTIFICATE proves, and a body claiming a different one is refused); only the wiring made it
	// unreachable.
	//
	// Off by default. An Edge that started admitting other tenants because a flag moved underneath it is the
	// opposite mistake, and every existing deployment is single-tenant.
	multiTenant *bool
}

func registerTransportAdmissionFlags() transportAdmissionFlags {
	return transportAdmissionFlags{
		multiTenant: flag.Bool("transport-multi-tenant-admission", false,
			"admit devices from EVERY tenant in the Tenant CA registry on this (T) listener, keying each connection to the tenant its certificate chains to, instead of pinning the Edge to its own bundle tenant"),
	}
}
