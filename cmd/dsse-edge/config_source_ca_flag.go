package main

import "flag"

// config_source_ca_flag.go — the CA an Edge verifies its CONTROL PLANE against, under the name somebody
// installing a deployment would look for.
//
// ★★★ THE SAME CA, UNDER THE NAME SOMEBODY INSTALLING A DEPLOYMENT WOULD LOOK FOR (2026-08-22, found by
// installing one). An Edge is pointed at its control plane with -config-source-url, and the certificate
// that control plane presents has to be verified against something. That something already existed as
// -steer-exclusion-source-ca, named after ONE of the things this client fetches — so a search for "config-source-ca" finds nothing,
// and the deployment starts, reports status ok, and quietly fails every pull:
//
//	revocation sync: pull failed (keeping revocations): tls: failed to verify certificate:
//	  x509: "… Management CA" certificate is not trusted
//
// The audit path already has -audit-ingest-ca. This is an alias rather than a rename because renaming
// would break every deployment that names the old one, and a deployment that cannot reach its control
// plane is the failure this whole flag exists to prevent.
func registerConfigSourceCAFlag() *string {
	return flag.String("config-source-ca", "", "PEM anchors this Edge verifies its CONTROL PLANE "+
		"against (-config-source-url / -config-source-endpoints). The same thing as "+
		"-steer-exclusion-source-ca, under the name an installer looks for; either may be given. Empty = the "+
		"host's own trust store, which is what a container image with the anchor mounted in relies on.")
}
