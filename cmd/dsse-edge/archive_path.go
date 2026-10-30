package main

// validArchivePathComponent prevents a tenant or stream identifier obtained
// from a hot store or persisted journal from changing the S3 key hierarchy.
// Tenant creation validates the same token alphabet, but archive retention
// must fail closed even when older or externally ingested rows are malformed.
func validArchivePathComponent(value string) bool {
	return safeAdminTenantToken(value)
}
