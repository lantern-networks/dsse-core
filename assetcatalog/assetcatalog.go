// Package assetcatalog holds the things a policy rule refers to — endpoints, groups, and services —
// each identified by a tenant-unique, human-readable alias. It lives in dsse-core (not the proprietary
// Console) so that audit logs and decisions can reference named entities; the Console reads/writes it
// through the admin API. Rules are written `source → destination : service`, where source/destination are
// endpoints or groups and service is a named port/protocol.
package assetcatalog

import (
	"strconv"
	"strings"
)

// Endpoint kinds.
const (
	KindSteeredDevice = "steered_device" // an enrolled device running the agent (macOS NE / Windows WFP)
	KindNetwork       = "network"        // a network address / CIDR / FQDN (server, appliance, egress dest)
)

// Endpoint sources.
const (
	SourceEnrolled = "enrolled" // auto-populated from the enrolled inventory; identity is read-only
	SourceManual   = "manual"   // added by an admin
)

// PortProto is one protocol+port a Service exposes (e.g. tcp/5432).
type PortProto struct {
	Protocol string `json:"protocol"` // "tcp" | "udp"
	Port     int    `json:"port"`
}

// Endpoint is a steered device or a network address that policy refers to.
type Endpoint struct {
	ID       string   `json:"id"`
	TenantID string   `json:"tenant_id"`
	Alias    string   `json:"alias"`              // tenant-unique display name (what logs/admin see)
	Kind     string   `json:"kind"`               // KindSteeredDevice | KindNetwork
	Platform string   `json:"platform,omitempty"` // "macos" | "windows" (steered devices)
	Steered  bool     `json:"steered"`
	Identity string   `json:"identity,omitempty"` // verified device identity (read-only; enrolled inventory)
	Address  string   `json:"address,omitempty"`  // IP / CIDR / FQDN (network endpoints)
	Tags     []string `json:"tags,omitempty"`
	Source   string   `json:"source"`             // SourceEnrolled | SourceManual
	BuiltIn  bool     `json:"built_in,omitempty"` // shipped (SaaS catalog) — read-only, not persisted, not deletable
	Category string   `json:"category,omitempty"` // built-in only: sign_in | ai | collaboration | optimize
}

// MembershipRule selects endpoints by attribute for a group's dynamic membership. A nil/zero field is "any";
// all set fields must match (AND).
type MembershipRule struct {
	Platform *string `json:"platform,omitempty"` // "macos" | "windows"
	Steered  *bool   `json:"steered,omitempty"`
	Tag      string  `json:"tag,omitempty"`    // endpoint must carry this tag
	Subnet   string  `json:"subnet,omitempty"` // endpoint address within this CIDR
}

// Group is a named set of endpoints — the subject of a rule. Membership is a static list and/or a dynamic
// attribute rule (both may be present; the resolved set is their union).
type Group struct {
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	Alias         string          `json:"alias"`
	Tier0         bool            `json:"tier0,omitempty"` // sensitive (e.g. domain controllers) — surfaced everywhere
	StaticMembers []string        `json:"static_members,omitempty"`
	Dynamic       *MembershipRule `json:"dynamic,omitempty"`
	BuiltIn       bool            `json:"built_in,omitempty"` // shipped (SaaS catalog) — read-only, not persisted, not deletable
	Category      string          `json:"category,omitempty"` // built-in only: sign_in | ai | collaboration | optimize
}

// Service is a named port/protocol set (the "what" of a connection), reused across rules.
type Service struct {
	ID       string      `json:"id"`
	TenantID string      `json:"tenant_id"`
	Alias    string      `json:"alias"`
	Ports    []PortProto `json:"ports"`
	BuiltIn  bool        `json:"built_in,omitempty"` // shipped well-known service — read-only, not persisted, not deletable
}

func normalizeAlias(a string) string {
	return strings.TrimSpace(a)
}

// uniqueAliasLocked returns an alias unique within the tenant's shared namespace (endpoints + groups +
// services). It honors `desired` when free or already owned by `ownerID`, otherwise it appends `-2`, `-3`,
// … until unique. Caller holds s.mu.
func (s *Store) uniqueAliasLocked(tenant, desired, ownerID string) string {
	desired = normalizeAlias(desired)
	if desired == "" {
		desired = ownerID
	}
	used := s.aliases[tenant]
	free := func(a string) bool {
		owner, taken := used[a]
		return !taken || owner == ownerID
	}
	if free(desired) {
		return desired
	}
	for n := 2; ; n++ {
		cand := desired + "-" + strconv.Itoa(n)
		if free(cand) {
			return cand
		}
	}
}
