package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ★★★ FOUR CHECKS ASKED ABOUT THE DEPLOYMENT AND WERE ANSWERED ABOUT ONE ORGANIZATION (2026-09-01, measured
// on a deployment where two connectors were carrying a customer's private access at the time).
//
// -verify asks with the DEPLOYMENT ADMINISTRATOR's token, and /admin/connectors answers for the caller's own
// organization. Connectors belong to CUSTOMER organizations. So every connector question came back empty and
// the checks said, in their own words:
//
//	no connector has been added to this deployment yet, and no control plane claims one — there is nothing
//	here to be inconsistent about
//
// Each sentence was true about the operator's organization. None of them was about the deployment, and all
// four turned that silence into a PASS — a readiness report that had measured nothing while reporting itself
// satisfied. This is the same shape found eight times in one week: a question about somebody else answered
// with an attribute of this node.
//
// connectorsForEveryOrganization asks once per organization the deployment holds, and merges.

// organizationsOfTheDeployment lists every organization. The second result is false when the operator's
// deployment-wide tenant list could not be read; falling back to one unnamed tenant would turn a partial
// fleet measurement into a reassuring zero.
func organizationsOfTheDeployment(client *http.Client, cpAdmin, token string) ([]string, bool) {
	code, body, err := get(client, strings.TrimRight(cpAdmin, "/")+"/admin/tenants", token)
	if err != nil || code != 200 {
		return nil, false
	}
	var payload struct {
		Tenants *[]struct {
			TenantID string `json:"tenant_id"`
		} `json:"tenants"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Tenants == nil {
		return nil, false
	}
	if len(*payload.Tenants) == 0 {
		return []string{""}, true
	}
	ids := []string{}
	for _, t := range *payload.Tenants {
		id := strings.TrimSpace(t.TenantID)
		if id == "" {
			return nil, false
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, true
}

// connectorsForEveryOrganization returns every connector id one door knows of, across the given organizations.
// The second return is false when a door could not be asked at all — the caller must not read that as "none".
func connectorsForEveryOrganization(client *http.Client, door, token string, organizations []string) ([]string, bool) {
	if len(organizations) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	for _, org := range organizations {
		endpoint := strings.TrimRight(door, "/") + "/admin/connectors"
		if org != "" {
			endpoint += "?tenant_id=" + url.QueryEscape(org)
		}
		code, body, err := get(client, endpoint, token)
		if err != nil || code != 200 {
			return nil, false
		}
		var payload struct {
			Connectors *[]struct {
				ID string `json:"id"`
			} `json:"connectors"`
			Count *int `json:"count"`
		}
		if json.Unmarshal(body, &payload) != nil || payload.Connectors == nil ||
			payload.Count == nil || *payload.Count != len(*payload.Connectors) {
			return nil, false
		}
		for _, c := range *payload.Connectors {
			id := strings.TrimSpace(c.ID)
			if id == "" {
				return nil, false
			}
			seen[id] = true
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, true
}
