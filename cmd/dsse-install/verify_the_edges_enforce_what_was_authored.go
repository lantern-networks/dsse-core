package main

// verify_the_edges_enforce_what_was_authored.go — the organization's own root is not a fact until the node
// that signs its traffic is using it.
//
// ★★★ THE CONSOLE AND THE ENFORCING EDGE GAVE OPPOSITE ANSWERS AND ONLY ONE OF THEM WAS ASKED (2026-08-27,
// measured after walking a customer's whole PKI through the Console).
//
// The control plane held the organization's interception authority and said so:
//
//	In use: CN=Kaede Logistics Interception Root,O=Kaede Logistics
//
// The Edge that terminates that organization's TLS said this, and it is the one whose answer a device sees:
//
//	per_tenant: []   per_tenant_issuers: []
//	signing_scope: {configured: "shared", effective: "shared_root_direct", per_tenant_signing: false}
//
// Every leaf was minted by the deployment's one shared CA. The customer's root was registered, listed, and
// distributed to their devices — and signed nothing.
//
// ★ THE CHECKS BESIDE THIS ONE BOTH PASSED, correctly, because neither asks this question.
// verifyAnOrganizationCanHaveItsOwnTree asks the control plane whether there is somewhere to KEEP an
// authority. verifyTheDeploymentInspects asks whether every Edge signs under the same DEFAULT one. Authoring
// and enforcing are different nodes; a deployment can do the first perfectly and none of the second.
//
// ★★ AND IT DOES NOT FAIL A DEPLOYMENT WITH NO CUSTOMERS. Per-organization signing is only owed where an
// organization actually has an authority of its own, so the control plane is asked WHICH ones do first. With
// none, this says so — an operator reading "ok" should not have to wonder whether it was measured.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// verifyTheEdgesEnforceWhatWasAuthored compares what the control plane holds per organization with what the
// Edges actually sign under.
func verifyTheEdgesEnforceWhatWasAuthored(client *http.Client, cpAdmin string, edgeAdmins []string,
	adminToken string) []verifyResult {

	const name = "the Edges inspect each organization under ITS OWN authority"
	cpAdmin = strings.TrimRight(strings.TrimSpace(cpAdmin), "/")
	if cpAdmin == "" || len(edgeAdmins) == 0 {
		return nil
	}

	owed, err := organizationsWithTheirOwnInterceptionAuthority(client, cpAdmin, adminToken)
	if err != nil {
		return []verifyResult{{name: name, note: fmt.Sprintf("%s could not be asked which organizations have an "+
			"authority of their own: %v", cpAdmin, err)}}
	}
	if len(owed) == 0 {
		return []verifyResult{{ok: true, name: name, note: "no organization on this deployment has an " +
			"interception authority of its own yet, so there is nothing for an Edge to be using instead — " +
			"this becomes a real check the moment one does"}}
	}
	sort.Strings(owed)

	shared, unreachable := []string{}, []string{}
	for _, admin := range edgeAdmins {
		admin = strings.TrimRight(strings.TrimSpace(admin), "/")
		if admin == "" {
			continue
		}
		status, body, gerr := get(client, admin+"/admin/interception-roots", adminToken)
		if gerr != nil || status != http.StatusOK {
			unreachable = append(unreachable, fmt.Sprintf("%s (HTTP %d %v)", admin, status, gerr))
			continue
		}
		var answer struct {
			SigningScope struct {
				Configured       string `json:"configured"`
				Effective        string `json:"effective"`
				PerTenantSigning bool   `json:"per_tenant_signing"`
				Note             string `json:"note"`
			} `json:"signing_scope"`
		}
		if jerr := json.Unmarshal(body, &answer); jerr != nil {
			unreachable = append(unreachable, admin+" (its answer could not be read)")
			continue
		}
		if !answer.SigningScope.PerTenantSigning {
			shared = append(shared, fmt.Sprintf("%s (%s)", admin, answer.SigningScope.Effective))
		}
	}

	switch {
	case len(shared) > 0:
		return []verifyResult{{name: name, note: fmt.Sprintf(
			"%d organization(s) have an interception authority of their own on the control plane (%s), and "+
				"%d Edge(s) sign every organization under the deployment's ONE shared root instead: %s. "+
				"Their customers' roots are registered, listed and trusted by their devices, and sign "+
				"nothing. An Edge assembles its organizations from the control plane only when it is "+
				"started with -tenant-transport-material-from-cp, on the audit-ingest endpoint and token "+
				"beside it%s",
			len(owed), strings.Join(owed, ", "), len(shared), strings.Join(shared, ", "),
			unreachableSuffix(unreachable))}}
	case len(unreachable) == len(edgeAdmins):
		return []verifyResult{{name: name, note: "no Edge could be asked what it signs under: " +
			strings.Join(unreachable, ", ")}}
	default:
		return []verifyResult{{ok: true, name: name, note: fmt.Sprintf(
			"every Edge that answered signs each organization under its own authority; %d organization(s) "+
				"have one (%s)%s", len(owed), strings.Join(owed, ", "), unreachableSuffix(unreachable))}}
	}
}

func unreachableSuffix(unreachable []string) string {
	if len(unreachable) == 0 {
		return ""
	}
	return " — and NOT measured on: " + strings.Join(unreachable, ", ")
}

// organizationsWithTheirOwnInterceptionAuthority asks the control plane, per organization, rather than
// assuming. There is no list route for this: the authority is read one organization at a time, in the
// organization's own context, which is the same shape the Console uses.
func organizationsWithTheirOwnInterceptionAuthority(client *http.Client, cpAdmin, adminToken string) ([]string, error) {
	status, body, err := get(client, cpAdmin+"/admin/tenants", adminToken)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", status, firstLineOf(body))
	}
	var listing struct {
		Tenants []struct {
			TenantID    string `json:"tenant_id"`
			DisplayName string `json:"display_name"`
		} `json:"tenants"`
	}
	if jerr := json.Unmarshal(body, &listing); jerr != nil {
		return nil, jerr
	}
	owed := []string{}
	for _, t := range listing.Tenants {
		id := strings.TrimSpace(t.TenantID)
		if id == "" {
			continue
		}
		astatus, abody, aerr := getAsOrganization(client, cpAdmin+"/admin/tenant-interception-authority", adminToken, id)
		if aerr != nil || astatus != http.StatusOK {
			continue
		}
		var answer struct {
			HasAuthority bool `json:"has_authority"`
		}
		if jerr := json.Unmarshal(abody, &answer); jerr == nil && answer.HasAuthority {
			label := strings.TrimSpace(t.DisplayName)
			if label == "" || label == id {
				label = id
			} else {
				label = label + " (" + id + ")"
			}
			owed = append(owed, label)
		}
	}
	return owed, nil
}

// getAsOrganization asks in one organization's context. The per-organization PKI reads resolve the caller's
// own organization by default and take X-Operate-Tenant from an operator, which is exactly what -verify is.
func getAsOrganization(client *http.Client, url, bearer, tenant string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if strings.TrimSpace(tenant) != "" {
		req.Header.Set("X-Operate-Tenant", strings.TrimSpace(tenant))
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}
