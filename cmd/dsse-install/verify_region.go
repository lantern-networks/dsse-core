package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// verify_region.go — the check for the LAST group of the multi-region install order.
//
// ★★★ WHY IT IS A CHECK AND NOT A DOCUMENT (2026-08-23, walked, then measured on the lab). The install order
// says the region entry list goes to every Edge once every region exists, and warns that writing it on one
// side makes a map that only connects one way. Walking it showed that step is N COMMAND-LINE EDITS: the map
// is built from -region-endpoints and from nothing else — not authored on the control plane, not carried in
// the config bundle.
//
// So an Edge somebody missed is HEALTHY. Measured, by taking one region out of one lab Edge's list:
//
//	its /healthz            status ok, role edge, configuration applied
//	the lab posture check   BOTH regions PASS — it asks whether each region's address is serving,
//	                        which is a different question
//	its devices             handed a valid map that simply does not contain the other region, so they
//	                        never fail over there
//
// Nothing reported it, and the operator who added the region saw every edit they made succeed. The only way
// to find it is to ask every node what it knows and compare, which is what this does.

// regionShape is what one node says about the regions it knows.
type regionShape struct {
	URL     string
	Role    string
	Region  string
	Regions []string
	Digest  string
	OK      bool
}

// nodeRegions asks one node which region it is in and which regions it knows about.
func nodeRegions(client *http.Client, adminURL string) regionShape {
	shape := regionShape{URL: strings.TrimRight(adminURL, "/")}
	code, body, err := get(client, shape.URL+"/healthz", "")
	if err != nil || code != 200 {
		return shape
	}
	var health struct {
		Role    string   `json:"role"`
		Region  string   `json:"region"`
		Regions []string `json:"region_endpoints"`
		Digest  string   `json:"region_endpoints_digest"`
	}
	if json.Unmarshal(body, &health) != nil {
		return shape
	}
	shape.Role, shape.Region, shape.Regions, shape.Digest, shape.OK =
		health.Role, health.Region, health.Regions, health.Digest, true
	return shape
}

// verifyRegionAgreement checks that every Edge given hands devices the same region map.
func verifyRegionAgreement(client *http.Client, edgeAdmins []string) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
	}

	shapes := []regionShape{}
	for _, url := range edgeAdmins {
		shape := nodeRegions(client, url)
		// ★ THE CONTROL PLANE IS NOT COMPARED. It is not agent-facing, so it holds no map, and requiring one
		// of it would be requiring the wrong thing of the wrong node.
		if shape.OK && shape.Role == "edge" {
			shapes = append(shapes, shape)
		}
	}
	if len(shapes) == 0 {
		return out
	}

	// ★★★ A MAP OF ONE REGION IS NOT A MULTI-REGION DEPLOYMENT (2026-09-03, measured on one region installed
	// on one machine — a shape this product publishes and nobody had walked). "Holds a map at all" was the
	// test, and a single-region deployment holds one: its own. So the check announced
	//
	//	could not be checked: this deployment is multi-region (…sakura.lab knows singapore) and only ONE
	//	Edge was given
	//
	// about a deployment with one region and one Edge, and told the operator to pass more Edges than exist.
	// What makes agreement a question is more than one REGION to agree about.
	multiRegion := false
	for _, s := range shapes {
		if s.Digest != "" && len(s.Regions) > 1 {
			multiRegion = true
		}
	}
	if !multiRegion {
		// One region: every Edge's map is its own region, and there is nothing for them to disagree about.
		return out
	}

	// ★★★ ONE EDGE CANNOT ANSWER THIS QUESTION. The deployment says it is multi-region, and agreement is a
	// property OF A FLEET: with one node there is nothing to compare and the check has not run. Reported as
	// what it is rather than passing — a fleet nobody compared is exactly the one that disagrees.
	if len(shapes) == 1 {
		add("every Edge hands devices the same region map", false,
			"could not be checked: this deployment is multi-region (%s knows %s) and only ONE Edge was given. "+
				"Pass every Edge to -edge-admin, comma-separated",
			shapes[0].URL, strings.Join(shapes[0].Regions, ","))
		return out
	}

	union := map[string]bool{}
	digests := map[string]bool{}
	for _, s := range shapes {
		digests[s.Digest] = true
		for _, r := range s.Regions {
			union[r] = true
		}
	}
	all := make([]string, 0, len(union))
	for r := range union {
		all = append(all, r)
	}
	sort.Strings(all)

	if len(digests) > 1 {
		behind := []string{}
		for _, s := range shapes {
			missing := []string{}
			for _, r := range all {
				if !contains(s.Regions, r) {
					missing = append(missing, r)
				}
			}
			if len(missing) > 0 {
				behind = append(behind, fmt.Sprintf("%s does not know %s", s.URL, strings.Join(missing, ",")))
			}
		}
		note := "the fleet disagrees"
		if len(behind) > 0 {
			note = strings.Join(behind, "; ")
		}
		add("every Edge hands devices the same region map", false,
			"%s. A device is handed whichever map the node it reached holds, so where it fails over to depends "+
				"on which Edge the front door picked", note)
	} else {
		add("every Edge hands devices the same region map", true,
			"%d Edges agree on %d region(s): %s", len(shapes), len(all), strings.Join(all, ", "))
	}

	// ★ AND EACH NODE HAS TO KNOW WHICH REGION IT IS IN. Without it an Edge cannot anchor a device to its home
	// region, and every east-west and residency decision it makes is about a region it cannot name.
	unnamed := []string{}
	for _, s := range shapes {
		if strings.TrimSpace(s.Region) == "" || s.Region == "local" {
			unnamed = append(unnamed, s.URL)
		}
	}
	if len(unnamed) > 0 {
		add("every Edge names the region it is in", false,
			"%s report no region (-edge-region-id). A multi-region deployment whose node cannot name its own "+
				"region anchors nobody to a home", strings.Join(unnamed, ", "))
	} else {
		add("every Edge names the region it is in", true, "%d Edge(s), each with a region", len(shapes))
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
