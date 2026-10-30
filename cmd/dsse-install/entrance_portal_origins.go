package main

import (
	"encoding/json"
	"fmt"
)

const entrancePortalOriginsKey = "DSSE_ENTRANCE_PORTAL_ORIGINS"

func (p *Plan) sharedEntryMachine() PlanMachine {
	if p.SharedEntryMachine != "" {
		_, m, _ := p.find(p.SharedEntryMachine)
		return m
	}
	return p.foundingRegion().controlPlane()
}

// The external generic aliases must name the same entrance as the signed map.
func (p *Plan) validateSharedEntryAddress(entryIP string, nodeIPs map[string]string) error {
	if entryIP != nodeIPs[p.sharedEntryMachine().Name] {
		return fmt.Errorf("shared entry address must match plan shared_entry_machine (%s); declare another CP/L4 there before changing generic DNS", p.sharedEntryMachine().Name)
	}
	return nil
}

func (p *Plan) entrancePortalOrigins() string {
	origins := map[string]string{}
	shared := "https://" + p.edgePortalName(p.sharedEntryMachine())
	if p.dedicatedMultiEdge() {
		region, _, _ := p.find(p.sharedEntryMachine().Name)
		shared = "https://" + p.regionPortalName(region.ID)
	}
	origins[p.Deployment] = shared
	for _, name := range p.Names {
		origins[name] = shared
	}
	for _, plane := range []string{"agents", "recovery"} {
		origins[plane+"."+p.Deployment] = shared
	}
	for _, region := range p.Regions {
		portal := shared
		if p.dedicatedMultiEdge() {
			portal = "https://" + p.regionPortalName(region.ID)
		}
		for _, plane := range []string{"agents", "recovery"} {
			origins[p.PlaneNamesFor(region.ID)[plane]] = portal
		}
		if p.oneRegionThreeNodes() {
			for _, m := range region.Machines {
				origins["agents."+m.Reachable] = "https://" + p.edgePortalName(m)
			}
		}
	}
	encoded, _ := json.Marshal(origins)
	return string(encoded)
}
