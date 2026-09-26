package main

import (
	"errors"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"testing"
)

func TestIdPFailureStillAppliesLaterInspectionSection(t *testing.T) {
	previous := theIdPRegistry.Load()
	t.Cleanup(func() { theIdPRegistry.Store(previous) })
	registry := idpregistry.NewStore()
	p := &allowlistSaveFixture{}
	if err := registry.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	theIdPRegistry.Store(registry)
	p.err = errors.New("save unavailable")
	current := inspectionposture.DefaultPosture()
	next := current
	next.Mode = inspectionposture.ModeBypassDefault
	payload := configBundlePayload{IdPConnections: &idpConnectionBundle{Complete: true, Connections: []idpregistry.Connection{idpFixture("own", "provider")}}, InspectionPosture: &inspectionPostureBundle{Posture: next}}
	targets := configApplyTargets{inspectionPosture: func() inspectionposture.Posture { return current }, setInspectionPosture: func(p inspectionposture.Posture, _ string) (inspectionposture.Posture, error) {
		current = p
		return p, nil
	}}
	src := configBundleSource{}
	if _, err := src.apply(payload, targets); err == nil {
		t.Fatal("failed IdP save acknowledged")
	}
	if current.Mode != next.Mode {
		t.Fatal("IdP save failure prevented later inspection update")
	}
	p.err = nil
	if _, err := src.apply(payload, targets); err != nil {
		t.Fatal(err)
	}
}
