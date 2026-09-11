package main

import (
	"reflect"
	"strings"
	"testing"
)

// TestAFreshConnectorAnnouncesNoApplications is the whole point of announcedApplicationIDs: a deployment's
// first connector must not claim to front applications that do not exist. This used to be a hard-coded list
// of five, so a brand-new site's Console showed five private applications nobody had created.
func TestAFreshConnectorAnnouncesNoApplications(t *testing.T) {
	for _, list := range []string{"", "   ", ",", " , ,, "} {
		if got := announcedApplicationIDs(list, false); len(got) != 0 {
			t.Fatalf("announcedApplicationIDs(%q, false) = %v, want none: a connector told nothing fronts nothing", list, got)
		}
	}
}

func TestAnnouncedApplicationsAreWhatTheConnectorWasTold(t *testing.T) {
	got := announcedApplicationIDs(" app_payroll , app_wiki ,", false)
	want := []string{"app_payroll", "app_wiki"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("announcedApplicationIDs = %v, want %v", got, want)
	}
}

// The samples are opt-in, and an explicit list still wins — a lab may serve the sample endpoints while
// announcing only the applications it really fronts.
func TestSampleApplicationsAreOptInAndNeverOverrideAnExplicitList(t *testing.T) {
	if got := announcedApplicationIDs("", true); !reflect.DeepEqual(got, sampleApplicationIDs) {
		t.Fatalf("with -sample-applications and no list, announced = %v, want the five samples", got)
	}
	got := announcedApplicationIDs("app_payroll", true)
	if !reflect.DeepEqual(got, []string{"app_payroll"}) {
		t.Fatalf("an explicit list must win over -sample-applications, got %v", got)
	}
	for _, id := range got {
		if strings.Contains(id, "dummy") {
			t.Fatalf("announced a sample id %q despite an explicit list", id)
		}
	}
}
