package policyrule

import "testing"

type stubEWResolver struct{}

func (stubEWResolver) SourceDeviceTokens(string, []string) []string { return nil }
func (stubEWResolver) DestinationTokens(string, []string) []string  { return []string{"prod-dc"} }
func (stubEWResolver) ServiceProtocols(string, string) []string     { return []string{"smb"} }

// An authored east-west authenticate rule carries its step-up assurance (required IdP + phishing-resistant
// AMR + freshness) through to the enforcement primitive — the controls that make a lateral hop bite.
func TestCompileEastWestCarriesStepUpAssurance(t *testing.T) {
	rules := []Rule{{
		ID: "r1", TenantID: "t1", Plane: PlaneEastWest, Direction: DirectionOutbound, Status: StatusActive,
		Source: []string{SubjectAny}, Destination: []string{"ep-dc"},
		Action: Action{Access: AccessAuthenticate, RequiredIdPID: "idp_priv", MinACR: "AAL3", RequiredAMR: []string{"phishing_resistant"}, MaxAgeSeconds: 300},
	}}
	out := CompileEastWest("t1", rules, stubEWResolver{})
	if len(out) != 1 {
		t.Fatalf("want 1 compiled rule, got %d", len(out))
	}
	ew := out[0]
	if ew.Mode != AccessAuthenticate || ew.RequiredIdPID != "idp_priv" || ew.MinACR != "AAL3" || ew.MaxAgeSeconds != 300 {
		t.Fatalf("assurance not carried: %+v", ew)
	}
	if len(ew.RequiredAMR) != 1 || ew.RequiredAMR[0] != "phishing_resistant" {
		t.Fatalf("required_amr not carried: %+v", ew.RequiredAMR)
	}
}
