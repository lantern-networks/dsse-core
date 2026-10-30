package installprofile

import (
	"strings"
	"testing"
	"time"
)

func TestIssuedProfilePreservesPortalTrustContract(t *testing.T) {
	deploymentRoot, _ := selfSigned(t, "Deployment Root")
	portalRoot, _ := selfSigned(t, "Separate Portal Root")
	for _, tc := range []struct {
		name     string
		operator bool
		anchor   string
	}{
		{"operator-provisioned", true, ""},
		{"separate-private-portal", false, portalRoot},
		{"deployment-fallback", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := Build(Options{Tenant: "tenant-a", TransportURL: "https://agents.example.test", Deployment: DeploymentSpec{
				AnchorPEM: deploymentRoot, StepUpPortalCertificateIsOperators: tc.operator,
				StepUpPortalAnchorPEM: tc.anchor, StepUpPortalOrigins: []string{"https://portal.example.test"},
			}}, time.Now())
			envelope, pin := signProfile(t, profile)
			loaded, verified, err := Load(envelope, pin)
			if err != nil || !verified {
				t.Fatalf("signed profile: verified=%v err=%v", verified, err)
			}
			material, err := DeriveDeployment(loaded.Deployment)
			if err != nil {
				t.Fatal(err)
			}
			wantAnchor := tc.anchor
			if !tc.operator && wantAnchor == "" {
				wantAnchor = deploymentRoot
			}
			if material.StepUpPortalCertificateIsOperators != tc.operator || strings.TrimSpace(string(material.StepUpPortalAnchorPEM)) != strings.TrimSpace(wantAnchor) {
				t.Fatal("issuing the signed profile changed which Portal authority the endpoint must trust")
			}
		})
	}
}
