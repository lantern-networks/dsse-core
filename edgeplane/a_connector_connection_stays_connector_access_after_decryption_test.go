package edgeplane

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The request built for the far side of decryption says which plane its connection was opened on.
func TestTheForwardedRequestSaysItsConnectionWasOpenedByConnectorAccess(t *testing.T) {
	for _, connectorAccess := range []bool{true, false} {
		in := httptest.NewRequest(http.MethodGet, "https://app.internal.example/", nil)
		route := NetworkExtensionRuntimeCopyTCPRoute{Host: "app.internal.example", Port: 443, TenantID: "tenant-a", ConnectorAccess: connectorAccess}
		out, err := BuildNetworkExtensionLabTLSForwardRequest(in, route)
		if err != nil {
			t.Fatal(err)
		}
		if got := ConnectorAccessAtOpenFromContext(out.Context()); got != connectorAccess {
			t.Fatalf("route opened by Connector Access = %t, the forwarded request says %t", connectorAccess, got)
		}
		if got := ConnectorSignInDoneForRuleFromContext(out.Context()); got != "" {
			t.Fatalf("a route that completed no sign-in says it did for %q", got)
		}
	}
	in := httptest.NewRequest(http.MethodGet, "https://app.internal.example/", nil)
	out, err := BuildNetworkExtensionLabTLSForwardRequest(in, NetworkExtensionRuntimeCopyTCPRoute{Host: "app.internal.example", Port: 443, TenantID: "tenant-a", ConnectorAccess: true, ConnectorSignInDoneForRule: "rule-signin"})
	if err != nil {
		t.Fatal(err)
	}
	if got := ConnectorSignInDoneForRuleFromContext(out.Context()); got != "rule-signin" {
		t.Fatalf("the rule whose sign-in was completed arrived as %q", got)
	}
}
