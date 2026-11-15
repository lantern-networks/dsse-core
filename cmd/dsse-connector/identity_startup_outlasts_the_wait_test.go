package main

import (
	"os"
	"strings"
	"testing"
)

// A first run tells the operator how long it will wait for its Site to reach the Edge. The start-up context
// must not end before that, or the promise in the log is cut short by a deadline the operator never sees.
func TestConnectorIdentityStartupOutlastsThePropagationWait(t *testing.T) {
	if connectorIdentityStartupTimeout <= connectorEnrolmentPropagationWait {
		t.Fatalf("start-up allows %s for the identity but the enrolment wait promises %s",
			connectorIdentityStartupTimeout, connectorEnrolmentPropagationWait)
	}
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	call := "return ensureConnectorIdentity(ctx, "
	i := strings.Index(string(src), call)
	if i < 0 {
		t.Fatalf("main.go no longer calls %q; point this test at the new call site", call)
	}
	before := string(src[:i])
	j := strings.LastIndex(before, "context.WithTimeout(")
	if j < 0 || !strings.Contains(before[j:], "connectorIdentityStartupTimeout") {
		t.Fatalf("the context given to ensureConnectorIdentity is not bounded by connectorIdentityStartupTimeout")
	}
}
