package edgeplane

import (
	"sync"
	"testing"
)

func TestInspectionPatternsCanChangeWhileRequestsAreMatched(t *testing.T) {
	e := NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for n := 0; n < 200; n++ {
				if worker == 0 {
					e.SetInterceptHosts([]string{"*.example.invalid"})
					e.SetBypassHosts([]string{"excluded.example.invalid"})
				} else {
					e.Matches(NetworkExtensionRuntimeCopyTCPRoute{Host: "app.example.invalid", Port: 443})
					e.InterceptHosts()
					e.BypassHosts()
				}
			}
		}(i)
	}
	wg.Wait()
	if !e.Matches(NetworkExtensionRuntimeCopyTCPRoute{Host: "app.example.invalid", Port: 443}) || e.Matches(NetworkExtensionRuntimeCopyTCPRoute{Host: "excluded.example.invalid", Port: 443}) {
		t.Fatal("runtime patterns disagree")
	}
}
