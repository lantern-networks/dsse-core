package updateplatform

import (
	"errors"
	"strings"
	"testing"
)

func TestPublisherCommandFailureCannotBecomeSuccess(t *testing.T) {
	for _, failedTool := range []string{"pkgutil", "spctl"} {
		t.Run(failedTool, func(t *testing.T) {
			calls := 0
			run := func(name string, args ...string) (string, error) {
				calls++
				out := realPkgutil
				if strings.HasSuffix(name, "/spctl") {
					out = realSpctl
				}
				if strings.HasSuffix(name, "/"+failedTool) {
					return out, errors.New("tool failed after producing output")
				}
				return out, nil
			}
			if _, err := verifyPublisherWithTool("test.pkg", PublisherRequirement{TeamID: realTeam}, run); !errors.Is(err, ErrPublisherUntrusted) {
				t.Fatalf("failed verification tool accepted: %v", err)
			}
			if failedTool == "pkgutil" && calls != 1 {
				t.Fatal("assessment continued after signature check failed")
			}
		})
	}
	_, err := verifyPublisherWithTool("test.pkg", PublisherRequirement{TeamID: realTeam}, func(name string, args ...string) (string, error) {
		if strings.HasSuffix(name, "/pkgutil") {
			return realPkgutil, nil
		}
		return realSpctl, nil
	})
	if err != nil {
		t.Fatal("successful tools refused:", err)
	}
}
