package updateplatform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublisherRequirementRejectsDamagedConfig(t *testing.T) {
	for _, raw := range []string{
		`null`,
		`{"update_publisher_team_id":null}`,
		`{"update_publisher_team_id":"M4U8GSBL6C","update_publisher_team_id":""}`,
		`{"update_publisher_team_id":"M4U8GSBL6C","UPDATE_PUBLISHER_TEAM_ID":""}`,
	} {
		t.Run(raw, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent_config.json")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if req, err := LoadPublisherRequirement(path); err == nil {
				t.Fatalf("damaged config disables publisher check: %+v", req)
			}
		})
	}
}
