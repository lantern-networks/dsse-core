package decision

import (
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// LegacyExceptionsFromModel converts stored governance records into the evaluator form, parsing the expiry
// timestamp and defaulting the mode to "allow".
func LegacyExceptionsFromModel(exs []model.LegacyException) []LegacyException {
	out := make([]LegacyException, 0, len(exs))
	for _, ex := range exs {
		var expires time.Time
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(ex.ExpiresAt)); err == nil {
			expires = t
		}
		mode := strings.TrimSpace(ex.Mode)
		if mode == "" {
			mode = "allow"
		}
		out = append(out, LegacyException{
			ID: ex.ID, SourceServer: ex.SourceServer, DeviceGroup: ex.DeviceGroup,
			ServiceFamily: ex.ServiceFamily, Protocol: ex.Protocol, Port: ex.Port,
			Mode: mode, ExpiresAt: expires, Active: strings.EqualFold(strings.TrimSpace(ex.Status), "active"),
		})
	}
	return out
}
