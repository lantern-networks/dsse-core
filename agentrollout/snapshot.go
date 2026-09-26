package agentrollout

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrInvalidSnapshot deliberately excludes saved tenant names and incident reasons.
var ErrInvalidSnapshot = errors.New("invalid agent rollout snapshot")

// The snapshot is a tenant map, not a request. In particular, a missing or null
// frozen field is unknown state, never permission to resume a rollout. Validate
// the entire snapshot before replacing the live map or binding a new persister.
func decodeRolloutSnapshot(raw []byte) (map[string]AgentRolloutPlan, error) {
	rows, err := rolloutSnapshotObject(raw)
	if err != nil {
		return nil, err
	}
	plans := make(map[string]AgentRolloutPlan, len(rows))
	for tenant, rawPlan := range rows {
		// The empty key is the legacy single-deployment scope. Keep its halt
		// without reassigning it to any named tenant.
		if tenant != strings.TrimSpace(tenant) {
			return nil, ErrInvalidSnapshot
		}
		fields, err := rolloutSnapshotObject(rawPlan)
		if err != nil {
			return nil, err
		}
		if fields["frozen"] == nil {
			return nil, ErrInvalidSnapshot
		}
		for key, value := range fields {
			switch key {
			case "frozen", "desired_version", "release_channel", "intent", "reason", "updated_at":
				if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					return nil, ErrInvalidSnapshot
				}
			case "waves":
				if err := validateSavedWaves(value); err != nil {
					return nil, err
				}
			case "window":
				if !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					if err := rolloutSnapshotFields(value, []string{"local_start", "local_end", "require_idle_minutes", "require_unattended", "require_ac_power", "deadline_days"}, nil); err != nil {
						return nil, err
					}
				}
			default:
				return nil, ErrInvalidSnapshot
			}
		}
		var plan AgentRolloutPlan
		if json.Unmarshal(rawPlan, &plan) != nil {
			return nil, ErrInvalidSnapshot
		}
		switch plan.Intent {
		case "", AgentRolloutIntentRollout, AgentRolloutIntentRollback, AgentRolloutIntentFreeze, AgentRolloutIntentSchedule, AgentRolloutIntentFollow:
		default:
			return nil, ErrInvalidSnapshot
		}
		if plan.UpdatedAt != "" {
			if _, err := time.Parse(time.RFC3339, plan.UpdatedAt); err != nil {
				return nil, ErrInvalidSnapshot
			}
		}
		if plan.Waves != nil && plan.Waves.Validate() != nil {
			return nil, ErrInvalidSnapshot
		}
		if validateWindow(plan.Window) != nil {
			return nil, ErrInvalidSnapshot
		}
		plans[tenant] = plan
	}
	return plans, nil
}

// Unlike unmarshalling into a map or struct, this rejects duplicate names,
// non-objects and trailing values. Exact field names are checked by each caller.
func rolloutSnapshotObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, ErrInvalidSnapshot
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInvalidSnapshot
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] != nil {
			return nil, ErrInvalidSnapshot
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrInvalidSnapshot
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalidSnapshot
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalidSnapshot
	}
	return fields, nil
}

func rolloutSnapshotFields(raw []byte, required, optional []string) error {
	fields, err := rolloutSnapshotObject(raw)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, key := range required {
		if fields[key] == nil {
			return ErrInvalidSnapshot
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key, value := range fields {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrInvalidSnapshot
		}
	}
	return nil
}

func validateSavedWaves(raw []byte) error {
	// Nil schedules, nil wave slices and a nil default are emitted by the
	// existing producer. Keep those distinct from missing delay/group fields.
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	fields, err := rolloutSnapshotObject(raw)
	if err != nil || fields["waves"] == nil {
		return ErrInvalidSnapshot
	}
	for key := range fields {
		if key != "waves" && key != "default_delay_days" {
			return ErrInvalidSnapshot
		}
	}
	var rows []json.RawMessage
	if json.Unmarshal(fields["waves"], &rows) != nil {
		return ErrInvalidSnapshot
	}
	for _, row := range rows {
		if err := rolloutSnapshotFields(row, []string{"group", "delay_days"}, []string{"priority"}); err != nil {
			return err
		}
	}
	return nil
}
