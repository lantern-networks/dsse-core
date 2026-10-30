package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// initialConnectorDoors treats a persisted authoritative withdrawal as an
// empty data-door set. The old enrolment EdgeURL remains a bootstrap fact, not
// permission to reconnect after the deployment withdrew every door.
func initialConnectorDoors(edgeEndpoints, edgeURL, stateDir string, pinnedTLS bool) (*connectorEndpoints, error) {
	if dir := strings.TrimSpace(stateDir); dir != "" {
		st, ok, err := loadConnectorState(filepath.Join(dir, "connector-state.json"))
		if err != nil {
			return nil, err
		}
		if ok && st.DoorListWithdrawn {
			profileDoor := parseConnectorEndpoints(st.ProfileDoorURL)
			if profileDoor.count() != 1 {
				return nil, fmt.Errorf("withdrawn-door profile GET address is missing or ambiguous")
			}
			if err := validateConnectorDoorURLs(profileDoor, pinnedTLS); err != nil {
				return nil, fmt.Errorf("withdrawn-door profile GET address: %w", err)
			}
			return &connectorEndpoints{profileURL: st.ProfileDoorURL}, nil
		}
	}
	doors := parseConnectorEndpoints(edgeEndpoints)
	if doors.count() == 0 {
		doors = parseConnectorEndpoints(edgeURL)
	}
	if err := validateConnectorDoorURLs(doors, pinnedTLS); err != nil {
		return nil, err
	}
	return doors, nil
}
