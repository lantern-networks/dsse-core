package main

import "encoding/json"

// The transport caller supplies only certificate-derived tenant/device and
// current admission. None of those may come from the control-frame payload.
func handleAuthResultQuery(store authFlowResultStore, verified bool, tenantID, deviceID string, admitted bool, payload []byte) []byte {
	if !verified || !admitted || store == nil || tenantID == "" || deviceID == "" || len(payload) > 256 {
		return nil
	}
	var query map[string]string
	if json.Unmarshal(payload, &query) != nil || len(query) != 3 {
		return nil
	}
	id, principal, session := query["request_id"], query["os_principal"], query["os_session"]
	if !validAuthResultRequestID(id) || !validAuthOwner(principal, session) {
		return nil
	}
	result, err := store.Lookup(id, tenantID, deviceID, principal, session)
	if err != nil || result == "" {
		return nil
	}
	answer, _ := json.Marshal(map[string]string{"request_id": id, "result": result})
	return answer
}
