package grantstore

import "encoding/json"

const FeatureSingleRequest = "single-request-v1"
const FeatureDeviceUser = "device-user-session-v1"

// FeatureScopedAuthorization keeps new grants away from released readers that
// do not enforce destination scope. New readers require an exact scope match.
const FeatureScopedAuthorization = "scoped-authorization-v1"
const FeatureRevocationReauthentication = "revocation-reauthentication-v1"

// RequiresModernReader separates rows that the released gate cannot enforce.
// Unknown requirements stay stored/forwarded but are never authorized locally.
func (g Grant) RequiresModernReader() bool {
	return g.ReauthenticateAfter != "" || g.OSPrincipal != "" || g.OSSession != "" || g.AuthenticationRequestID != "" || g.ReauthenticationStartedAt != "" || len(g.RequiredFeatures) > 0
}
func (g Grant) Supported() bool {
	for _, f := range g.RequiredFeatures {
		if f != FeatureSingleRequest && f != FeatureDeviceUser && f != FeatureScopedAuthorization && f != FeatureRevocationReauthentication {
			return false
		}
	}
	return true
}

type grantWire Grant

func (g Grant) MarshalJSON() ([]byte, error) {
	w := grantWire(cloneGrant(g))
	w.UnknownFields = nil
	if g.AuthenticationRequestID != "" {
		found := false
		for _, f := range w.RequiredFeatures {
			if f == FeatureSingleRequest {
				found = true
			}
		}
		if !found {
			w.RequiredFeatures = append(append([]string(nil), w.RequiredFeatures...), FeatureSingleRequest)
		}
	}
	raw, e := json.Marshal(w)
	if e != nil {
		return nil, e
	}
	// The common row has no unknown fields. Avoid decoding and re-encoding every
	// known field into an intermediate map for every row of every snapshot.
	if len(g.UnknownFields) == 0 {
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(raw, &fields); e != nil {
		return nil, e
	}
	for k, v := range g.UnknownFields {
		if !knownGrantFields[k] {
			fields[k] = v
		}
	}
	return json.Marshal(fields)
}
func (g *Grant) UnmarshalJSON(raw []byte) error {
	var w grantWire
	if e := json.Unmarshal(raw, &w); e != nil {
		return e
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	for k := range fields {
		if knownGrantFields[k] {
			delete(fields, k)
		}
	}
	*g = Grant(w)
	if len(fields) > 0 {
		g.UnknownFields = fields
	}
	return nil
}

var knownGrantFields = func() map[string]bool {
	// Derive keys from the wire struct, including omitempty fields, without using
	// Grant's own marshaler or treating unknown JSON names as instructions.
	m := map[string]bool{}
	for _, k := range []string{"os_principal", "os_session", "reauthentication_started_at", "authentication_request_id", "reauthenticate_after", "grant_id", "tenant_id", "user_id", "user_email", "username", "user_display_name", "device_id", "idp_id", "issuer", "provider_config_sha256", "acr", "amr", "auth_time", "scope", "issued_at", "expires_at", "revoked", "consumed_at", "required_features"} {
		m[k] = true
	}
	return m
}()
