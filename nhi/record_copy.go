package nhi

import "github.com/lantern-networks/dsse-core/model"

func copyIdentity(identity model.NonHumanIdentity) model.NonHumanIdentity {
	copyString := func(value *string) *string {
		if value == nil {
			return nil
		}
		copy := *value
		return &copy
	}
	identity.TrustDomain = copyString(identity.TrustDomain)
	identity.Issuer = copyString(identity.Issuer)
	identity.Subject = copyString(identity.Subject)
	identity.CredentialType = copyString(identity.CredentialType)
	identity.LastUsedAt = copyString(identity.LastUsedAt)
	identity.ExpiresAt = copyString(identity.ExpiresAt)
	identity.AllowedApplicationIDs = append(identity.AllowedApplicationIDs[:0:0], identity.AllowedApplicationIDs...)
	identity.AllowedScopes = append(identity.AllowedScopes[:0:0], identity.AllowedScopes...)
	if identity.Metadata != nil {
		identity.Metadata = copyMetadataValue(identity.Metadata).(map[string]any)
	}
	return identity
}

// Metadata arrives as JSON objects/arrays. Preserve scalar values and copy each
// mutable container, including the typed string containers used by Go callers.
func copyMetadataValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		copy := make(map[string]any, len(value))
		for key, item := range value {
			copy[key] = copyMetadataValue(item)
		}
		return copy
	case []any:
		copy := make([]any, len(value))
		for i, item := range value {
			copy[i] = copyMetadataValue(item)
		}
		return copy
	case map[string]string:
		copy := make(map[string]string, len(value))
		for key, item := range value {
			copy[key] = item
		}
		return copy
	case []string:
		return append(value[:0:0], value...)
	case []byte:
		return append(value[:0:0], value...)
	default:
		return value
	}
}
