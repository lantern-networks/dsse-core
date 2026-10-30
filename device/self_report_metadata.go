package device

import (
	"reflect"

	"github.com/lantern-networks/dsse-core/model"
)

// SelfReportedMetadata removes fields whose authority is the Edge, control plane,
// administrator, or IdP rather than the reporting device. It always makes a new
// map: callers must not retain a request body's mutable map in the store.
func SelfReportedMetadata(metadata map[string]any) map[string]any {
	filtered := make(map[string]any, len(metadata))
	for key, value := range metadata {
		if !authorityOwnedDeviceMetadata(key) {
			filtered[key] = cloneDeviceMetadataValue(value)
		}
	}
	return filtered
}

func authorityOwnedDeviceMetadata(key string) bool {
	switch key {
	case "device_group", "posture_compliant", "posture_trust_source", "posture_failed_signals",
		"risk_state_severity", "admin_high_risk", "risk_state_id", "risk_state_updated_at",
		"risk_recommended_action", "risk_signal_sources", "manual_high_risk",
		"idp_risk_level", "authentication_anomaly":
		return true
	default:
		return false
	}
}

func retainAuthorityOwnedMetadata(target, previous map[string]any) {
	for key, value := range previous {
		if authorityOwnedDeviceMetadata(key) && key != "device_group" && key != "posture_compliant" &&
			key != "posture_trust_source" && key != "posture_failed_signals" {
			target[key] = cloneDeviceMetadataValue(value)
		}
	}
}

func cloneDeviceMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	clone := make(map[string]any, len(metadata))
	for key, value := range metadata {
		clone[key] = cloneDeviceMetadataValue(value)
	}
	return clone
}

// Preserve the types of in-process metadata while severing mutable aliases.
// The wire format normally contains JSON collections, but store callers may
// also supply typed nested maps or slices before encoding the snapshot.
func cloneDeviceMetadataValue(value any) any {
	if value == nil {
		return nil
	}
	return cloneDeviceMetadataReflect(reflect.ValueOf(value), make(map[deviceMetadataReference]reflect.Value)).Interface()
}

type deviceMetadataReference struct {
	typ reflect.Type
	ptr uintptr
	len int
	cap int
}

func cloneDeviceMetadataReflect(value reflect.Value, seen map[deviceMetadataReference]reflect.Value) reflect.Value {
	if !value.IsValid() {
		return value
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		clone := reflect.New(value.Type()).Elem()
		clone.Set(cloneDeviceMetadataReflect(value.Elem(), seen))
		return clone
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		key := deviceMetadataReference{typ: value.Type(), ptr: value.Pointer()}
		if clone, ok := seen[key]; ok {
			return clone
		}
		clone := reflect.MakeMapWithSize(value.Type(), value.Len())
		seen[key] = clone
		iter := value.MapRange()
		for iter.Next() {
			clone.SetMapIndex(iter.Key(), cloneDeviceMetadataReflect(iter.Value(), seen))
		}
		return clone
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		key := deviceMetadataReference{typ: value.Type(), ptr: value.Pointer(), len: value.Len(), cap: value.Cap()}
		if clone, ok := seen[key]; ok {
			return clone
		}
		clone := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		seen[key] = clone
		for i := range value.Len() {
			clone.Index(i).Set(cloneDeviceMetadataReflect(value.Index(i), seen))
		}
		return clone
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		key := deviceMetadataReference{typ: value.Type(), ptr: value.Pointer()}
		if clone, ok := seen[key]; ok {
			return clone
		}
		clone := reflect.New(value.Type().Elem())
		seen[key] = clone
		clone.Elem().Set(cloneDeviceMetadataReflect(value.Elem(), seen))
		return clone
	case reflect.Array:
		clone := reflect.New(value.Type()).Elem()
		for i := range value.Len() {
			clone.Index(i).Set(cloneDeviceMetadataReflect(value.Index(i), seen))
		}
		return clone
	case reflect.Struct:
		clone := reflect.New(value.Type()).Elem()
		clone.Set(value)
		for i := range value.NumField() {
			if clone.Field(i).CanSet() {
				clone.Field(i).Set(cloneDeviceMetadataReflect(value.Field(i), seen))
			}
		}
		return clone
	default:
		return value
	}
}

func cloneDevicePosture(posture *model.DevicePostureSignals) *model.DevicePostureSignals {
	if posture == nil {
		return nil
	}
	clone := *posture
	clone.DiskEncryptionEnabled = cloneDeviceBool(posture.DiskEncryptionEnabled)
	clone.FirewallEnabled = cloneDeviceBool(posture.FirewallEnabled)
	clone.EnforcementAgentHealthy = cloneDeviceBool(posture.EnforcementAgentHealthy)
	return &clone
}

func cloneDeviceBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
