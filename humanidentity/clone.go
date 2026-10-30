package humanidentity

import (
	"reflect"

	"github.com/lantern-networks/dsse-core/model"
)

// Directory records and source policies contain mutable metadata and optional
// pointers. Never expose those references across the store boundary: changing
// one could otherwise alter identity or connector policy without a saved write.
func cloneHumanIdentity(user model.HumanIdentity) model.HumanIdentity {
	return cloneDirectoryValue(reflect.ValueOf(user), map[directoryCloneRef]reflect.Value{}).Interface().(model.HumanIdentity)
}

func cloneSourcePolicy(policy HumanIdentitySourcePolicy) HumanIdentitySourcePolicy {
	return cloneDirectoryValue(reflect.ValueOf(policy), map[directoryCloneRef]reflect.Value{}).Interface().(HumanIdentitySourcePolicy)
}

func cloneDirectoryMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	return cloneDirectoryValue(reflect.ValueOf(metadata), map[directoryCloneRef]reflect.Value{}).Interface().(map[string]any)
}

type directoryCloneRef struct {
	typ reflect.Type
	ptr uintptr
	len int
	cap int
}

func cloneDirectoryValue(value reflect.Value, seen map[directoryCloneRef]reflect.Value) reflect.Value {
	if !value.IsValid() {
		return value
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return value
		}
		out := reflect.New(value.Type()).Elem()
		out.Set(cloneDirectoryValue(value.Elem(), seen))
		return out
	case reflect.Pointer, reflect.Map, reflect.Slice:
		if value.IsNil() {
			return value
		}
		ref := directoryCloneRef{typ: value.Type(), ptr: value.Pointer()}
		if value.Kind() == reflect.Slice {
			ref.len, ref.cap = value.Len(), value.Cap()
		}
		if prior, ok := seen[ref]; ok {
			return prior
		}
		switch value.Kind() {
		case reflect.Pointer:
			out := reflect.New(value.Type().Elem())
			seen[ref] = out
			out.Elem().Set(cloneDirectoryValue(value.Elem(), seen))
			return out
		case reflect.Map:
			out := reflect.MakeMapWithSize(value.Type(), value.Len())
			seen[ref] = out
			iter := value.MapRange()
			for iter.Next() {
				out.SetMapIndex(iter.Key(), cloneDirectoryValue(iter.Value(), seen))
			}
			return out
		case reflect.Slice:
			out := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
			seen[ref] = out
			for i := 0; i < value.Len(); i++ {
				out.Index(i).Set(cloneDirectoryValue(value.Index(i), seen))
			}
			return out
		}
	case reflect.Array:
		out := reflect.New(value.Type()).Elem()
		for i := 0; i < value.Len(); i++ {
			out.Index(i).Set(cloneDirectoryValue(value.Index(i), seen))
		}
		return out
	case reflect.Struct:
		out := reflect.New(value.Type()).Elem()
		out.Set(value)
		for i := 0; i < value.NumField(); i++ {
			if out.Field(i).CanSet() {
				out.Field(i).Set(cloneDirectoryValue(value.Field(i), seen))
			}
		}
		return out
	}
	return value
}
