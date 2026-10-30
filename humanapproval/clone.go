package humanapproval

import (
	"reflect"

	"github.com/lantern-networks/dsse-core/model"
)

// Approval records contain pointers, slices and arbitrary JSON metadata. A
// struct assignment would let a caller change stored authorization after the
// write (or through a read result) without persistence or transition checks.
func cloneApprovalEvent(event model.HumanApprovalEvent) model.HumanApprovalEvent {
	return cloneApprovalValue(reflect.ValueOf(event), map[approvalCloneRef]reflect.Value{}).Interface().(model.HumanApprovalEvent)
}

type approvalCloneRef struct {
	typ reflect.Type
	ptr uintptr
	len int
	cap int
}

func cloneApprovalValue(value reflect.Value, seen map[approvalCloneRef]reflect.Value) reflect.Value {
	if !value.IsValid() {
		return value
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return value
		}
		out := reflect.New(value.Type()).Elem()
		out.Set(cloneApprovalValue(value.Elem(), seen))
		return out
	case reflect.Pointer, reflect.Map, reflect.Slice:
		if value.IsNil() {
			return value
		}
		ref := approvalCloneRef{typ: value.Type(), ptr: value.Pointer()}
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
			out.Elem().Set(cloneApprovalValue(value.Elem(), seen))
			return out
		case reflect.Map:
			out := reflect.MakeMapWithSize(value.Type(), value.Len())
			seen[ref] = out
			iter := value.MapRange()
			for iter.Next() {
				out.SetMapIndex(iter.Key(), cloneApprovalValue(iter.Value(), seen))
			}
			return out
		case reflect.Slice:
			out := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
			seen[ref] = out
			for i := 0; i < value.Len(); i++ {
				out.Index(i).Set(cloneApprovalValue(value.Index(i), seen))
			}
			return out
		}
	case reflect.Array:
		out := reflect.New(value.Type()).Elem()
		for i := 0; i < value.Len(); i++ {
			out.Index(i).Set(cloneApprovalValue(value.Index(i), seen))
		}
		return out
	case reflect.Struct:
		out := reflect.New(value.Type()).Elem()
		out.Set(value)
		for i := 0; i < value.NumField(); i++ {
			if out.Field(i).CanSet() {
				out.Field(i).Set(cloneApprovalValue(value.Field(i), seen))
			}
		}
		return out
	}
	return value
}
