package schema

import "testing"

func TestValidateRequiredAcceptsCompleteDocument(t *testing.T) {
	schemaData := []byte(`{"required":["id","tenant_id"]}`)
	documentData := []byte(`{"id":"pol_001","tenant_id":"tenant_001"}`)

	if err := ValidateRequired(schemaData, documentData); err != nil {
		t.Fatalf("ValidateRequired returned error: %v", err)
	}
}

func TestValidateRequiredRejectsMissingField(t *testing.T) {
	schemaData := []byte(`{"required":["id","tenant_id"]}`)
	documentData := []byte(`{"id":"pol_001"}`)

	err := ValidateRequired(schemaData, documentData)
	if err == nil {
		t.Fatal("ValidateRequired returned nil, want missing field error")
	}
}

func TestValidateRequiredRejectsInvalidType(t *testing.T) {
	schemaData := []byte(`{
		"required":["id","priority"],
		"properties":{
			"id":{"type":"string"},
			"priority":{"type":"integer"}
		}
	}`)
	documentData := []byte(`{"id":"pol_001","priority":"high"}`)

	err := ValidateRequired(schemaData, documentData)
	if err == nil {
		t.Fatal("ValidateRequired returned nil, want invalid type error")
	}
}

func TestValidateRequiredRejectsInvalidEnum(t *testing.T) {
	schemaData := []byte(`{
		"required":["status"],
		"properties":{"status":{"type":"string","enum":["active","paused"]}}
	}`)
	documentData := []byte(`{"status":"draft"}`)

	err := ValidateRequired(schemaData, documentData)
	if err == nil {
		t.Fatal("ValidateRequired returned nil, want invalid enum error")
	}
}

func TestValidateRequiredRejectsInvalidDateTime(t *testing.T) {
	schemaData := []byte(`{
		"required":["created_at"],
		"properties":{"created_at":{"type":"string","format":"date-time"}}
	}`)
	documentData := []byte(`{"created_at":"2026/05/22"}`)

	err := ValidateRequired(schemaData, documentData)
	if err == nil {
		t.Fatal("ValidateRequired returned nil, want invalid date-time error")
	}
}
