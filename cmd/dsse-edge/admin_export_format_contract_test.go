package main

import (
	"os"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestExportFormatContractMatchesRequestResponseAndValidator(t *testing.T) {
	data, err := os.ReadFile("../../openapi/admin_api.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	at := func(keys ...string) any {
		var value any = doc
		for _, key := range keys {
			m, ok := value.(map[string]any)
			if !ok {
				t.Fatalf("invalid schema path %v", keys)
			}
			value = m[key]
		}
		return value
	}
	const ref = "#/components/schemas/ExportFormat"
	if at("components", "schemas", "ExportJob", "properties", "format", "$ref") != ref ||
		at("paths", "/admin/export-jobs", "post", "requestBody", "content", "application/json", "schema", "properties", "format", "$ref") != ref {
		t.Fatal("request and response must share the format contract")
	}
	values, ok := at("components", "schemas", "ExportFormat", "enum").([]any)
	if !ok || len(values) != 1 || values[0] != "ndjson" {
		t.Fatalf("unexpected export formats: %v", values)
	}
	for _, format := range []string{"ndjson", "csv", ""} {
		err := validateAdminExportJobRequest(adminExportJobRequest{Stream: "access", Format: format, From: "2026-09-14T00:00:00Z", To: "2026-09-14T01:00:00Z"})
		if (err == nil) != (format != "csv") {
			t.Fatalf("validator disagrees with format contract for %q: %v", format, err)
		}
	}
	if at("components", "schemas", "ExportFormat", "default") != "ndjson" {
		t.Fatal("default format drift")
	}
}
