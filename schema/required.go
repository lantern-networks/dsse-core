package schema

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"time"
)

type document map[string]any

func ValidateRequiredFiles(schemaPath, documentPath string) error {
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	documentData, err := os.ReadFile(documentPath)
	if err != nil {
		return fmt.Errorf("read document: %w", err)
	}
	return ValidateRequired(schemaData, documentData)
}

func ValidateRequired(schemaData, documentData []byte) error {
	var schemaDoc document
	if err := json.Unmarshal(schemaData, &schemaDoc); err != nil {
		return fmt.Errorf("parse schema: %w", err)
	}
	var doc document
	if err := json.Unmarshal(documentData, &doc); err != nil {
		return fmt.Errorf("parse document: %w", err)
	}

	required, err := requiredFields(schemaDoc)
	if err != nil {
		return err
	}
	for _, field := range required {
		if _, ok := doc[field]; !ok {
			return fmt.Errorf("missing required field: %s", field)
		}
	}
	if err := validateProperties(schemaDoc, doc); err != nil {
		return err
	}
	return nil
}

func requiredFields(schemaDoc document) ([]string, error) {
	raw, ok := schemaDoc["required"]
	if !ok {
		return nil, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("schema required must be an array")
	}
	fields := make([]string, 0, len(values))
	for _, value := range values {
		field, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("schema required entries must be strings")
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func validateProperties(schemaDoc, doc document) error {
	rawProperties, ok := schemaDoc["properties"]
	if !ok {
		return nil
	}
	properties, ok := rawProperties.(map[string]any)
	if !ok {
		return fmt.Errorf("schema properties must be an object")
	}
	for field, value := range doc {
		rawProperty, ok := properties[field]
		if !ok {
			continue
		}
		property, ok := rawProperty.(map[string]any)
		if !ok {
			return fmt.Errorf("schema property %s must be an object", field)
		}
		if err := validatePropertyType(field, property["type"], value); err != nil {
			return err
		}
		if err := validatePropertyEnum(field, property["enum"], value); err != nil {
			return err
		}
		if err := validatePropertyFormat(field, property["format"], value); err != nil {
			return err
		}
	}
	return nil
}

func validatePropertyType(field string, rawType, value any) error {
	if rawType == nil {
		return nil
	}
	for _, allowedType := range allowedTypes(rawType) {
		if valueMatchesType(value, allowedType) {
			return nil
		}
	}
	return fmt.Errorf("field %s type is invalid", field)
}

func allowedTypes(rawType any) []string {
	switch typed := rawType.(type) {
	case string:
		return []string{typed}
	case []any:
		values := make([]string, 0, len(typed))
		for _, value := range typed {
			if str, ok := value.(string); ok {
				values = append(values, str)
			}
		}
		return values
	default:
		return nil
	}
}

func valueMatchesType(value any, allowedType string) bool {
	switch allowedType {
	case "null":
		return value == nil
	case "string":
		_, ok := value.(string)
		return ok
	case "integer":
		number, ok := value.(float64)
		return ok && math.Trunc(number) == number
	case "number":
		_, ok := value.(float64)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	default:
		return false
	}
}

func validatePropertyEnum(field string, rawEnum, value any) error {
	if rawEnum == nil {
		return nil
	}
	values, ok := rawEnum.([]any)
	if !ok {
		return fmt.Errorf("schema enum for %s must be an array", field)
	}
	for _, candidate := range values {
		if reflect.DeepEqual(candidate, value) {
			return nil
		}
	}
	return fmt.Errorf("field %s enum value is invalid", field)
}

func validatePropertyFormat(field string, rawFormat, value any) error {
	format, ok := rawFormat.(string)
	if !ok || format != "date-time" || value == nil {
		return nil
	}
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("field %s date-time value must be a string", field)
	}
	if _, err := time.Parse(time.RFC3339, str); err != nil {
		return fmt.Errorf("field %s date-time format is invalid", field)
	}
	return nil
}
