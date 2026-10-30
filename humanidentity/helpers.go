package humanidentity

import (
	"fmt"
	"strings"
	"time"
)

// Small package-local helpers replicated so the directory store carries no edge-glue dependency.

func copyAnyMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	return cloneDirectoryMetadata(input)
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func validateOptionalRFC3339(value *string, field string) error {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(*value)); err != nil {
		return fmt.Errorf("%s must be RFC3339", field)
	}
	return nil
}
