package swg

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
