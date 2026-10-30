package main

import "testing"

func TestMalformedRolloutControlCannotLiftLocalFreeze(t *testing.T) {
	for name, raw := range map[string]string{
		"null":             `null`,
		"trailing_json":    `{"frozen":false} {"frozen":true}`,
		"trailing_garbage": `{"frozen":false} broken`,
		"duplicate":        `{"frozen":true,"frozen":false}`,
		"alias":            `{"frozen":true,"Frozen":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeControl(t, raw)
			rc, err := loadRolloutControl(path)
			if err == nil || !rc.Frozen {
				t.Fatalf("malformed halt file accepted: %+v, %v", rc, err)
			}
		})
	}
}
